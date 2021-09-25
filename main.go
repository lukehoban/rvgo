package main

import (
	"bytes"
	"debug/elf"
	_ "embed"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/gdamore/tcell/v2"
)

var MEMORYBASE uint64 = 0x80000000

var DEBUG = false
var debugFile *os.File

const (
	FFLAGS = 0x001
	FRM    = 0x002
	FCSR   = 0x003

	MVENDORID = 0xF11
	MARCHID   = 0xF12
	MIMPID    = 0xF13
	MHARTID   = 0xF14

	MSTATUS    = 0x300
	MISA       = 0x301
	MEDELEG    = 0x302
	MIDELEG    = 0x303
	MIE        = 0x304
	MTVEC      = 0x305
	MCOUNTEREN = 0x306
	MSCRATCH   = 0x340
	MEPC       = 0x341
	MCAUSE     = 0x342
	MTVAL      = 0x343
	MIP        = 0x344

	SSTATUS    = 0x100
	SEDELEG    = 0x102
	SIDELEG    = 0x103
	SIE        = 0x104
	STVEC      = 0x105
	SCOUNTEREN = 0x106
	SSCRATCH   = 0x140
	SEPC       = 0x141
	SCAUSE     = 0x142
	STVAL      = 0x143
	SIP        = 0x144
	SATP       = 0x180

	USTATUS  = 0x000
	UIE      = 0x004
	UTVEC    = 0x005
	USCRATCH = 0x040
	UEPC     = 0x041
	UCAUSE   = 0x042
	UTVAL    = 0x043
	UIP      = 0x044

	CYCLE   = 0xC00
	TIME    = 0xC01
	INSTRET = 0xC02
)

const (
	MIP_MEIP = 0x800
	MIP_MTIP = 0x080
	MIP_MSIP = 0x008
	MIP_SEIP = 0x200
	MIP_STIP = 0x020
	MIP_SSIP = 0x002
)

type Privilege uint8

const (
	User       Privilege = 0
	Supervisor Privilege = 1
	Hypervisor Privilege = 2
	Machine    Privilege = 3
)

type AddressMode uint8

const (
	None AddressMode = 0
	SV39 AddressMode = 8
	SV48 AddressMode = 9
)

type Access uint8

const (
	Read    Access = 0
	Write   Access = 1
	Execute Access = 2
	Unknown Access = 3
)

//go:embed dtb/dtb.dtb
var dtb []byte

type CPU struct {
	pc    uint64
	mem   []byte
	mem32 []uint32
	mem64 []uint64
	x     [32]int64
	f     [32]float64
	csr   [4096]uint64
	priv  Privilege
	mode  AddressMode
	wfi   bool

	reservation    uint64
	reservationSet bool

	uart  *Uart
	plic  Plic
	clint Clint
	disk  VirtioBlock

	count uint64
}

func NewCPU(mem []byte, pc uint64, disk []byte, screen tcell.Screen) CPU {
	cpu := CPU{
		pc:    pc,
		mem:   mem,
		mem32: *((*[]uint32)(unsafe.Pointer(&mem))),
		mem64: *((*[]uint64)(unsafe.Pointer(&mem))),
		priv:  Machine,
		uart:  NewUart(screen),
		plic:  NewPlic(),
		clint: NewClint(),
	}
	cpu.disk = NewVirtioBlock(disk, &cpu)

	// TODO: Why?
	cpu.x[0xb] = 0x1020
	cpu.writecsr(MISA, 0x800000008014312f)
	return cpu
}

func (cpu *CPU) run() {
	for {
		cpu.step()
	}
}

func (cpu *CPU) step() {
	addr := cpu.pc
	ok, trap := cpu.stepInner()
	if !ok {
		cpu.exception(trap, addr)
	}

	cpu.count++
	cpu.disk.step()
	cpu.uart.step(cpu.count)
	cpu.clint.step(cpu.count, &cpu.csr[MIP])
	cpu.plic.step(cpu.count, cpu.uart.interrupting, cpu.disk.interruptStatus&0b1 == 1, &cpu.csr[MIP])

	cpu.interrupt(cpu.pc)

	cpu.csr[CYCLE] = cpu.count * 8
}

func (cpu *CPU) stepInner() (bool, Trap) {
	if cpu.wfi {
		if cpu.readcsr(MIE)&cpu.readcsr(MIP) != 0 {
			cpu.wfi = false
		}
		return true, Trap{}
	}
	instr, ok, trap := cpu.fetch()
	if !ok {
		cpu.pc += 4 // TODO: okay?
		return false, trap
	}

	addr := cpu.pc

	if DEBUG {
		// if cpu.count > 10084750 {
		if cpu.count%100000 == 0 {
			var regs []string
			for _, r := range cpu.x {
				regs = append(regs, fmt.Sprintf("%x", uint64(r)))
			}
			// memHash := sha1.Sum(cpu.mem)
			// csrSlice := cpu.csr[:]
			// csrBytes := *((*[]uint8)(unsafe.Pointer(&csrSlice)))
			// csrHash := sha1.Sum(csrBytes)
			// fmt.Fprintf(debugFile, "%08d -- [%08x]: %08x [%s] mem=%0x csrs=%0x\n", cpu.count, cpu.pc, instr, strings.Join(regs, ", "), memHash, csrHash)
			fmt.Fprintf(debugFile, "%08d -- [%08x]: %08x [%s]\n", cpu.count, cpu.pc, instr, strings.Join(regs, ", "))
		}
	}

	if instr&0b11 == 0b11 {
		cpu.pc += 4
	} else {
		cpu.pc += 2
		instr = cpu.decompress(instr & 0xFFFF)
	}
	ok, trap = cpu.exec(instr, addr)
	cpu.x[0] = 0
	if !ok {
		return false, trap
	}
	return true, Trap{}
}

func (cpu *CPU) fetch() (uint32, bool, Trap) {
	v := uint32(0)
	if cpu.pc&0xfff <= 0x1000-4 { // instruction is within a single page
		paddr, ok := cpu.virtualToPhysical(cpu.pc, Execute)
		if !ok {
			return 0, false, Trap{reason: InstructionPageFault, value: cpu.pc}
		}
		if paddr >= MEMORYBASE && paddr%4 == 0 {
			memaddr := paddr - MEMORYBASE
			v = uint32(cpu.mem32[memaddr/4])
		} else {
			for i := uint64(0); i < 4; i++ {
				x := cpu.readphysical(paddr + i)
				v |= uint32(x) << (i * 8)
			}
		}
	} else { // instruction is across two pages
		for i := uint64(0); i < 4; i++ {
			paddr, ok := cpu.virtualToPhysical(cpu.pc+i, Execute)
			if !ok {
				return 0, false, Trap{reason: InstructionPageFault, value: cpu.pc + i}
			}
			x := cpu.readphysical(paddr)
			v |= uint32(x) << (i * 8)
		}
	}
	return v, true, Trap{}
}

type TrapReason uint64

const (
	UserSoftwareInterrupt       TrapReason = 0x8000000000000000
	SupervisorSoftwareInterrupt TrapReason = 0x8000000000000001
	HypervisorSoftwareInterrupt TrapReason = 0x8000000000000002
	MachineSoftwareInterrupt    TrapReason = 0x8000000000000003
	UserTimerInterrupt          TrapReason = 0x8000000000000004
	SupervisorTimerInterrupt    TrapReason = 0x8000000000000005
	HypervisorTimerInterrupt    TrapReason = 0x8000000000000006
	MachineTimerInterrupt       TrapReason = 0x8000000000000007
	UserExternalInterrupt       TrapReason = 0x8000000000000008
	SupervisorExternalInterrupt TrapReason = 0x8000000000000009
	HypervisorExternalInterrupt TrapReason = 0x800000000000000A
	MachineExternalInterrupt    TrapReason = 0x800000000000000B

	InstructionAddressMisaligned TrapReason = 0x0000000000000000
	InstructionAccessFault       TrapReason = 0x0000000000000001
	IllegalInstruction           TrapReason = 0x0000000000000002
	Breakpoint                   TrapReason = 0x0000000000000003
	LoadAddressMisaligned        TrapReason = 0x0000000000000004
	LoadAccessFault              TrapReason = 0x0000000000000005
	StoreAddressMisaligned       TrapReason = 0x0000000000000006
	StoreAccessFault             TrapReason = 0x0000000000000007
	EnvironmentCallFromUMode     TrapReason = 0x0000000000000008
	EnvironmentCallFromSMode     TrapReason = 0x0000000000000009
	EnvironmentCallFromHMode     TrapReason = 0x000000000000000A
	EnvironmentCallFromMMode     TrapReason = 0x000000000000000B
	InstructionPageFault         TrapReason = 0x000000000000000C
	LoadPageFault                TrapReason = 0x000000000000000D
	StorePageFault               TrapReason = 0x000000000000000F
)

type Trap struct {
	reason TrapReason
	value  uint64
}

func (cpu *CPU) exception(trap Trap, instructionaddr uint64) {
	cpu.trap(trap.reason, trap.value, instructionaddr, false)
}

func (cpu *CPU) interrupt(pc uint64) {
	minterrupt := cpu.readcsr(MIP) & cpu.readcsr(MIE)
	if minterrupt&MIP_MEIP != 0 {
		panic("nyi - handle MachineExternalInterrupt")
	}
	if minterrupt&MIP_MSIP != 0 {
		panic("nyi - handle MachineSoftwareInterrupt")
	}
	if minterrupt&MIP_MTIP != 0 {
		traptaken := cpu.trap(MachineTimerInterrupt, cpu.pc, pc, true)
		if traptaken {
			cpu.writecsr(MIP, cpu.readcsr(MIP)&^MIP_MTIP)
			cpu.wfi = false
		}
	}
	if minterrupt&MIP_SEIP != 0 {
		traptaken := cpu.trap(SupervisorExternalInterrupt, cpu.pc, pc, true)
		if traptaken {
			cpu.writecsr(MIP, cpu.readcsr(MIP)&^MIP_SEIP)
			cpu.wfi = false
		}
	}
	if minterrupt&MIP_SSIP != 0 {
		panic("nyi - handle SupervisorSoftwareInterrupt")
	}
	if minterrupt&MIP_STIP != 0 {
		traptaken := cpu.trap(SupervisorTimerInterrupt, cpu.pc, pc, true)
		if traptaken {
			cpu.writecsr(MIP, cpu.readcsr(MIP)&^MIP_STIP)
			cpu.wfi = false
		}
	}
}

func (cpu *CPU) trap(reason TrapReason, value, addr uint64, isInterrupt bool) bool {
	// if reason != 0x8000000000000007 && reason != 0x8000000000000005 {
	// if reason == 0x8000000000000009 {
	// 	fmt.Fprintf(debugFile, "Handling trap: %d, %08x, %08x, %08x\n", cpu.count, reason, value, addr)
	// }
	var mdeleg, sdeleg uint64
	if isInterrupt {
		mdeleg, sdeleg = cpu.readcsr(MIDELEG), cpu.readcsr(SIDELEG)
	} else {
		mdeleg, sdeleg = cpu.readcsr(MEDELEG), cpu.readcsr(SEDELEG)
	}
	pos := uint64(reason) & 0xFFFF

	fromPriv := cpu.priv
	var handlePriv Privilege
	var status, ie uint64
	var epcAddr, causeAddr, tvalAddr, tvecAddr uint16
	if (mdeleg>>pos)&1 == 0 {
		handlePriv = Machine
		status = cpu.readcsr(MSTATUS)
		ie = cpu.readcsr(MIE)
		epcAddr, causeAddr, tvalAddr, tvecAddr = MEPC, MCAUSE, MTVAL, MTVEC
	} else if (sdeleg>>pos)&1 == 0 {
		handlePriv = Supervisor
		status = cpu.readcsr(SSTATUS)
		ie = cpu.readcsr(SIE)
		epcAddr, causeAddr, tvalAddr, tvecAddr = SEPC, SCAUSE, STVAL, STVEC
	} else {
		handlePriv = User
		status = cpu.readcsr(USTATUS)
		ie = cpu.readcsr(UIE)
		epcAddr, causeAddr, tvalAddr, tvecAddr = UEPC, UCAUSE, UTVAL, UTVEC
	}

	if isInterrupt {
		if handlePriv < fromPriv {
			return false
		} else if handlePriv == fromPriv {
			switch fromPriv {
			case Machine:
				if (status>>3)&1 == 0 {
					return false
				}
			case Supervisor:
				if (status>>1)&1 == 0 {
					return false
				}
			case User:
				if (status>>0)&1 == 0 {
					return false
				}
			default:
				panic("invalid privilege")
			}
		}
		switch reason {
		case UserSoftwareInterrupt:
			if (ie>>0)&1 == 0 {
				return false
			}
		case SupervisorSoftwareInterrupt:
			if (ie>>1)&1 == 0 {
				return false
			}
		case MachineSoftwareInterrupt:
			if (ie>>3)&1 == 0 {
				return false
			}
		case UserTimerInterrupt:
			if (ie>>4)&1 == 0 {
				return false
			}
		case SupervisorTimerInterrupt:
			if (ie>>5)&1 == 0 {
				return false
			}
		case MachineTimerInterrupt:
			if (ie>>7)&1 == 0 {
				return false
			}
		case UserExternalInterrupt:
			if (ie>>8)&1 == 0 {
				return false
			}
		case SupervisorExternalInterrupt:
			if (ie>>9)&1 == 0 {
				return false
			}
		case MachineExternalInterrupt:
			if (ie>>11)&1 == 0 {
				return false
			}
		}
	}

	cpu.priv = handlePriv
	cpu.writecsr(epcAddr, addr)
	cpu.writecsr(causeAddr, uint64(reason))
	cpu.writecsr(tvalAddr, value)
	cpu.pc = cpu.readcsr(tvecAddr)
	if (cpu.pc & 0b11) != 0 {
		panic("vector type address")
		cpu.pc = (cpu.pc>>2)<<2 + (4 * (uint64(reason) & 0xFFFF))
	}

	switch cpu.priv {
	case Machine:
		status := cpu.readcsr(MSTATUS)
		mie := (status >> 3) & 0b1
		status = (status &^ 0x1888) | mie<<7 | uint64(fromPriv)<<11
		cpu.writecsr(MSTATUS, status)
	case Supervisor:
		status := cpu.readcsr(SSTATUS)
		sie := (status >> 1) & 0b1
		status = (status &^ 0x122) | sie<<5 | uint64(fromPriv&1)<<8
		cpu.writecsr(SSTATUS, status)
	case User:
		panic("nyi - user mode exception handler")
	default:
		panic("invalid privilege")
	}

	return true
}

type I struct {
	imm    int32
	rs1    uint32
	funct3 uint32
	rd     uint32
}

func parseI(instr uint32) I {
	imm := uint32(0)
	if (instr>>31)&0b1 == 0b1 {
		imm = 0xfffff800
	}
	return I{
		imm:    int32(imm | (instr>>20)&0x000007ff),
		rs1:    (instr >> 15) & 0b11111,
		funct3: (instr >> 12) & 0b111,
		rd:     (instr >> 7) & 0b11111,
	}
}

type S struct {
	imm    int32
	rs1    uint32
	funct3 uint32
	rs2    uint32
}

func parseS(instr uint32) S {
	imm := uint32(0)
	if (instr>>31)&0b1 == 0b1 {
		imm = 0xfffff800
	}
	return S{
		imm:    int32(imm | ((instr>>25)&0x3f)<<5 | (instr>>7)&0x1f), // 1 + 6 + 5
		rs1:    (instr >> 15) & 0b11111,                              // 5
		rs2:    (instr >> 20) & 0b11111,                              // 5
		funct3: (instr >> 12) & 0b111,                                // 3
	}
}

type B struct {
	imm    int32
	rs1    uint32
	funct3 uint32
	rs2    uint32
}

func parseB(instr uint32) B {
	imm := uint32(0)
	if (instr>>31)&0b1 == 0b1 {
		imm = 0xfffff000
	}
	return B{
		imm:    int32(imm | ((instr>>25)&0x3f)<<5 | (instr>>7)&0x1e | (instr>>7)&0b1<<11), // 1 + 6 + 4 + 1
		rs1:    (instr >> 15) & 0b11111,                                                   // 5
		rs2:    (instr >> 20) & 0b11111,                                                   // 5
		funct3: (instr >> 12) & 0b111,                                                     // 3
	}
}

type U struct {
	imm int64
	rd  uint32
}

func parseU(instr uint32) U {
	imm := uint64(0)
	if (instr>>31)&0b1 == 0b1 {
		imm = 0xffffffff00000000
	}
	return U{
		imm: int64(imm | uint64(instr)&0xfffff000),
		rd:  (instr >> 7) & 0b11111,
	}
}

type J struct {
	imm int32
	rd  uint32
}

func parseJ(instr uint32) J {
	imm := uint32(0)
	if (instr>>31)&0b1 == 0b1 {
		imm = 0xfff00000
	}
	return J{
		imm: int32(imm | (instr & 0x000ff000) | (instr&0x00100000)>>9 | (instr&0x7fe00000)>>20),
		rd:  (instr >> 7) & 0b11111,
	}
}

type CSR struct {
	csr    uint32
	rs     uint32
	funct3 uint32
	rd     uint32
}

func parseCSR(instr uint32) CSR {
	return CSR{
		csr:    (instr >> 20) & 0x00000fff,
		rs:     (instr >> 15) & 0b11111,
		funct3: (instr >> 12) & 0b111,
		rd:     (instr >> 7) & 0b11111,
	}
}

type R struct {
	funct7 uint32
	rs2    uint32
	rs1    uint32
	funct3 uint32
	rd     uint32
}

func parseR(instr uint32) R {
	return R{
		funct7: (instr >> 25) & 0b1111111,
		rs2:    (instr >> 20) & 0b11111,
		rs1:    (instr >> 15) & 0b11111,
		funct3: (instr >> 12) & 0b111,
		rd:     (instr >> 7) & 0b11111,
	}
}

func (cpu *CPU) exec(instr uint32, addr uint64) (bool, Trap) {
	switch instr & 0x7f {
	case 0b0110111: // LUI
		op := parseU(instr)
		cpu.x[op.rd] = int64(op.imm)
	case 0b0010111: // AUIPC
		op := parseU(instr)
		cpu.x[op.rd] = int64(addr) + op.imm
	case 0b1101111: // JAL
		op := parseJ(instr)
		cpu.x[op.rd] = int64(cpu.pc)
		cpu.pc = addr + uint64(int64(op.imm))
	case 0b1100111: // JALR
		op := parseI(instr)
		rd := op.rd
		// TODO: Check on this?
		// if rd == 0 {
		// 	rd = 1
		// }
		t := int64(cpu.pc)
		cpu.pc = (uint64(cpu.x[op.rs1]+int64(op.imm)) >> 1) << 1
		cpu.x[rd] = t
	case 0b1100011:
		op := parseB(instr)
		switch op.funct3 {
		case 0b000: // BEQ
			if cpu.x[op.rs1] == cpu.x[op.rs2] {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b001: // BNE
			if cpu.x[op.rs1] != cpu.x[op.rs2] {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b100: // BLT
			if cpu.x[op.rs1] < cpu.x[op.rs2] {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b101: // BGE
			if cpu.x[op.rs1] >= cpu.x[op.rs2] {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b110: // BLTU
			if uint64(cpu.x[op.rs1]) < uint64(cpu.x[op.rs2]) {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b111: // BGEU
			if uint64(cpu.x[op.rs1]) >= uint64(cpu.x[op.rs2]) {
				cpu.pc = addr + uint64(op.imm)
			}
		default:
			panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
		}
	case 0b0000011:
		op := parseI(instr)
		switch op.funct3 {
		case 0b000: // LB
			data, ok, trap := cpu.readuint8(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, trap
			}
			cpu.x[op.rd] = int64(int8(data))
		case 0b001: // LH
			data, ok, trap := cpu.readuint16(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, trap
			}
			cpu.x[op.rd] = int64(int16(data))
		case 0b010: // LW
			data, ok, trap := cpu.readuint32(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, trap
			}
			cpu.x[op.rd] = int64(int32(data))
		case 0b100: // LBU
			data, ok, trap := cpu.readuint8(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, trap
			}
			cpu.x[op.rd] = int64(data)
		case 0b101: // LHU
			data, ok, trap := cpu.readuint16(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, trap
			}
			cpu.x[op.rd] = int64(data)
		case 0b011: // LD
			data, ok, trap := cpu.readuint64(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, trap
			}
			cpu.x[op.rd] = int64(data)
		case 0b110: // LWU
			data, ok, trap := cpu.readuint32(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, trap
			}
			cpu.x[op.rd] = int64(uint64(data))
		default:
			panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
		}
	case 0b0100011:
		op := parseS(instr)
		switch op.funct3 {
		case 0b000: // SB
			ok, trap := cpu.writeuint8(uint64(cpu.x[op.rs1]+int64(op.imm)), uint8(cpu.x[op.rs2]))
			if !ok {
				return false, trap
			}
		case 0b001: // SH
			ok, trap := cpu.writeuint16(uint64(cpu.x[op.rs1]+int64(op.imm)), uint16(cpu.x[op.rs2]))
			if !ok {
				return false, trap
			}
		case 0b010: // SW
			ok, trap := cpu.writeuint32(uint64(cpu.x[op.rs1]+int64(op.imm)), uint32(cpu.x[op.rs2]))
			if !ok {
				return false, trap
			}
		case 0b011: // SD
			ok, trap := cpu.writeuint64(uint64(cpu.x[op.rs1]+int64(op.imm)), uint64(cpu.x[op.rs2]))
			if !ok {
				return false, trap
			}
		default:
			panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
		}
	case 0b0010011:
		op := parseI(instr)
		switch op.funct3 {
		case 0b000: // ADDI
			cpu.x[op.rd] = cpu.x[op.rs1] + int64(op.imm)
		case 0b010: // SLTI
			if cpu.x[op.rs1] < int64(op.imm) {
				cpu.x[op.rd] = 1
			} else {
				cpu.x[op.rd] = 0
			}
		case 0b011: // SLTIU
			if uint64(cpu.x[op.rs1]) < uint64(int64(op.imm)) {
				cpu.x[op.rd] = 1
			} else {
				cpu.x[op.rd] = 0
			}
		case 0b100: // XORI
			cpu.x[op.rd] = cpu.x[op.rs1] ^ int64(op.imm)
		case 0b110: // ORI
			cpu.x[op.rd] = cpu.x[op.rs1] | int64(op.imm)
		case 0b111: // ANDI
			cpu.x[op.rd] = cpu.x[op.rs1] & int64(op.imm)
		case 0b001: // SLLI
			if op.imm>>6 != 0 {
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
			cpu.x[op.rd] = cpu.x[op.rs1] << op.imm
		case 0b101:
			switch op.imm >> 6 {
			case 0: // SRLI
				cpu.x[op.rd] = int64(uint64(cpu.x[op.rs1]) >> (op.imm & 0b111111))
			case 0b010000: // SRAI
				cpu.x[op.rd] = cpu.x[op.rs1] >> (op.imm & 0b111111)
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		default:
			panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
		}
	case 0b0110011:
		op := parseR(instr)
		switch op.funct3 {
		case 0b000:
			switch op.funct7 {
			case 0b0000000: // ADD
				cpu.x[op.rd] = cpu.x[op.rs1] + cpu.x[op.rs2]
			case 0b0100000: // SUB
				cpu.x[op.rd] = cpu.x[op.rs1] - cpu.x[op.rs2]
			case 0b0000001: // MUL
				cpu.x[op.rd] = cpu.x[op.rs1] * cpu.x[op.rs2]
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b001:
			switch op.funct7 {
			case 0: // SLL
				cpu.x[op.rd] = cpu.x[op.rs1] << (cpu.x[op.rs2] & 0b111111)
			case 1: // MULH
				panic("nyi - MULH")
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b010:
			switch op.funct7 {
			case 0: // SLT
				if cpu.x[op.rs1] < cpu.x[op.rs2] {
					cpu.x[op.rd] = 1
				} else {
					cpu.x[op.rd] = 0
				}
			case 1: // MULHSU
				panic("nyi - MULHSU")
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b011:
			switch op.funct7 {
			case 0: // SLTU
				if uint64(cpu.x[op.rs1]) < uint64(cpu.x[op.rs2]) {
					cpu.x[op.rd] = 1
				} else {
					cpu.x[op.rd] = 0
				}
			case 1: // MULHU
				a := uint64(cpu.x[op.rs1])
				b := uint64(cpu.x[op.rs2])
				alo := a & 0xffffffff
				ahi := (a >> 32) & 0xffffffff
				blo := b & 0xffffffff
				bhi := (b >> 32) & 0xffffffff
				axbhi := ahi * bhi
				axbmid := ahi * blo
				bxamid := alo * bhi
				axblo := alo * blo
				carry := (uint64(uint32(axbmid)) + uint64(uint32(bxamid)) + axblo>>32) >> 32
				cpu.x[op.rd] = int64(axbhi + axbmid>>32 + bxamid>>32 + carry)
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b100:
			switch op.funct7 {
			case 0: // XOR
				cpu.x[op.rd] = cpu.x[op.rs1] ^ cpu.x[op.rs2]
			case 1: // DIV
				op := parseR(instr)
				a1 := cpu.x[op.rs1]
				a2 := cpu.x[op.rs2]
				if a2 == 0 {
					cpu.x[op.rd] = -1
				} else if a1 == math.MinInt64 && a2 == -1 {
					cpu.x[op.rd] = a1
				} else {
					cpu.x[op.rd] = a1 / a2
				}
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b101:
			switch op.funct7 {
			case 0: // SRL
				cpu.x[op.rd] = int64(uint64(cpu.x[op.rs1]) >> (cpu.x[op.rs2] & 0b111111))
			case 0b0100000: // SRA
				cpu.x[op.rd] = cpu.x[op.rs1] >> (cpu.x[op.rs2] & 0b111111)
			case 1: // DIVU
				op := parseR(instr)
				a1 := uint64(cpu.x[op.rs1])
				a2 := uint64(cpu.x[op.rs2])
				if a2 == 0 {
					cpu.x[op.rd] = -1
				} else {
					cpu.x[op.rd] = int64(a1 / a2)
				}
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b110:
			switch op.funct7 {
			case 0: // OR
				cpu.x[op.rd] = cpu.x[op.rs1] | cpu.x[op.rs2]
			case 1: // REM
				op := parseR(instr)
				a1 := cpu.x[op.rs1]
				a2 := cpu.x[op.rs2]
				if a2 == 0 {
					cpu.x[op.rd] = a1
				} else if a1 == math.MinInt64 && a2 == -1 {
					cpu.x[op.rd] = 0
				} else {
					cpu.x[op.rd] = a1 % a2
				}
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b111:
			switch op.funct7 {
			case 0: // AND
				cpu.x[op.rd] = cpu.x[op.rs1] & cpu.x[op.rs2]
			case 1: // REMU
				op := parseR(instr)
				a1 := uint64(cpu.x[op.rs1])
				a2 := uint64(cpu.x[op.rs2])
				if a2 == 0 {
					cpu.x[op.rd] = int64(a1)
				} else {
					cpu.x[op.rd] = int64(a1 % a2)
				}
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		default:
			panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
		}
	case 0b0001111: // FENCE/FENCE.I
		// TODO: Is it okay to do nothing?
	case 0b1110011:
		op := parseCSR(instr)
		switch op.funct3 {
		case 0b000:
			if op.rd != 0 {
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
			switch op.csr {
			case 0: // ECALL
				switch cpu.priv {
				case User:
					return false, Trap{reason: EnvironmentCallFromUMode, value: addr}
				case Supervisor:
					return false, Trap{reason: EnvironmentCallFromSMode, value: addr}
				case Hypervisor:
					return false, Trap{reason: EnvironmentCallFromHMode, value: addr}
				case Machine:
					return false, Trap{reason: EnvironmentCallFromMMode, value: addr}
				default:
					panic("invalid CPU privilege")
				}
			case 1:
				panic("nyi - EBREAK")
			case 0b000000000010: // URET
				panic("nyi - URET")
			case 0b000100000010: // SRET
				cpu.pc = cpu.readcsr(SEPC)
				status := cpu.readcsr(SSTATUS)
				cpu.priv = Privilege((status >> 8) & 0b1)
				spie := (status >> 5) & 0b1
				var mpriv uint64
				if cpu.priv == Machine {
					mpriv = (status >> 17) & 0b1
				}
				status = status&^0x20122 | mpriv<<17 | spie<<1 | 1<<5
				cpu.writecsr(SSTATUS, status)
			case 0b001100000010: // MRET
				cpu.pc = cpu.readcsr(MEPC)
				status := cpu.readcsr(MSTATUS)
				cpu.priv = Privilege((status >> 11) & 0b11)
				mpie := (status >> 7) & 0b1
				var mpriv uint64
				if cpu.priv == Machine {
					mpriv = (status >> 17) & 0b1
				}
				status = status&^0x21888 | mpriv<<17 | mpie<<3 | 1<<7
				cpu.writecsr(MSTATUS, status)
			case 0b000100000101: // WFI
				cpu.wfi = true
			default:
				switch op.csr >> 5 {
				case 0b0001001: // SFENCE.VMA
					// TODO: Is it okat to do nothing?
				case 0b0010001:
					panic("nyi - HFENCE.BVMA")
				case 0b1010001:
					panic("nyi - HFENCE.GVMA")
				default:
					panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
				}
			}
		case 0b001: // CSRRW
			t := cpu.readcsr(uint16(op.csr))
			cpu.writecsr(uint16(op.csr), uint64(cpu.x[op.rs]))
			cpu.x[op.rd] = int64(t)
		case 0b010: // CSRRS
			t := cpu.readcsr(uint16(op.csr))
			cpu.writecsr(uint16(op.csr), t|uint64(cpu.x[op.rs]))
			cpu.x[op.rd] = int64(t)
		case 0b011: // CSRRC
			t := cpu.readcsr(uint16(op.csr))
			trs := cpu.x[op.rs]
			cpu.x[op.rd] = int64(t)
			cpu.writecsr(uint16(op.csr), uint64(cpu.x[op.rd] & ^trs))
		case 0b101: // CSRRWI
			t := cpu.readcsr(uint16(op.csr))
			cpu.x[op.rd] = int64(t)
			cpu.writecsr(uint16(op.csr), uint64(op.rs))
		case 0b110: // CSRRSI
			t := cpu.readcsr(uint16(op.csr))
			cpu.x[op.rd] = int64(t)
			cpu.writecsr(uint16(op.csr), uint64(cpu.x[op.rd]|int64(op.rs)))
		case 0b111: // CSRRCI
			t := cpu.readcsr(uint16(op.csr))
			cpu.x[op.rd] = int64(t)
			cpu.writecsr(uint16(op.csr), uint64(cpu.x[op.rd] & ^int64(op.rs)))
		default:
			panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
		}
	case 0b0111011:
		op := parseR(instr)
		switch op.funct3 {
		case 0b000:
			switch op.funct7 {
			case 0b0000000: // ADD
				cpu.x[op.rd] = int64(int32(cpu.x[op.rs1]) + int32(cpu.x[op.rs2]))
			case 0b0100000: // SUB
				cpu.x[op.rd] = int64(int32(cpu.x[op.rs1]) - int32(cpu.x[op.rs2]))
			case 1: // MULW
				cpu.x[op.rd] = int64(int32(cpu.x[op.rs1]) * int32(cpu.x[op.rs2]))
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b001:
			switch op.funct7 {
			case 0:
				cpu.x[op.rd] = int64(int32(cpu.x[op.rs1]) << (cpu.x[op.rs2] & 0b11111))
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b100:
			switch op.funct7 {
			case 1: // DIVW
				op := parseR(instr)
				a1 := int32(cpu.x[op.rs1])
				a2 := int32(cpu.x[op.rs2])
				if a2 == 0 {
					cpu.x[op.rd] = -1
				} else if a1 == math.MinInt32 && a2 == -1 {
					cpu.x[op.rd] = int64(a1)
				} else {
					cpu.x[op.rd] = int64(a1 / a2)
				}
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b101:
			switch op.funct7 {
			case 0: // SRL
				cpu.x[op.rd] = int64(int32(uint32(uint64(cpu.x[op.rs1])) >> (cpu.x[op.rs2] & 0b11111)))
			case 0b0100000: // SRA
				cpu.x[op.rd] = int64(int32(cpu.x[op.rs1]) >> (cpu.x[op.rs2] & 0b11111))
			case 1: // DIVUW
				op := parseR(instr)
				a1 := uint32(cpu.x[op.rs1])
				a2 := uint32(cpu.x[op.rs2])
				if a2 == 0 {
					cpu.x[op.rd] = -1
				} else {
					cpu.x[op.rd] = int64(int32(a1 / a2))
				}
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b110:
			switch op.funct7 {
			case 1: // REMW
				op := parseR(instr)
				a1 := int32(cpu.x[op.rs1])
				a2 := int32(cpu.x[op.rs2])
				if a2 == 0 {
					cpu.x[op.rd] = int64(a1)
				} else if a1 == math.MinInt32 && a2 == -1 {
					cpu.x[op.rd] = 0
				} else {
					cpu.x[op.rd] = int64(a1 % a2)
				}
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b111:
			switch op.funct7 {
			case 1: // REMUW
				op := parseR(instr)
				a1 := uint32(cpu.x[op.rs1])
				a2 := uint32(cpu.x[op.rs2])
				if a2 == 0 {
					cpu.x[op.rd] = int64(int32(a1))
				} else {
					cpu.x[op.rd] = int64(int32(a1 % a2))
				}
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		default:
			panic("nyi - 0111011")
		}
	case 0b0101111:
		op := parseR(instr)
		switch op.funct7 >> 2 {
		case 0b00010:
			switch op.funct3 {
			case 0b010: // LR.W
				v, ok, trap := cpu.readuint32(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				cpu.reservationSet = true
				cpu.reservation = uint64(cpu.x[op.rs1])
				cpu.x[op.rd] = int64(int32(v))
			case 0b011: // LR.D
				v, ok, trap := cpu.readuint64(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				cpu.reservationSet = true
				cpu.reservation = uint64(cpu.x[op.rs1])
				cpu.x[op.rd] = int64(v)
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b00011:
			switch op.funct3 {
			case 0b010: // SC.W
				if cpu.reservationSet && cpu.reservation == uint64(cpu.x[op.rs1]) {
					ok, trap := cpu.writeuint32(uint64(cpu.x[op.rs1]), uint32(cpu.x[op.rs2]))
					if !ok {
						return false, trap
					}
					cpu.reservationSet = false
					cpu.x[op.rd] = 0
				} else {
					cpu.x[op.rd] = 1
				}
			case 0b011: // SC.D
				if cpu.reservationSet && cpu.reservation == uint64(cpu.x[op.rs1]) {
					ok, trap := cpu.writeuint64(uint64(cpu.x[op.rs1]), uint64(cpu.x[op.rs2]))
					if !ok {
						return false, trap
					}
					cpu.reservationSet = false
					cpu.x[op.rd] = 0
				} else {
					cpu.x[op.rd] = 1
				}
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b00001:
			switch op.funct3 {
			case 0b010: // AMOSWAP.W
				v, ok, trap := cpu.readuint32(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				ok, trap = cpu.writeuint32(uint64(cpu.x[op.rs1]), uint32(cpu.x[op.rs2]))
				if !ok {
					return false, trap
				}
				cpu.x[op.rd] = int64(int32(v))
			case 0b011: // AMOSWAP.D
				v, ok, trap := cpu.readuint64(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				ok, trap = cpu.writeuint64(uint64(cpu.x[op.rs1]), uint64(cpu.x[op.rs2]))
				if !ok {
					return false, trap
				}
				cpu.x[op.rd] = int64(v)
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b00000:
			switch op.funct3 {
			case 0b010: // AMOADD.W
				v, ok, trap := cpu.readuint32(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				ok, trap = cpu.writeuint32(uint64(cpu.x[op.rs1]), uint32(cpu.x[op.rs2]+int64(int32(v))))
				if !ok {
					return false, trap
				}
				cpu.x[op.rd] = int64(int32(v))
			case 0b011: // AMOADD.D
				v, ok, trap := cpu.readuint64(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				ok, trap = cpu.writeuint64(uint64(cpu.x[op.rs1]), uint64(cpu.x[op.rs2]+int64(v)))
				if !ok {
					return false, trap
				}
				cpu.x[op.rd] = int64(v)
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b00100:
			panic("nyi - AMOXOR.W")
		case 0b01100:
			switch op.funct3 {
			case 0b010: // AMOAND.W
				v, ok, trap := cpu.readuint32(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				ok, trap = cpu.writeuint32(uint64(cpu.x[op.rs1]), uint32(cpu.x[op.rs2]&int64(int32(v))))
				if !ok {
					return false, trap
				}
				cpu.x[op.rd] = int64(int32(v))
			case 0b011: // AMOAND.D
				v, ok, trap := cpu.readuint64(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				ok, trap = cpu.writeuint64(uint64(cpu.x[op.rs1]), uint64(cpu.x[op.rs2]&int64(v)))
				if !ok {
					return false, trap
				}
				cpu.x[op.rd] = int64(v)
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b01000:
			switch op.funct3 {
			case 0b010: // AMOOR.W
				v, ok, trap := cpu.readuint32(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				ok, trap = cpu.writeuint32(uint64(cpu.x[op.rs1]), uint32(cpu.x[op.rs2]|int64(int32(v))))
				if !ok {
					return false, trap
				}
				cpu.x[op.rd] = int64(int32(v))
			case 0b011: // AMOOR.D
				v, ok, trap := cpu.readuint64(uint64(cpu.x[op.rs1]))
				if !ok {
					return false, trap
				}
				ok, trap = cpu.writeuint64(uint64(cpu.x[op.rs1]), uint64(cpu.x[op.rs2]|int64(v)))
				if !ok {
					return false, trap
				}
				cpu.x[op.rd] = int64(v)
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		case 0b10000:
			panic("nyi - AMOMIN.W")
		case 0b10100:
			panic("nyi - AMOMAX.W")
		case 0b11000:
			panic("nyi - AMOMINU.W")
		case 0b11100:
			panic("nyi - AMOMAXU.W")
		default:
			panic("nyi - atomic")
		}
	case 0b0000111: // FLW
		op := parseI(instr)
		v, ok, trap := cpu.readuint32(uint64(cpu.x[op.rs1] + int64(op.imm)))
		if !ok {
			return false, trap
		}
		cpu.f[op.rd] = math.Float64frombits(uint64(int64(int32(v))))
	case 0b0100111: // FSW
		op := parseS(instr)
		v := uint32(math.Float64bits(cpu.f[op.rs2]))
		ok, trap := cpu.writeuint32(uint64(cpu.x[op.rs1]+int64(op.imm)), v)
		if !ok {
			return false, trap
		}
	case 0b1000011:
		panic("nyi - FMADD.S")
	case 0b1000111:
		panic("nyi - FMSUB.S")
	case 0b1001011:
		panic("nyi - FNMSUB.S")
	case 0b1001111:
		panic("nyi - FNMADD.S")
	case 0b1010011:
		op := parseR(instr)
		switch op.funct7 {
		case 0b0000000:
			panic("nyi - FADD.S")
		case 0b0000100:
			panic("nyi - FSUB.S")
		case 0b0001000:
			panic("nyi - FMUL.S")
		case 0b0001100:
			panic("nyi - FDIV.S")
		case 0b0101100:
			panic("nyi - FSQRT.S")
		case 0b0010000:
			panic("nyi - FSGN*.S")
		case 0b0010100:
			panic("nyi - FM**.S")
		case 0b1100000:
			panic("nyi - FCVT.W*.S")
		case 0b1110000:
			panic("nyi - FMV.X.W")
		case 0b1010000:
			panic("nyi - FEQ.S/*")
		case 0b1101000:
			panic("nyi - FCVT.S.W*")
		case 0b1111000: // FMV.W.X
			op := parseR(instr)
			cpu.f[op.rd] = math.Float64frombits(uint64(uint32(cpu.x[op.rs1])))
		default:
			panic("invalid")
		}
	case 0b0011011:
		op := parseI(instr)
		switch op.funct3 {
		case 0b000: // ADDIW
			cpu.x[op.rd] = int64(int32(cpu.x[op.rs1] + int64(op.imm)))
		case 0b001: // SLLIW
			if op.imm>>5 != 0 {
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
			cpu.x[op.rd] = int64(int32(cpu.x[op.rs1] << op.imm))
		case 0b101:
			switch op.imm >> 6 {
			case 0: // SRLIW
				cpu.x[op.rd] = int64(int32(uint32(int32(cpu.x[op.rs1])) >> (op.imm & 0b111111)))
			case 0b010000: // SRAIW
				cpu.x[op.rd] = int64(int32(cpu.x[op.rs1]) >> (op.imm & 0b111111))
			default:
				panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
			}
		default:
			panic(fmt.Sprintf("nyi - invalid instruction %x", instr))
		}
	default:
		panic(fmt.Sprintf("nyi - opcode %x", instr&0x7f))
	}
	return true, Trap{}
}

func (cpu *CPU) readcsr(csr uint16) uint64 {
	switch csr {
	case FFLAGS:
		panic(fmt.Sprintf("not yet implemented - masking of other CSR: csr[%x] ", csr))
	case FRM:
		panic(fmt.Sprintf("not yet implemented - masking of other CSR: csr[%x] ", csr))
	case SSTATUS:
		return cpu.readcsr(MSTATUS) & 0x80000003000de162
	case SIE:
		return cpu.csr[MIE] & 0x222
	case SIP:
		return cpu.csr[MIP] & 0x222
	case TIME:
		return cpu.clint.mtime
	case MSTATUS:
		// Force UXL and SXL to RV64
		return cpu.csr[MSTATUS]&^0xF00000000 | 0xA00000000
	}
	return cpu.csr[csr]
}

func (cpu *CPU) writecsr(csr uint16, v uint64) {
	switch csr {
	case FFLAGS:
		panic(fmt.Sprintf("not yet implemented - masking of other CSR: csr[%x] = %x", csr, v))
	case FRM:
		panic(fmt.Sprintf("not yet implemented - masking of other CSR: csr[%x] = %x", csr, v))
	case SSTATUS:
		// if (cpu.csr[MSTATUS]>>1)&1 != (v>>1)&1 {
		// 	fmt.Fprintf(os.Stderr, "sie = %d\n", (v>>1)&1)
		// }
		cpu.csr[MSTATUS] = cpu.csr[MSTATUS]&^0x80000003000de162 | v&0x80000003000de162
	case SIE:
		cpu.csr[MIE] = cpu.csr[MIE]&^0x222 | v&0x222
	case SIP:
		cpu.csr[MIP] = cpu.csr[MIP]&^0x222 | v&0x222
	case TIME:
		cpu.clint.mtime = v
	case MIDELEG:
		cpu.csr[csr] = v & 0x666
	case SATP:
		switch v >> 60 {
		case 0, 8, 9:
			cpu.mode = AddressMode(v >> 60)
		default:
			panic("invalid addressing mode")
		}
		cpu.csr[csr] = v
	default:
		cpu.csr[csr] = v
	}
}

func (cpu *CPU) virtualToPhysical(vaddr uint64, access Access) (uint64, bool) {
	switch cpu.mode {
	case None:
		return vaddr, true
	case SV39:
		switch cpu.priv {
		case Machine:
			mstatus := cpu.readcsr(MSTATUS)
			if access == Execute {
				return vaddr, true
			}
			if (mstatus>>17)&1 == 0 {
				return vaddr, true
			}
			priv := Privilege((mstatus >> 9) & 3)
			if priv == Machine {
				return vaddr, true
			}
			currentPriv := cpu.priv
			cpu.priv = priv
			v, ok := cpu.virtualToPhysical(vaddr, access)
			cpu.priv = currentPriv
			return v, ok
		case User, Supervisor:
			rootppn := cpu.readcsr(SATP) & 0xfffffffffff
			vpns := []uint64{(vaddr >> 12) & 0x1ff, (vaddr >> 21) & 0x1ff, (vaddr >> 30) & 0x1ff}
			paddr, ok := cpu.walkPageTables(vaddr, 3-1, rootppn, vpns, access)
			if !ok {
				return 0, false
			}
			return paddr, true
		default:
			panic("invalid CPU priv")
		}
	default:
		panic("invalid addressing mode")
	}
}

func (cpu *CPU) walkPageTables(vaddr uint64, level uint8, parentppn uint64, vpns []uint64, access Access) (uint64, bool) {
	// fmt.Printf("walkPageTables: %x, %d, %x, %x\n", vaddr, level, parentppn, vpns)
	pagesize := uint64(4096)
	ptesize := uint64(8)
	pteaddr := parentppn*pagesize + vpns[level]*ptesize
	pte := cpu.readphysicaluint64(pteaddr)
	ppn := (pte >> 10) & 0xfffffffffff
	ppns := []uint64{(pte >> 10) & 0x1ff, (pte >> 19) & 0x1ff, (pte >> 28) & 0x3ffffff}
	// rsw := (pte >> 8) & 0b11
	d := (pte >> 7) & 0b1
	a := (pte >> 6) & 0b1
	// g := (pte >> 5) & 0b1
	// u := (pte >> 4) & 0b1
	x := (pte >> 3) & 0b1
	w := (pte >> 2) & 0b1
	r := (pte >> 1) & 0b1
	v := (pte >> 0) & 0b1

	if v == 0 || (r == 0 && w == 1) { // Not valid, or invalid write-only
		return 0, false
	}

	if r == 0 && x == 0 {
		if level == 0 { // pointer to page table entry at leaf layer
			return 0, false
		}
		return cpu.walkPageTables(vaddr, level-1, ppn, vpns, access)
	}

	if a == 0 || (access == Write && d == 0) {
		newpte := pte | 1<<6
		if access == Write {
			newpte |= 1 << 7
		}
		cpu.writephysical(pteaddr, uint8(newpte))
		cpu.writephysical(pteaddr+1, uint8(newpte>>8))
		cpu.writephysical(pteaddr+2, uint8(newpte>>16))
		cpu.writephysical(pteaddr+3, uint8(newpte>>24))
		cpu.writephysical(pteaddr+4, uint8(newpte>>32))
		cpu.writephysical(pteaddr+5, uint8(newpte>>40))
		cpu.writephysical(pteaddr+6, uint8(newpte>>48))
		cpu.writephysical(pteaddr+7, uint8(newpte>>56))
	}

	if (access == Execute && x == 0) || (access == Read && r == 0) || (access == Write && w == 0) {
		return 0, false
	}

	offset := vaddr & 0xfff
	if level == 2 {
		if ppns[1] != 0 || ppns[0] != 0 {
			return 0, false
		}
		return ppns[2]<<30 | vpns[1]<<21 | vpns[0]<<12 | offset, true
	} else if level == 1 {
		if ppns[0] != 0 {
			return 0, false
		}
		return ppns[2]<<30 | ppns[1]<<21 | vpns[0]<<12 | offset, true
	} else if level == 0 {
		return ppn<<12 | offset, true
	}

	panic("invalid level")
}

func (cpu *CPU) readraw(vaddr uint64) (uint8, bool) {
	paddr, ok := cpu.virtualToPhysical(vaddr, Read)
	if !ok {
		return 0, false
	}
	return cpu.readphysical(paddr), true
}

func (cpu *CPU) readphysical(addr uint64) (ret uint8) {
	if addr >= MEMORYBASE {
		return cpu.mem[addr-MEMORYBASE]
	}
	if addr >= 0x00001020 && addr <= 0x00001fff {
		daddr := addr - 0x00001020
		if daddr >= uint64(len(dtb)) {
			return 0
		}
		return dtb[daddr]
	}
	if addr >= 0x02000000 && addr <= 0x0200ffff {
		return cpu.clint.readuint8(addr)
	}
	if addr >= 0x0C000000 && addr <= 0x0fffffff {
		return cpu.plic.readuint8(addr)
	}
	if addr >= 0x10000000 && addr <= 0x100000ff {
		return cpu.uart.readuint8(addr)
	}
	if addr >= 0x10001000 && addr <= 0x10001fff {
		return cpu.disk.readuint8(addr)
	}
	panic(fmt.Sprintf("nyi - unsupported address %x", addr))
}

func (cpu *CPU) readphysicaluint64(addr uint64) uint64 {
	val := uint64(0)
	if addr >= MEMORYBASE && addr%8 == 0 { // Read directly from RAM
		memaddr := addr - MEMORYBASE
		val = cpu.mem64[memaddr/8]
	} else {
		for i := uint64(0); i < 8; i++ {
			val |= uint64(cpu.readphysical(addr)) << (i * 8)
		}
	}
	return val
}

func (cpu *CPU) writeraw(vaddr uint64, v byte) bool {
	paddr, ok := cpu.virtualToPhysical(vaddr, Write)
	if !ok {
		return false
	}
	cpu.writephysical(paddr, v)
	return true
}

func (cpu *CPU) writephysical(addr uint64, v byte) {
	if addr >= MEMORYBASE {
		cpu.mem[addr-MEMORYBASE] = v
		return
	}
	if addr >= 0x00001020 && addr <= 0x00001fff {
		panic("nyi - cannot write to dtb")
	}
	if addr >= 0x02000000 && addr <= 0x0200ffff {
		cpu.clint.writeuint8(addr, v)
		return
	}
	if addr >= 0x0C000000 && addr <= 0x0fffffff {
		cpu.plic.writeuint8(addr, v)
		return
	}
	if addr >= 0x10000000 && addr <= 0x100000ff {
		cpu.uart.writeuint8(addr, v)
		return
	}
	if addr >= 0x10001000 && addr <= 0x10001FFF {
		cpu.disk.writeuint8(addr, v)
		return
	}
	panic(fmt.Sprintf("nyi - unsupported address %x: %x", addr, v))
}

func (cpu *CPU) readuint64(addr uint64) (uint64, bool, Trap) {
	val := uint64(0)
	if addr&0xfff <= 0x1000-4 { // instruction is within a single page
		paddr, ok := cpu.virtualToPhysical(addr, Read)
		if !ok {
			return 0, false, Trap{reason: LoadPageFault, value: addr}
		}
		for i := uint64(0); i < 8; i++ {
			x := cpu.readphysical(paddr + i)
			val |= uint64(x) << (i * 8)
		}
	} else { // instruction is across two pages
		for i := uint64(0); i < 8; i++ {
			paddr, ok := cpu.virtualToPhysical(addr+i, Execute)
			if !ok {
				return 0, false, Trap{reason: LoadPageFault, value: addr + i}
			}
			x := cpu.readphysical(paddr)
			val |= uint64(x) << (i * 8)
		}
	}
	return val, true, Trap{}
}

func (cpu *CPU) readuint32(addr uint64) (uint32, bool, Trap) {
	val := uint32(0)
	for i := uint64(0); i < 4; i++ {
		x, ok := cpu.readraw(addr + i)
		if !ok {
			return 0, false, Trap{reason: LoadPageFault, value: addr + i}
		}
		val |= uint32(x) << (i * 8)
	}
	return val, true, Trap{}
}

func (cpu *CPU) readuint16(addr uint64) (uint16, bool, Trap) {
	val := uint16(0)
	for i := uint64(0); i < 2; i++ {
		x, ok := cpu.readraw(addr + i)
		if !ok {
			return 0, false, Trap{reason: LoadPageFault, value: addr + i}
		}
		val |= uint16(x) << (i * 8)
	}
	return val, true, Trap{}
}

func (cpu *CPU) readuint8(addr uint64) (uint8, bool, Trap) {
	x, ok := cpu.readraw(addr)
	if !ok {
		return 0, false, Trap{reason: LoadPageFault, value: addr}
	}
	return x, true, Trap{}
}

func (cpu *CPU) writeuint64(addr uint64, val uint64) (bool, Trap) {
	if addr&0xfff <= 0x1000-8 { // uint64 is within a single page
		paddr, ok := cpu.virtualToPhysical(addr, Write)
		if !ok {
			return false, Trap{reason: StorePageFault, value: addr}
		}
		if paddr >= MEMORYBASE {
			memaddr := paddr - MEMORYBASE
			cpu.mem64[memaddr/8] = val
		} else {
			for i := uint64(0); i < 8; i++ {
				cpu.writephysical(paddr+i, byte(val>>(i*8)))
			}
		}
		return true, Trap{}
	} else { // uint64 is across two pages
		for i := uint64(0); i < 8; i++ {
			paddr, ok := cpu.virtualToPhysical(addr+i, Write)
			if !ok {
				return false, Trap{reason: StorePageFault, value: addr + i}
			}
			cpu.writephysical(paddr, byte(val>>(i*8)))
		}
		return true, Trap{}
	}
}

func (cpu *CPU) writeuint32(addr uint64, val uint32) (bool, Trap) {
	for i := uint64(0); i < 4; i++ {
		ok := cpu.writeraw(addr+i, byte(val>>(i*8)))
		if !ok {
			return false, Trap{reason: StorePageFault, value: addr + i}
		}
	}
	return true, Trap{}
}

func (cpu *CPU) writeuint16(addr uint64, val uint16) (bool, Trap) {
	for i := uint64(0); i < 2; i++ {
		ok := cpu.writeraw(addr+i, byte(val>>(i*8)))
		if !ok {
			return false, Trap{reason: StorePageFault, value: addr + i}
		}
	}
	return true, Trap{}
}

func (cpu *CPU) writeuint8(addr uint64, val uint8) (bool, Trap) {
	ok := cpu.writeraw(addr, byte(val))
	if !ok {
		return false, Trap{reason: StorePageFault, value: addr}
	}
	return true, Trap{}
}

func (cpu *CPU) decompress(instr uint32) uint32 {
	op := instr & 0b11
	funct3 := (instr >> 13) & 0b111
	switch op {
	case 0b00:
		switch funct3 {
		case 0b000:
			rd := (instr >> 2) & 0x7
			nzuimm := (instr>>7)&0x30 | (instr>>1)&0x3c0 | (instr>>4)&0x4 | (instr>>2)&0x8
			if nzuimm != 0 { // C.ADDI4SPN = addi rd+8, x2, nzuimm
				return nzuimm<<20 | 2<<15 | (rd+8)<<7 | 0x13
			} else {
				panic("reserved")
			}
		case 0b001: // C.FLD = fld rd+8, offset(rs1+8)
			rs1 := (instr >> 7) & 0x7
			rd := (instr >> 2) & 0x7
			offset := (instr>>7)&0x38 | (instr<<1)&0xc0
			return offset<<20 | (rs1+8)<<15 | 3<<12 | (rd+8)<<7 | 0x7
		case 0b010: // C.LW = lw rd+8, offset(rs1+8)
			rs1 := (instr >> 7) & 0x7
			rd := (instr >> 2) & 0x7
			offset := (instr>>7)&0x38 | (instr<<1)&0x40 | (instr>>4)&0x4
			return offset<<20 | (rs1+8)<<15 | 2<<12 | (rd+8)<<7 | 0x3
		case 0b011: // C.LD = ld rd+8, offset(rs1+8)
			rs1 := (instr >> 7) & 0x7
			rd := (instr >> 2) & 0x7
			offset := (instr>>7)&0x38 | (instr<<1)&0xc0
			return offset<<20 | (rs1+8)<<15 | 3<<12 | (rd+8)<<7 | 0x3
		case 0b100:
			panic("nyi - reserved")
		case 0b101: // C.FSD = fsd rs2+8, offset(rs1+8)
			rs1 := (instr >> 7) & 0x7
			rs2 := (instr >> 2) & 0x7
			offset := (instr>>7)&0x38 | (instr<<1)&0xc0
			imm115 := (offset >> 5) & 0x7f
			imm40 := offset & 0x1f
			return imm115<<25 | (rs2+8)<<20 | (rs1+8)<<15 | 3<<12 | imm40<<7 | 0x27
		case 0b110: // C.SW = sw rs2+8, offset(rs1+8)
			rs1 := (instr >> 7) & 0x7
			rs2 := (instr >> 2) & 0x7
			offset := (instr>>7)&0x38 | (instr<<1)&0x40 | (instr>>4)&0x4
			imm115 := (offset >> 5) & 0x3f
			imm40 := offset & 0x1f
			return imm115<<25 | (rs2+8)<<20 | (rs1+8)<<15 | 2<<12 | imm40<<7 | 0x23
		case 0b111: // C.SD = sd rs2+8, offset(rs1+8)
			rs1 := (instr >> 7) & 0x7
			rs2 := (instr >> 2) & 0x7
			offset := (instr>>7)&0x38 | (instr<<1)&0xc0
			imm115 := (offset >> 5) & 0x7f
			imm40 := offset & 0x1f
			return imm115<<25 | (rs2+8)<<20 | (rs1+8)<<15 | 3<<12 | imm40<<7 | 0x23
		default:
			panic("unreachable")
		}
	case 0b01:
		switch funct3 {
		case 0b000:
			r := instr & 0b111110000000
			imm := (instr>>7)&0x20 | (instr>>2)&0x1f
			if instr&0x1000 != 0 {
				imm |= 0xffffffc0
			}
			if r == 0 && imm == 0 { // C.NOP = addi x0, x0, 0
				return 0x13
			} else { // C.ADDI = addi r, r, imm
				return imm<<20 | r<<8 | r | 0x13
			}
		case 0b001:
			r := instr & 0b111110000000
			imm := (instr>>7)&0x20 | (instr>>2)&0x1f
			if instr&0x1000 != 0 {
				imm |= 0xffffffc0
			}
			if r != 0 { // C.ADDIW = addiw r, r, imm
				return imm<<20 | r<<8 | r | 0x1b
			} else {
				panic("reserved")
			}
		case 0b010: // C.LI = addi rd, x0, imm
			r := instr & 0b111110000000
			imm := (instr>>7)&0x20 | (instr>>2)&0x1f
			if instr&0x1000 != 0 {
				imm |= 0xffffffc0
			}
			if r != 0 { // C.LI = addi rd, x0, imm
				return imm<<20 | r | 0x13
			} else { // hint
				panic("nyi - hint")
			}
		case 0b011:
			r := instr & 0b111110000000
			if r == 0b100000000 {
				imm := (instr>>3)&0x200 | (instr>>2)&0x10 | (instr<<1)&0x40 | (instr<<4)&0x180 | (instr<<3)&0x20
				if instr&0x1000 != 0 {
					imm |= 0xfffffc00
				}
				if imm != 0 { // C.ADDI16SP
					return imm<<20 | r<<8 | r | 0x13
				} else {
					panic("reserved")
				}
			} else if r != 0 {
				nzimm := (instr<<5)&0x20000 | (instr<<10)&0x1f000
				if instr&0x1000 != 0 {
					nzimm |= 0xfffc0000
				}
				if nzimm != 0 { // C.LUI = lui r, nzimm
					return nzimm | r | 0x37
				} else {
					panic("nyi - reserved")
				}
			} else {
				panic("nyi")
			}
		case 0b100:
			funct2 := (instr >> 10) & 0x3
			switch funct2 {
			case 0b00: // C.SRLI = srli rs1+8, rs1+8, shamt
				rs1 := (instr >> 7) & 0x7
				shamt := (instr>>7)&0x20 | (instr>>2)&0x1f
				return shamt<<20 | (rs1+8)<<15 | 5<<12 | (rs1+8)<<7 | 0x13
			case 0b01: // C.SRAI = srai rs1+8, rs1+8, shamt
				rs1 := (instr >> 7) & 0x7
				shamt := (instr>>7)&0x20 | (instr>>2)&0x1f
				return 0x20<<25 | shamt<<20 | (rs1+8)<<15 | 5<<12 | (rs1+8)<<7 | 0x13

			case 0b10: // C.ANDI = andi, r+8, r+8, imm
				r := (instr >> 7) & 0x7
				imm := (instr>>7)&0x20 | (instr>>2)&0x1f
				if instr&0x1000 != 0 {
					imm |= 0xffffffc0
				}
				return imm<<20 | (r+8)<<15 | 7<<12 | (r+8)<<7 | 0x13
			case 0b11:
				funct1 := (instr >> 12) & 1
				funct22 := (instr >> 5) & 0x3
				rs1 := (instr >> 7) & 0x7
				rs2 := (instr >> 2) & 0x7
				switch funct1 {
				case 0:
					switch funct22 {
					case 0b00: // C.SUB = sub rs1+8, rs1+8, rs2+8
						return 0x20<<25 | (rs2+8)<<20 | (rs1+8)<<15 | (rs1+8)<<7 | 0x33
					case 0b01: // C.XOR = xor rs1+8, rs1+8, rs2+8
						return (rs2+8)<<20 | (rs1+8)<<15 | 4<<12 | (rs1+8)<<7 | 0x33
					case 0b10: // C.OR = or rs1+8, rs1+8, rs2+8
						return (rs2+8)<<20 | (rs1+8)<<15 | 6<<12 | (rs1+8)<<7 | 0x33
					case 0b11: // C.AND = and rs1+8, rs1+8, rs2+8
						return (rs2+8)<<20 | (rs1+8)<<15 | 7<<12 | (rs1+8)<<7 | 0x33
					default:
						panic("unreachable")
					}
				case 1:
					switch funct22 {
					case 0b00: // C.SUBW = subw r1+8, r1+8, r2+8
						return 0x20<<25 | (rs2+8)<<20 | (rs1+8)<<15 | (rs1+8)<<7 | 0x3b
					case 0b01: // C.ADDW = addw r1+8, r1+8, r2+8
						return (rs2+8)<<20 | (rs1+8)<<15 | (rs1+8)<<7 | 0x3b
					case 0b10:
						panic("reserved")
					case 0b11:
						panic("reserved")
					default:
						panic("unreachable")
					}
				default:
					panic("unreachable")
				}
			default:
				panic("unreachable")
			}
		case 0b101: // C.J = jal x0, imm
			offset := (instr>>1)&0x800 | (instr>>7)&0x10 | (instr>>1)&0x300 | (instr<<2)&0x400 | (instr>>1)&0x40 | (instr<<1)&0x80 | (instr>>2)&0xe | (instr<<3)&0x20
			if instr&0x1000 != 0 {
				offset |= 0xfffff000
			}
			imm := (offset>>1)&0x80000 | (offset<<8)&0x7fe00 | (offset>>3)&0x100 | (offset>>12)&0xff
			return imm<<12 | 0x6f
		case 0b110: // C.BEQZ = beq r+8, x0, offset
			r := (instr >> 7) & 0x7
			offset := (instr>>4)&0x100 | (instr>>7)&0x18 | (instr<<1)&0xc0 | (instr>>2)&0x6 | (instr<<3)&0x20
			if instr&0x1000 != 0 {
				offset |= 0xfffffe00
			}
			imm2 := (offset>>6)&0x40 | (offset>>5)&0x3f
			imm1 := (offset>>0)&0x1e | (offset>>11)&0x1
			return imm2<<25 | (r+8)<<20 | imm1<<7 | 0x63
		case 0b111: // C.BNEZ = bne r+8, x0, offset
			r := (instr >> 7) & 0x7
			offset := (instr>>4)&0x100 | (instr>>7)&0x18 | (instr<<1)&0xc0 | (instr>>2)&0x6 | (instr<<3)&0x20
			if instr&0x1000 != 0 {
				offset |= 0xfffffe00
			}
			imm2 := (offset>>6)&0x40 | (offset>>5)&0x3f
			imm1 := (offset>>0)&0x1e | (offset>>11)&0x1
			return imm2<<25 | (r+8)<<20 | 1<<12 | imm1<<7 | 0x63
		default:
			panic("unreachable")
		}
	case 0b10:
		switch funct3 {
		case 0b000: // C.SLLI = slli r, r, shamt
			r := (instr >> 7) & 0x1f
			shamt := (instr>>7)&0x20 | (instr>>2)&0x1f
			if r != 0 {
				return shamt<<20 | r<<15 | 1<<12 | r<<7 | 0x13
			} else {
				panic("reserved")
			}
		case 0b001:
			panic("nyi - C.FLDSP/C.LQSP")
		case 0b010: // C.LWSP = lw r, offset(x2)
			r := (instr >> 7) & 0x1f
			offset := (instr>>7)&0x20 | (instr>>2)&0x1c | (instr<<4)&0xc0
			if r != 0 {
				return offset<<20 | 2<<15 | 2<<12 | r<<7 | 0x3
			} else {
				panic("reserved")
			}
		case 0b011: // C.LDSP = ld rd, offset(x2)
			rd := (instr >> 7) & 0x1f
			offset := (instr>>7)&0x20 | (instr>>2)&0x18 | (instr<<4)&0x1c0
			if rd != 0 {
				return offset<<20 | 2<<15 | 3<<12 | rd<<7 | 0x3
			} else {
				panic("reserved")
			}
		case 0b100:
			rs1 := (instr >> 7) & 0b11111
			rs2 := (instr >> 2) & 0b11111
			if instr&0x1000 == 0 {
				if rs1 == 0 {
					panic("reserved")
				} else {
					if rs2 == 0 { // C.JR
						return (rs1 << 15) | 0x67
					} else { // C.MV
						return (rs2 << 20) | (rs1 << 7) | 0x33
					}
				}
			} else {
				if rs2 == 0 {
					if rs1 == 0 { // C.EBREAK
						return 0x00100073
					} else { // C.JALR
						return (rs1 << 15) | (1 << 7) | 0x67
					}
				} else {
					if rs1 == 0 {
						panic("reserved")
					} else { // C.ADD
						return (rs2 << 20) | (rs1 << 15) | (rs1 << 7) | 0x33
					}
				}
			}
		case 0b101:
			panic("nyi - C.FSDSP/C.SQSP")
		case 0b110: // C.SWSP = sw rs2, offset(x2)
			rs2 := (instr >> 2) & 0x1f
			offset := (instr>>7)&0x3c | (instr>>1)&0xc0
			imm115 := (offset >> 5) & 0x3f
			imm40 := offset & 0x1f
			return imm115<<25 | rs2<<20 | 2<<15 | 2<<12 | imm40<<7 | 0x23
		case 0b111: // C.SDSP = sd rs, offset(x2)
			rs2 := (instr >> 2) & 0x1f
			offset := (instr>>7)&0x38 | (instr>>1)&0x1c0
			imm115 := (offset >> 5) & 0x3f
			imm40 := offset & 0x1f
			return imm115<<25 | rs2<<20 | 2<<15 | 3<<12 | imm40<<7 | 0x23
		default:
			panic("unreachable")
		}
	default:
		panic("compressed instruction cannot be 0b11")
	}
}

const (
	IER_RXINT_BIT      uint8 = 0x1
	IER_THREINT_BIT    uint8 = 0x2
	IIR_THR_EMPTY      uint8 = 0x2
	IIR_RD_AVAILABLE   uint8 = 0x4
	IIR_NO_INTERRUPT   uint8 = 0x7
	LSR_DATA_AVAILABLE uint8 = 0x1
	LSR_THR_EMPTY      uint8 = 0x20
)

const (
	DISK_IRQ uint32 = 1
	UART_IRQ uint32 = 10
)

type Plic struct {
	irq        uint32
	enabled    uint64 // TODO: Contexts other than 1?
	threshold  uint32
	ips        [1024]uint8
	priorities [1024]uint32
	updateIRQ  bool

	lastdiskip bool
}

func NewPlic() Plic {
	return Plic{}
}

func (plic *Plic) step(clock uint64, uartip, diskip bool, mip *uint64) {
	// TOOD: Generalize to set of connected interrupt sources
	if diskip != plic.lastdiskip { // Track edge of ip signal and trigger on raising edge only
		if diskip { // Disk is interrupting
			index := DISK_IRQ >> 3
			plic.ips[index] |= 1 << (DISK_IRQ & 7)
			plic.updateIRQ = true
		}
		plic.lastdiskip = diskip
	}
	if uartip { // Uart is interrupting
		index := UART_IRQ >> 3
		plic.ips[index] |= 1 << (UART_IRQ & 7)
		plic.updateIRQ = true
	}
	if plic.updateIRQ {
		diskip := (plic.ips[DISK_IRQ>>3]>>(DISK_IRQ&7))&1 == 1
		diskpri := plic.priorities[DISK_IRQ]
		diskenabled := (plic.enabled>>DISK_IRQ)&1 == 1

		uartip := (plic.ips[UART_IRQ>>3]>>(UART_IRQ&7))&1 == 1
		uartpri := plic.priorities[UART_IRQ]
		uartenabled := (plic.enabled>>UART_IRQ)&1 == 1

		irq := uint32(0)
		pri := uint32(0)
		if diskip && diskenabled && diskpri > plic.threshold && diskpri > pri {
			irq = DISK_IRQ
			pri = diskpri
		}
		if uartip && uartenabled && uartpri > plic.threshold && uartpri > pri {
			irq = UART_IRQ
			pri = uartpri
		}

		plic.irq = irq
		if plic.irq != 0 {
			*mip |= MIP_SEIP
		}

		plic.updateIRQ = false
	}
}

func (plic *Plic) readuint8(addr uint64) (v uint8) {
	// defer func() { fmt.Printf("plic[%x] => %x\n", addr, v) }()
	if addr >= 0x0c000000 && addr <= 0x0c000fff {
		panic("nyi - read from  plicpriorities")
	} else if addr >= 0x0c001000 && addr <= 0x0c00107f {
		panic("nyi - read from  plic ips")
	} else if addr >= 0x0c002080 && addr <= 0x0c002087 {
		return uint8(plic.enabled >> ((addr - 0x0c002080) * 8))
	} else if addr >= 0x0c201000 && addr <= 0x0c201003 {
		return uint8(plic.threshold >> ((addr - 0x0c201000) * 8))
	} else if addr >= 0x0c201004 && addr <= 0x0c201007 {
		return uint8(plic.irq >> ((addr - 0x0c201004) * 8))
	} else {
		fmt.Printf("warning: ignored plic[%x] => \n", addr)
		return 0
	}
}

func (plic *Plic) writeuint8(addr uint64, v uint8) {
	// fmt.Printf("plic[%x] <= %x\n", addr, v)
	if addr >= 0x0c000000 && addr <= 0x0c000fff {
		offset := addr & 0b11
		index := (addr - 0xc000000) >> 2
		pos := offset << 3
		plic.priorities[index] = plic.priorities[index]&^(0xff<<pos) | uint32(v)<<pos
		plic.updateIRQ = true
	} else if addr >= 0x0c002080 && addr <= 0x0c002087 {
		pos := 8 * (addr & 0b111)
		plic.enabled = plic.enabled & ^(0xff<<pos) | uint64(v)<<pos
		if pos == 0 {
			plic.updateIRQ = true
		}
	} else if addr >= 0x0c201000 && addr <= 0x0c201003 {
		pos := 8 * (addr & 0b11)
		plic.threshold = plic.threshold & ^(0xff<<pos) | uint32(v)<<pos
		if pos == 0 {
			plic.updateIRQ = true
		}
	} else if addr == 0x0c201004 {
		index := v >> 3
		plic.ips[index] &= ^(1 << (v & 0b111))
		plic.updateIRQ = true
	} else {
		// fmt.Printf("warning: ignored plic[%x] <= %x\n", addr, v)
	}
}

type Uart struct {
	rbr          uint8
	thr          uint8
	ier          uint8
	iir          uint8
	lcr          uint8
	mcr          uint8
	lsr          uint8
	scr          uint8
	threip       bool
	interrupting bool

	inputBuffer bytes.Buffer
}

func NewUart(screen tcell.Screen) *Uart {
	uart := &Uart{
		lsr: LSR_THR_EMPTY,
	}
	if screen != nil {
		go func() {
			for {
				ev := screen.PollEvent()
				switch ev := ev.(type) {
				case *tcell.EventKey:
					switch ev.Key() {
					case tcell.KeyRune:
						var b [4]byte
						n := utf8.EncodeRune(b[:], ev.Rune())
						if n == 1 {
							uart.inputBuffer.WriteByte(b[0])
						} else {
							panic(b)
						}
					case tcell.KeyEnter:
						uart.inputBuffer.WriteByte('\n')
					case tcell.KeyCtrlC:
						screen.Fini()
						panic("ctrl-c: exiting")
					}
				}
			}
		}()
	}
	return uart
}

func (uart *Uart) step(clock uint64) {
	rxip := false

	if clock%0x38400 == 0 && uart.rbr == 0 {
		b, err := uart.inputBuffer.ReadByte()
		if err == nil {
			uart.rbr = b
			uart.lsr |= LSR_DATA_AVAILABLE
			uart.updateIIR()
			if uart.ier&IER_RXINT_BIT != 0 {
				rxip = true
			}
		}
	}

	if clock%0x10 == 0 && uart.thr != 0 {
		_, err := os.Stdout.Write([]byte{uart.thr})
		if err != nil {
			panic("unable to write byte")
		}
		uart.thr = 0
		uart.lsr |= LSR_THR_EMPTY
		uart.updateIIR()
		if uart.ier&IER_THREINT_BIT != 0 {
			uart.threip = true
		}
	}

	if uart.threip || rxip {
		uart.interrupting = true
		uart.threip = false
	} else {
		uart.interrupting = false
	}
}

func (uart *Uart) updateIIR() {
	rxip := uart.ier&IER_RXINT_BIT != 0 && uart.rbr != 0
	threip := uart.ier&IER_THREINT_BIT != 0 && uart.thr == 0
	if rxip {
		uart.iir = IIR_RD_AVAILABLE
	} else if threip {
		uart.iir = IIR_THR_EMPTY
	} else {
		uart.iir = IIR_NO_INTERRUPT
	}
}

func (uart *Uart) readuint8(addr uint64) (v uint8) {
	// defer func() { fmt.Printf("uart[%x] => %x\n", addr, v) }()
	switch addr {
	case 0x10000000:
		if (uart.lcr >> 7) == 0 {
			rbr := uart.rbr
			uart.rbr = 0
			uart.lsr &= ^LSR_DATA_AVAILABLE
			uart.updateIIR()
			return rbr
		} else {
			return 0
		}
	case 0x10000001:
		if (uart.lcr >> 7) == 0 {
			return uart.ier
		} else {
			return 0
		}
	case 0x10000002:
		return uart.iir
	case 0x10000003:
		return uart.lcr
	case 0x10000004:
		return uart.mcr
	case 0x10000005:
		return uart.lsr
	case 0x10000007:
		return uart.scr
	default:
		return 0
	}
}

func (uart *Uart) writeuint8(addr uint64, v uint8) {
	// fmt.Printf("uart[%x] <= %x\n", addr, v)
	switch addr {
	case 0x10000000:
		if (uart.lcr >> 7) == 0 {
			uart.thr = v
			uart.lsr &= ^LSR_THR_EMPTY
			uart.updateIIR()
		} else {
			// TODO: ??
		}
	case 0x10000001:
		if (uart.lcr >> 7) == 0 {
			if uart.ier&IER_THREINT_BIT == 0 && v&IER_THREINT_BIT != 0 && uart.thr == 0 {
				uart.threip = true
			}
			uart.ier = v
			uart.updateIIR()
		} else {
			// TODO: ??
		}
	case 0x10000003:
		uart.lcr = v
	case 0x10000004:
		uart.mcr = v
	case 0x10000007:
		uart.scr = v
	default:
		// Do nothing
	}
}

func loadElf(file string, mem []byte) (uint64, error) {
	f, err := elf.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Paddr < MEMORYBASE {
			panic("ELF memory segment below 0x80000000 mapped to RAM")
		}
		memaddr := prog.Paddr - MEMORYBASE
		n, err := prog.ReadAt(mem[memaddr:memaddr+prog.Filesz], 0)
		if err != nil {
			return 0, err
		}
		if n != int(prog.Filesz) {
			return 0, fmt.Errorf("didn't read full section")
		}
		for i := prog.Filesz; i < prog.Memsz; i++ {
			mem[memaddr+i] = 0
		}
	}
	return f.Entry, nil
}

type Clint struct {
	msip     uint32
	mtimecmp uint64
	mtime    uint64
}

func NewClint() Clint {
	return Clint{}
}

func (clint *Clint) step(clock uint64, mip *uint64) {
	clint.mtime++
	if clint.msip&1 != 0 {
		*mip |= MIP_MSIP
	}
	if clint.mtimecmp > 0 && clint.mtime >= clint.mtimecmp {
		*mip |= MIP_MTIP
	}
}

func (clint *Clint) readuint8(addr uint64) (v uint8) {
	// defer func() { fmt.Printf("clint[%x] => %x\n", addr, v) }()
	// fmt.Printf("warning: ignored cint[%x] =>\n", addr)
	panic("nyi - read from clint")
}

func (clint *Clint) writeuint8(addr uint64, v uint8) {
	// fmt.Printf("clint[%x] <= %x\n", addr, v)
	switch addr {
	case 0x02000000:
		clint.msip = clint.msip&^0x1 | uint32(v)&1
	case 0x02000001, 0x02000002, 0x02000003:
		// Hardwired to zero
	case 0x02004000, 0x02004001, 0x02004002, 0x02004003,
		0x02004004, 0x02004005, 0x02004006, 0x02004007:
		sh := (addr - 0x02004000) * 8
		clint.mtimecmp = clint.mtimecmp&^(0xff<<sh) | uint64(v)<<sh
	case 0x0200bff8, 0x0200bff9, 0x0200bffa, 0x0200bffb,
		0x0200bffc, 0x0200bffd, 0x0200bffe, 0x0200bfff:
		sh := (addr - 0x0200bff8) * 8
		clint.mtime = clint.mtime&^(0xff<<sh) | uint64(v)<<sh
	default:
		fmt.Printf("warning: ignored clint[%x] <= %v\n", addr, v)
	}
}

type VirtioBlock struct {
	data          []uint64
	clock         uint64
	notifications []uint64
	usedRingIndex uint16

	guestpagesize          uint32
	deviceFeaturesSelector uint32
	deviceFeatures         uint64
	guestFeatures          uint32
	guestFeaturesSel       uint32

	queueSel    uint32
	queueNum    [1]uint32
	queueAlign  [1]uint32
	queuePFN    [1]uint32
	queueNotify uint32

	status          uint32
	interruptStatus uint32

	cpu *CPU
}

func NewVirtioBlock(byts []uint8, cpu *CPU) VirtioBlock {
	data := make([]uint64, (len(byts)+7)/8)
	for i := range byts {
		data[i>>3] |= uint64(byts[i]) << ((i % 8) * 8)
	}
	return VirtioBlock{
		cpu:        cpu,
		data:       data,
		queueAlign: [1]uint32{0x1000},
	}
}

func (vb *VirtioBlock) step() {
	if len(vb.notifications) != 0 && vb.clock == vb.notifications[0]+500 {
		vb.interruptStatus |= 0b1
		vb.handleNotification()
		vb.notifications = vb.notifications[1:]
	}
	vb.clock++
}

func (vb *VirtioBlock) handleNotification() {
	baseDescAddr := uint64(vb.queuePFN[vb.queueSel]) * uint64(vb.guestpagesize)
	queueSize := uint64(vb.queueNum[vb.queueSel])
	baseAvailAddr := baseDescAddr + queueSize*16
	align := uint64(vb.queueAlign[vb.queueSel])
	baseUsedAddr := ((baseAvailAddr + 4 + queueSize*2 + align - 1) / align) * align

	descIndexAddr := baseAvailAddr + 4 + (uint64(vb.usedRingIndex)%queueSize)*2
	descHeadIndex := (uint64(vb.cpu.readphysical(descIndexAddr)) + uint64(vb.cpu.readphysical(descIndexAddr+1))<<8) % queueSize

	var blkSector, descNum, next uint64
	for {
		descElemAddr := baseDescAddr + 16*next
		descAddr := vb.cpu.readphysicaluint64(descElemAddr)
		descLenFlagsNext := vb.cpu.readphysicaluint64(descElemAddr + 8)
		descLen := uint64(uint32(descLenFlagsNext))
		descFlags := uint16(descLenFlagsNext >> 32)
		descNext := uint16(descLenFlagsNext >> 48)
		next = uint64(descNext) % queueSize

		switch descNum {
		case 0:
			blkSector = vb.cpu.readphysicaluint64(descAddr + 8)
		case 1:
			if descFlags&0x2 == 0 { // Write
				for i := uint64(0); i < descLen; i++ {
					v := vb.cpu.readphysical(descAddr + i)
					diskAddr := blkSector*512 + i
					diskIndex := diskAddr >> 3
					diskPos := (diskAddr % 8) * 8
					vb.data[diskIndex] = vb.data[diskIndex]&^(0xff<<diskPos) | uint64(v)<<diskPos
				}
			} else { // Read
				for i := uint64(0); i < descLen; i++ {
					diskAddr := blkSector*512 + i
					diskIndex := diskAddr >> 3
					diskPos := (diskAddr % 8) * 8
					v := uint8(vb.data[diskIndex] >> diskPos)
					vb.cpu.writephysical(descAddr+i, v)
				}
			}
		case 2:
			if descFlags&0x2 == 0 {
				panic("Third descriptor should be write.")
			}
			if descLen != 1 {
				panic("Third descriptor length should be one.")
			}
			vb.cpu.writephysical(descAddr, 0)
		default:
		}

		descNum++
		if descFlags&0b1 == 0 {
			break
		}
	}

	if descNum != 3 {
		panic("expected 3 element descriptor chain")
	}

	vb.cpu.writephysical(baseUsedAddr+4+(uint64(vb.usedRingIndex)%queueSize)*8, uint8(descHeadIndex))
	vb.cpu.writephysical(baseUsedAddr+5+(uint64(vb.usedRingIndex)%queueSize)*8, uint8(descHeadIndex>>8))
	vb.cpu.writephysical(baseUsedAddr+6+(uint64(vb.usedRingIndex)%queueSize)*8, uint8(descHeadIndex>>16))
	vb.cpu.writephysical(baseUsedAddr+7+(uint64(vb.usedRingIndex)%queueSize)*8, uint8(descHeadIndex>>24))

	vb.usedRingIndex++
	vb.cpu.writephysical(baseUsedAddr+2, uint8(vb.usedRingIndex))
	vb.cpu.writephysical(baseUsedAddr+3, uint8(vb.usedRingIndex>>8))
}

func (vb *VirtioBlock) readuint8(addr uint64) (v uint8) {
	// defer func() { fmt.Printf("virtioblock[%x] => %x\n", addr, v) }()
	switch addr {
	case 0x10001000, 0x10001001, 0x10001002, 0x10001003: // MagicValue
		sh := (addr - 0x10001000) * 8
		return uint8(uint64(0x74726976) >> sh)
	case 0x10001004, 0x10001005, 0x10001006, 0x10001007: // Version
		sh := (addr - 0x10001004) * 8
		return uint8(uint64(0x1) >> sh)
	case 0x10001008, 0x10001009, 0x1000100a, 0x1000100b: // DeviceID
		sh := (addr - 0x10001008) * 8
		return uint8(uint64(0x2) >> sh)
	case 0x1000100c, 0x1000100d, 0x1000100e, 0x1000100f: // VendorID
		sh := (addr - 0x1000100c) * 8
		return uint8(uint64(0x554d4551) >> sh)
	case 0x10001010, 0x10001011, 0x10001012, 0x10001013: // HostFeatures
		sh := (addr - 0x10001010) * 8
		return uint8((vb.deviceFeatures >> (vb.deviceFeaturesSelector * 32)) >> sh)
	case 0x10001034, 0x10001035, 0x10001036, 0x10001037: // QueueNumMax
		sh := (addr - 0x10001034) * 8
		maxQueueSize := 0x2000
		return uint8(maxQueueSize >> sh)
	case 0x10001040, 0x10001041, 0x10001042, 0x10001043: // QueuePFN
		sh := (addr - 0x10001040) * 8
		return uint8(vb.queuePFN[vb.queueSel] >> sh)
	case 0x10001050, 0x10001051, 0x10001052, 0x10001053: // QueueNotify
		sh := (addr - 0x10001050) * 8
		return uint8(vb.queueNotify >> sh)
	case 0x10001060, 0x10001061, 0x10001062, 0x10001063: // InterruptStatus
		sh := (addr - 0x10001060) * 8
		return uint8(vb.interruptStatus >> sh)
	case 0x10001070, 0x10001071, 0x10001072, 0x10001073: // Status
		sh := (addr - 0x10001070) * 8
		return uint8(vb.status >> sh)
	case 0x10001100, 0x10001101, 0x10001102, 0x10001103, 0x10001104,
		0x10001105, 0x10001106, 0x10001107: // Capacity
		sh := (addr - 0x10001100) * 8
		return uint8(uint64(0x32000) >> sh) /// 104MB??
	default:
		panic("nyi - read from virtio block device")
	}
}

func (vb *VirtioBlock) writeuint8(addr uint64, v uint8) {
	// fmt.Printf("virtioblock[%x] <= %x\n", addr, v)
	switch addr {
	case 0x10001014, 0x10001015, 0x10001016, 0x10001017:
		sh := (addr - 0x10001014) * 8
		vb.deviceFeaturesSelector = vb.deviceFeaturesSelector&^(0xff<<sh) | uint32(v)<<sh
	case 0x10001020, 0x10001021, 0x10001022, 0x10001023:
		sh := (addr - 0x10001020) * 8
		vb.guestFeatures = vb.guestFeatures&^(0xff<<sh) | uint32(v)<<sh
	case 0x10001024, 0x10001025, 0x10001026, 0x10001027:
		sh := (addr - 0x10001024) * 8
		vb.guestFeaturesSel = vb.guestFeaturesSel&^(0xff<<sh) | uint32(v)<<sh
	case 0x10001028, 0x10001029, 0x1000102a, 0x1000102b:
		sh := (addr - 0x10001028) * 8
		vb.guestpagesize = vb.guestpagesize&^(0xff<<sh) | uint32(v)<<sh
	case 0x10001030, 0x10001031, 0x10001032, 0x10001033:
		sh := (addr - 0x10001030) * 8
		vb.queueSel = vb.queueSel&^(0xff<<sh) | uint32(v)<<sh
		if addr == 0x10001033 && vb.queueSel != 0 {
			panic("nyi - multi queue")
		}
	case 0x10001038, 0x10001039, 0x1000103a, 0x1000103b:
		sh := (addr - 0x10001038) * 8
		vb.queueNum[vb.queueSel] = vb.queueNum[vb.queueSel]&^(0xff<<sh) | uint32(v)<<sh
	case 0x1000103c, 0x1000103d, 0x1000103e, 0x1000103f:
		sh := (addr - 0x1000103c) * 8
		vb.queueAlign[vb.queueSel] = vb.queueAlign[vb.queueSel]&^(0xff<<sh) | uint32(v)<<sh
	case 0x10001040, 0x10001041, 0x10001042, 0x10001043:
		sh := (addr - 0x10001040) * 8
		vb.queuePFN[vb.queueSel] = vb.queuePFN[vb.queueSel]&^(0xff<<sh) | uint32(v)<<sh
	case 0x10001050, 0x10001051, 0x10001052, 0x10001053:
		sh := (addr - 0x10001050) * 8
		vb.queueNotify = vb.queueNotify&^(0xff<<sh) | uint32(v)<<sh
		if addr == 0x10001053 {
			vb.notifications = append(vb.notifications, vb.clock)
		}
	case 0x10001064:
		if v&0b1 == 1 {
			vb.interruptStatus &= ^uint32(0b1)
		}
	case 0x10001065, 0x10001066, 0x10001067:
		// do nothing
	case 0x10001070, 0x10001071, 0x10001072, 0x10001073:
		sh := (addr - 0x10001070) * 8
		vb.status = vb.status&^(0xff<<sh) | uint32(v)<<sh
	default:
		panic("nyi - write to virtio block device")
	}
}

func do() error {
	mem := make([]byte, 0x10000000)
	entry, err := loadElf(filepath.Join("linux", "fw_payload.elf"), mem)
	if err != nil {
		return err
	}
	rootfs, err := ioutil.ReadFile(filepath.Join("linux", "rootfs.img"))
	if err != nil {
		return err
	}

	screen, err := tcell.NewScreen()
	if err != nil {
		return err
	}
	err = screen.Init()
	if err != nil {
		return err
	}
	screen.Clear()
	screen.Show()
	defer screen.Fini()
	cpu := NewCPU(mem, entry, rootfs, screen)
	cpu.run()
	return nil
}

func main() {
	err := do()
	if err != nil {
		panic(err)
	}
}
