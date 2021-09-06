package main

import (
	"debug/elf"
	_ "embed"
	"fmt"
	"math"
	"os"
	"strings"
)

const DEBUG = false

const (
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
	CYCLE    = 0xC00
	TIME     = 0xC01
	INSTRET  = 0xC02
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

//go:embed dtb/dtb.dtb
var dtb []byte

type CPU struct {
	pc   uint64
	mem  []byte
	x    [32]int64
	f    [32]float64
	csr  [4096]uint64
	priv Privilege
	wfi  bool

	uart  Uart
	plic  Plic
	clint Clint

	count uint64
}

func NewCPU(mem []byte, pc uint64) CPU {
	cpu := CPU{
		pc:    pc,
		mem:   mem,
		priv:  Machine,
		uart:  NewUart(),
		plic:  NewPlic(),
		clint: NewClint(),
	}
	// TODO: Why?
	cpu.x[0xb] = 0x1020
	cpu.csr[MISA] = 0x800000008014312f
	return cpu
}

func (cpu *CPU) run() {
	for {
		cpu.step()
	}
}

func (cpu *CPU) step() {
	addr := cpu.pc
	ok, reason, trapaddr := cpu.stepInner()
	if !ok {
		cpu.exception(reason, trapaddr, addr)
	}

	cpu.clint.step(cpu.count, &cpu.csr[MIP])
	cpu.uart.step(cpu.count)
	cpu.plic.step(cpu.count, cpu.uart.interrupting, &cpu.csr[MIP])
	cpu.count++

	cpu.interrupt(cpu.pc)
}

func (cpu *CPU) stepInner() (bool, TrapReason, uint64) {
	if cpu.wfi {
		// TODO: Support interrupts
		return true, 0, 0
	}
	instr, ok, reason := cpu.fetch()
	if !ok {
		return false, reason, cpu.pc
	}

	addr := cpu.pc

	if DEBUG {
		var regs []string
		for _, r := range cpu.x {
			regs = append(regs, fmt.Sprintf("%x", uint64(r)))
		}
		fmt.Printf("%08d -- [%08x]: %08x [%s]\n", cpu.count, cpu.pc, instr, strings.Join(regs, ", "))
	}

	if instr&0b11 == 0b11 {
		cpu.pc += 4
	} else {
		cpu.pc += 2
		instr = cpu.decompress(instr & 0xFFFF)
	}
	ok, reason, trapaddr := cpu.exec(instr, addr)
	cpu.x[0] = 0
	if !ok {
		return false, reason, trapaddr
	}
	return true, 0, 0
}

func (cpu *CPU) fetch() (uint32, bool, TrapReason) {
	return cpu.readuint32(cpu.pc)
}

type TrapReason int64

const (
	UserSoftwareInterrupt       TrapReason = 0x800000000000000
	SupervisorSoftwareInterrupt TrapReason = 0x800000000000001
	HypervisorSoftwareInterrupt TrapReason = 0x800000000000002
	MachineSoftwareInterrupt    TrapReason = 0x800000000000003
	UserTimerInterrupt          TrapReason = 0x800000000000004
	SupervisorTimerInterrupt    TrapReason = 0x800000000000005
	HypervisorTimerInterrupt    TrapReason = 0x800000000000006
	MachineTimerInterrupt       TrapReason = 0x800000000000007
	UserExternalInterrupt       TrapReason = 0x800000000000008
	SupervisorExternalInterrupt TrapReason = 0x800000000000009
	HypervisorExternalInterrupt TrapReason = 0x80000000000000A
	MachineExternalInterrupt    TrapReason = 0x80000000000000B

	InstructionAddressMisaligned TrapReason = 0x000000000000000
	InstructionAccessFault       TrapReason = 0x000000000000001
	IllegalInstruction           TrapReason = 0x000000000000002
	Breakpoint                   TrapReason = 0x000000000000003
	LoadAddressMisaligned        TrapReason = 0x000000000000004
	LoadAccessFault              TrapReason = 0x000000000000005
	StoreAddressMisaligned       TrapReason = 0x000000000000006
	StoreAccessFault             TrapReason = 0x000000000000007
	EnvironmentCallFromUMode     TrapReason = 0x000000000000008
	EnvironmentCallFromSMode     TrapReason = 0x000000000000009
	EnvironmentCallFromHMode     TrapReason = 0x00000000000000A
	EnvironmentCallFromMMode     TrapReason = 0x00000000000000B
	InstructionPageFault         TrapReason = 0x00000000000000C
	LoadPageFault                TrapReason = 0x00000000000000D
	StorePageFault               TrapReason = 0x00000000000000F
)

func (cpu *CPU) exception(reason TrapReason, trapaddr uint64, instructionaddr uint64) {
	cpu.trap(reason, trapaddr, instructionaddr, false)
}

func (cpu *CPU) interrupt(pc uint64) {
	minterrupt := cpu.csr[MIP] & cpu.csr[MIE]
	if minterrupt&MIP_MEIP != 0 {
		panic("nyi - handle MachineExternalInterrupt")
	}
	if minterrupt&MIP_MSIP != 0 {
		panic("nyi - handle MachineSoftwareInterrupt")
	}
	if minterrupt&MIP_MTIP != 0 {
		panic("nyi - handle MachineTimerInterrupt")
	}
	if minterrupt&MIP_SEIP != 0 {
		panic("nyi - handle SupervisorExternalInterrupt")
	}
	if minterrupt&MIP_MSIP != 0 {
		panic("nyi - handle SupervisorSoftwareInterrupt")
	}
	if minterrupt&MIP_MTIP != 0 {
		panic("nyi - handle SupervisorTimerInterrupt")
	}
}

func (cpu *CPU) trap(reason TrapReason, trapaddr, addr uint64, isInterrupt bool) bool {
	var mdeleg, sdeleg uint64
	if isInterrupt {
		mdeleg, sdeleg = cpu.csr[MIDELEG], cpu.csr[SIDELEG]
	} else {
		mdeleg, sdeleg = cpu.csr[MEDELEG], cpu.csr[SEDELEG]
	}
	pos := uint64(reason) & 0xFFFF

	var handlePriv Privilege
	if (mdeleg>>pos)&1 == 0 {
		handlePriv = Machine
	} else if (sdeleg>>pos)&1 == 0 {
		handlePriv = Supervisor
	} else {
		handlePriv = User
	}

	// TODO: Decision about whether to take trap

	cpu.priv = handlePriv

	var epcAddr, causeAddr, tvalAddr, tvecAddr uint64
	switch cpu.priv {
	case Machine:
		epcAddr, causeAddr, tvalAddr, tvecAddr = MEPC, MCAUSE, MTVAL, MTVEC
	case User:
		epcAddr, causeAddr, tvalAddr, tvecAddr = UEPC, UCAUSE, UTVAL, UTVEC
	default:
		panic("not yet implemented non-machine privilege")
	}

	cpu.csr[epcAddr] = addr
	cpu.csr[causeAddr] = uint64(reason)
	cpu.csr[tvalAddr] = trapaddr
	cpu.pc = cpu.csr[tvecAddr]
	if (cpu.pc & 0b11) != 0 {
		panic("vector type address")
		cpu.pc = (cpu.pc>>2)<<2 + (4 * (uint64(reason) & 0xFFFF))
	}

	switch cpu.priv {
	case Machine:
		cpu.setMPIE(cpu.getMIE())
		cpu.setMIE(0)
		cpu.setMPP(uint64(cpu.priv))
	case User:
		cpu.setMPIE(cpu.getMIE())
		cpu.setMIE(0)
		cpu.setMPP(uint64(cpu.priv))
	default:
		panic("not yet implemented non-machine privilege")
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

func (cpu *CPU) exec(instr uint32, addr uint64) (bool, TrapReason, uint64) {
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
			panic("invalid insruction")
		}
	case 0b0000011:
		op := parseI(instr)
		switch op.funct3 {
		case 0b000: // LB
			data, ok, reason := cpu.readuint8(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, reason, addr
			}
			cpu.x[op.rd] = int64(int8(data))
		case 0b001: // LH
			data, ok, reason := cpu.readuint16(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, reason, addr
			}
			cpu.x[op.rd] = int64(int16(data))
		case 0b010: // LW
			data, ok, reason := cpu.readuint32(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, reason, addr
			}
			cpu.x[op.rd] = int64(int32(data))
		case 0b100: // LBU
			data, ok, reason := cpu.readuint8(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, reason, addr
			}
			cpu.x[op.rd] = int64(data)
		case 0b101: // LHU
			data, ok, reason := cpu.readuint16(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, reason, addr
			}
			cpu.x[op.rd] = int64(data)
		case 0b011: // LD
			data, ok, reason := cpu.readuint64(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, reason, addr
			}
			cpu.x[op.rd] = int64(data)
		case 0b110: // LWU
			data, ok, reason := cpu.readuint32(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if !ok {
				return false, reason, addr
			}
			cpu.x[op.rd] = int64(uint64(data))
		default:
			panic("invalid insruction")
		}
	case 0b0100011:
		op := parseS(instr)
		switch op.funct3 {
		case 0b000: // SB
			cpu.writeuint8(uint64(cpu.x[op.rs1]+int64(op.imm)), uint8(cpu.x[op.rs2]))
		case 0b001: // SH
			cpu.writeuint16(uint64(cpu.x[op.rs1]+int64(op.imm)), uint16(cpu.x[op.rs2]))
		case 0b010: // SW
			cpu.writeuint32(uint64(cpu.x[op.rs1]+int64(op.imm)), uint32(cpu.x[op.rs2]))
		case 0b011: // SD
			cpu.writeuint64(uint64(cpu.x[op.rs1]+int64(op.imm)), uint64(cpu.x[op.rs2]))
		default:
			panic("invalid insruction")
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
				panic("invalid insruction")
			}
			cpu.x[op.rd] = cpu.x[op.rs1] << op.imm
		case 0b101:
			switch op.imm >> 6 {
			case 0: // SRLI
				cpu.x[op.rd] = int64(uint64(cpu.x[op.rs1]) >> (op.imm & 0b111111))
			case 0b010000: // SRAI
				cpu.x[op.rd] = cpu.x[op.rs1] >> (op.imm & 0b111111)
			default:
				panic("invalid insruction")
			}
		default:
			panic("invalid insruction")
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
				panic("invalid insruction")
			}
		case 0b001:
			switch op.funct7 {
			case 0: // SLL
				cpu.x[op.rd] = cpu.x[op.rs1] << (cpu.x[op.rs2] & 0b111111)
			case 1: // MULH
				panic("nyi - MULH")
			default:
				panic("invalid insruction")
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
				panic("invalid insruction")
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
				panic("nyi - MULHU")
			default:
				panic("invalid insruction")
			}
		case 0b100:
			switch op.funct7 {
			case 0: // XOR
				cpu.x[op.rd] = cpu.x[op.rs1] ^ cpu.x[op.rs2]
			case 1: // DIV
				panic("nyi - DIV")
			default:
				panic("invalid insruction")
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
				panic("invalid insruction")
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
				panic("invalid insruction")
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
				panic("invalid insruction")
			}
		default:
			panic("invalid insruction")
		}
	case 0b0001111:
		// Do nothing?
	case 0b1110011:
		op := parseCSR(instr)
		switch op.funct3 {
		case 0b000:
			if op.funct3 != 0 || op.rd != 0 || op.rs != 0 {
				panic("invalid insruction")
			}
			switch op.csr {
			case 0: // ECALL
				switch cpu.priv {
				case User:
					return false, EnvironmentCallFromUMode, addr
				case Supervisor:
					return false, EnvironmentCallFromSMode, addr
				case Hypervisor:
					return false, EnvironmentCallFromHMode, addr
				case Machine:
					return false, EnvironmentCallFromMMode, addr
				default:
					panic("invalid CPU privilege")
				}
			case 1:
				panic("nyi - EBREAK")
			case 0b000000000010: // URET
				panic("nyi - URET")
			case 0b000100000010: // SRET
				panic("nyi - SRET")
			case 0b001100000010: // MRET
				cpu.pc = cpu.csr[MEPC]
				cpu.priv = cpu.getMPP()
				cpu.setMIE(cpu.getMPIE())
				cpu.setMPIE(1)
				cpu.setMPP(0)
			case 0b000100000101: // WFI
				cpu.wfi = true
			default:
				switch op.csr >> 5 {
				case 0b0001001:
					panic("nyi - SFENCE.VMA")
				case 0b0010001:
					panic("nyi - HFENCE.BVMA")
				case 0b1010001:
					panic("nyi - HFENCE.GVMA")
				default:
					panic("nyi - invalid instruction")
				}
			}
		case 0b001: // CSRRW
			t := cpu.csr[op.csr]
			cpu.csr[op.csr] = uint64(cpu.x[op.rs])
			cpu.x[op.rd] = int64(t)
		case 0b010: // CSRRS
			t := cpu.csr[op.csr]
			cpu.csr[op.csr] |= uint64(cpu.x[op.rs])
			cpu.x[op.rd] = int64(t)
		case 0b011: // CSRRC
			t := cpu.csr[op.csr]
			trs := cpu.x[op.rs]
			cpu.x[op.rd] = int64(t)
			cpu.csr[op.csr] = uint64(cpu.x[op.rd] & ^trs)
		case 0b101: // CSRRWI
			t := cpu.csr[op.csr]
			cpu.x[op.rd] = int64(t)
			cpu.csr[op.csr] = uint64(op.rs)
		case 0b110: // CSRRSI
			t := cpu.csr[op.csr]
			cpu.x[op.rd] = int64(t)
			cpu.csr[op.csr] = uint64(cpu.x[op.rd] | int64(op.rs))
		case 0b111: // CSRRCI
			t := cpu.csr[op.csr]
			cpu.x[op.rd] = int64(t)
			cpu.csr[op.csr] = uint64(cpu.x[op.rd] & ^int64(op.rs))
		default:
			panic("invalid insruction")
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
				panic("nyi - MULW")
			default:
				panic("invalid insruction")
			}
		case 0b001:
			switch op.funct7 {
			case 0:
				cpu.x[op.rd] = int64(int32(cpu.x[op.rs1]) << (cpu.x[op.rs2] & 0b11111))
			default:
				panic("invalid insruction")
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
					cpu.x[op.rd] = int64(int32(a1 / a2))
				}
			default:
				panic("invalid insruction")
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
				panic("invalid insruction")
			}
		case 0b110:
			switch op.funct7 {
			case 1: // REMW
				panic("nyi - REMW")
			default:
				panic("invalid insruction")
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
				panic("invalid insruction")
			}
		default:
			panic("nyi - 0111011")
		}
	case 0b0101111:
		op := parseR(instr)
		switch op.funct7 >> 2 {
		case 0b00010:
			panic("nyi - LR.W")
		case 0b00011:
			panic("nyi - SC.W")
		case 0b00001: // AMOSWAP.W
			op := parseR(instr)
			v, ok, reason := cpu.readuint32(uint64(cpu.x[op.rs1]))
			if !ok {
				return false, reason, addr
			}
			ok, reason = cpu.writeuint32(uint64(cpu.x[op.rs1]), uint32(cpu.x[op.rs2]))
			if !ok {
				return false, reason, addr
			}
			cpu.x[op.rd] = int64(int32(v))
		case 0b00000: // AMOADD.W
			v, ok, reason := cpu.readuint32(uint64(cpu.x[op.rs1]))
			if !ok {
				return false, reason, addr
			}
			ok, reason = cpu.writeuint32(uint64(cpu.x[op.rs1]), uint32(cpu.x[op.rs2]+int64(int32(v))))
			if !ok {
				return false, reason, addr
			}
			cpu.x[op.rd] = int64(int32(v))
		case 0b00100:
			panic("nyi - AMOXOR.W")
		case 0b01100:
			panic("nyi - AMOAND.W")
		case 0b01000:
			panic("nyi - AMOOR.W")
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
	case 0b0000111:
		panic("nyi - flw")
	case 0b0100111:
		panic("nyi - fsw")
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
		case 0b1111000:
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
				panic("invalid insruction")
			}
			cpu.x[op.rd] = int64(int32(cpu.x[op.rs1] << op.imm))
		case 0b101:
			switch op.imm >> 6 {
			case 0: // SRLIW
				cpu.x[op.rd] = int64(int32(uint32(int32(cpu.x[op.rs1])) >> (op.imm & 0b111111)))
			case 0b010000: // SRAIW
				cpu.x[op.rd] = int64(int32(cpu.x[op.rs1]) >> (op.imm & 0b111111))
			default:
				panic("invalid insruction")
			}
		default:
			panic("invalid insruction")
		}
	default:
		panic(fmt.Sprintf("nyi - opcode %x", instr&0x7f))
	}
	return true, 0, 0
}

func (cpu *CPU) getMPP() Privilege {
	return Privilege((cpu.csr[MSTATUS] >> 11) & 0b11)
}

func (cpu *CPU) setMPP(v uint64) {
	cpu.csr[MSTATUS] |= (v & 0b11) << 11
}

func (cpu *CPU) getMIE() uint64 {
	return (cpu.csr[MSTATUS] >> 3) & 0b1
}

func (cpu *CPU) setMIE(v uint64) {
	cpu.csr[MSTATUS] |= (v & 0b1) << 3
}

func (cpu *CPU) getMPIE() uint64 {
	return (cpu.csr[MSTATUS] >> 7) & 0b1
}

func (cpu *CPU) setMPIE(v uint64) {
	cpu.csr[MSTATUS] |= (v & 0b1) << 7
}

func (cpu *CPU) readraw(addr uint64) uint8 {
	if addr >= 0x80000000 {
		// TODO: allow the ram to be smaller (-0x80000000)
		return cpu.mem[addr]
	}
	if addr >= 0x00001020 && addr <= 0x00001fff {
		daddr := addr - 0x00001020
		if daddr >= uint64(len(dtb)) {
			return 0
		}
		return dtb[addr-0x00001020]
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
		panic(fmt.Sprintf("nyi - read disk %x", addr))
	}
	panic(fmt.Sprintf("nyi - unsupported address %x", addr))
}

func (cpu *CPU) writeraw(addr uint64, v byte) {
	if addr >= 0x80000000 {
		// TODO: allow the ram to be smaller (-0x80000000)
		cpu.mem[addr] = v
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
		panic(fmt.Sprintf("nyi - write disk %x: %x", addr, v))
	}
	panic(fmt.Sprintf("nyi - unsupported address %x: %x", addr, v))
}

func (cpu *CPU) readuint64(addr uint64) (uint64, bool, TrapReason) {
	val := uint64(0)
	for i := uint64(0); i < 8; i++ {
		val |= (uint64(cpu.readraw(addr+i)) << (i * 8))
	}
	return val, true, 0
}

func (cpu *CPU) readuint32(addr uint64) (uint32, bool, TrapReason) {
	val := uint32(0)
	for i := uint64(0); i < 4; i++ {
		val |= (uint32(cpu.readraw(addr+i)) << (i * 8))
	}
	return val, true, 0
}

func (cpu *CPU) readuint16(addr uint64) (uint16, bool, TrapReason) {
	val := uint16(0)
	for i := uint64(0); i < 2; i++ {
		val |= (uint16(cpu.readraw(addr+i)) << (i * 8))
	}
	return val, true, 0
}

func (cpu *CPU) readuint8(addr uint64) (uint8, bool, TrapReason) {
	return cpu.readraw(addr), true, 0
}

func (cpu *CPU) writeuint64(addr uint64, val uint64) (bool, TrapReason) {
	for i := uint64(0); i < 8; i++ {
		cpu.writeraw(addr+i, byte(val>>(i*8)))
	}
	return true, 0
}

func (cpu *CPU) writeuint32(addr uint64, val uint32) (bool, TrapReason) {
	for i := uint64(0); i < 4; i++ {
		cpu.writeraw(addr+i, byte(val>>(i*8)))
	}
	return true, 0
}

func (cpu *CPU) writeuint16(addr uint64, val uint16) (bool, TrapReason) {
	for i := uint64(0); i < 2; i++ {
		cpu.writeraw(addr+i, byte(val>>(i*8)))
	}
	return true, 0
}

func (cpu *CPU) writeuint8(addr uint64, val uint8) (bool, TrapReason) {
	cpu.writeraw(addr, byte(val))
	return true, 0
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
		case 0b001:
			panic("nyi - C.FLD/C.LQ")
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
		case 0b101:
			panic("nyi - C.FSD/C.SQ")
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
					nzimm |= 0xfffc0
				}
				if nzimm != 0 {
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
		case 0b010:
			panic("nyi - C.LWSP")
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
		case 0b110:
			panic("nyi - C.SWSP")
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
	UART_IRQ uint32 = 10
)

type Plic struct {
	irq        uint32
	enabled    uint64 // TODO: Contexts other than 1?
	threshold  uint32
	ips        [1024]uint8
	priorities [1024]uint32
	updateIRQ  bool
}

func NewPlic() Plic {
	return Plic{}
}

func (plic *Plic) step(clock uint64, uartip bool, mip *uint64) {
	// TODO: Only handling UART so far
	if uartip { // Uart is interrupting
		index := 10 >> 3
		plic.ips[index] |= 1 << (10 & 7)
		plic.updateIRQ = true
	}
	if plic.updateIRQ {
		uartip := (plic.ips[10>>3]>>(10&7))&1 == 1
		uartpri := plic.priorities[10]
		uartenabled := (plic.enabled>>10)&1 == 1

		irq := uint32(0)
		if uartip && uartenabled && uartpri > plic.threshold {
			irq = 10
		}

		plic.irq = irq
		if plic.irq != 0 {
			*mip |= MIP_SEIP
		}

		plic.updateIRQ = false
	}
}

func (plic *Plic) readuint8(addr uint64) (v uint8) {
	defer func() { fmt.Printf("plic[%x] => %x\n", addr, v) }()
	fmt.Printf("warning: ignored plic[%x] =>\n", addr)
	panic("nyi - read from plic")
}

func (plic *Plic) writeuint8(addr uint64, v uint8) {
	fmt.Printf("plic[%x] <= %x\n", addr, v)
	if addr >= 0x0c000000 && addr <= 0x0c000fff {
		offset := addr & 0b11
		index := (addr - 0xc000000) >> 2
		pos := offset << 3
		plic.priorities[index] = plic.priorities[index]&^(0xff<<pos) | uint32(v)<<pos
		plic.updateIRQ = true
	} else if addr >= 0x0c002080 && addr <= 0x0c002087 {
		pos := 8 * (addr & 0x11)
		plic.enabled = plic.enabled & ^(0xff<<pos) | uint64(v)<<pos
		if pos == 0 {
			plic.updateIRQ = true
		}
	} else if addr >= 0x0c201000 && addr <= 0x0c201003 {
		pos := 8 * (addr & 0x11)
		plic.threshold = plic.threshold & ^(0xff<<pos) | uint32(v)<<pos
		if pos == 0 {
			plic.updateIRQ = true
		}
	} else if addr == 0x0c201004 {
		panic("nyi - write to plic claim")
	} else {
		fmt.Printf("warning: ignored plic[%x] <= %x\n", addr, v)
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
}

func NewUart() Uart {
	return Uart{
		lsr: LSR_THR_EMPTY,
	}
}

func (uart *Uart) step(clock uint64) {
	rxip := false

	// TODO: input

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
	defer func() { fmt.Printf("uart[%x] => %x\n", addr, v) }()
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
	fmt.Printf("uart[%x] <= %x\n", addr, v)
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
		n, err := prog.ReadAt(mem[prog.Paddr:prog.Paddr+prog.Filesz], 0)
		if err != nil {
			return 0, err
		}
		if n != int(prog.Filesz) {
			return 0, fmt.Errorf("didn't read full section")
		}
		for i := prog.Filesz; i < prog.Memsz; i++ {
			mem[prog.Paddr+i] = 0
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
		*mip = MIP_MSIP
	}
	if clint.mtimecmp > 0 && clint.mtime >= clint.mtimecmp {
		*mip = MIP_MTIP
	}
}

func (clint *Clint) readuint8(addr uint64) (v uint8) {
	defer func() { fmt.Printf("clint[%x] => %x\n", addr, v) }()
	fmt.Printf("warning: ignored cint[%x] =>\n", addr)
	panic("nyi - read from clint")
}

func (clint *Clint) writeuint8(addr uint64, v uint8) {
	fmt.Printf("clint[%x] <= %x\n", addr, v)
	switch addr {
	case 0x02000000:
		clint.msip = clint.msip&^0x1 | uint32(v)&1
	case 0x02000001, 0x02000002, 0x02000003:
		// Hardwired to zero
	default:
		fmt.Printf("warning: ignored clint[%x] <= %v\n", addr, v)
	}
}

func do() error {
	mem := make([]byte, 0x100000000)
	entry, err := loadElf("rv64ui-p-add", mem)
	if err != nil {
		return err
	}

	cpu := NewCPU(mem, entry)
	cpu.run()
	return nil
}

func main() {
	err := do()
	if err != nil {
		panic(err)
	}
}
