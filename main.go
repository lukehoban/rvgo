package main

import (
	"debug/elf"
	"fmt"
)

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

type Privilege uint8

const (
	User       Privilege = 0
	Supervisor Privilege = 1
	Hypervisor Privilege = 2
	Machine    Privilege = 3
)

type CPU struct {
	pc   uint64
	mem  []byte
	x    [32]int64
	csr  [4096]uint64
	priv Privilege

	count uint64
}

func NewCPU(mem []byte, pc uint64) CPU {
	return CPU{
		pc:   pc,
		mem:  mem,
		priv: Machine,
	}
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
	cpu.interrupt(cpu.pc)
	cpu.count++
}

func (cpu *CPU) stepInner() (bool, TrapReason, uint64) {
	instr, ok, reason := cpu.fetch()
	if !ok {
		return false, reason, cpu.pc
	}

	addr := cpu.pc
	// fmt.Printf("%08d -- [%08x]: %08x %x\n", cpu.count, cpu.pc, instr, cpu.x)
	if instr&0b11 == 0b11 {
		cpu.pc += 4
	} else {
		cpu.pc += 2
		instr &= 0xFFFF
		panic(fmt.Sprintf("nyi: compressed: %08x", instr))
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
	// TODO: handle interrupts
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
	case 0b1100111:
		op := parseI(instr)
		rd := op.rd
		if rd == 0 {
			rd = 1
		}
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
			return false, IllegalInstruction, addr
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
		default:
			return false, IllegalInstruction, addr
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
		default:
			return false, IllegalInstruction, addr
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
				return false, IllegalInstruction, addr
			}
			cpu.x[op.rd] = cpu.x[op.rs1] << op.imm
		case 0b101:
			switch op.imm >> 6 {
			case 0: // SRLI
				cpu.x[op.rd] = int64(uint64(cpu.x[op.rs1]) >> (op.imm & 0b111111))
			case 0b0100000: // SRAI
				cpu.x[op.rd] = cpu.x[op.rs1] >> (op.imm & 0b111111)
			default:
				return false, IllegalInstruction, addr
			}
		default:
			return false, IllegalInstruction, addr
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
			default:
				return false, IllegalInstruction, addr
			}
		case 0b001: // SLL
			cpu.x[op.rd] = cpu.x[op.rs1] << (cpu.x[op.rs2] & 0b111111)
		case 0b010: // SLT
			if cpu.x[op.rs1] < cpu.x[op.rs2] {
				cpu.x[op.rd] = 1
			} else {
				cpu.x[op.rd] = 0
			}
		case 0b011: // SLTU
			if uint64(cpu.x[op.rs1]) < uint64(cpu.x[op.rs2]) {
				cpu.x[op.rd] = 1
			} else {
				cpu.x[op.rd] = 0
			}
		case 0b100: // XOR
			cpu.x[op.rd] = cpu.x[op.rs1] ^ cpu.x[op.rs2]
		case 0b101:
			switch op.funct7 {
			case 0: // SRL
				cpu.x[op.rd] = int64(uint64(cpu.x[op.rs1]) >> (cpu.x[op.rs2] & 0b111111))
			case 0b0100000: // SRA
				cpu.x[op.rd] = cpu.x[op.rs1] >> (cpu.x[op.rs2] & 0b111111)
			default:
				return false, IllegalInstruction, addr
			}
		case 0b110:
			cpu.x[op.rd] = cpu.x[op.rs1] | cpu.x[op.rs2]
		case 0b111:
			cpu.x[op.rd] = cpu.x[op.rs1] & cpu.x[op.rs2]
		default:
			return false, IllegalInstruction, addr
		}

	case 0b0001111:
		// Do nothing?
	case 0b1110011:
		op := parseCSR(instr)
		switch op.funct3 {
		case 0b000:
			if op.funct3 != 0 || op.rd != 0 || op.rs != 0 {
				return false, IllegalInstruction, addr
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
			case 0b001100000010:
				cpu.pc = cpu.csr[MEPC]
				cpu.priv = cpu.getMPP()
				cpu.setMIE(cpu.getMPIE())
				cpu.setMPIE(1)
				cpu.setMPP(0)
			default:
				return false, IllegalInstruction, addr
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
			panic("nyi - CSRRC")
		case 0b101: // CSRRWI
			t := cpu.csr[op.csr]
			cpu.csr[op.csr] = uint64(op.rs)
			cpu.x[op.rd] = int64(t)
		case 0b110:
			panic("nyi - CSRRSI")
		case 0b111:
			panic("nyi - CSRRCI")
		default:
			return false, IllegalInstruction, addr
		}
	case 0b0111011:
		panic("nyi - M extensions")
	case 0b0101111:
		panic("nyi - A extensions")
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
		panic("nyi - F extension")
	case 0b0011011:
		op := parseI(instr)
		switch op.funct3 {
		case 0b000: // ADDIW
			cpu.x[op.rd] = int64(int32(cpu.x[op.rs1] + int64(op.imm)))
		case 0b001: // SLLIW
			if op.imm>>5 != 0 {
				return false, IllegalInstruction, addr
			}
			cpu.x[op.rd] = int64(int32(cpu.x[op.rs1] << op.imm))
		case 0b101:
			switch op.imm >> 6 {
			case 0: // SRLIW
				cpu.x[op.rd] = int64(int32(uint32(int32(cpu.x[op.rs1])) >> (op.imm & 0b111111)))
			case 0b0100000: // SRAIW
				cpu.x[op.rd] = int64(int32(cpu.x[op.rs1]) >> (op.imm & 0b111111))
			default:
				return false, IllegalInstruction, addr
			}
		default:
			return false, IllegalInstruction, addr
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

func (cpu *CPU) readuint32(addr uint64) (uint32, bool, TrapReason) {
	val := uint32(0)
	for i := uint64(0); i < 4; i++ {
		val |= (uint32(cpu.mem[addr+i]) << (i * 8))
	}
	return val, true, 0
}

func (cpu *CPU) readuint16(addr uint64) (uint16, bool, TrapReason) {
	val := uint16(0)
	for i := uint64(0); i < 2; i++ {
		val |= (uint16(cpu.mem[addr+i]) << (i * 8))
	}
	return val, true, 0
}

func (cpu *CPU) readuint8(addr uint64) (uint8, bool, TrapReason) {
	return uint8(cpu.mem[addr]), true, 0
}

func (cpu *CPU) writeuint32(addr uint64, val uint32) (bool, TrapReason) {
	for i := uint64(0); i < 4; i++ {
		cpu.mem[addr+i] = byte(val >> (i * 8))
	}
	return true, 0
}

func (cpu *CPU) writeuint16(addr uint64, val uint16) (bool, TrapReason) {
	for i := uint64(0); i < 2; i++ {
		cpu.mem[addr+i] = byte(val >> (i * 8))
	}
	return true, 0
}

func (cpu *CPU) writeuint8(addr uint64, val uint8) (bool, TrapReason) {
	cpu.mem[addr] = byte(val)
	return true, 0
}

func loadElf(file string, mem []byte) (uint64, error) {
	f, err := elf.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	for _, prog := range f.Progs {
		n, err := prog.ReadAt(mem[prog.Paddr:prog.Paddr+prog.Memsz], 0)
		if err != nil {
			return 0, err
		}
		if n != int(prog.Memsz) {
			return 0, fmt.Errorf("didn't read full section")
		}
	}
	return f.Entry, nil
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
