package main

import (
	"debug/elf"
	"fmt"
)

const (
	MVENDORID  = 0xF11
	MARCHID    = 0xF12
	MIMPID     = 0xF13
	MHARTID    = 0xF14
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

func (cpu *CPU) run() error {
	for {
		err := cpu.step()
		if err != nil {
			return err
		}
	}
}

func (cpu *CPU) step() error {
	instr, err := cpu.fetch()
	if err != nil {
		return err
	}
	cpu.count++
	addr := cpu.pc
	fmt.Printf("%08d -- [%08x]: %08x %x\n", cpu.count, cpu.pc, instr, cpu.x)
	if instr&0b11 == 0b11 {
		cpu.pc += 4
	} else {
		cpu.pc += 2
		instr &= 0xFFFF
		panic(fmt.Sprintf("nyi: compressed: %08x", instr))
	}
	err = cpu.exec(instr, addr)
	if err != nil {
		return err
	}

	cpu.x[0] = 0

	return nil
}

func (cpu *CPU) fetch() (uint32, error) {
	return cpu.readuint32(cpu.pc)
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

func (cpu *CPU) exec(instr uint32, addr uint64) error {
	switch instr & 0x7f {
	case 0b0110111: // LUI
		op := parseU(instr)
		fmt.Printf("LUI %v\n", op)
		cpu.x[op.rd] = int64(op.imm)
	case 0b0010111: // AUIPC
		op := parseU(instr)
		fmt.Printf("AIUPC %x\n", op)
		cpu.x[op.rd] = int64(addr) + op.imm
	case 0b1101111: // JAL
		op := parseJ(instr)
		fmt.Printf("JAL %x\n", op)
		cpu.x[op.rd] = int64(cpu.pc)
		cpu.pc = addr + uint64(op.imm)
	case 0b1100111:
		panic("nyi - jalr")
	case 0b1100011:
		op := parseB(instr)
		switch op.funct3 {
		case 0b000: // BEQ
			fmt.Printf("BEQ %x\n", op)
			if cpu.x[op.rs1] == cpu.x[op.rs2] {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b001: // BNE
			fmt.Printf("BNE %x\n", op)
			if cpu.x[op.rs1] != cpu.x[op.rs2] {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b100: // BLT
			fmt.Printf("BLT %x\n", op)
			if cpu.x[op.rs1] < cpu.x[op.rs2] {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b101: // BGE
			fmt.Printf("BGE %x\n", op)
			if cpu.x[op.rs1] >= cpu.x[op.rs2] {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b110: // BLTU
			fmt.Printf("BLTU %x\n", op)
			if uint64(cpu.x[op.rs1]) < uint64(cpu.x[op.rs2]) {
				cpu.pc = addr + uint64(op.imm)
			}
		case 0b111: // BGEU
			fmt.Printf("BGEU %x\n", op)
			if uint64(cpu.x[op.rs1]) >= uint64(cpu.x[op.rs2]) {
				cpu.pc = addr + uint64(op.imm)
			}
		default:
			return fmt.Errorf("invalid branch op funct3: %x", op.funct3)
		}
	case 0b0000011:
		op := parseI(instr)
		switch op.funct3 {
		case 0b000: // LB
			data, err := cpu.readuint8(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if err != nil {
				return err
			}
			cpu.x[op.rd] = int64(int8(data))
		case 0b001: // LH
			data, err := cpu.readuint16(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if err != nil {
				return err
			}
			cpu.x[op.rd] = int64(int16(data))
		case 0b010: // LW
			data, err := cpu.readuint32(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if err != nil {
				return err
			}
			cpu.x[op.rd] = int64(int32(data))
		case 0b100: // LBU
			data, err := cpu.readuint8(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if err != nil {
				return err
			}
			cpu.x[op.rd] = int64(data)
		case 0b101: // LHU
			data, err := cpu.readuint16(uint64(cpu.x[op.rs1] + int64(op.imm)))
			if err != nil {
				return err
			}
			cpu.x[op.rd] = int64(data)
		default:
			return fmt.Errorf("invalid load op funct3: %x", op.funct3)
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
			return fmt.Errorf("invalid store op funct3: %x", op.funct3)
		}
	case 0b0010011:
		op := parseI(instr)
		switch op.funct3 {
		case 0b000: // ADDI
			fmt.Printf("ADDI %x\n", op)
			cpu.x[op.rd] = cpu.x[op.rs1] + int64(op.imm)
		case 0b010: // SLTI
			fmt.Printf("SLTI %x\n", op)
			panic("nyi - SLTI")
		case 0b011: // SLTIU
			fmt.Printf("SLTIU %x\n", op)
			panic("nyi - SLTIU")
		case 0b100: // XORI
			fmt.Printf("ADDI %x\n", op)
			cpu.x[op.rd] = cpu.x[op.rs1] ^ int64(op.imm)
		case 0b110: // ORI
			fmt.Printf("ORI %x\n", op)
			cpu.x[op.rd] = cpu.x[op.rs1] | int64(op.imm)
		case 0b111: // ANDI
			fmt.Printf("ANDI %x\n", op)
			cpu.x[op.rd] = cpu.x[op.rs1] & int64(op.imm)
		case 0b001: // SLLI
			fmt.Printf("SLLI %x\n", op)
			if op.imm>>6 != 0 {
				return fmt.Errorf("invalid shamt %x", op.funct3)
			}
			cpu.x[op.rd] = cpu.x[op.rs1] << op.imm
		case 0b101: // SR_I
			fmt.Printf("SR_I %x\n", op)
			panic("nyi - SR_I")
		default:
			return fmt.Errorf("invalid arith op funct3: %x", op.funct3)
		}
	case 0b0110011:
		panic("nyi - arith")
	case 0b0001111:
		panic("nyi - fence")
	case 0b1110011:
		op := parseCSR(instr)
		switch op.funct3 {
		case 0b000:
			if op.funct3 != 0 || op.rd != 0 || op.rs != 0 {
				return fmt.Errorf("invalid op ECALL/EBREAK: %x", op)
			}
			switch op.csr {
			case 0:
				panic("nyi - ECALL")
			case 1:
				panic("nyi - EBREAK")
			case 0b001100000010:
				cpu.pc = cpu.csr[MEPC]
				cpu.priv = cpu.getMPP()
				cpu.setMIE(cpu.getMPIE())
				cpu.setMPIE(1)
				// TODO: When we support user mode, go back to user mode on MRET?
				//cpu.setMPP(0)
			default:
				return fmt.Errorf("invalid op ECALL/EBREAK: %x", op)
			}
		case 0b001:
			fmt.Printf("CSRRW %v\n", op)
			t := cpu.csr[op.csr]
			cpu.csr[op.csr] = uint64(cpu.x[op.rs])
			cpu.x[op.rd] = int64(t)
		case 0b010:
			fmt.Printf("CSRRS %v\n", op)
			t := cpu.csr[op.csr]
			cpu.csr[op.csr] |= uint64(cpu.x[op.rs])
			cpu.x[op.rd] = int64(t)
		case 0b011:
			panic("nyi - CSRRC")
		case 0b101:
			fmt.Printf("CSRRWI %v\n", op)
			t := cpu.csr[op.csr]
			cpu.csr[op.csr] = uint64(op.rs)
			cpu.x[op.rd] = int64(t)
		case 0b110:
			panic("nyi - CSRRSI")
		case 0b111:
			panic("nyi - CSRRCI")
		default:
			return fmt.Errorf("invalid csr op funct3: %x", op.funct3)
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
		case 0b000:
			fmt.Printf("ADDIW %v\n", op)
			cpu.x[op.rd] = int64(int32(cpu.x[op.rs1] + int64(op.imm)))
		case 0b001:
			fmt.Printf("SLLIW %v\n", op)
			panic("nyi - SLLIW")
		case 0b101:
			if (op.imm>>11)&0b1 == 0b1 {
				fmt.Printf("SRAIW %v\n", op)
				panic("nyi - SRAIW")
			} else {
				fmt.Printf("SRLIW %v\n", op)
				panic("nyi - SRLIW")
			}
		default:
			return fmt.Errorf("invalid op %x funct3: %x", instr&0x7f, op.funct3)
		}
	default:
		panic(fmt.Sprintf("nyi - opcode %x", instr&0x7f))
	}
	return nil
}

func (cpu *CPU) getMPP() Privilege {
	return Privilege((cpu.csr[MSTATUS] >> 11) & 0b11)
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

func (cpu *CPU) readuint32(addr uint64) (uint32, error) {
	val := uint32(0)
	for i := uint64(0); i < 4; i++ {
		val |= (uint32(cpu.mem[addr+i]) << (i * 8))
	}
	return val, nil
}

func (cpu *CPU) readuint16(addr uint64) (uint16, error) {
	val := uint16(0)
	for i := uint64(0); i < 2; i++ {
		val |= (uint16(cpu.mem[addr+i]) << (i * 8))
	}
	return val, nil
}

func (cpu *CPU) readuint8(addr uint64) (uint8, error) {
	return uint8(cpu.mem[addr]), nil
}

func (cpu *CPU) writeuint32(addr uint64, val uint32) {
	for i := uint64(0); i < 4; i++ {
		cpu.mem[addr+i] = byte(val >> (i * 8))
	}
}

func (cpu *CPU) writeuint16(addr uint64, val uint16) {
	for i := uint64(0); i < 2; i++ {
		cpu.mem[addr+i] = byte(val >> (i * 8))
	}
}

func (cpu *CPU) writeuint8(addr uint64, val uint8) {
	cpu.mem[addr] = byte(val)
}

func do() error {
	mem := make([]byte, 0x100000000)

	f, err := elf.Open("rv64ui-p-add")
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", f.FileHeader)
	for _, prog := range f.Progs {
		n, err := prog.ReadAt(mem[prog.Paddr:prog.Paddr+prog.Memsz], 0)
		if err != nil {
			return err
		}
		if n != int(prog.Memsz) {
			return fmt.Errorf("didn't read full section")
		}
	}
	err = f.Close()
	if err != nil {
		return err
	}

	cpu := NewCPU(mem, f.Entry)
	err = cpu.run()
	if err != nil {
		return err
	}

	return nil
}

func main() {
	err := do()
	if err != nil {
		panic(err)
	}
}
