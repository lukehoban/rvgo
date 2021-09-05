package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFoo(t *testing.T) {
	x := uint8(0xff)
	y := int8(x)
	a := uint32(x)
	b := int32(x)
	c := int32(int8(x))
	d := uint32(int8(x))

	fmt.Printf("%d, %d, %d, b=%d, c=%d, %d\n", x, y, a, b, c, d)
}

func TestRV64UIpADD(t *testing.T) {
	mem := make([]byte, 0x100000000)
	entry, err := loadElf("rv64ui-p-add", mem)
	assert.NoError(t, err)

	cpu := NewCPU(mem, entry)
	for {
		cpu.step()
		exitcode := mem[0x80001000]
		if exitcode != 0 {
			assert.Equal(t, uint8(1), exitcode, "failing exitcode %d recieved", exitcode)
			return
		}
	}
}

func TestMain(t *testing.T) {
	err := do()
	if err != nil {
		t.Fail()
	}
}
