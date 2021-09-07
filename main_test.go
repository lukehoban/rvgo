package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRiscvTests(t *testing.T) {
	files, err := ioutil.ReadDir("testdata")
	assert.NoError(t, err)
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".dump") {
			continue
		}
		// if file.Name() != "rv64ui-p-srai" {
		// 	continue
		// }
		t.Run(file.Name(), func(t *testing.T) {
			mem := make([]byte, 0x100000000)
			entry, err := loadElf(filepath.Join("testdata", file.Name()), mem)
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
		})
	}
}

func TestFirmware(t *testing.T) {
	var err error
	debugFile, err = os.Create("trace.txt")
	assert.NoError(t, err)
	defer debugFile.Close()
	DEBUG = false

	mem := make([]byte, 0x100000000)
	entry, err := loadElf(filepath.Join("linux", "fw_payload.elf"), mem)
	assert.NoError(t, err)
	cpu := NewCPU(mem, entry)

	defer func() {
		err := recover()
		fmt.Printf("finished at cycle: %d\n", cpu.count)
		assert.Nil(t, err)
	}()

	for {
		cpu.step()
		if cpu.wfi {
			// TODO: Support interrupts needed to make more progress
			return
		}
	}
}
