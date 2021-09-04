package main

import (
	"fmt"
	"testing"
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
