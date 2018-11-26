package rop

import (
	"fmt"
	"os"

	"../../pkg/parser"
)

// ARCH - type to determine arch
type ARCH uint

// Different archs
const (
	ARM ARCH = 0
)

func setUpGadgets(arch ARCH) ([]Gadget, error) {
	var gadgets []Gadget
	if arch == ARM {
		// Define the gadgets for ARM
		// All ARM instructions are same size/alignment
		const ARMSize = 4
		const ARMAlign = 4
		ret := Gadget{[]byte("\xc0\x03\x5f\xd6"), ARMSize, ARMAlign}
		bx := Gadget{[]byte("[\x10-\x19\x1e]{1}\xff\x2f\xe1"), ARMSize, ARMAlign}
		blx := Gadget{[]byte("[\x30-\x39\x3e]{1}\xff\x2f\xe1"), ARMSize, ARMAlign}
		ldm := Gadget{[]byte("[\x00-\xff][\x80-\xff][\x10-\x1e\x30-\x3e\x50-\x5e\x70-\x7e\x90-\x9e\xb0-\xbe\xd0-\xde\xf0-\xfe][\xe8\xe9]"), ARMSize, ARMAlign}
		svc := Gadget{[]byte("\x00-\xff]{3}\xef"), ARMSize, ARMAlign}

		// add gadgets together
		gadgets = append(gadgets, ret, bx, blx, ldm, svc)
	} else {
		fmt.Println("architecture not supported")
		return nil, nil
	}

	return gadgets, nil
}

// FindGadgets - finds gadgets in the binary for specified architecture
func FindGadgets(blocks []parser.BasicBlock, arch ARCH) ([]Gadget, error) {

	gadgets, err := setUpGadgets(arch)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(gadgets)

	for i := 0; i < len(blocks); i++ {
		// fmt.Println(blocks[i].StartAddress)
	}
	return nil, nil

}

type Gadget struct {
	binary    []byte
	size      uint
	alignment uint
}
