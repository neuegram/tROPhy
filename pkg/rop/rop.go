package rop

import (
	"errors"
	"fmt"

	"../../pkg/parser"
	"github.com/bnagy/gapstone"
	"github.com/glenn-brown/golang-pkg-pcre/src/pkg/pcre"
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
		ret := Gadget{"ret", `\xc0\x03\x5f\xd6`, ARMSize, ARMAlign}
		bx := Gadget{"bx", `[\x10-\x19\x1e]\xff\x2f\xe1`, ARMSize, ARMAlign}
		blx := Gadget{"blx", "[\x30-\x39\x3e]\xff\x2f\xe1", ARMSize, ARMAlign}
		ldm := Gadget{"ldm", `[\x00-\xff][\x80-\xff][\x10-\x1e\x30-\x3e\x50-\x5e\x70-\x7e\x90-\x9e\xb0-\xbe\xd0-\xde\xf0-\xfe][\xe8\xe9]`, ARMSize, ARMAlign}
		svc := Gadget{"svc", `[\x00-\xff]{3}\xef`, ARMSize, ARMAlign}

		// add gadgets together
		gadgets = append(gadgets, ret, bx, blx, ldm, svc)
	} else {
		return nil, errors.New("Architecture not supported")
	}

	return gadgets, nil
}

// FindGadgets - finds gadgets in the binary for specified architecture
func FindGadgets(blocks []parser.BasicBlock, arch ARCH) ([]Gadget, error) {
	var engine gapstone.Engine
	gadgets, err := setUpGadgets(arch)
	if err != nil {
		panic(err)
	}

	if arch == ARM {
		engine, err = gapstone.New(gapstone.CS_ARCH_ARM, gapstone.CS_MODE_ARM)
		if err != nil {
			panic(err)
		}
		engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

	} else {
		panic(errors.New("Architecture not supported"))
	}

	for _, block := range blocks {
		for _, gadget := range gadgets {
			// Go's regex is fucking dumb as shit and can't do ASCII/Bytes
			re := pcre.MustCompile(gadget.pattern, 0)
			match := re.Matcher(block.Raw, 0)
			if match.Matches() {
				fmt.Println(gadget.name)
				fmt.Println(match.Group(0))
			}

		}
	}
	return nil, nil

}

type Gadget struct {
	name      string
	pattern   string
	size      uint
	alignment uint
}
