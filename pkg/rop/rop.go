package rop

import (
	"fmt"

	"../../pkg/parser"
)

func FindGadgets(blocks []parser.BasicBlock) ([]Gadget, error) {

	for i := 0; i < len(blocks); i++ {
		fmt.Println(blocks[i].StartAddress)
	}
	return nil, nil

}

type Gadget struct {
	temp string
}
