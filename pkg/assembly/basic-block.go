package assembly

import (
	"fmt"
	"github.com/bnagy/gapstone"
	"strings"
)

type BasicBlock struct {
	instructions []gapstone.Instruction
}

func NewBasicBlock() *BasicBlock {
	return &BasicBlock{}
}

func (bb *BasicBlock) Instructions() *[]gapstone.Instruction {
	return &bb.instructions
}

func (bb *BasicBlock) AddInstruction(instruction gapstone.Instruction) {
	bb.instructions = append(bb.instructions, instruction)
}

func (bb *BasicBlock) String() string {
	var sb strings.Builder
	first := true
	for _, instruction := range *bb.Instructions() {
		var str string
		if first {
			str = fmt.Sprintf("[*] <0x%08x>:", instruction.Address)
			sb.WriteString(str)
			first = false
		}
		str = fmt.Sprintf(" %s %s;", instruction.Mnemonic, instruction.OpStr)
		sb.WriteString(str)
	}
	return sb.String()
}
