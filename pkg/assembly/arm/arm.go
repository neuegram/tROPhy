package arm

import (
	"github.com/bnagy/gapstone"
	. "github.com/neuegram/tROPhy/pkg/assembly"
	. "github.com/neuegram/tROPhy/pkg/auto"
)

func Disassemble(buf *[]byte, mode uint) (*[]BasicBlock, *Taint) {
	blocks := []BasicBlock{}

	// Initialize instance of capstone engine using nasty Cgo bindings
	engine, err := gapstone.New(gapstone.CS_ARCH_ARM, mode)
	if err != nil {
		panic(err)
	}
	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

	// DisasmIter()'s implementation seems a little goroutine happy, but fuck it
	bb := NewBasicBlock()
	taint := *NewTaint()
	for instruction := range engine.DisasmIter(*buf, 0x0) {
		if mode == gapstone.CS_MODE_THUMB {
			instruction.Address++
		}
		bb.AddInstruction(instruction)
		// TODO - Get taint working
		//_, ok := taint[&instruction]
		//if !ok {
		//	// Construct new TaintTag
		//	NewTaintTag(&instruction)
		//} else { /* Add offset to TaintTag */
		//}

		if IsControlFlowInstruction(&instruction) {
			blocks = append(blocks, *bb)
			bb = NewBasicBlock()
		}
	}

	return &blocks, &taint
}

func IsControlFlowInstruction(instruction *gapstone.Instruction) bool {
	// Handles any branch to an address stored in a register
	for group := range instruction.Groups {
		if group == gapstone.ARM_GRP_JUMP {
			return true
		}
	}
	// Handles the edge case of a branch caused by a pop into pc
	for _, operand := range instruction.Arm.Operands {
		if operand.Reg == gapstone.ARM_REG_PC {
			return true
		}
	}
	return false
}
