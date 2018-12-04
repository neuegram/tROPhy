package auto

import (
	"fmt"
	"github.com/bnagy/gapstone"
)

type TaintTag struct {
	dst []uint
	src uint
	idx uint
	disp int
	imm int32
}

func NewTaintTag(instruction *gapstone.Instruction) *TaintTag {
	fmt.Printf("[*] Instruction : %s %s\n", instruction.Mnemonic, instruction.OpStr)

	t := TaintTag{
		dst: []uint{},
		src: 0,
		idx: 0,
		disp: 0,
		imm: 0,
	}

	dst_count := 0
	for i := 0; i < len(instruction.Arm.Operands) && (t.src == 0 && t.imm == 0); i++ {
		if !(instruction.Id == gapstone.ARM_INS_STR || instruction.Id != gapstone.ARM_INS_PUSH) {
			switch instruction.Arm.Operands[i].Type {
			case gapstone.ARM_OP_REG:
				{
					if dst_count == 0 || instruction.Id == gapstone.ARM_INS_POP {
						t.dst = append(t.dst, instruction.Arm.Operands[i].Reg)
						dst_count++
						fmt.Printf(" dst=r%d", instruction.Arm.Operands[i].Reg)
					} else {
						t.src = instruction.Arm.Operands[i].Reg
						fmt.Printf(" src=r%d", instruction.Arm.Operands[i].Reg)
					}
					break
				}
			case gapstone.ARM_OP_MEM:
				{
					t.src = instruction.Arm.Operands[i].Mem.Base
					t.idx = instruction.Arm.Operands[i].Mem.Index
					t.disp = instruction.Arm.Operands[i].Mem.Disp
					fmt.Printf(" src=r%d, idx=%d, disp=%d", t.src, t.idx, t.disp)
					break
				}
			case gapstone.ARM_OP_IMM:
				{
					t.imm = instruction.Arm.Operands[i].Imm
					fmt.Printf(" imm=%d", instruction.Arm.Operands[i].Imm)
					break
				}
			}
		}
	}
	fmt.Println()

	return &t
}

func (t *TaintTag) Dst() *[]uint {
	return &t.dst
}

func (t *TaintTag) Src() uint {
	return t.src
}

func (t *TaintTag) Disp() int {
	return t.disp
}

func (t *TaintTag) Imm() int32 {
	return t.imm
}