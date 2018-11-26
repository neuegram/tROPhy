package parser

import (
	"bufio"
	"debug/elf"
	"io"

	"github.com/bnagy/gapstone"
)

//type Executable interface {
//	Parse(in string) ([]BasicBlock, error)
//}

// Parse - Parses binary into BasicBlocks
func Parse(in string) ([]BasicBlock, error) {
	bin, err := elf.Open(in)
	if err != nil {
		panic(err)
	}

	section := bin.Section(".text")
	if section == nil {
		panic("Section == nil")
	}

	// Get an io.Reader so we can buffer reading the Elf, distributing work of disassembling to pool of goroutines
	rs := section.Open()
	if rs == nil {
		panic("section.Open() == nil")
	}

	// Read in 4096 bytes at a time
	reader := bufio.NewReader(rs)
	buf := make([]byte, 4096)
	if _, err := reader.Read(buf); err != nil && err != io.EOF {
		panic(err)
	}
	blocks := dissemble(&buf)

	return blocks, nil

}

func calculateTaintTag(instruction *gapstone.Instruction) TaintTag {
	return TaintTag{0, 0}
}

func isControlFlowInstruction(instruction *gapstone.Instruction) bool {
	for group := range instruction.Groups {
		if group == gapstone.ARM_GRP_JUMP {
			// fmt.Println("ARM_GRP_JUMP")
			// fmt.Println(instruction.Mnemonic)
			return true
		}
	}

	// range keyword was not working here
	// for i := 0; i < len(instruction.Arm.Operands); i++ {
	// 	if instruction.Arm.Operands[i].Reg == gapstone.ARM_REG_PC {
	// 		fmt.Println("ARM_REG_PC")
	// 		fmt.Println(instruction.Mnemonic)
	// 		return false
	// 	}
	// }

	return false
}

func dissemble(buf *[]byte) []BasicBlock {
	blocks := []BasicBlock{}

	// Initialize instance of capstone engine using nasty Cgo bindings
	engine, err := gapstone.New(gapstone.CS_ARCH_ARM, gapstone.CS_MODE_ARM)
	if err != nil {
		panic(err)
	}
	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

	// DisasmIter()'s implementation seems a little goroutine happy, but fuck it
	var bag []gapstone.Instruction
	var tags []TaintTag
	var bytes []byte
	var addr uint
	var length uint
	var size uint
	for instruction := range engine.DisasmIter(*buf, 0x0) {
		length++
		size += instruction.Size
		if addr == 0 {
			addr = instruction.Address
		}
		bag = append(bag, instruction)
		tags = append(tags, calculateTaintTag(&instruction))
		bytes = append(bytes, instruction.Bytes[:]...)
		// fmt.Printf("[*] <0x%08x>: %s %s\n", instruction.Address, instruction.Mnemonic, instruction.OpStr)

		if isControlFlowInstruction(&instruction) {
			blocks = append(blocks, BasicBlock{addr, length, size, bag, bytes, nil})
			bag = []gapstone.Instruction{}
			bytes = []byte("")
			addr = 0
			length = 0
			size = 0
		}
	}

	return blocks
}

// BasicBlock - A Block of code followed by a control flow
type BasicBlock struct {
	StartAddress uint
	Length       uint
	Size         uint
	Instructions []gapstone.Instruction
	Raw          []byte
	Tags         []TaintTag
}

// TaintTag - A tag to keep track of the registers being modified
type TaintTag struct {
	Source uint
	Sink   uint
}
