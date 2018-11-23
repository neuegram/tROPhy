package executable

import (
	"bufio"
	"debug/elf"
	"io"

	"github.com/bnagy/gapstone"
)

//type Executable interface {
//	Parse(in string) ([]BasicBlock, error)
//}

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
	blocks := Disassemble(&buf)

	return blocks, nil

}

func isControlFlowInstruction(instruction *gapstone.Instruction) bool {
	for group := range instruction.Groups {
		if group == gapstone.ARM_GRP_JUMP {
			// fmt.Println("ARM_GRP_JUMP")
			return true
		}
	}

	// range keyword was not working here
	for i := 0; i < len(instruction.Arm.Operands); i++ {
		if instruction.Arm.Operands[i].Reg == gapstone.ARM_REG_PC {
			// fmt.Println("ARM_REG_PC")
			// return true
		}
	}

	return false
}

func Disassemble(buf *[]byte) []BasicBlock {
	blocks := []BasicBlock{}

	// Initialize instance of capstone engine using nasty Cgo bindings
	engine, err := gapstone.New(gapstone.CS_ARCH_ARM, gapstone.CS_MODE_ARM)
	if err != nil {
		panic(err)
	}
	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

	// DisasmIter()'s implementation seems a little goroutine happy, but fuck it
	var bag []gapstone.Instruction
	var addr uint
	var length uint

	for instruction := range engine.DisasmIter(*buf, 0x0) {
		length++
		if addr == 0 {
			addr = instruction.Address
		}
		bag = append(bag, instruction)
		// fmt.Printf("[*] <0x%08x>: %s %s\n", instruction.Address, instruction.Mnemonic, instruction.OpStr)
		// confused what determines a block, so essentially
		// I grouped up everything until a control flow happens, kind of makes sense
		// but also iffy on how ROP works
		if isControlFlowInstruction(&instruction) {
			blocks = append(blocks, BasicBlock{addr, length, bag, nil})
			addr = 0
			length = 0
		}
	}

	return blocks
}

type BasicBlock struct {
	StartAddress uint
	Length       uint
	Instructions []gapstone.Instruction
	Tags         []TaintTag
}

type TaintTag struct {
	Source uint
	Sink   uint
}
