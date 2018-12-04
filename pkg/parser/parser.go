package parser

import (
	"bufio"
	"debug/elf"
	"github.com/bnagy/gapstone"
	. "github.com/neuegram/tROPhy/pkg/assembly"
	. "github.com/neuegram/tROPhy/pkg/assembly/arm"
	. "github.com/neuegram/tROPhy/pkg/auto"
	"io"
)

// Parse - Parses binary into BasicBlocks
func Parse(in string) (*[]BasicBlock, *Taint) {
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
	thumbBlocks, _ := Disassemble(&buf, gapstone.CS_MODE_THUMB)
	armBlocks, _ := Disassemble(&buf, gapstone.CS_MODE_ARM)
	allBlocks := *thumbBlocks
	for _, bb := range *armBlocks {
		allBlocks = append(allBlocks, bb)
	}

	return &allBlocks, nil
}
