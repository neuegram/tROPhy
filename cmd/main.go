package main

import (
	"flag"
	"fmt"
	"os"

	"../pkg/parser"
	"../pkg/rop"
)

var in = flag.String("input", "./test/stack0.dms", "ARM32 Binary file input")
var out = flag.String("output", "", "Gadget output file")

func main() {
	// Parse command-line flags
	flag.Parse()

	// Parse executable
	blocks, err := parser.Parse(*in)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// fmt.Printf("Trophy found %d blocks\n", len(blocks))

	gadgets, err := rop.FindGadgets(blocks)
	if err != nil {
		// Log failure
	}
	//
	// Allow further refinement of search, generate automatic chain, or output all rop
	fmt.Println(len(gadgets))
}
