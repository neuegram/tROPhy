package main

import (
	"flag"
	"fmt"

	"../pkg/executable"
)

var in = flag.String("input", "./test/stack0.dms", "ARM32 Binary file input")
var out = flag.String("output", "", "Gadget output file")

func main() {
	// Parse command-line flags
	flag.Parse()

	// Parse executable
	blocks, err := executable.Parse(*in)
	if err != nil {
		// Log failure
	}
	fmt.Printf("Trophy found %d blocks\n", len(blocks))

	// gadgets, err := rop.FindGadgets(blocks)
	// if err != nil {
	// Log failure
	// }
	//
	//// Allow further refinement of search, generate automatic chain, or output all rop
	//fmt.Println(gadgets)
}
