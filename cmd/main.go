package main

import (
	"flag"
	"fmt"
	"net/http"

	"../pkg/parser"
	"../pkg/rop"
)

var in = flag.String("input", "./test/stack0.dms", "ARM32 Binary file input")
var out = flag.String("output", "", "Gadget output file")

func main() {
	fs := http.FileServer(http.Dir("static/"))

	http.Handle("/", http.StripPrefix("/", fs))
	http.HandleFunc("/analyze", analyze)
	// http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.ListenAndServe(":80", nil)
}

func analyze(writer http.ResponseWriter, request *http.Request) {
	flag.Parse()
	blocks, err := parser.Parse(*in)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Trophy found %d blocks\n", len(blocks))

	gadgets, err := rop.FindGadgets(blocks, rop.ARM)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(gadgets))
}

// func main() {
// 	http.HandleFunc("/", handler)
// 	http.ListenAndServe(":8080", nil)
// Parse command-line flags
// flag.Parse()

// Parse executable

//
// Allow further refinement of search, generate automatic chain, or output all rop
// fmt.Println(len(gadgets))
// }
