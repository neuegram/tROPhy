package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/neuegram/tROPhy/pkg/parser"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
)

type binary struct {
	File string `json:"binary"`
}

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
	var t map[string]interface{}

	if err := json.Unmarshal([]byte(request.FormValue("file")), &t); err != nil {
		panic(err)
	}
	// log.Println(t["binary"])
	dec, err := base64.StdEncoding.DecodeString(t["binary"].(string))
	if err != nil {
		panic(err)
	}

	fn, err := exec.Command("uuidgen").Output()
	h := sha1.New()
	io.WriteString(h, string(fn))
	if err != nil {
		log.Fatal(err)
	}
	path := "temp/" + hex.EncodeToString(h.Sum(nil))
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if _, err := f.Write(dec); err != nil {
		panic(err)
	}
	if err := f.Sync(); err != nil {
		panic(err)
	}
	// fmt.Println(request.FormValue("file"))
	// writer.Write("Hello")
	// flag.Parse()
	blocks, _ := parser.Parse(path)
	// fmt.Printf("Trophy found %d blocks\n", len(blocks))

	for _, bb := range *blocks {
		fmt.Fprintf(writer, bb.String())
	}
	exec.Command("rm", path).Run()

}