package auto

import "github.com/bnagy/gapstone"

type Taint map[*gapstone.Instruction]*TaintTag

func NewTaint() *Taint {
	t := make(Taint)
	return &t
}
