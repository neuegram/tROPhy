package rop

// Terribly inefficient, not working
//func FindGadgets(blocks *[]BasicBlock, taint *Taint) *[]BasicBlock {
//	var gadgets []BasicBlock
//	for _, bb := range *blocks {
//		for _, instruction := range *bb.Instructions() {
//			t, ok := (*taint)[&instruction]
//			if ok && t.Dst() != nil {
//				for _, reg := range *t.Dst() {
//					if reg == 0 {
//						fmt.Println("Found (!)")
//						gadgets = append(gadgets, bb)
//						continue
//					}
//				}
//			}
//		}
//	}
//	return &gadgets
//}