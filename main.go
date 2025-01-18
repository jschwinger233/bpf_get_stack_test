package main

import (
	"github.com/jschwinger233/bpf_get_stack_test/bpf"
)

func main() {
	obj := &bpf.TestObjects{}
	if err := bpf.LoadTestObjects(obj, nil); err != nil {
		panic(err)
	}
}
