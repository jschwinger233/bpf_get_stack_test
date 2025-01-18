package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event_helper Test ./test.c -- -I./headers -I. -Wall
