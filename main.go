package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/jschwinger233/bpf_get_stack_test/bpf"
)

type StackData struct {
	IPs [50]uint64
}

func main() {
	objs := &bpf.TestObjects{}
	if err := bpf.LoadTestObjects(objs, nil); err != nil {
		panic(err)
	}

	target := os.Args[2]

	if os.Args[1] == "--helper" {
		k, err := link.Kprobe(target, objs.HelperGetStack, nil)
		if err != nil {
			panic(err)
		}
		defer k.Close()

		eventsReader, err := ringbuf.NewReader(objs.EventRingbuf)
		if err != nil {
			slog.Error("Failed to create ringbuf reader", "err", err)
			return
		}
		defer eventsReader.Close()

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		go func() {
			<-ctx.Done()
			eventsReader.Close()
		}()

		for {
			rec, err := eventsReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				slog.Debug("failed to read ringbuf", "err", err)
				continue
			}

			var event bpf.TestEventHelper
			if err = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event); err != nil {
				slog.Debug("failed to parse ringbuf event", "err", err)
				continue
			}

			if err != nil {
				slog.Error("Failed to get dwarf", "err", err)
				return
			}

			id := uint32(event.Stackid)
			fmt.Printf("\nStack ID: %d\n", id)
			var stack StackData
			if err := objs.PrintStackMap.Lookup(&id, &stack); err == nil {
				for _, ip := range stack.IPs {
					if ip == 0 {
						break
					}
					ksym, _ := NearestKsym(ip)
					fmt.Printf("%s\n", ksym.Name)
				}
			}
		}

	} else if os.Args[1] == "--manual" {
		k, err := link.Kprobe(target, objs.ManualGetStack, nil)
		if err != nil {
			panic(err)
		}
		defer k.Close()
	} else {
		panic("Unknown mode")
	}
}
