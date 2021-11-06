package probe

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/kprobe_send.c -- -I../headers

const mapKey uint32 = 0

func Start() error {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	if err := attachKprobes(&objs); err != nil {
		return fmt.Errorf("attach kprobes: %w", err)
	}
	if err := attachUprobes(&objs); err != nil {
		return fmt.Errorf("attach uprobes: %w", err)
	}

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	log.Println("Waiting for events..")

	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
				return fmt.Errorf("lookup kprobe map: %w", err)
			}
			log.Printf("%s called %d times\n", fn, value)
		case <-stopper:
			return nil
		}
	}
}

// attachKprobes will link the kernel ebpf probes
func attachKprobes(objs *bpfObjects) error {
	kp, err := link.Kprobe("sys_sendto", objs.KprobeSendto)
	if err != nil {
		return fmt.Errorf("opening kprobe: %w", err)
	}
	defer kp.Close()
}

func attachUprobes(objs *bpfObjects) error {
	return nil
}
