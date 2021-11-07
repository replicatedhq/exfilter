package probe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type Event struct {
	Comm [16]byte
}

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

	probes, err := attachKprobes(&objs)
	if err != nil {
		return fmt.Errorf("attach kprobes: %w", err)
	}
	for _, probe := range probes {
		defer probe.Close()
	}

	probes, err = attachUprobes(&objs)
	if err != nil {
		return fmt.Errorf("attach uprobes: %w", err)
	}
	for _, probe := range probes {
		defer probe.Close()
	}

	log.Println("waiting for events from probes...")

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf event reader: %w", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			fmt.Printf("closing perf event reader: %s", err)
		}
	}()

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return nil
			}
			log.Printf("reading from perf event reader: %s", err)
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf("event.comm: %s\n", event.Comm)
	}
}

// attachKprobes will link the kernel ebpf probes
// the caller is responsible for closing the probes
func attachKprobes(objs *bpfObjects) ([]link.Link, error) {
	log.Println("opening kprobe for sys_sendto")
	sendTo, err := link.Kprobe("sys_sendto", objs.KprobeSendto)
	if err != nil {
		return nil, fmt.Errorf("opening kprobe: %w", err)
	}

	return []link.Link{sendTo}, nil
}

func attachUprobes(objs *bpfObjects) ([]link.Link, error) {
	return nil, nil
}
