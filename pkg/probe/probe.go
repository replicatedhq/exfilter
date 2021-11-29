package probe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type EventCommon struct {
	Comm [16]byte
}

type SendMsgEvent struct {
	EventCommon
}

type SendMMsgEvent struct {
	EventCommon
}

type SendToEvent struct {
	EventCommon
}

type SendEvent struct {
	EventCommon
}

type SendFileEvent struct {
	EventCommon
}

type WriteEvent struct {
	EventCommon
}

type WritevEvent struct {
	EventCommon
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

	// probes, err = attachUprobes(&objs)
	// if err != nil {
	// 	return fmt.Errorf("attach uprobes: %w", err)
	// }
	// for _, probe := range probes {
	// 	defer probe.Close()
	// }

	log.Println("waiting for events from probes...")

	// also for debugging and in dev, let's ignore
	// some really noisy processes that run on a codespace
	// (char 16)
	// THIS SHOULD NOT REMAIN
	ignoredProcesses := []string{
		"vsls-agent\x00\x00\x00\x00\x00\x00",
		"codespaces\x00\x00\x00\x00\x00\x00",
		"systemd\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"systemd-journal\x00",
		"systemd-resolve\x00",
		"systemd-udevd\x00\x00\x00",
		"dbus-daemon\x00\x00\x00\x00\x00",
	}

	sendmsgReader, err := readEventsFrom("sendmsg", objs.SendmsgEvents, func(data []byte) {
		// Parse the perf event entry into an Event structure.
		event := SendMsgEvent{}
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}

		for _, ignoredProcess := range ignoredProcesses {
			if string(event.EventCommon.Comm[:]) == ignoredProcess {
				return
			}
		}

		fmt.Printf("[%s] event.comm: %s\n", "sendmsg", event.Comm)
	})
	if err != nil {
		return fmt.Errorf("read events from: %w", err)
	}
	defer sendmsgReader.Close()

	sendmmsgReader, err := readEventsFrom("sendmmsg", objs.SendmmsgEvents, func(data []byte) {
		// Parse the perf event entry into an Event structure.
		event := SendMMsgEvent{}
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}

		for _, ignoredProcess := range ignoredProcesses {
			if string(event.EventCommon.Comm[:]) == ignoredProcess {
				return
			}
		}

		fmt.Printf("[%s] event.comm: %s\n", "sendmmsg", event.Comm)
	})
	if err != nil {
		return fmt.Errorf("read events from: %w", err)
	}
	defer sendmmsgReader.Close()

	sendfileReader, err := readEventsFrom("sendfile", objs.SendfileEvents, func(data []byte) {
		// Parse the perf event entry into an Event structure.
		event := SendFileEvent{}
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}

		for _, ignoredProcess := range ignoredProcesses {
			if string(event.EventCommon.Comm[:]) == ignoredProcess {
				return
			}
		}

		fmt.Printf("[%s] event.comm: %s\n", "sendfile", event.Comm)
	})
	if err != nil {
		return fmt.Errorf("read events from: %w", err)
	}
	defer sendfileReader.Close()

	sendtoReader, err := readEventsFrom("sendto", objs.SendtoEvents, func(data []byte) {
		// Parse the perf event entry into an Event structure.
		event := SendToEvent{}
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}

		for _, ignoredProcess := range ignoredProcesses {
			if string(event.EventCommon.Comm[:]) == ignoredProcess {
				return
			}
		}

		fmt.Printf("[%s] event.comm: %s\n", "sendto", event.Comm)
	})
	if err != nil {
		return fmt.Errorf("read events from: %w", err)
	}
	defer sendtoReader.Close()

	sendReader, err := readEventsFrom("send", objs.SendEvents, func(data []byte) {
		// Parse the perf event entry into an Event structure.
		event := SendEvent{}
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}

		for _, ignoredProcess := range ignoredProcesses {
			if string(event.EventCommon.Comm[:]) == ignoredProcess {
				return
			}
		}

		fmt.Printf("[%s] event.comm: %s\n", "send", event.Comm)
	})
	if err != nil {
		return fmt.Errorf("read events from: %w", err)
	}
	defer sendReader.Close()

	writeReader, err := readEventsFrom("write", objs.SendEvents, func(data []byte) {
		// Parse the perf event entry into an Event structure.
		event := WriteEvent{}
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}

		for _, ignoredProcess := range ignoredProcesses {
			if string(event.EventCommon.Comm[:]) == ignoredProcess {
				return
			}
		}

		fmt.Printf("[%s] event.comm: %s\n", "write", event.Comm)
	})
	if err != nil {
		return fmt.Errorf("read events from: %w", err)
	}
	defer writeReader.Close()

	writevReader, err := readEventsFrom("writev", objs.SendEvents, func(data []byte) {
		// Parse the perf event entry into an Event structure.
		event := WritevEvent{}
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}

		for _, ignoredProcess := range ignoredProcesses {
			if string(event.EventCommon.Comm[:]) == ignoredProcess {
				return
			}
		}

		fmt.Printf("[%s] event.comm: %s\n", "writev", event.Comm)
	})
	if err != nil {
		return fmt.Errorf("read events from: %w", err)
	}
	defer writevReader.Close()

	<-stopper

	log.Println("Received signal, closing all probes and exiting program..")
	if err := sendmsgReader.Close(); err != nil {
		return fmt.Errorf("closing sendmsg reader: %w", err)
	}
	if err := sendmmsgReader.Close(); err != nil {
		return fmt.Errorf("closing sendmmsg reader: %w", err)
	}
	if err := sendtoReader.Close(); err != nil {
		return fmt.Errorf("closing sendto reader: %w", err)
	}
	if err := sendReader.Close(); err != nil {
		return fmt.Errorf("closing send reader: %w", err)
	}
	if err := sendfileReader.Close(); err != nil {
		return fmt.Errorf("closing sendfile reader: %w", err)
	}

	return nil
}

func readEventsFrom(symbol string, m *ebpf.Map, cb func(data []byte)) (*perf.Reader, error) {
	rd, err := perf.NewReader(m, os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("creating perf event reader: %w", err)
	}

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if perf.IsClosed(err) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
			}

			if record.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			cb(record.RawSample)

		}
	}()

	return rd, nil
}

// attachKprobes will link the kernel ebpf probes
// the caller is responsible for closing the probes
func attachKprobes(objs *bpfObjects) ([]link.Link, error) {
	probes := map[string]*ebpf.Program{
		"sys_sendto":   objs.KprobeSendto,
		"sys_send":     objs.KprobeSend,
		"sys_sendmsg":  objs.KprobeSendmsg,
		"sys_sendmmsg": objs.KprobeSendmmsg,
		"sys_sendfile": objs.KprobeSendfile,
		"sys_write":    objs.KprobeWrite,
		"sys_writev":   objs.KprobeWritev,
	}

	links := []link.Link{}

	log.Println("opening kprobes")
	for symbol, prog := range probes {
		l, err := link.Kprobe(symbol, prog)
		if err != nil {
			return nil, fmt.Errorf("opening kprobe: %w", err)
		}

		links = append(links, l)
	}

	return links, nil
}

func attachUprobes(objs *bpfObjects) ([]link.Link, error) {
	return nil, nil
}
