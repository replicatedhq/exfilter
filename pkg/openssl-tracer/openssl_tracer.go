package openssltracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/mitchellh/go-ps"
)

// #cgo LDFLAGS: -lbcc

type AttachType int64

const (
	PROBE_ENTRY AttachType = iota
	PROBE_RET
)

type UprobeSpec struct {
	ObjPath string
	Symbol  string
	Type    AttachType
	ProbeFn string
}

type SSLDataEvent struct {
	EventType    int64
	Timestamp_ns uint64
	Pid          uint32
	Tid          uint32
	Data         [4096]byte
	Data_len     int32
}

var kSSLWriteEntryProbeSpec = UprobeSpec{ObjPath: "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", Symbol: "SSL_write", Type: PROBE_ENTRY, ProbeFn: "probe_entry_SSL_write"}
var kSSLWriteRetProbeSpec = UprobeSpec{ObjPath: "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", Symbol: "SSL_write", Type: PROBE_RET, ProbeFn: "probe_ret_SSL_write"}
var kSSLReadEntryProbeSpec = UprobeSpec{ObjPath: "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", Symbol: "SSL_read", Type: PROBE_ENTRY, ProbeFn: "probe_entry_SSL_read"}
var kSSLReadRetProbeSpec = UprobeSpec{ObjPath: "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", Symbol: "SSL_read", Type: PROBE_RET, ProbeFn: "probe_ret_SSL_read"}

var kUProbes = []UprobeSpec{kSSLWriteEntryProbeSpec, kSSLWriteRetProbeSpec}

// var kUProbes = []UprobeSpec{kSSLWriteEntryProbeSpec, kSSLWriteRetProbeSpec, kSSLReadEntryProbeSpec, kSSLReadRetProbeSpec}

func Start() error {
	b, err := ioutil.ReadFile("./bpf/openssl_tracer_bpf_funcs.c") // read c file to bytes slice
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	source := string(b) // convert content to a 'string'

	m := bpf.NewModule(source, []string{})
	defer m.Close()

	for _, probeSpec := range kUProbes {
		Uprobe, _ := m.LoadUprobe(probeSpec.ProbeFn)
		if err != nil {
			return fmt.Errorf("failed to load %s: %w", probeSpec.ProbeFn, err)
		}
		if probeSpec.Type == PROBE_ENTRY {
			m.AttachUprobe(probeSpec.ObjPath, probeSpec.Symbol, Uprobe, -1)
		} else {
			m.AttachUretprobe(probeSpec.ObjPath, probeSpec.Symbol, Uprobe, -1)
		}
	}

	table := bpf.NewTable(m.TableId("tls_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		return fmt.Errorf("failed to init perf map: %w", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Printf("%10s\t%10s\t%30s\t%8s\n", "PID", "PROCESSNAME", "DATA", "TYPE(IN/OUT)")
	go func() {
		var event SSLDataEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}

			comm := string(event.Data[:])
			var eventType string
			if AttachType(event.EventType) == PROBE_ENTRY {
				eventType = "Entry"
			} else {
				eventType = "Exit"
			}
			p, _ := ps.FindProcess(int(event.Pid))
			fmt.Printf("%10d\t%10s\t%30s\t%8s\n", event.Pid, p.Executable(), comm, eventType)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
	return nil
}

func InitTLSTracer() (*bpf.Module, error) {
	b, err := ioutil.ReadFile("pkg/openssl-tracer/bpf/openssl_tracer_bpf_funcs.c")
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	source := string(b)
	m := bpf.NewModule(source, []string{})
	fmt.Println("loaded openssl tracer")
	return m, nil
}

func DeInitTLSTracer(m *bpf.Module) {
	m.Close()
}

func LoadBPFTable(m *bpf.Module) (*bpf.Table, error) {
	for _, probeSpec := range kUProbes {
		Uprobe, err := m.LoadUprobe(probeSpec.ProbeFn)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", probeSpec.ProbeFn, err)
		}
		if probeSpec.Type == PROBE_ENTRY {
			m.AttachUprobe(probeSpec.ObjPath, probeSpec.Symbol, Uprobe, -1)
		} else {
			m.AttachUretprobe(probeSpec.ObjPath, probeSpec.Symbol, Uprobe, -1)
		}
	}

	table := bpf.NewTable(m.TableId("tls_events"), m)

	return table, nil
}
