package tcpegresstracer

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/mitchellh/go-ps"
)

// #cgo LDFLAGS: -lbcc

const SS_MAX_SEG_SIZE = 1024 * 50

type TCPEgressEvent struct {
	Pid     uint32
	Saddr   uint32
	Daddr   uint32
	Lport   uint16
	Dport   uint16
	DataLen uint32
	Data    []byte
}

func Inet_ntoa(ip uint32) string {
	// return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8),
	// 	byte(ip))
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// var PerfMap *bpf.PerfMap

func Start(pid uint32) error {
	b, err := ioutil.ReadFile("./bpf/tcpegress_tracer_bpf.c") // read c file to bytes slice
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	source := string(b) // convert content to a 'string'

	if pid > 0 {
		source = strings.Replace(source, "FILTER_PID", fmt.Sprintf("if (pid != %d) { return 0; }", pid), -1)
	} else {
		source = strings.Replace(source, "FILTER_PID", "", -1)
	}

	m := bpf.NewModule(source, []string{})
	defer m.Close()

	KProbe, err := m.LoadKprobe("probe_tcp_sendmsg")
	if err != nil {
		return fmt.Errorf("failed to load probe_tcp_sendmsg: %w", err)
	}

	m.AttachKprobe("tcp_sendmsg", KProbe, -1)

	table := bpf.NewTable(m.TableId("ipv4_send_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Errorf("failed to init perf map: %w\n", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Printf("%10s\t%10s\t%30s\t%30s\t%50s\n", "PID", "PROCESSNAME", "LADDR", "RADDR", "DATA")
	go func() {
		var event TCPEgressEvent
		for {
			data := <-channel
			event.Pid = binary.LittleEndian.Uint32(data[0:4])
			event.Saddr = binary.LittleEndian.Uint32(data[4:8])
			event.Daddr = binary.LittleEndian.Uint32(data[8:12])
			event.Lport = binary.LittleEndian.Uint16(data[12:14])
			event.Dport = binary.LittleEndian.Uint16(data[14:16])
			event.DataLen = binary.LittleEndian.Uint32(data[16:20])
			event.Data = data[20:]
			p, _ := ps.FindProcess(int(event.Pid))
			fmt.Printf("%-10d\t%-10s\t%-30s\t%-30s\t%-50s\n", event.Pid, p.Executable(), Inet_ntoa(event.Saddr)+":"+strconv.Itoa(int(event.Lport)), Inet_ntoa(event.Daddr)+":"+strconv.Itoa(int(event.Dport)), event.Data)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
	return nil
}

func InitTCPTracer(pid uint32) (*bpf.Table, error) {
	b, err := ioutil.ReadFile("../tcpegress-tracer/bpf/tcpegress_tracer_bpf.c") // read c file to bytes slice
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	source := string(b) // convert content to a 'string'

	if pid > 0 {
		source = strings.Replace(source, "FILTER_PID", fmt.Sprintf("if (pid != %d) { return 0; }", pid), -1)
	} else {
		source = strings.Replace(source, "FILTER_PID", "", -1)
	}

	m := bpf.NewModule(source, []string{})
	// defer m.Close()

	KProbe, err := m.LoadKprobe("probe_tcp_sendmsg")
	if err != nil {
		return nil, fmt.Errorf("failed to load probe_tcp_sendmsg: %w", err)
	}

	m.AttachKprobe("tcp_sendmsg", KProbe, -1)

	table := bpf.NewTable(m.TableId("ipv4_send_events"), m)

	return table, nil
}
