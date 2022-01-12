package matchengine

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/exfilter/exfilter/pkg/exfilterlogger"
	ruleparser "github.com/exfilter/exfilter/pkg/rule-parser"
	tcpegresstracer "github.com/exfilter/exfilter/pkg/tcpegress-tracer"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/mitchellh/go-ps"
)

// type RuleNode struct {
// 	Next       *RuleNode
// 	RnRuleData *OTNX
// 	RuleNodeID int
// }

func MatchEvents() error {
	prMap := ruleparser.ParseRuleFile("example.rules")

	table, err := tcpegresstracer.InitTCPTracer(0)
	if err != nil {
		return fmt.Errorf("error initializing tcp egress tracer: %w", err)
	}

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Println("failed to init perf map, ", err)
		return fmt.Errorf("failed to init perf map: %w", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	f, err := exfilterlogger.InitLogger("exfilter.log")
	if err != nil {
		return err
	}
	defer exfilterlogger.DeinitLogger(f)
	fmt.Printf("%10s\t%10s\t%30s\t%30s\t%50s\n", "PID", "PROCESSNAME", "LADDR", "RADDR", "DATA")
	go func() {
		var event tcpegresstracer.TCPEgressEvent
		for {
			data := <-channel
			event.Pid = binary.LittleEndian.Uint32(data[0:4])
			event.Saddr = binary.LittleEndian.Uint32(data[4:8])
			event.Daddr = binary.LittleEndian.Uint32(data[8:12])
			event.Lport = binary.LittleEndian.Uint16(data[12:14])
			event.Dport = binary.LittleEndian.Uint16(data[14:16])
			event.DataLen = binary.LittleEndian.Uint32(data[16:20])
			event.Data = data[20:]

			// port match
			if prMap["dstPortRules"][int(event.Dport)] == nil {
				continue
			}

			// payload match
			isMatch := false
			var eventmsg string
			for _, ruleOpt := range prMap["dstPortRules"][int(event.Dport)] {
				if strings.Contains(strings.ToLower(string(event.Data)), strings.ToLower(ruleOpt.Content)) {
					isMatch = true
					eventmsg = ruleOpt.Message
					break
				}
			}

			if !isMatch {
				continue
			}

			p, _ := ps.FindProcess(int(event.Pid))
			logevent := exfilterlogger.EgressEvent{}
			logevent.Pid = event.Pid
			logevent.Saddr = tcpegresstracer.Inet_ntoa(event.Saddr) + ":" + strconv.Itoa(int(event.Lport))
			logevent.Daddr = tcpegresstracer.Inet_ntoa(event.Daddr) + ":" + strconv.Itoa(int(event.Dport))
			logevent.Data = string(event.Data)
			logevent.Msg = eventmsg

			exfilterlogger.LogEvent(logevent)

			fmt.Printf("%-10d\t%-10s\t%-30s\t%-30s\t%-50s\n", event.Pid, p.Executable(), tcpegresstracer.Inet_ntoa(event.Saddr)+":"+strconv.Itoa(int(event.Lport)), tcpegresstracer.Inet_ntoa(event.Daddr)+":"+strconv.Itoa(int(event.Dport)), string(event.Data))
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
	return nil
}
