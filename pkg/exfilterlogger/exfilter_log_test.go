package exfilterlogger

import (
	"fmt"
	"testing"
)

func TestExfilterLogger(t *testing.T) {
	f, err := InitLogger("eventlogtest.log")
	if err != nil {
		fmt.Printf("exfilter logger test failed with err:%s", err)
		t.Fail()
	}

	events := make([]EgressEvent, 3)

	for i := 0; i < len(events); i++ {
		events[i] = EgressEvent{Pid: 100, Saddr: "192.168.1.10:80", Daddr: "74.56.92.0:12345", Data: "testdata", Msg: "testmsg"}
		LogEvent(events[i])
	}

	DeinitLogger(f)
}
