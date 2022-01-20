package tcpegresstracer

import (
	"testing"
)

func TestStartTCPProbe(t *testing.T) {
	err := Start(2505812)
	if err != nil {
		t.Errorf("error testing tcp probe: %w", err)
		t.Fail()
	}
}
