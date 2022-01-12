package tcpegresstracer

import (
	"testing"
)

func TestStartTCPProbe(t *testing.T) {
	err := Start(20183)
	if err != nil {
		t.Errorf("error testing tls probe: %w", err)
		t.Fail()
	}
}
