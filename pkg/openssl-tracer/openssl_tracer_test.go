package openssltracer

import (
	"testing"
)

func TestStartTLSProbe(t *testing.T) {
	err := Start()
	if err != nil {
		t.Errorf("error testing tls probe: %w", err)
		t.Fail()
	}
}
