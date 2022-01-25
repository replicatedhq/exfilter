package matchengine

import (
	"testing"
)

func TestStartMatchEvents(t *testing.T) {
	err := MatchEvents()

	if err != nil {
		t.Fail()
	}
}
