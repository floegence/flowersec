package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

func TestStreamConnNormalTimeoutUsesOriginalDirectionPreset(t *testing.T) {
	f, _, _, _, _, _ := connFixture(t, 64)
	p := &StreamTerminationService{admission: f.local.admission, policy: StreamTerminationPolicy{NormalMS: 5000, QuarantineMS: 10000, QuarantineDirections: 2}, wake: make(chan struct{}, 1)}
	send, receive := directionTermination{service: p}, directionTermination{service: p}
	if err := selectConnTermination(&send, &receive, 30000); err != nil {
		t.Fatal(err)
	}
	send.start(false, nil)
	receive.start(false, nil)
	for _, d := range [...]*directionTermination{&send, &receive} {
		remaining, err := d.normal.RemainingMS()
		if err != nil || remaining < 29000 || remaining > 30000 {
			t.Fatal("native adapter retained the earlier 5-second timeout", remaining, err)
		}
	}
	if err := selectConnTermination(&send, &receive, 30000); err != nil {
		t.Fatal("same preset changed its original clock", err)
	}
	if err := selectConnTermination(&send, &receive, 60000); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("running termination window was extended", err)
	}
}

func TestStreamConnPresetMismatchLeavesBothDirectionsUnchanged(t *testing.T) {
	f, _, _, _, _, _ := connFixture(t, 64)
	p := &StreamTerminationService{admission: f.local.admission, policy: StreamTerminationPolicy{NormalMS: 5000, QuarantineMS: 10000, QuarantineDirections: 2}, wake: make(chan struct{}, 1)}
	send, receive := directionTermination{service: p}, directionTermination{service: p}
	receive.start(false, nil)
	if err := selectConnTermination(&send, &receive, 30000); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal(err)
	}
	if send.normalMS != 0 || receive.normalMS != 0 || send.normal != nil {
		t.Fatal("failed joint selection changed one direction")
	}
}
