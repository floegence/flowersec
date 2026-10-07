package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Only directional shutdown is expected after the authenticated rejection.
// An unexpected data/provider operation fails through the unused interface.
type completedOpenNativeStream struct {
	native.Stream
	closed bool
}

func (*completedOpenNativeStream) CloseWrite() error  { return nil }
func (*completedOpenNativeStream) StopSending() error { return nil }
func (s *completedOpenNativeStream) Close() error     { s.closed = true; return nil }

func TestNativeCompletedOpenDeadlineCannotCloseSessionAfterProofRetirement(t *testing.T) {
	tick := RekeyClockSample{Incarnation: [16]byte{7}}
	clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) { return tick, nil })
	client := newOpenEndpointClock(t, protocolv4.ClientToServer, 2, 2, 1, clock)
	server := newOpenEndpointClock(t, protocolv4.ServerToClient, 2, 2, 1, clock)
	deadline, err := timev4.NewAge(clock, 100, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	provider := &completedOpenNativeStream{}
	transport := &nativeStreamTransport{admission: client.admission, wake: make(chan struct{}, 1)}
	// The original opening caller retains its physical generation after the
	// provider closes. Logical retirement must not revive admission work.
	slot := &nativeStreamSlot{used: true, caller: true, generation: 1, stream: provider,
		deadline: deadline, ready: make(chan struct{}), retry: make(chan struct{}, 1)}
	wire := new(bytes.Buffer)
	local, result, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil,
		&slot.association, client.reservation(wire, 8), deadline)
	if err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	record, err := server.receiver.ReceiveOpen(context.Background(), wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := server.admission.Hold(record, &CarrierAssociation{}, deadline)
	record.Release()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.admission.Decide(context.Background(), peer, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	transport.progress(slot)
	if !provider.closed {
		t.Fatal("rejected native direction did not close")
	}
	if err = client.admission.CarrierClosed(local); err != nil {
		t.Fatal(err)
	}
	if err = server.admission.CarrierClosed(peer); err != nil {
		t.Fatal(err)
	}
	cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, server.maintenance)
	if _, err = cr.Start(context.Background(), 1, streamTestDeadline(t, client.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	if _, err = sr.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, client, cr, server.control.Bytes())
	if client.admission.Usage().PositiveProofs != 0 {
		t.Fatal("original proof did not retire")
	}
	tick.Milliseconds = 101
	if !errors.Is(deadline.Check(), timev4.ErrExpired) {
		t.Fatal("test did not cross the original OPEN deadline")
	}
	transport.progress(slot)
	if err = client.engine.ApplicationReady(); err != nil {
		t.Fatal("completed OPEN deadline closed the healthy Session after proof retirement", err)
	}
}
