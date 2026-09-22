package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type rejectionFixture struct {
	local, peer *openEndpoint
	service     *StreamTerminationService
	now         atomic.Uint64
}

func newRejectionFixture(t *testing.T) *rejectionFixture {
	t.Helper()
	return newRejectionFixtureRole(t, protocolv4.ServerToClient)
}

func newRejectionFixtureRole(t *testing.T, role protocolv4.Direction) *rejectionFixture {
	t.Helper()
	f := new(rejectionFixture)
	clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: f.now.Load(), Incarnation: [16]byte{1}}, nil
	})
	f.local = newOpenEndpointClock(t, role, 4, 1, 1, clock)
	f.peer = newOpenEndpointClock(t, 1-role, 4, 1, 1, clock)
	charge, _ := StreamTerminationServiceCharge(4)
	root, ref := testResourceReservation(t, charge, 1)
	var err error
	f.service, err = NewStreamTerminationService(f.local.admission, f.local.maintenance, StreamTerminationPolicy{50, 100, 8}, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.local.admission.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := f.service.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := f.service.retire(); err != nil || root.Snapshot().Reservations != 0 {
			t.Error("retained rejection publication resources", err, root.Snapshot())
		}
	})
	startTestOpen(t, f.peer, f.local, 0)
	return f
}

func (f *rejectionFixture) hold(t *testing.T) (OpenHandle, OpenHandle) {
	t.Helper()
	var wire bytes.Buffer
	peer, _, err := f.peer.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", []byte("discarded metadata"), &CarrierAssociation{}, f.peer.reservation(&wire, 8), streamTestDeadline(t, f.peer.engine))
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.local.receiver.ReceiveOpen(context.Background(), wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	carrier := &CarrierAssociation{}
	deadline, err := timev4.NewAge(f.local.engine.Clock(), 80, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.admission.Hold(r, carrier, deadline); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("test did not exhaust ordinary ingress", err)
	}
	h, err := f.local.admission.HoldRejection(r, carrier, deadline)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := f.local.admission.slot(h)
	if s.metadataSize != 0 || s.flow != nil || s.deadline != deadline || s.carrier != carrier || !s.pendingRejection() {
		t.Fatal("rejection retained metadata or changed the original association")
	}
	if _, err := f.local.admission.Flow(h); !errors.Is(err, ErrOpenPending) {
		t.Fatal("unpublished rejection became an outcome", err)
	}
	return h, peer
}

type rejectionBlockedWriter struct {
	frames  chan []byte
	release chan struct{}
}

func (w *rejectionBlockedWriter) Write(b []byte) (int, error) {
	w.frames <- bytes.Clone(b)
	<-w.release
	return len(b), nil
}

func receiveRejectionFrame(t *testing.T, frames <-chan []byte) []byte {
	t.Helper()
	select {
	case b := <-frames:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("no original maintenance publication")
		return nil
	}
}

func rejectionPing(t *testing.T, from, to *openEndpoint) {
	t.Helper()
	if _, err := from.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 1)); err != nil {
		t.Fatal(err)
	}
	r, err := to.receiver.Receive(context.Background(), from.control.Bytes())
	if err != nil {
		t.Fatal("released OPEN decoder did not accept maintenance", err)
	}
	if err := r.AcceptMessage(); err != nil {
		t.Fatal(err)
	}
	r.Release()
	from.control.Reset()
}

func TestOpenRejectionDetachesDecoderAndRetainsPublicationTail(t *testing.T) {
	f := newRejectionFixture(t)
	h, peer := f.hold(t)
	w := &rejectionBlockedWriter{make(chan []byte, 1), make(chan struct{})}
	defer close(w.release)
	f.local.maintenance.writer = w
	done := make(chan error, 1)
	go func() {
		_, _, err := f.service.Progress(context.Background())
		done <- err
	}()
	wire := receiveRejectionFrame(t, w.frames)
	if got := applyTerminalWire(t, f.peer, wire); got != "OPEN_ACCEPT" {
		t.Fatal(got)
	}
	if _, err := f.peer.admission.Flow(peer); !errors.Is(err, ErrOpenRejected) {
		t.Fatal(err)
	}
	rejectionPing(t, f.peer, f.local)
	if _, err := f.local.admission.PublishRejection(context.Background(), h, f.local.maintenance); !errors.Is(err, ErrOpenAssociation) {
		t.Fatal("second rejected outcome admitted", err)
	}
	f.local.admission.mu.Lock()
	s, _ := f.local.admission.slot(h)
	if s.retirementReferences != 2 || s.phase != openRecent || s.flow != nil || s.incoming != nil {
		t.Error("lost actual rejection tail", s.phase, s.retirementReferences)
	}
	f.local.admission.mu.Unlock()
	f.local.admission.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := f.service.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("reported cleanup before provider exited", err)
	}
	if err := f.service.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("released actual publication reservation", err)
	}
}

func TestOpenRejectionContentionKeepsOneOriginalOwner(t *testing.T) {
	f := newRejectionFixture(t)
	h, peer := f.hold(t)
	s, _ := f.local.admission.slot(h)
	incoming, deadline, digest := s.incoming, s.deadline, s.digest
	w := &rejectionBlockedWriter{make(chan []byte, 2), make(chan struct{})}
	release := sync.OnceFunc(func() { close(w.release) })
	defer release()
	f.local.maintenance.writer = w
	done := make(chan error, 1)
	body := pingBody(t, 1)
	go func() {
		_, err := f.local.maintenance.Write(context.Background(), protocolv4.FramePing, body)
		done <- err
	}()
	ping := receiveRejectionFrame(t, w.frames)
	for range 3 {
		result, ready, err := f.service.Progress(context.Background())
		if err != nil || ready || result.Submitted {
			t.Fatal("ordinary maintenance contention closed Session", result, ready, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := f.local.admission.PublishRejection(cancelled, h, f.local.maintenance); !errors.Is(err, context.Canceled) || result.Submitted {
		t.Fatal(result, err)
	}
	if s.incoming != incoming || s.deadline != deadline || s.digest != digest || s.deciding || s.retirementReferences != 0 || f.local.admission.Usage().RejectionProofs != 1 {
		t.Fatal("contention changed or duplicated the original rejection")
	}
	rejectionPing(t, f.peer, f.local)
	release()
	if err := nativeResult(t, done); err != nil {
		t.Fatal(err)
	}
	r, err := f.peer.receiver.Receive(context.Background(), ping)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AcceptMessage(); err != nil {
		t.Fatal(err)
	}
	r.Release()
	result, ready, err := f.service.Progress(context.Background())
	if err != nil || !ready || !result.Complete {
		t.Fatal(result, ready, err)
	}
	applyTerminalWire(t, f.peer, receiveRejectionFrame(t, w.frames))
	if _, err := f.peer.admission.Flow(peer); !errors.Is(err, ErrOpenRejected) {
		t.Fatal(err)
	}
	if result, ready, err := f.service.Progress(context.Background()); err != nil || ready || result.Submitted {
		t.Fatal("rejected OPEN generated an extra terminal message", result, ready, err)
	}
}

func TestOpenRejectionOriginalDeadlineIncludesBlockedPublication(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "queued", true: "submitted"}[blocked], func(t *testing.T) {
			f := newRejectionFixture(t)
			h, _ := f.hold(t)
			if !blocked {
				f.now.Store(80)
				if err := f.local.admission.CheckDeadlines(); !errors.Is(err, cryptov4.ErrExpired) {
					t.Fatal("queued rejection restarted OPEN deadline", err)
				}
				if result, err := f.local.admission.PublishRejection(context.Background(), h, f.local.maintenance); !errors.Is(err, cryptov4.ErrExpired) || result.Submitted {
					t.Fatal(result, err)
				}
				return
			}
			w := &rejectionBlockedWriter{make(chan []byte, 1), make(chan struct{})}
			defer close(w.release)
			f.local.maintenance.writer = w
			done := make(chan error, 1)
			go func() { done <- f.service.Run(context.Background()) }()
			receiveRejectionFrame(t, w.frames)
			f.now.Store(80)
			f.service.notify()
			if err := nativeResult(t, done); !errors.Is(err, cryptov4.ErrExpired) {
				t.Fatal("submitted rejection erased original deadline", err)
			}
			select {
			case <-f.local.engine.Done():
			default:
				t.Fatal("expired original rejection did not close Session")
			}
		})
	}
}

func TestOpenRejectionPreservesOriginalTupleAcrossRekey(t *testing.T) {
	f := newRejectionFixture(t)
	c, s := exchange(t, f.peer), exchange(t, f.local)
	h, peer := f.hold(t)
	original, _ := f.local.admission.slot(h)
	if _, err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, f.peer, f.local, s)
	exchangeProgress(t, s)
	exchangeFlight(t, f.local, f.peer, c)
	exchangeProgress(t, c)
	exchangeFlight(t, f.peer, f.local, s)
	exchangeProgress(t, s)
	exchangeFlight(t, f.local, f.peer, c)
	if result, ready, err := f.service.Progress(context.Background()); err != nil || !ready || result.Header.Epoch != 1 {
		t.Fatal(result, ready, err)
	}
	applyTestOutcome(t, f.local, f.peer)
	if _, err := f.peer.admission.Flow(peer); !errors.Is(err, ErrOpenRejected) {
		t.Fatal(err)
	}
	if original.header.Epoch != 0 || original.terminal[protocolv4.ClientToServer].Terminal != (TerminalTuple{NextSequence: 1}) || original.terminal[protocolv4.ServerToClient].Terminal != (TerminalTuple{}) || original.barrierReferences != 0 {
		t.Fatal("rekey rewrote original rejected OPEN proof", original.header, original.terminal)
	}
}

func TestOpenRejectionEarlyNewEpochWaitsForOriginalACK(t *testing.T) {
	f := newRejectionFixtureRole(t, protocolv4.ClientToServer)
	c, s := exchange(t, f.local), exchange(t, f.peer)
	if _, err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, f.local, f.peer, s)
	exchangeProgress(t, s)
	exchangeFlight(t, f.peer, f.local, c)
	exchangeProgress(t, c)
	exchangeFlight(t, f.local, f.peer, s)
	exchangeProgress(t, s)
	// The server's ACK is still waiting on its independent maintenance carrier.
	h, peer := f.hold(t)
	if result, ready, err := f.service.Progress(context.Background()); err != nil || ready || result.Submitted {
		t.Fatal("early new-epoch OPEN consumed an old rejection ticket", result, ready, err)
	}
	exchangeFlight(t, f.peer, f.local, c)
	if result, ready, err := f.service.Progress(context.Background()); err != nil || !ready || !result.Complete || result.Header.Epoch != 1 {
		t.Fatal(result, ready, err)
	}
	applyTestOutcome(t, f.local, f.peer)
	if _, err := f.peer.admission.Flow(peer); !errors.Is(err, ErrOpenRejected) {
		t.Fatal(err)
	}
	proof, _ := f.local.admission.slot(h)
	if proof.header.Epoch != 1 || proof.terminal[protocolv4.ServerToClient].Terminal != (TerminalTuple{Epoch: 1, NextSequence: 1}) {
		t.Fatal("lost original early OPEN epoch", proof.header, proof.terminal)
	}
}

func TestOpenRejectionWithoutProofCapacityClosesSession(t *testing.T) {
	f := newRejectionFixture(t)
	f.hold(t)
	var wire bytes.Buffer
	if _, _, err := f.peer.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, f.peer.reservation(&wire, 0), streamTestDeadline(t, f.peer.engine)); err != nil {
		t.Fatal(err)
	}
	r, err := f.local.receiver.ReceiveOpen(context.Background(), wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	if _, err := f.local.admission.HoldRejection(r, &CarrierAssociation{}, streamTestDeadline(t, f.local.engine)); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	select {
	case <-f.local.engine.Done():
	default:
		t.Fatal("valid OPEN was dropped without a proof owner")
	}
	if usage := f.local.admission.Usage(); usage.Pending != 1 || usage.RejectionProofs != 1 || usage.Active != 0 {
		t.Fatal("capacity failure invented an owner or rewrote existing facts", usage)
	}
}
