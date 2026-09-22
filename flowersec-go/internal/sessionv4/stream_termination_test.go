package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func terminationFixture(t *testing.T, streams, quarantine uint32) (*nativeServiceFixture, *atomic.Uint64) {
	t.Helper()
	now := new(atomic.Uint64)
	clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: now.Load(), Incarnation: [16]byte{1}}, nil
	})
	policy := &StreamTerminationPolicy{NormalMS: 50, QuarantineMS: 100, QuarantineDirections: quarantine}
	return newNativeServiceFixtureOptions(t, streams, 1, policy, clock), now
}

func applyTerminalWire(t *testing.T, e *openEndpoint, wire []byte) string {
	t.Helper()
	r, err := e.receiver.Receive(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	f, err := r.Body()
	if err != nil {
		t.Fatal(err)
	}
	schema := f.Schema
	err = e.admission.ApplyMaintenance(r)
	r.Release()
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func progressTerminal(t *testing.T, f *nativeServiceFixture, schema string) {
	t.Helper()
	result, ready, err := f.termination.Progress(f.ctx)
	if err != nil || !ready || !result.Complete {
		t.Fatal("terminal publication", result, ready, err)
	}
	if got := applyTerminalWire(t, f.peer, f.local.control.Bytes()); got != schema {
		t.Fatal(got, schema)
	}
	f.local.control.Reset()
}

func peerTerminal(t *testing.T, f *nativeServiceFixture, stream *nativeServiceStream, drained bool) {
	t.Helper()
	h := OpenHandle{f.peer.admission, stream.h.scope}
	var err error
	if drained {
		_, err = f.peer.admission.PublishDrained(f.ctx, h, f.peer.maintenance)
	} else {
		_, err = f.peer.admission.PublishStopped(f.ctx, h, f.peer.maintenance)
	}
	if err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
}

func TestStreamTerminationGracefulFINPreservesUnreadAndReverse(t *testing.T) {
	f, _ := terminationFixture(t, 1, 2)
	s := f.open(t)
	f.start()
	if _, err := s.peer.send.Write(f.ctx, []byte("unread"), true); err != nil {
		t.Fatal(err)
	}
	if err := nativeResult(t, f.read(s, bytes.NewReader(s.wire.Bytes()))); err != nil {
		t.Fatal(err)
	}
	progressTerminal(t, f, "STREAM_ACK_DRAINED")
	_, _, _, drained, _ := s.peer.send.Snapshot()
	if !drained || f.local.pool.Outstanding() != 6 {
		t.Fatal("wire proof lost unread bytes", drained, f.local.pool.Outstanding())
	}
	var body [16]byte
	if n, terminal, err := s.flow.receive.TryRead(body[:]); err != nil || n != 6 || terminal != protocolv4.V4ReadTerminalEof || string(body[:n]) != "unread" {
		t.Fatal(n, terminal, err)
	}
	if _, err := s.flow.send.Write(f.ctx, []byte("reverse"), false); err != nil {
		t.Fatal("half-close reset reverse", err)
	}
	if result, ready, err := f.termination.Progress(f.ctx); err != nil || ready || result.Submitted {
		t.Fatal("FIN emitted redundant STOPPED", result, ready, err)
	}
}

func TestStreamTerminationResetCompletesOriginalProofs(t *testing.T) {
	f, _ := terminationFixture(t, 1, 2)
	s := f.open(t)
	if err := f.local.admission.Cancel(s.h); err != nil {
		t.Fatal(err)
	}
	progressTerminal(t, f, "STREAM_ACK_STOPPED")
	progressTerminal(t, f, "STREAM_ACK_STOP")
	peerTerminal(t, f, s, false)
	peerTerminal(t, f, s, true)
	progressTerminal(t, f, "STREAM_ACK_DRAINED")
	if f.local.admission.Usage().Active != 1 {
		t.Fatal("wire completion released live provider association")
	}
	slot, err := f.local.admission.slot(s.h)
	if err != nil || slot.phase != openRecent {
		t.Fatal("did not retain unique recent proof", err)
	}
	if f.termination.quarantined.Load() != 0 || f.local.pool.Outstanding() != 0 {
		t.Fatal("terminal promise retained")
	}
	if result, ready, err := f.termination.Progress(f.ctx); err != nil || ready || result.Submitted {
		t.Fatal("duplicate automatic proof", result, ready, err)
	}
}

func TestStreamTerminationNativeFailureUsesAbortedAndPreservesHealthyScope(t *testing.T) {
	f, _ := terminationFixture(t, 2, 4)
	bad, healthy := f.open(t), f.open(t)
	f.start()
	if _, err := bad.peer.send.Write(f.ctx, []byte("lost"), false); err != nil {
		t.Fatal(err)
	}
	wire := bytes.Clone(bad.wire.Bytes())
	wire[len(wire)-1] ^= 1
	first := nativeResult(t, f.read(bad, bytes.NewReader(wire)))
	if first == nil || f.termination.quarantined.Load() != 1 {
		t.Fatal("failure did not immediately quarantine its direction", first)
	}
	var read [8]byte
	if _, _, err := bad.flow.receive.TryRead(read[:]); err != first {
		t.Fatal("application read lost original failure", err, first)
	}
	progressTerminal(t, f, "STREAM_ACK_STOPPED")
	progressTerminal(t, f, "STREAM_ACK_STOP")
	peerTerminal(t, f, bad, false)
	peerTerminal(t, f, bad, true)
	progressTerminal(t, f, "STREAM_ACK_DRAINED")
	bad.peer.send.mu.Lock()
	proof := bad.peer.send.proof
	bad.peer.send.mu.Unlock()
	if !proof.Aborted || proof.Observed.Offset != 0 || proof.Terminal.Offset != 4 {
		t.Fatal("bad DATA became authenticated coverage", proof)
	}
	bad.flow.nativeReceive.pool.mu.Lock()
	cause := bad.flow.nativeReceive.cause
	bad.flow.nativeReceive.pool.mu.Unlock()
	if cause != first || f.termination.quarantined.Load() != 0 {
		t.Fatal("first failure or quarantine release", cause, first)
	}
	if _, err := healthy.peer.send.Write(f.ctx, []byte("healthy"), true); err != nil {
		t.Fatal(err)
	}
	if err := nativeResult(t, f.read(healthy, bytes.NewReader(healthy.wire.Bytes()))); err != nil {
		t.Fatal(err)
	}
	progressTerminal(t, f, "STREAM_ACK_DRAINED")
	if err := f.local.engine.CheckApplicationAuthorization(); err != nil {
		t.Fatal("local failure closed healthy Session", err)
	}
}

func TestStreamTerminationOriginalDeadlinesAndQuarantineCapacity(t *testing.T) {
	for _, mode := range []string{"ordinary", "late scheduler", "capacity", "early failure"} {
		t.Run(mode, func(t *testing.T) {
			cap := uint32(2)
			if mode == "capacity" {
				cap = 1
			}
			f, now := terminationFixture(t, 1, cap)
			s := f.open(t)
			if err := f.local.admission.Cancel(s.h); err != nil {
				t.Fatal(err)
			}
			if mode == "early failure" {
				now.Store(20)
				s.flow.receive.Fence()
				if f.termination.quarantined.Load() != 1 {
					t.Fatal("direction not quarantined")
				}
				now.Store(120)
			} else if mode == "late scheduler" {
				now.Store(151)
			} else {
				now.Store(49)
				progressTerminal(t, f, "STREAM_ACK_STOPPED")
				if f.termination.quarantined.Load() != 0 {
					t.Fatal("early quarantine")
				}
				now.Store(50)
				_, _, err := f.termination.Progress(f.ctx)
				if mode == "capacity" {
					if !errors.Is(err, ErrQuarantineCapacity) {
						t.Fatal(err)
					}
					return
				}
				if err != nil || f.termination.quarantined.Load() != 2 {
					t.Fatal("normal deadline did not isolate both directions", err)
				}
				now.Store(149)
				if _, _, err := f.termination.Progress(f.ctx); err != nil {
					t.Fatal(err)
				}
				now.Store(150)
			}
			if _, _, err := f.termination.Progress(f.ctx); !errors.Is(err, ErrTerminationDeadline) {
				t.Fatal("original deadline extended", err)
			}
			select {
			case <-f.local.engine.Done():
			default:
				t.Fatal("missing terminal evidence did not close Session")
			}
		})
	}
}

func TestStreamTerminationAutomaticPublicationAndBlockedProviderDeadline(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "automatic reset", true: "blocked provider"}[blocked], func(t *testing.T) {
			f, now := terminationFixture(t, 1, 2)
			s := f.open(t)
			w := &serviceTestWriter{frames: make(chan []byte, 8)}
			var held *blockedWriter
			if blocked {
				held = &blockedWriter{entered: make(chan struct{}), finish: make(chan struct{})}
				defer close(held.finish)
				f.local.maintenance.writer = held
			} else {
				f.local.maintenance.writer = w
			}
			done := make(chan error, 1)
			go func() { done <- f.termination.Run(f.ctx) }()
			if err := f.local.admission.Cancel(s.h); err != nil {
				t.Fatal(err)
			}
			if !blocked {
				for range 2 {
					applyTerminalWire(t, f.peer, nextServiceFrame(t, w))
				}
				peerTerminal(t, f, s, false)
				peerTerminal(t, f, s, true)
				if schema := applyTerminalWire(t, f.peer, nextServiceFrame(t, w)); schema != "STREAM_ACK_DRAINED" {
					t.Fatal(schema)
				}
				f.cancel()
				_ = nativeResult(t, done)
				return
			}
			select {
			case <-held.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("publication did not reach provider")
			}
			now.Store(151)
			f.termination.notify()
			if err := nativeResult(t, done); !errors.Is(err, ErrTerminationDeadline) {
				t.Fatal("blocked publication postponed expiry", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			if err := f.termination.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("provider tail reported complete", err)
			}
			if err := f.termination.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
				t.Fatal("provider tail released reservation", err)
			}
		})
	}
}

func TestStreamTerminationLateProofCannotEraseDeadline(t *testing.T) {
	f, now := terminationFixture(t, 1, 2)
	s := f.open(t)
	if err := f.local.admission.Cancel(s.h); err != nil {
		t.Fatal(err)
	}
	progressTerminal(t, f, "STREAM_ACK_STOPPED")
	if _, err := f.peer.admission.PublishDrained(f.ctx, OpenHandle{f.peer.admission, s.h.scope}, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	now.Store(151)
	r, err := f.local.receiver.Receive(f.ctx, f.peer.control.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	err = f.local.admission.ApplyMaintenance(r)
	r.Release()
	if !errors.Is(err, ErrTerminationDeadline) {
		t.Fatal("late proof bypassed original timer", err)
	}
	_, _, _, drained, _ := s.flow.send.Snapshot()
	if drained {
		t.Fatal("late proof became send_drained")
	}
}

func TestStreamTerminationDrainedPublicationRetainsDeadlineAndUnread(t *testing.T) {
	f, now := terminationFixture(t, 1, 2)
	s := f.open(t)
	f.start()
	if _, err := s.peer.send.Write(f.ctx, []byte("unread"), true); err != nil {
		t.Fatal(err)
	}
	if err := nativeResult(t, f.read(s, bytes.NewReader(s.wire.Bytes()))); err != nil {
		t.Fatal(err)
	}
	held := &blockedWriter{entered: make(chan struct{}), finish: make(chan struct{})}
	defer close(held.finish)
	f.local.maintenance.writer = held
	done := make(chan error, 1)
	go func() { done <- f.termination.Run(f.ctx) }()
	select {
	case <-held.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no DRAINED publication")
	}
	now.Store(50)
	f.local.admission.mu.Lock()
	_, err := f.termination.checkLocked()
	f.local.admission.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var dst [16]byte
	if n, terminal, err := s.flow.receive.TryRead(dst[:]); err != nil || n != 6 || terminal != protocolv4.V4ReadTerminalEof {
		t.Fatal("maintenance tail discarded graceful unread data", n, terminal, err)
	}
	now.Store(151)
	f.termination.notify()
	if err := nativeResult(t, done); !errors.Is(err, ErrTerminationDeadline) {
		t.Fatal("submitted DRAINED lost provider deadline", err)
	}
}

func TestStreamTerminationAcrossActualRekeyKeepsOriginalWindow(t *testing.T) {
	f, now := terminationFixture(t, 1, 2)
	s := f.open(t)
	s.flow.send.Stop()
	original, _ := s.flow.send.Terminal()
	c, peer := exchange(t, f.local), exchange(t, f.peer)
	if _, err := c.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, f.local, f.peer, peer)
	exchangeProgress(t, peer)
	exchangeFlight(t, f.peer, f.local, c)
	exchangeProgress(t, c)
	exchangeFlight(t, f.local, f.peer, peer)
	exchangeProgress(t, peer)
	exchangeFlight(t, f.peer, f.local, c)
	if result, ready, err := f.termination.Progress(f.ctx); err != nil || !ready || result.Header.Epoch != 1 {
		t.Fatal(result, ready, err)
	}
	applyTerminalWire(t, f.peer, f.local.control.Bytes())
	f.local.control.Reset()
	proof, ok := s.peer.receive.DrainProof()
	if !ok || proof.Terminal != original || proof.Observed != original {
		t.Fatal("rekey replaced terminal frontier", proof)
	}
	now.Store(150)
	if _, _, err := f.termination.Progress(f.ctx); !errors.Is(err, ErrTerminationDeadline) {
		t.Fatal("rekey refreshed original termination window", err)
	}
}

func TestStreamTerminationHonorsEarlierIrreversibleRekeyCap(t *testing.T) {
	f, now := terminationFixture(t, 1, 2)
	s := f.open(t)
	c := exchange(t, f.local)
	sample, err := f.local.engine.Clock().Sample()
	if err != nil {
		t.Fatal(err)
	}
	c.round.TightenDeadline(sample.LowerMS + 20)
	s.flow.receive.Fence()
	if _, err := c.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	now.Store(21)
	if _, _, err := f.termination.Progress(f.ctx); err == nil {
		t.Fatal("quarantine outlived irreversible rekey cap")
	}
	select {
	case <-f.local.engine.Done():
	default:
		t.Fatal("earlier rekey cap did not close Session")
	}
}
