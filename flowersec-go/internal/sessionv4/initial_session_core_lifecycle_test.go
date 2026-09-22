package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// The original provider retains its write alias after Close. Its actual Close
// return can be held independently, keeping the precharged carrier task alive.
type initialCoreGateStream struct {
	io.ReadWriteCloser
	frame                   protocolv4.FrameType
	entered, resume, closed chan struct{}
	closeResume             chan struct{}
	intact                  chan bool
	writeOnce, closeOnce    sync.Once
}

func (s *initialCoreGateStream) Write(p []byte) (written int, err error) {
	if len(p) >= protocolv4.EnvelopePrefixSize && protocolv4.FrameType(p[4]) == s.frame {
		s.writeOnce.Do(func() {
			original := bytes.Clone(p)
			close(s.entered)
			<-s.resume
			s.intact <- bytes.Equal(original, p)
		})
	}
	// Complete short underlying writes here so each invocation above sees the
	// original envelope prefix, never a suffix mistaken for a new frame.
	for written < len(p) {
		n, err := s.ReadWriteCloser.Write(p[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (s *initialCoreGateStream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.ReadWriteCloser.Close()
		close(s.closed)
		if s.closeResume != nil {
			<-s.closeResume
		}
	})
	return nil
}

func initialCoreGate(t *testing.T, x *InitialExchange, frame protocolv4.FrameType, holdClose bool) (*initialCoreGateStream, func(), func()) {
	t.Helper()
	s := &initialCoreGateStream{frame: frame, entered: make(chan struct{}), resume: make(chan struct{}), closed: make(chan struct{}), intact: make(chan bool, 1)}
	if holdClose {
		s.closeResume = make(chan struct{})
	}
	x.mu.Lock()
	s.ReadWriteCloser, x.stream = x.stream, s
	x.mu.Unlock()
	releaseWrite := sync.OnceFunc(func() { close(s.resume) })
	releaseClose := sync.OnceFunc(func() {
		if s.closeResume != nil {
			close(s.closeResume)
		}
	})
	return s, releaseWrite, releaseClose
}

func waitInitialCoreGate(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(name, "did not reach its original provider gate")
	}
}

type initialCoreOutcome struct {
	core *SessionCore
	err  error
}

func startInitialCorePair(pair [2]*InitialExchange, configs [2]cryptov4.HandshakeConfig, fixtures *[2]initialCoreFixture) [2]<-chan initialCoreOutcome {
	var results [2]<-chan initialCoreOutcome
	for role := range 2 {
		done := make(chan initialCoreOutcome, 1)
		results[role] = done
		go func() {
			core, err := pair[role].AuthenticateCore(configs[role], fixtures[role].plan)
			done <- initialCoreOutcome{core, err}
		}()
	}
	return results
}

func waitInitialCoreOutcome(t *testing.T, done <-chan initialCoreOutcome) initialCoreOutcome {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("original core authentication did not return")
		return initialCoreOutcome{}
	}
}

func retireInitialCorePair(t *testing.T, pair [2]*InitialExchange, fixtures *[2]initialCoreFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for role := range 2 {
		if err := fixtures[role].plan.Abort(ctx); err != nil {
			t.Fatal(role, err)
		}
		if err := pair[role].WaitCleanup(ctx); err != nil {
			t.Fatal(role, err)
		}
		if got := fixtures[role].root.Snapshot().Reservations; got != 1 {
			t.Fatal("authentication retained resources beyond its Environment", role, got)
		}
	}
}

func requireInitialCoreTail(t *testing.T, plan *SessionCorePlan) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := plan.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("core cleanup passed an unfinished original provider", err)
	}
	if err := plan.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("core retired before original provider cleanup", err)
	}
}

func closeInitialCorePromptly(t *testing.T, plan *SessionCorePlan) {
	t.Helper()
	done := make(chan struct{})
	go func() { plan.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("logical close waited for the provider's physical Close callback")
	}
}

func TestInitialCoreCancellationRetainsOriginalNoiseAndReadyProvider(t *testing.T) {
	for _, stage := range []struct {
		name  string
		frame protocolv4.FrameType
	}{{"noise", protocolv4.FrameHandshake}, {"ready", protocolv4.FrameReady}} {
		for _, cancelParent := range []bool{false, true} {
			name := stage.name + "/plan-close"
			if cancelParent {
				name = stage.name + "/parent-cancel"
			}
			t.Run(name, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				var fixtures [2]initialCoreFixture
				pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, "stream", 4, initialCorePrepare(t, &fixtures), parent, context.Background())
				provider, releaseWrite, releaseClose := initialCoreGate(t, pair[0], stage.frame, true)
				defer releaseClose()
				defer releaseWrite()
				results := startInitialCorePair(pair, configs, &fixtures)
				waitInitialCoreGate(t, provider.entered, stage.name)
				plan := fixtures[0].plan
				plan.mu.Lock()
				installed := plan.engine != nil && plan.runtime != nil
				input := plan.input.(*sessionStreamInput)
				plan.mu.Unlock()
				if input == nil || installed != (stage.frame == protocolv4.FrameReady) {
					t.Fatal("provider gate missed the intended authentication stage")
				}
				pair[0].mu.Lock()
				original := pair[0].config.Reservation
				pair[0].mu.Unlock()
				input.mu.Lock()
				carrierReservation := input.reservation
				input.mu.Unlock()
				if cancelParent {
					cancel()
				} else {
					closeInitialCorePromptly(t, plan)
				}
				waitInitialCoreGate(t, provider.closed, "close request")
				// After parent cancellation, closing the aggregate also seals its
				// future installation gates while the original write still runs.
				closeInitialCorePromptly(t, plan)
				requireInitialCoreTail(t, plan)
				for _, account := range []resourcev4.Account{fixtures[0].scope.Tenant, fixtures[0].scope.Session} {
					used, err := account.Usage()
					if err != nil || used[resourcev4.Sessions] != 1 {
						t.Fatal("live provider tail lost its original Session slot", used, err)
					}
				}
				if err := original.Check(); !errors.Is(err, resourcev4.ErrClosed) {
					t.Fatal("initial reservation was refunded before its write exited", err)
				}
				releaseWrite()
				client := waitInitialCoreOutcome(t, results[0])
				want := cryptov4.ErrClosed
				if cancelParent {
					want = context.Canceled
				}
				if client.core != nil || !errors.Is(client.err, want) {
					t.Fatal("cancelled authentication exposed a core or lost its cause", client.err)
				}
				if !<-provider.intact {
					t.Fatal("cleanup cleared a live provider write alias")
				}
				peer := waitInitialCoreOutcome(t, results[1])
				if peer.core != nil || peer.err == nil {
					t.Fatal("peer authentication succeeded without both READY flights", peer.err)
				}
				// Initial work can finish once its write returns. The plan's
				// carrier worker still owns the provider Close callback and its
				// separate original charge until that callback actually exits.
				ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := pair[0].WaitCleanup(ctx); err != nil {
					t.Fatal("carrier shutdown retained completed Initial work", err)
				}
				if err := original.Check(); !errors.Is(err, resourcev4.ErrOwner) {
					t.Fatal("completed Initial work retained its old reservation", err)
				}
				requireInitialCoreTail(t, plan)
				for _, account := range []resourcev4.Account{fixtures[0].scope.Tenant, fixtures[0].scope.Session} {
					used, err := account.Usage()
					if err != nil || used[resourcev4.Sessions] != 1 {
						t.Fatal("live provider tail lost its original Session slot", used, err)
					}
				}
				if err := carrierReservation.Check(); err != nil && !errors.Is(err, resourcev4.ErrClosed) {
					t.Fatal("carrier reservation was refunded before provider Close exited", err)
				}
				releaseClose()
				retireInitialCorePair(t, pair, &fixtures)
			})
		}
	}
}

func TestInitialCoreRejectsMismatchWithoutConsumingPlan(t *testing.T) {
	for _, mismatch := range []string{"clock", "idle-duration", "environment"} {
		t.Run(mismatch, func(t *testing.T) {
			var fixtures [2]initialCoreFixture
			pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, "stream", 4, initialCorePrepare(t, &fixtures))
			config, plan, want := configs[0], fixtures[0].plan, cryptov4.ErrConfiguration
			switch mismatch {
			case "clock":
				config.Clock = sessionTestClock(t)
			case "idle-duration":
				config.LocalIdleDurationMS++
			case "environment":
				plan, want = fixtures[1].plan, resourcev4.ErrOwner
			}
			before := [2]resourcev4.Snapshot{fixtures[0].root.Snapshot(), fixtures[1].root.Snapshot()}
			if core, err := pair[0].AuthenticateCore(config, plan); core != nil || !errors.Is(err, want) {
				t.Fatal("mismatched authentication reached the original plan", err)
			}
			for role := range 2 {
				if after := fixtures[role].root.Snapshot(); after != before[role] {
					t.Fatal("pre-claim rejection changed resource ownership", role, before[role], after)
				}
			}
			// Real Noise and both READY flights must still succeed using the
			// same plans and initial carriers after the rejected projection.
			for _, done := range startInitialCorePair(pair, configs, &fixtures) {
				result := waitInitialCoreOutcome(t, done)
				if result.core == nil || result.err != nil {
					t.Fatal("pre-claim rejection consumed the original plan", result.err)
				}
			}
			retireInitialCorePair(t, pair, &fixtures)
		})
	}
}

func TestInitialCoreRejectsReuseWithoutClosingOriginalAuthentication(t *testing.T) {
	var fixtures [2]initialCoreFixture
	pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, "stream", 4, initialCorePrepare(t, &fixtures))
	provider, releaseWrite, releaseClose := initialCoreGate(t, pair[0], protocolv4.FrameHandshake, false)
	defer releaseClose()
	defer releaseWrite()
	results := startInitialCorePair(pair, configs, &fixtures)
	waitInitialCoreGate(t, provider.entered, "Noise")
	before := fixtures[0].root.Snapshot()
	if core, err := pair[0].AuthenticateCore(configs[0], fixtures[0].plan); core != nil || !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("one plan admitted another authentication", err)
	}
	if after := fixtures[0].root.Snapshot(); after != before {
		t.Fatal("duplicate authentication changed the original reservations", before, after)
	}
	select {
	case <-provider.closed:
		t.Fatal("duplicate authentication closed the original provider")
	default:
	}
	releaseWrite()
	for _, done := range results {
		result := waitInitialCoreOutcome(t, done)
		if result.core == nil || result.err != nil {
			t.Fatal("duplicate authentication invalidated the original attempt", result.err)
		}
	}
	if !<-provider.intact {
		t.Fatal("duplicate authentication changed the original Noise flight")
	}
	retireInitialCorePair(t, pair, &fixtures)
}

func TestInitialCoreRejectsDifferentPlanWithoutConsumingItsClaim(t *testing.T) {
	var fixtures [2]initialCoreFixture
	pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, "stream", 4, initialCorePrepare(t, &fixtures))
	original := fixtures[0].plan
	original.mu.Lock()
	config, environment := original.config, fixtures[0].environment
	original.mu.Unlock()
	second, err := NewSessionCorePlan(config, fixtures[0].root, resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{4}, Backing: [16]byte{1}, Kind: 2}, environment, corePlanTestScope(t, fixtures[0].root, fixtures[0].limit, 2))
	if err != nil {
		t.Fatal(err)
	}
	cleanupCorePlanUnit(t, second)
	provider, releaseWrite, releaseClose := initialCoreGate(t, pair[0], protocolv4.FrameHandshake, false)
	defer releaseClose()
	defer releaseWrite()
	results := startInitialCorePair(pair, configs, &fixtures)
	waitInitialCoreGate(t, provider.entered, "Noise")
	before := fixtures[0].root.Snapshot()
	if core, err := pair[0].AuthenticateCore(configs[0], second); core != nil || !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("one Initial exchange consumed a second core plan", err)
	}
	if after := fixtures[0].root.Snapshot(); after != before {
		t.Fatal("rejected second plan changed the original reservations", before, after)
	}
	if err := second.Claim(config.Session, protocolv4.ClientToServer); err != nil {
		t.Fatal("rejected second plan lost its original claim", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := second.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-provider.closed:
		t.Fatal("rejecting or retiring the second plan closed the original provider")
	default:
	}
	releaseWrite()
	for _, done := range results {
		result := waitInitialCoreOutcome(t, done)
		if result.core == nil || result.err != nil {
			t.Fatal("second plan disturbed the original authentication", result.err)
		}
	}
	if !<-provider.intact {
		t.Fatal("second plan changed the original Noise flight")
	}
	retireInitialCorePair(t, pair, &fixtures)
}
