package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestRetirementServiceSubmittedOpenWakesOriginalAggregation(t *testing.T) {
	now := new(atomic.Uint64)
	clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: now.Load(), Incarnation: [16]byte{1}}, nil
	})
	client := newOpenEndpointClock(t, protocolv4.ClientToServer, 4, 4, 2, clock)
	server := newOpenEndpointClock(t, protocolv4.ServerToClient, 4, 4, 2, clock)
	f := &runtimeFixture{local: client, resources: backgroundResources(t, client)}
	p := runtimeRetirement(t, f)
	proof, _ := rejectTestOpen(t, client, server)
	tail := &retirementTailWriter{messages: make(chan []byte, 1), finish: make(chan struct{}, 1)}
	defer close(tail.finish)
	client.maintenance.writer = tail
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	limit := time.NewTimer(time.Second)
	defer limit.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	var original *timev4.Deadline
	for original == nil {
		p.mu.Lock()
		original = p.outDeadline
		p.mu.Unlock()
		if original == nil {
			select {
			case <-tick.C:
			case <-limit.C:
				t.Fatal("original service never entered retirement aggregation")
			}
		}
	}
	// Observe and forward the actual OPEN-ticket notification, so an ordinary
	// flush-timer expiry cannot satisfy the wake assertion under a slow runner.
	// The coordinator and its original deadline/publication worker stay live.
	observed := make(chan struct{}, 1)
	client.admission.mu.Lock()
	originalWake := p.retirement.wake
	p.retirement.wake = observed
	client.admission.mu.Unlock()
	defer func() {
		client.admission.mu.Lock()
		p.retirement.wake = originalWake
		client.admission.mu.Unlock()
	}()
	now.Store(7)
	provider := new(bytes.Buffer)
	opening, result, err := client.admission.OpenLocal(ctx, BusinessStream, "example/raw", nil,
		&CarrierAssociation{}, client.reservation(provider, 8), streamTestDeadline(t, client.engine))
	if err != nil || !result.Submitted || !result.Complete {
		t.Fatal("late original OPEN did not acquire its actual ticket", result, err)
	}
	select {
	case <-observed:
		select {
		case originalWake <- struct{}{}:
		default:
		}
	case <-limit.C:
		t.Fatal("submitted OPEN left the original retirement service asleep")
	}
	client.admission.mu.Lock()
	slot, err := client.admission.slot(opening)
	awaiting := err == nil && slot.phase == openOpening && slot.submitted
	client.admission.mu.Unlock()
	if !awaiting {
		t.Fatal("wake did not retain the original submitted OPEN awaiting outcome", err)
	}
	select {
	case wire := <-tail.messages:
		record, err := server.receiver.Receive(ctx, wire)
		if err != nil {
			t.Fatal(err)
		}
		defer record.Release()
		body, err := record.Body()
		var ids [1]uint64
		if err != nil || body.Schema != "STREAM_ACK_RETIRE_BATCH" {
			t.Fatal("wake did not publish an authenticated retirement batch", err)
		}
		if count, ok := body.Field("scope_ids").CopyUints(ids[:]); !ok || count != 1 || ids[0] != proof.Scope() {
			t.Fatal("wake changed the original eligible proof", ids)
		}
		client.admission.mu.Lock()
		deadline := p.retirement.out.deadline
		client.admission.mu.Unlock()
		if deadline != original {
			t.Fatal("late OPEN restarted the original retirement deadline")
		}
		if remaining, err := deadline.RemainingMS(); err != nil || remaining != p.timeoutMS-7 {
			t.Fatal("late OPEN extended the original retirement cap", remaining, err)
		}
	case err := <-done:
		t.Fatal("original retirement service stopped before publication", err)
	case <-limit.C:
		t.Fatal("late OPEN did not drive the existing retirement worker")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("original retirement coordinator did not exit")
	}
	p.Close()
	select {
	case <-p.done:
		t.Fatal("Close refunded the still blocked original provider tail")
	default:
	}
	tail.finish <- struct{}{}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := p.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
}

func TestRetirementServiceFlushesAdjacentProofsInOneOriginalBatch(t *testing.T) {
	now := new(atomic.Uint64)
	clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: now.Load(), Incarnation: [16]byte{1}}, nil
	})
	client := newOpenEndpointClock(t, protocolv4.ClientToServer, 4, 4, 2, clock)
	server := newOpenEndpointClock(t, protocolv4.ServerToClient, 4, 4, 2, clock)
	f := &runtimeFixture{local: client, resources: backgroundResources(t, client)}
	p := runtimeRetirement(t, f)
	var expected [2]uint64
	for i := range expected {
		local, _ := rejectTestOpen(t, client, server)
		expected[i] = local.Scope()
	}
	tail := &retirementTailWriter{messages: make(chan []byte, 1), finish: make(chan struct{}, 1)}
	defer close(tail.finish)
	client.maintenance.writer = tail
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	var original *timev4.Deadline
	limit := time.NewTimer(time.Second)
	defer limit.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for original == nil {
		p.mu.Lock()
		original = p.outDeadline
		p.mu.Unlock()
		if original == nil {
			select {
			case <-tick.C:
			case <-limit.C:
				t.Fatal("eligible proofs never acquired their original batch deadline")
			}
		}
	}
	now.Store(7)
	p.notify()
	select {
	case wire := <-tail.messages:
		record, err := server.receiver.Receive(ctx, wire)
		if err != nil {
			t.Fatal(err)
		}
		defer record.Release()
		body, err := record.Body()
		var ids [2]uint64
		if err != nil || body.Schema != "STREAM_ACK_RETIRE_BATCH" {
			t.Fatal("flush did not publish one authenticated retirement batch", err)
		}
		if count, ok := body.Field("scope_ids").CopyUints(ids[:]); !ok || count != len(ids) || ids != expected {
			t.Fatal("adjacent original proofs were not gathered in one batch", ids)
		}
		client.admission.mu.Lock()
		deadline := p.retirement.out.deadline
		client.admission.mu.Unlock()
		if deadline != original {
			t.Fatal("flush restarted the original eligible-proof deadline")
		}
		if remaining, err := deadline.RemainingMS(); err != nil || remaining != p.timeoutMS-7 {
			t.Fatal("flush hid elapsed time from the original deadline", remaining, err)
		}
	case err := <-done:
		t.Fatal("retirement ended before the original flush", err)
	case <-limit.C:
		t.Fatal("flush waited for another application operation")
	}
	cancel()
	tail.finish <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("original retirement tasks did not exit")
	}
}

func TestRetirementServiceDeadlineRunsDuringBlockedPublication(t *testing.T) {
	client, server, now := idleEndpoints(t, 0)
	f := &runtimeFixture{local: client, resources: backgroundResources(t, client)}
	p := runtimeRetirement(t, f)
	p.timeoutMS = 20
	rejectTestOpen(t, client, server)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	client.maintenance.writer = idleWriterFunc(func(b []byte) (int, error) {
		close(entered)
		<-release
		return len(b), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("retirement did not publish")
	}
	now.Store(21)
	select {
	case err := <-done:
		if !errors.Is(err, timev4.ErrExpired) {
			t.Fatal("original publication deadline lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked provider disabled retirement timeout")
	}
	select {
	case <-p.done:
		t.Fatal("logical timeout released original provider tail")
	default:
	}
	once.Do(func() { close(release) })
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := p.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := client.engine.ApplicationReady(); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("expired responsibility left Session live", err)
	}
}

func TestBarrierCancellationWakesRetirementEligibility(t *testing.T) {
	client, server, _ := idleEndpoints(t, 0)
	f := &runtimeFixture{local: client, resources: backgroundResources(t, client)}
	p := runtimeRetirement(t, f)
	b, err := NewBarriers(client.admission)
	if err != nil {
		t.Fatal(err)
	}
	local, peer, _, _ := startTestOpen(t, client, server, 8)
	if err := b.Freeze(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	if ready, _, err := p.status(); err != nil || ready {
		t.Fatal("unpublished barrier admitted retirement", ready, err)
	}
	select {
	case <-p.wake:
	default:
	}
	if err := b.Cancel(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.wake:
	default:
		t.Fatal("cancelled barrier left retirement asleep")
	}
	if ready, _, err := p.status(); err != nil || !ready {
		t.Fatal("original recent proof did not become eligible", local.Scope(), ready, err)
	}
}

func runtimeRetirement(t *testing.T, f *runtimeFixture) *RetirementService {
	t.Helper()
	r := testRetirement(t, f.local, f.local.maintenance)
	charge, err := RetirementServiceCharge()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewRetirementService(r, 10000, f.resources.reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := p.retire(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestSessionRuntimeAutomaticallyRetiresRejectedOpen(t *testing.T) {
	client, server := newOpenEndpoint(t, 0, 2, 2, 1), newOpenEndpoint(t, 1, 2, 2, 1)
	cr, cw := io.Pipe()
	sr, sw := io.Pipe()
	defer cw.Close()
	defer sw.Close()
	cf := newRuntimeFixture(t, client, &runtimeTestInput{Reader: cr, interrupt: func() { _ = cr.Close() }}, false)
	sf := newRuntimeFixture(t, server, &runtimeTestInput{Reader: sr, interrupt: func() { _ = sr.Close() }}, false)
	runtimeRetirement(t, cf)
	runtimeRetirement(t, sf)
	local, peer := rejectTestOpen(t, client, server)
	// Preserve the original writer identities while joining the test's two
	// real streams after the already completed OPEN outcome exchange.
	client.maintenance.writer = sw
	server.maintenance.writer = cw
	c, s := cf.startOwner(t), sf.startOwner(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cd, sd := make(chan error, 1), make(chan error, 1)
	go func() { cd <- c.Run(ctx) }()
	go func() { sd <- s.Run(ctx) }()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		client.admission.mu.Lock()
		cs := client.admission.isStable(local.Scope())
		client.admission.mu.Unlock()
		server.admission.mu.Lock()
		ss := server.admission.isStable(peer.Scope())
		server.admission.mu.Unlock()
		if cs && ss {
			break
		}
		select {
		case err := <-cd:
			t.Fatal("client retirement failed", err)
		case err := <-sd:
			t.Fatal("server retirement failed", err)
		case <-timer.C:
			t.Fatal("retirement response was not driven")
		case <-tick.C:
		}
	}
	if client.admission.Usage().PositiveProofs != 1 || server.admission.Usage().RejectionProofs != 1 {
		t.Fatal("retirement ACK erased physical cleanup responsibility")
	}
	if err := client.admission.CarrierClosed(local); err != nil {
		t.Fatal(err)
	}
	if err := server.admission.CarrierClosed(peer); err != nil {
		t.Fatal(err)
	}
	if client.admission.Usage().PositiveProofs != 0 || server.admission.Usage().RejectionProofs != 0 {
		t.Fatal("original cleanup did not release retired proofs")
	}
	cancel()
	waitRuntime(t, cd)
	waitRuntime(t, sd)
}
