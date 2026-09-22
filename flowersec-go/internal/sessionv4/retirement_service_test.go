package sessionv4

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

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
