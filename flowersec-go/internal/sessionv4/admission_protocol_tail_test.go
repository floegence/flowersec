package sessionv4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func waitAdmissionProtocolPublication(t *testing.T, writer *retirementTailWriter) {
	t.Helper()
	select {
	case <-writer.messages:
	case <-time.After(5 * time.Second):
		t.Fatal("protocol publication did not enter its original provider")
	}
}

func TestAdmissionRekeyTailDelaysClosedBarrierDisposal(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	h, _, _, _ := startTestOpen(t, client, server, 8)
	x := exchange(t, client)
	w := &retirementTailWriter{messages: make(chan []byte, 1), finish: make(chan struct{})}
	release := sync.OnceFunc(func() { close(w.finish) })
	defer release()
	client.maintenance.writer = w
	done := make(chan error, 1)
	go func() { _, err := x.Start(context.Background()); done <- err }()
	waitAdmissionProtocolPublication(t, w)
	a := client.admission
	a.Close()
	a.mu.Lock()
	s, err := a.slot(h)
	retained := err == nil && s.barrierReferences == 1 && a.methodTails != 0 && !x.barriers.disposeClosedLocked() && !a.isStable(h.scope)
	a.mu.Unlock()
	if !retained {
		t.Fatal("logical close released a live rekey publisher or its barrier")
	}
	release()
	_ = waitRuntime(t, done)
	a.mu.Lock()
	disposed := a.methodTails == 0 && x.barriers.disposeClosedLocked()
	s, err = a.slot(h)
	preserved := err == nil && s.barrierReferences == 0 && !a.isStable(h.scope)
	empty := x.barriers.local == nil && x.barriers.peer == nil && x.barriers.waiting == nil && x.barriers.freeze == nil
	a.mu.Unlock()
	if !disposed || !preserved || !empty {
		t.Fatal("closed disposal lost an unresolved scope or retained barrier backing")
	}
	x.Close()
	if _, err := x.Start(context.Background()); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("stale exchange regained work", err)
	}
}

func TestAdmissionRetirementTailDelaysClosedProofDisposal(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	h, _ := rejectTestOpen(t, client, server)
	r := testRetirement(t, client, client.maintenance)
	w := &retirementTailWriter{messages: make(chan []byte, 1), finish: make(chan struct{})}
	release := sync.OnceFunc(func() { close(w.finish) })
	defer release()
	client.maintenance.writer = w
	deadline := streamTestDeadline(t, client.engine)
	done := make(chan error, 1)
	go func() { _, err := r.Start(context.Background(), 1, deadline); done <- err }()
	waitAdmissionProtocolPublication(t, w)
	a := client.admission
	a.Close()
	a.mu.Lock()
	s, err := a.slot(h)
	retained := err == nil && s.retirementReferences == 1 && a.methodTails != 0 && !r.disposeClosedLocked()
	a.mu.Unlock()
	if !retained {
		t.Fatal("logical close released a live retirement publisher or its proof")
	}
	release()
	_ = waitRuntime(t, done)
	a.mu.Lock()
	disposed := a.methodTails == 0 && r.disposeClosedLocked()
	s, err = a.slot(h)
	preserved := err == nil && s.retirementReferences == 0 && !a.isStable(h.scope) && r.lastSent == 0
	empty := r.out.ids == nil && r.in[0].ids == nil && r.in[1].ids == nil && r.batchBytes == nil && r.arrayBytes == nil
	a.mu.Unlock()
	if !disposed || !preserved || !empty {
		t.Fatal("closed disposal invented retirement or retained its backing")
	}
	if _, err := r.Start(context.Background(), 1, deadline); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("stale retirement publisher regained work", err)
	}
	if _, err := r.Acknowledge(context.Background()); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("stale retirement acknowledger regained work", err)
	}
}

func TestAdmissionClosedRetirementDisposalReleasesUnacknowledgedPeerBatch(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	_, h := rejectTestOpen(t, client, server)
	cr := testRetirement(t, client, client.maintenance)
	r := testRetirement(t, server, server.maintenance)
	if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, client.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, r, client.control.Bytes())
	a := server.admission
	a.mu.Lock()
	s, err := a.slot(h)
	retained := err == nil && s.retirementReferences == 1 && !r.disposeClosedLocked()
	a.mu.Unlock()
	if !retained {
		t.Fatal("live Session lost an unacknowledged peer batch")
	}
	a.Close()
	a.mu.Lock()
	disposed := r.disposeClosedLocked()
	s, err = a.slot(h)
	preserved := err == nil && s.retirementReferences == 0 && !a.isStable(h.scope) && r.lastReceived == 0
	a.mu.Unlock()
	if !disposed || !preserved {
		t.Fatal("closed disposal fabricated the peer batch ACK")
	}
}

func TestAdmissionBootstrapPrefixRetainsTailThroughProviderExit(t *testing.T) {
	client, server := newBootstrapPair(t, protocolv4.DHProfileX25519, "services")
	client.complete(t, server)
	w := &retirementTailWriter{messages: make(chan []byte, 1), finish: make(chan struct{})}
	release := sync.OnceFunc(func() { close(w.finish) })
	defer release()
	if err := client.bootstrap.BindLocalCarrier(client.carrier, w); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := client.bootstrap.PublishPrefix(context.Background()); done <- err }()
	waitAdmissionProtocolPublication(t, w)
	a := client.admission
	a.Close()
	a.mu.Lock()
	tails := a.methodTails
	a.mu.Unlock()
	if tails == 0 {
		t.Fatal("logical close forgot the bootstrap prefix publisher")
	}
	release()
	_ = waitRuntime(t, done)
	a.mu.Lock()
	tails = a.methodTails
	a.mu.Unlock()
	if tails != 0 {
		t.Fatal("bootstrap prefix returned without releasing its method tail")
	}
}
