package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// Pause the original caller outside every SDK lock. Its actual method tail
// remains live while another owner delivers an outcome or closes the Session.
type openPausedWaitContext struct {
	context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (c *openPausedWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Context.Done()
}

func pauseOpenWait(t *testing.T, base context.Context, wait func(context.Context) error) (func(), <-chan error) {
	t.Helper()
	ctx := &openPausedWaitContext{Context: base, entered: make(chan struct{}), release: make(chan struct{})}
	resume := sync.OnceFunc(func() { close(ctx.release) })
	t.Cleanup(resume)
	done := make(chan error, 1)
	go func() { done <- wait(ctx) }()
	select {
	case <-ctx.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("OPEN observer did not reach its original wait position")
	}
	return resume, done
}

func TestOpenNextPendingCancellationPreservesSingleDelivery(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	a := server.admission
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resume, done := pauseOpenWait(t, ctx, func(ctx context.Context) error {
		_, err := a.NextPending(ctx)
		return err
	})
	if _, err := a.NextPending(context.Background()); !errors.Is(err, ErrOpenWaitBusy) {
		t.Fatal("second dispatcher occupied the original wait position", err)
	}
	_, first, _, _ := startTestOpen(t, client, server, 8)
	before := a.Usage()
	cancel()
	resume()
	if err := waitRuntime(t, done); !errors.Is(err, context.Canceled) || a.Usage() != before {
		t.Fatal("cancelled dispatcher changed original pending OPEN", err)
	}
	got, err := a.NextPending(context.Background())
	if err != nil || got != first {
		t.Fatal("cancelled observation consumed pending delivery", got, err)
	}
	var next OpenHandle
	resume, done = pauseOpenWait(t, context.Background(), func(ctx context.Context) error {
		var err error
		next, err = a.NextPending(ctx)
		return err
	})
	_, second, _, _ := startTestOpen(t, client, server, 8)
	resume()
	if err := waitRuntime(t, done); err != nil || next != second {
		t.Fatal("dispatcher repeated an already delivered OPEN", next, err)
	}
	if _, _, _, err := a.CopyRequest(first, make([]byte, 128)); err != nil {
		t.Fatal("dispatch discarded original request", err)
	}
}

func TestOpenWaitOutcomeCancellationPreservesSubmittedOpen(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer, _, _ := startTestOpen(t, client, server, 8)
	a := client.admission
	before := a.Usage()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resume, done := pauseOpenWait(t, ctx, func(ctx context.Context) error { return a.WaitOutcome(ctx, local) })
	if err := a.WaitOutcome(context.Background(), local); !errors.Is(err, ErrOpenWaitBusy) {
		t.Fatal("second outcome observer occupied the original wait position", err)
	}
	cancel()
	resume()
	if err := waitRuntime(t, done); !errors.Is(err, context.Canceled) || a.Usage() != before {
		t.Fatal("observation cancellation refunded submitted OPEN", err)
	}
	a.mu.Lock()
	s, err := a.slot(local)
	preserved := err == nil && s.submitted && !s.cancelled && s.phase == openOpening && s.retirementReferences == 0 && !s.outcomeWaiting && a.methodTails == 0
	a.mu.Unlock()
	if !preserved {
		t.Fatal("observation cancellation invented an OPEN outcome")
	}
	resume, done = pauseOpenWait(t, context.Background(), func(ctx context.Context) error { return a.WaitOutcome(ctx, local) })
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 8), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	resume()
	if err := waitRuntime(t, done); err != nil {
		t.Fatal("original OPEN could not be observed again", err)
	}
}

func TestOpenWaitOutcomeAcceptedAndRejectedWake(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "accepted"
		if reject {
			name = "rejected"
		}
		t.Run(name, func(t *testing.T) {
			client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
			server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
			local, peer, _, _ := startTestOpen(t, client, server, 8)
			resume, done := pauseOpenWait(t, context.Background(), func(ctx context.Context) error { return client.admission.WaitOutcome(ctx, local) })
			label, reservation := "", StreamReservation{}
			var want error
			if reject {
				label, want = "kind_unavailable", ErrOpenRejected
			} else {
				reservation = server.reservation(new(bytes.Buffer), 8)
			}
			if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, label, reservation, server.maintenance); err != nil {
				t.Fatal(err)
			}
			applyTestOutcome(t, server, client)
			resume()
			if err := waitRuntime(t, done); !errors.Is(err, want) {
				t.Fatal("authenticated outcome did not wake original waiter", err)
			}
		})
	}
}

func TestOpenWaitOutcomeMovesWithOriginalSlotAndDelaysCollection(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer, _, _ := startTestOpen(t, client, server, 8)
	a := server.admission
	resume, done := pauseOpenWait(t, context.Background(), func(ctx context.Context) error { return a.WaitOutcome(ctx, peer) })
	a.mu.Lock()
	source := a.find(peer.scope)
	wake := a.outcomeWake[source]
	a.mu.Unlock()
	if _, err := a.Decide(context.Background(), peer, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, server.maintenance)
	if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, client.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	client.control.Reset()
	if _, err := sr.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, client, cr, server.control.Bytes())
	server.control.Reset()
	if err := a.CarrierClosed(peer); err != nil {
		t.Fatal(err)
	}
	if err := client.admission.CarrierClosed(local); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	target := a.find(peer.scope)
	s, err := a.slot(peer)
	retained := err == nil && source != target && target < int(a.limits.Terminal) && a.outcomeWake[target] == wake && s.retirementReferences == 1 && s.outcomeWaiting && s.phase == openHeld
	a.mu.Unlock()
	if !retained || a.Usage().RejectionProofs != 1 {
		t.Fatal("retirement lost the original moved observer or its proof slot")
	}
	resume()
	if err := waitRuntime(t, done); !errors.Is(err, ErrOpenRejected) {
		t.Fatal("slot movement stranded outcome waiter", err)
	}
	if a.Usage().RejectionProofs != 0 {
		t.Fatal("completed original observer retained recyclable proof capacity")
	}
}

func TestOpenWaitCancelWakesWithoutInventingPeerOutcome(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, _, _, _ := startTestOpen(t, client, server, 8)
	a := client.admission
	before := a.Usage()
	resume, done := pauseOpenWait(t, context.Background(), func(ctx context.Context) error { return a.WaitOutcome(ctx, local) })
	if err := a.Cancel(local); err != nil {
		t.Fatal(err)
	}
	resume()
	if err := waitRuntime(t, done); !errors.Is(err, ErrAbandoned) || a.Usage() != before {
		t.Fatal("local cancellation fabricated peer acceptance or released original OPEN", err)
	}
}

func TestOpenWaitCloseIncludesOriginalObserverTail(t *testing.T) {
	for _, outcome := range []bool{false, true} {
		name := "dispatcher"
		if outcome {
			name = "outcome"
		}
		t.Run(name, func(t *testing.T) {
			server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
			a := server.admission
			var h OpenHandle
			wait := func(ctx context.Context) error { _, err := a.NextPending(ctx); return err }
			if outcome {
				client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
				_, h, _, _ = startTestOpen(t, client, server, 8)
				wait = func(ctx context.Context) error { return a.WaitOutcome(ctx, h) }
			}
			resume, done := pauseOpenWait(t, context.Background(), wait)
			a.Close()
			if outcome {
				if err := a.CarrierClosed(h); err != nil {
					t.Fatal(err)
				}
			}
			resumeCleanup, cleaned := pauseOpenWait(t, context.Background(), a.cleanupClosed)
			a.mu.Lock()
			retained := a.methodTails == 1 && !a.cleaned
			if outcome {
				s, err := a.slot(h)
				retained = retained && err == nil && s.retirementReferences == 1
			}
			a.mu.Unlock()
			if !retained || !errors.Is(a.Retire(), cryptov4.ErrCapacity) {
				t.Fatal("close or retirement released the still-running observer")
			}
			resume()
			if err := waitRuntime(t, done); !errors.Is(err, cryptov4.ErrClosed) {
				t.Fatal("close did not wake original observer", err)
			}
			resumeCleanup()
			if err := waitRuntime(t, cleaned); err != nil {
				t.Fatal(err)
			}
			if err := a.Retire(); err != nil || a.outcomeWake != nil {
				t.Fatal("cleanup retained completed observer backing", err)
			}
		})
	}
}

func TestOpenRuntimeCanonicalReceivePoolRejectsForeignPromise(t *testing.T) {
	e := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	canonical, err := testReceivePool(t, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	e.admission.receivePool = canonical
	before := e.admission.Usage()
	_, result, err := e.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, e.reservation(new(bytes.Buffer), 8), streamTestDeadline(t, e.engine))
	if !errors.Is(err, cryptov4.ErrConfiguration) || result.Submitted || e.admission.Usage() != before || e.pool.Outstanding() != 0 || canonical.Outstanding() != 0 {
		t.Fatal("foreign receive pool created a second Session promise owner", result, err)
	}
}

func TestOpenDecisionOpportunityNotifiesEachOriginalPendingOwner(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 3, 3, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 3, 3, 1)
	local, rejected := rejectTestOpen(t, client, server)
	_, first, _, _ := startTestOpen(t, client, server, 8)
	_, second, _, _ := startTestOpen(t, client, server, 8)
	a := server.admission
	for _, h := range []OpenHandle{first, second} {
		if _, err := a.Decide(context.Background(), h, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); !errors.Is(err, ErrOpenPending) {
			t.Fatal("exhausted rejection reserve did not retain pending OPEN", err)
		}
	}
	resumeFirst, firstDone := pauseOpenWait(t, context.Background(), func(ctx context.Context) error { return a.WaitDecisionOpportunity(ctx, first) })
	resumeSecond, secondDone := pauseOpenWait(t, context.Background(), func(ctx context.Context) error { return a.WaitDecisionOpportunity(ctx, second) })
	if err := a.WaitDecisionOpportunity(context.Background(), first); !errors.Is(err, ErrOpenWaitBusy) {
		t.Fatal("pending retry allocated a second observer", err)
	}
	if err := a.CarrierClosed(rejected); err != nil {
		t.Fatal(err)
	}
	if err := client.admission.CarrierClosed(local); err != nil {
		t.Fatal(err)
	}
	cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, server.maintenance)
	if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, client.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	client.control.Reset()
	if _, err := sr.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, client, cr, server.control.Bytes())
	server.control.Reset()
	resumeFirst()
	resumeSecond()
	if err := waitRuntime(t, firstDone); err != nil {
		t.Fatal("first original owner missed capacity recovery", err)
	}
	if err := waitRuntime(t, secondDone); err != nil {
		t.Fatal("second original owner lost notification to another waiter", err)
	}
	if got := a.Usage(); got.Pending != 2 || got.RejectionProofs != 0 {
		t.Fatal("notification itself selected an outcome or reserved capacity", got)
	}
}
