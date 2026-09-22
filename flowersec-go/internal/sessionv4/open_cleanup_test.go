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

func assertAdmissionCleanupPending(t *testing.T, a *OpenAdmission) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := a.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("live original owner reported cleanup complete", err)
	}
	if err := a.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("live original owner released admission", err)
	}
}

func startAdmissionCleanup(t *testing.T, a *OpenAdmission) <-chan error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- a.cleanupClosed(ctx) }()
	return done
}

func TestClosedAdmissionKeepsPendingCarrierWithoutInventingRetirement(t *testing.T) {
	client, server := newOpenEndpoint(t, 0, 1, 1, 1), newOpenEndpoint(t, 1, 1, 1, 1)
	_, h, _, _ := startTestOpen(t, client, server, 8)
	a := server.admission
	a.Close()
	done := startAdmissionCleanup(t, a)
	assertAdmissionCleanupPending(t, a)
	a.mu.Lock()
	s, err := a.slot(h)
	preserved := err == nil && s.phase == openPending && s.incoming != nil && !a.isStable(h.scope)
	a.mu.Unlock()
	if !preserved {
		t.Fatal("logical close fabricated an OPEN outcome")
	}
	if err := a.CarrierClosed(h); err != nil {
		t.Fatal(err)
	}
	if err := waitRuntime(t, done); err != nil {
		t.Fatal(err)
	}
	if a.Usage() != (OpenUsage{}) || a.isStable(h.scope) {
		t.Fatal("physical cleanup fabricated authenticated retirement")
	}
	if err := a.Retire(); err != nil {
		t.Fatal(err)
	}
}

func TestClosedAdmissionJoinsOriginalOpenPublication(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 1, 1, 1)
	w := &retirementTailWriter{messages: make(chan []byte, 1), finish: make(chan struct{})}
	release := sync.OnceFunc(func() { close(w.finish) })
	defer release()
	r := client.reservation(new(bytes.Buffer), 8)
	r.Writer = w
	publication := make(chan error, 1)
	go func() {
		_, _, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, r, streamTestDeadline(t, client.engine))
		publication <- err
	}()
	waitAdmissionProtocolPublication(t, w)
	a := client.admission
	a.Close()
	done := startAdmissionCleanup(t, a)
	assertAdmissionCleanupPending(t, a)
	a.mu.Lock()
	retained := a.methodTails != 0 && a.slots[a.find(1)].submitted
	a.mu.Unlock()
	if !retained {
		t.Fatal("OPEN provider tail lost its original owner")
	}
	release()
	_ = waitRuntime(t, publication)
	assertAdmissionCleanupPending(t, a)
	if err := a.CarrierClosed(OpenHandle{a, 1}); err != nil {
		t.Fatal(err)
	}
	if err := waitRuntime(t, done); err != nil {
		t.Fatal(err)
	}
	for _, b := range r.OpenStorage {
		if b != 0 {
			t.Fatal("cleanup preceded original OPEN snapshot clearing")
		}
	}
}

func TestClosedAdmissionJoinsReceiveCursorBeforeReleasingFlow(t *testing.T) {
	client, server := newOpenEndpoint(t, 0, 1, 1, 1), newOpenEndpoint(t, 1, 1, 1, 1)
	h, peer, _, _ := startTestOpen(t, client, server, 8)
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 8), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	f, err := client.admission.Flow(h)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := exactCursorTarget(8, 8)
	cursor, _ := testReaderCursor(t, f.receive, target, testAuthorization{})
	defer cursor.Close()
	a := client.admission
	a.Close()
	if err := a.CarrierClosed(h); err != nil {
		t.Fatal(err)
	}
	done := startAdmissionCleanup(t, a)
	assertAdmissionCleanupPending(t, a)
	f.receive.pool.mu.Lock()
	retained := f.receive.readPending && !f.receive.cleaned && f.receive.storage != nil
	f.receive.pool.mu.Unlock()
	if !retained {
		t.Fatal("closed Session forgot the cursor advancement claim")
	}
	cursor.Close()
	if err := waitRuntime(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestClosedAdmissionWaitsForFullStreamReleaseWithNoIOMethods(t *testing.T) {
	f, _, _, h, ref := ownedFixture(t, 8)
	o := ownFixtureStream(t, f, h, ref)
	a := f.local.admission
	a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.service.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.CarrierClosed(h); err != nil {
		t.Fatal(err)
	}
	done := startAdmissionCleanup(t, a)
	assertAdmissionCleanupPending(t, a)
	if err := o.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	assertAdmissionCleanupPending(t, a)
	if err := o.Release(); err != nil {
		t.Fatal(err)
	}
	if err := waitRuntime(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRuntimeCleanupIncludesUnresolvedNativeAssociation(t *testing.T) {
	local, peer := newOpenEndpoint(t, 0, 1, 1, 1), newOpenEndpoint(t, 1, 1, 1, 1)
	f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: bytes.NewReader(nil)}, true)
	runtime := f.startOwner(t)
	h, _, _, _ := startTestOpen(t, local, peer, 8)
	runtime.Close()
	assertAdmissionCleanupPending(t, local.admission)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := runtime.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("runtime lost original Stream provider ownership", err)
	}
	cancel()
	if err := local.admission.CarrierClosed(h); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}
