package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func ownedFixture(t *testing.T, capacity uint64) (*serviceFixture, *SendQueue, *StreamFlow, OpenHandle, resourcev4.Reference) {
	t.Helper()
	f := newServiceFixtureResources(t, 1, [3]uint32{1}, capacity, 2, testAuthorization{}, true, []resourcev4.Vector{StreamOwnershipCharge()})
	w := &serviceTestWriter{frames: make(chan []byte, 16)}
	q, peer := f.open(t, BusinessStream, 64, w)
	h := OpenHandle{f.local.admission, f.flows[0].receive.scope}
	ref := f.reserve(t, StreamOwnershipCharge())
	t.Cleanup(ref.Release)
	return f, q, peer, h, ref
}

func TestStreamOwnershipCleanupReturnWakesOriginalReleaseWaiter(t *testing.T) {
	f, _, _, h, ref := ownedFixture(t, 64)
	o := ownFixtureStream(t, f, h, ref)
	a := f.local.admission
	a.mu.Lock()
	released := false
	defer func() {
		if !released {
			a.mu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- o.Cleanup(context.Background()) }()
	until := time.Now().Add(3 * time.Second)
	for {
		o.mu.Lock()
		cleaning := o.cleaning
		o.mu.Unlock()
		if cleaning {
			break
		}
		if time.Now().After(until) {
			t.Fatal("cleanup did not enter original method")
		}
		runtime.Gosched()
	}
	if err := o.Release(); !errors.Is(err, ErrStreamOwnershipBusy) {
		t.Fatal("release overtook original cleanup", err)
	}
	select {
	case <-o.changed:
	default:
	}
	a.mu.Unlock()
	released = true
	if err := <-done; !errors.Is(err, ErrTerminal) {
		t.Fatal("cleanup invented a terminal result", err)
	}
	select {
	case <-o.changed:
	case <-time.After(time.Second):
		t.Fatal("completed cleanup stranded release observation")
	}
	if err := o.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamOwnershipCannotBlockTrustedNativeFailureCancellation(t *testing.T) {
	f := newNativeServiceFixtureResources(t, 2, 1, nil, nil, true)
	s, healthy := f.open(t), f.open(t)
	ref := f.resources.reserve(t, StreamOwnershipCharge())
	t.Cleanup(ref.Release)
	o, err := f.local.admission.OwnStream(s.h, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		o.Revoke()
		if err := o.Release(); err != nil {
			t.Error(err)
		}
	})
	f.start()
	if err := nativeResult(t, f.read(s, bytes.NewReader(nil))); err == nil {
		t.Fatal("truncated native input reported success")
	}
	if _, err := o.Write(context.Background(), []byte("late")); err == nil {
		t.Fatal("full capability suppressed native failure Reset")
	}
	f.local.admission.mu.Lock()
	slot, err := f.local.admission.slot(s.h)
	cancelled := err == nil && slot.cancelled
	f.local.admission.mu.Unlock()
	if !cancelled {
		t.Fatal("native failure did not reach original cancellation")
	}
	if _, err := healthy.flow.send.queueOwner.Write(context.Background(), []byte("healthy")); err != nil {
		t.Fatal("owned stream-local failure closed unrelated stream", err)
	}
}

func TestStreamOwnershipCancelAvailableWithAllIOMethodsBlocked(t *testing.T) {
	f, q, _, h, ref := ownedFixture(t, 1)
	o := ownFixtureStream(t, f, h, ref)
	if _, err := o.Write(context.Background(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 3)
	for range 2 {
		go func() { _, err := o.Write(ctx, []byte("blocked")); done <- err }()
	}
	go func() { _, err := o.ReadInto(ctx, make([]byte, 1)); done <- err }()
	waitSendQueueWriters(t, q, 2)
	waitReadAdmitted(t, f.flows[0].receive)
	if _, err := o.CloseResult(); err != nil {
		t.Fatal("I/O saturation denied finite lifecycle observation", err)
	}
	if err := o.Cancel(); err != nil {
		t.Fatal("I/O saturation denied original Reset", err)
	}
	for range 3 {
		if err := <-done; err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("Reset failed to end owned I/O", err)
		}
	}
	if o.AcceptedBytes() != 1 {
		t.Fatal("Reset erased accepted bytes")
	}
}

func TestStreamOwnershipCopyWakesOnOppositeEndpointRevocation(t *testing.T) {
	for _, scenario := range []string{"target_wait", "source_wait", "target_cancel", "target_seal"} {
		t.Run(scenario, func(t *testing.T) {
			waitingOnSource := scenario != "target_wait"
			charge, _ := CopyCharge(4)
			f := newServiceFixtureResources(t, 2, [3]uint32{1}, 2, 2, testAuthorization{}, true, []resourcev4.Vector{StreamOwnershipCharge(), StreamOwnershipCharge(), charge})
			_, peer := f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
			q, _ := f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
			var owners [2]*StreamOwnership
			for i := range owners {
				ref := f.reserve(t, StreamOwnershipCharge())
				t.Cleanup(ref.Release)
				owners[i] = ownFixtureStream(t, f, OpenHandle{f.local.admission, f.flows[i].receive.scope}, ref)
			}
			ref := f.reserve(t, charge)
			t.Cleanup(ref.Release)
			if !waitingOnSource {
				deliverOwnedInput(t, f, peer, "data", true)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			run := &copyRun{done: make(chan struct{})}
			go func() {
				run.result, run.err = owners[0].CopyTo(ctx, owners[1], 4, ref)
				close(run.done)
			}()
			if waitingOnSource {
				waitReadAdmitted(t, f.flows[0].receive)
				if scenario == "target_cancel" {
					if err := owners[1].Cancel(); err != nil {
						t.Fatal(err)
					}
				} else if scenario == "target_seal" {
					owners[1].sealApplication()
				} else {
					owners[1].Revoke()
				}
			} else {
				waitSendQueueWriters(t, q, 1)
				owners[0].Revoke()
			}
			<-run.done
			if scenario != "target_cancel" && !errors.Is(run.err, ErrStreamOwned) || scenario == "target_cancel" && !errors.Is(run.err, ErrAbandoned) {
				t.Fatal("Copy did not wake for opposite endpoint", run.err)
			}
			p := run.result.Progress
			if waitingOnSource {
				if p.SourceReadBytes != 0 || p.DestinationAcceptedBytes != 0 {
					t.Fatal(p)
				}
			} else if p.SourceReadBytes != 4 || p.DestinationAcceptedBytes != 2 || string(p.UnacceptedTail) != "ta" {
				t.Fatal(p)
			}
		})
	}
}

func TestStreamOwnershipCursorAdmissionFailureDoesNotRetainReadClaim(t *testing.T) {
	charge, _ := ReaderCursorCharge(8)
	f := newServiceFixtureResources(t, 1, [3]uint32{1}, 8, 2, testAuthorization{}, true, []resourcev4.Vector{StreamOwnershipCharge(), charge})
	f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
	o := ownFixtureStream(t, f, OpenHandle{f.local.admission, f.flows[0].receive.scope}, f.reserve(t, StreamOwnershipCharge()))
	ref := f.reserve(t, charge)
	t.Cleanup(ref.Release)
	if _, err := o.ExactReaderCursor(9, 8, ref, &protocolv4.DeliveryAuthorization{}); err == nil || ref.Check() != nil {
		t.Fatal("invalid target stole caller reservation", err)
	}
	before := f.root.Snapshot().Reservations
	if _, err := o.ExactReaderCursor(8, 8, ref, &protocolv4.DeliveryAuthorization{}); err == nil {
		t.Fatal("cursor accepted absent original delivery authorization")
	}
	if f.root.Snapshot().Reservations != before-1 {
		t.Fatal("failed authorization leaked transferred cursor budget")
	}
	if _, _, err := o.TryRead(make([]byte, 1)); err != nil {
		t.Fatal("failed constructor retained advancement claim", err)
	}
}

func TestStreamOwnershipCannotOvertakeCopyWaitingForSource(t *testing.T) {
	charge, _ := CopyCharge(4)
	f := newServiceFixtureResources(t, 2, [3]uint32{1}, 8, 2, testAuthorization{}, true, []resourcev4.Vector{StreamOwnershipCharge(), charge})
	f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
	q, _ := f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
	ref, copyRef := f.reserve(t, StreamOwnershipCharge()), f.reserve(t, charge)
	t.Cleanup(ref.Release)
	t.Cleanup(copyRef.Release)
	run := startCopy(t, q, f.flows[0].receive, 4, copyRef)
	waitReadAdmitted(t, f.flows[0].receive)
	h := OpenHandle{f.local.admission, f.flows[1].receive.scope}
	_, err := f.local.admission.OwnStream(h, ref)
	run.cancel()
	<-run.done
	if !errors.Is(err, ErrStreamOwnershipBusy) || ref.Check() != nil {
		t.Fatal("full owner overtook the original Copy destination", err)
	}
	_ = ownFixtureStream(t, f, h, ref)
}

func TestStreamOwnershipWriteAllKeepsLifetimeClaim(t *testing.T) {
	f, q, _, h, ref := ownedFixture(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := q.WriteAll(ctx, []byte("suffix")); done <- err }()
	waitSendQueueWriters(t, q, 1)
	// This end-to-end check proves that WriteAll wires its complete lifetime
	// to the original method budget, including the current blocked child.
	q.mu.Lock()
	if q.methodTails != 1 {
		t.Fatal("WriteAll has no lifetime claim")
	}
	q.mu.Unlock()
	if _, err := f.local.admission.OwnStream(h, ref); !errors.Is(err, ErrStreamOwnershipBusy) {
		t.Fatal(err)
	}
	cancel()
	<-done
	_ = ownFixtureStream(t, f, h, ref)
}

func TestStreamOwnershipHelperClaimBetweenChildWrites(t *testing.T) {
	f, q, _, h, ref := ownedFixture(t, 1)
	// Mechanics check of the exact gap between child writes, with no linked
	// FIFO request independently preventing acquisition of full ownership.
	if err := q.beginWriteMethod(nil); err != nil {
		t.Fatal(err)
	}
	if q.waiters != 0 || q.methodTails != 1 {
		t.Fatal("invalid method gap fixture")
	}
	_, err := f.local.admission.OwnStream(h, ref)
	q.endWriteMethod()
	if !errors.Is(err, ErrStreamOwnershipBusy) || ref.Check() != nil {
		t.Fatal("full handoff ignored existing helper responsibility", err)
	}
	_ = ownFixtureStream(t, f, h, ref)
}

func TestStreamOwnershipRevokeFreezesPreparedPartialAcceptance(t *testing.T) {
	f, q, _, h, ref := ownedFixture(t, 8)
	o := ownFixtureStream(t, f, h, ref)
	// With no remote credit the original service cannot free the full ring.
	q.flow.mu.Lock()
	q.flow.limit = 0
	q.flow.mu.Unlock()
	runWriteService(t, f)
	if n, err := o.Write(context.Background(), []byte("123456")); n != 6 || err != nil {
		t.Fatal(n, err)
	}
	op, err := o.PrepareWrite([]byte("ABCD"), WriteOptions{TimeoutMS: 3000, HardDeadline: streamTestDeadline(t, f.local.engine)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Cancel)
	if err := op.Start(); err != nil {
		t.Fatal(err)
	}
	waitWriteProgress(t, op, 2)
	o.Revoke()
	p := awaitWriteTerminal(t, op)
	if p.AcceptedBytes != 2 || o.AcceptedBytes() != 8 {
		t.Fatal(p, o.AcceptedBytes())
	}
	if err := op.Start(); err == nil || op.Progress().AcceptedBytes != 2 {
		t.Fatal("revoked request restarted", err)
	}
	for range 10 {
		runtime.Gosched()
	}
	if o.AcceptedBytes() != 8 || op.queue.Load() != nil {
		t.Fatal("late service changed stable acceptance or retained request")
	}
}

func TestStreamOwnershipRejectsForeignHandleAndBudgetBeforeClaim(t *testing.T) {
	f, _, _, h, ref := ownedFixture(t, 8)
	other, _, _, otherHandle, otherRef := ownedFixture(t, 8)
	if _, err := f.local.admission.OwnStream(otherHandle, ref); err == nil {
		t.Fatal("foreign admission handle acquired authority")
	}
	if _, err := f.local.admission.OwnStream(h, otherRef); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("private budget acquired authority", err)
	}
	if ref.Check() != nil || otherRef.Check() != nil {
		t.Fatal("failed admission consumed a reservation")
	}
	_ = ownFixtureStream(t, f, h, ref)
	_ = ownFixtureStream(t, other, otherHandle, otherRef)
}

func TestStreamOwnershipPreparedAcceptanceFinishAndStableRetirement(t *testing.T) {
	f, q, peer, h, ref := ownedFixture(t, 64)
	writer := q.flow.writer.writer.(*serviceTestWriter)
	o := ownFixtureStream(t, f, h, ref)
	runWriteService(t, f)
	op, err := o.PrepareWrite([]byte("owned request"), WriteOptions{TimeoutMS: 3000, HardDeadline: streamTestDeadline(t, f.local.engine)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Cancel)
	if o.AcceptedBytes() != 0 {
		t.Fatal("Prepare accepted bytes")
	}
	if err := op.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, err := op.Wait(ctx)
	if err != nil || p.AcceptedBytes != 13 || o.AcceptedBytes() != 13 {
		t.Fatal("prepared request lost its owner's exact acceptance", p, err, o.AcceptedBytes())
	}
	if err := op.Start(); err != nil || o.AcceptedBytes() != 13 {
		t.Fatal("repeated Start credited twice", err)
	}
	if err := o.CloseWrite(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		r, err := f.peer.receiver.Receive(ctx, nextServiceFrame(t, writer))
		if err != nil {
			t.Fatal(err)
		}
		frame, _ := r.Body()
		fin, _ := frame.Field("fin").Bool()
		err = peer.Apply(r)
		r.Release()
		if err != nil {
			t.Fatal(err)
		}
		if fin {
			break
		}
	}
	var data [32]byte
	if n, terminal, err := peer.receive.TryRead(data[:]); n != 13 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(data[:n]) != "owned request" {
		t.Fatal(n, terminal, err)
	}
	if _, err := f.peer.admission.PublishDrained(ctx, OpenHandle{f.peer.admission, h.scope}, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	r, err := f.local.receiver.Receive(ctx, f.peer.control.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	err = f.flows[0].Apply(r)
	r.Release()
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Finish(ctx); err != nil || !q.SendStatus().SendDrained || o.AcceptedBytes() != 13 {
		t.Fatal("ownership changed real completion facts", err)
	}
	deliverOwnedInput(t, f, peer, "reply", true)
	if result, err := o.ReadInto(ctx, data[:]); err != nil || result.ReadTerminal != protocolv4.V4ReadTerminalEof {
		t.Fatal(result, err)
	}
	if _, err := f.local.admission.PublishDrained(ctx, h, f.local.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.peer, f.local.control.Bytes())
	f.local.control.Reset()
	f.peer.control.Reset()
	if err := o.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.local.admission.CarrierClosed(h); err != nil {
		t.Fatal(err)
	}
	cr := testRetirement(t, f.local, f.local.maintenance)
	sr := testRetirement(t, f.peer, f.peer.maintenance)
	if _, err := cr.Start(ctx, 1, streamTestDeadline(t, f.local.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, f.peer, sr, f.local.control.Bytes())
	if _, err := sr.Acknowledge(ctx); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, f.local, cr, f.peer.control.Bytes())
	f.local.admission.Collect()
	f.local.admission.mu.Lock()
	slot, err := f.local.admission.slot(h)
	retained := err == nil && slot.owner == o && slot.retirementReferences == 1 && slot.coreCleaned && slot.carrierDone && f.local.admission.isStable(h.scope)
	f.local.admission.mu.Unlock()
	if !retained || f.local.admission.Usage().PositiveProofs != 1 {
		t.Fatal("authenticated retirement collected the live capability")
	}
	if err := o.Release(); err != nil {
		t.Fatal(err)
	}
	f.local.admission.Collect()
	if f.local.admission.Usage().PositiveProofs != 0 || o.AcceptedBytes() != 13 {
		t.Fatal("released capability retained retired Stream or erased result")
	}
	// Original retirement performed the full flow cleanup; the fixture must
	// not ask a permanently retired admission handle to clean that flow again.
	f.flows = nil
}

func TestStreamOwnershipCopyUsesBothClaimsAndRetainsExactTail(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "eof", true: "revoked"}[revoke], func(t *testing.T) {
			charge, _ := CopyCharge(4)
			capacity := uint64(16)
			if revoke {
				capacity = 2
			}
			f := newServiceFixtureResources(t, 2, [3]uint32{1}, capacity, 2, testAuthorization{}, true, []resourcev4.Vector{StreamOwnershipCharge(), StreamOwnershipCharge(), charge})
			_, peer := f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
			q, _ := f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
			var owners [2]*StreamOwnership
			for i := range owners {
				ref := f.reserve(t, StreamOwnershipCharge())
				t.Cleanup(ref.Release)
				owners[i] = ownFixtureStream(t, f, OpenHandle{f.local.admission, f.flows[i].receive.scope}, ref)
			}
			ref := f.reserve(t, charge)
			t.Cleanup(ref.Release)
			deliverOwnedInput(t, f, peer, "abcdefgh", true)
			if _, err := Copy(context.Background(), q, f.flows[0].receive, 4, ref); !errors.Is(err, ErrStreamOwned) {
				t.Fatal("ordinary Copy crossed full claims", err)
			}
			if _, err := owners[0].CopyTo(context.Background(), owners[0], 4, ref); !errors.Is(err, cryptov4.ErrConfiguration) || ref.Check() != nil {
				t.Fatal("same canonical endpoint consumed resources", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			run := &copyRun{done: make(chan struct{})}
			go func() {
				run.result, run.err = owners[0].CopyTo(ctx, owners[1], 4, ref)
				close(run.done)
			}()
			if revoke {
				waitSendQueueWriters(t, q, 1)
				if err := owners[0].Release(); !errors.Is(err, ErrStreamOwnershipBusy) {
					t.Fatal("released actual Copy source", err)
				}
				owners[1].Revoke()
			}
			<-run.done
			p := run.result.Progress
			if revoke {
				if !errors.Is(run.err, ErrStreamOwned) || p.SourceReadBytes != 4 || p.DestinationAcceptedBytes != 2 || string(p.UnacceptedTail) != "cd" || owners[1].AcceptedBytes() != 2 {
					t.Fatal(p, run.err, owners[1].AcceptedBytes())
				}
			} else if run.err != nil || p.SourceReadBytes != 8 || p.DestinationAcceptedBytes != 8 || len(p.UnacceptedTail) != 0 || owners[1].AcceptedBytes() != 8 || run.result.SourceTerminal != protocolv4.V4ReadTerminalEof {
				t.Fatal(p, run.err, owners[1].AcceptedBytes())
			}
			if owners[0].AcceptedBytes() != 0 {
				t.Fatal("source borrowed target acceptance")
			}
		})
	}
}

func ownFixtureStream(t *testing.T, f *serviceFixture, h OpenHandle, ref resourcev4.Reference) *StreamOwnership {
	t.Helper()
	o, err := f.local.admission.OwnStream(h, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		o.Revoke()
		if err := o.Release(); err != nil {
			t.Error(err)
		}
	})
	return o
}

func deliverOwnedInput(t *testing.T, f *serviceFixture, peer *StreamFlow, payload string, fin bool) {
	t.Helper()
	if _, err := peer.send.Write(context.Background(), []byte(payload), fin); err != nil {
		t.Fatal(err)
	}
	r, err := f.local.receiver.Receive(context.Background(), nextServiceFrame(t, peer.send.writer.writer.(*serviceTestWriter)))
	if err != nil {
		t.Fatal(err)
	}
	err = f.flows[0].Apply(r)
	r.Release()
	if err != nil {
		t.Fatal(err)
	}
}

func TestStreamOwnershipFencesUnownedEntrypointsAndDetaches(t *testing.T) {
	f, q, peer, h, ref := ownedFixture(t, 64)
	if n, err := q.Write(context.Background(), []byte("old")); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	o := ownFixtureStream(t, f, h, ref)
	source := f.flows[0].receive
	if _, err := f.local.admission.OwnStream(h, ref); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("duplicate full owner", err)
	}
	for _, call := range []func() error{
		func() error { _, e := q.Write(context.Background(), []byte("x")); return e },
		func() error { _, e := q.WriteAll(context.Background(), []byte("x")); return e },
		q.Seal,
		func() error { return q.CloseWrite(context.Background()) },
		func() error { return q.Finish(context.Background()) },
		func() error { return f.local.admission.Cancel(h) },
		func() error { return f.local.admission.CleanupStream(context.Background(), h) },
	} {
		if err := call(); !errors.Is(err, ErrStreamOwned) {
			t.Fatal("unowned mutation crossed full claim", err)
		}
	}
	if _, _, err := source.TryRead(make([]byte, 4)); !errors.Is(err, ErrReadInProgress) {
		t.Fatal(err)
	}
	if _, err := source.ReadInto(context.Background(), make([]byte, 4)); !errors.Is(err, ErrReadInProgress) {
		t.Fatal(err)
	}
	if _, err := NewExactReaderCursor(source, 4, 4, resourcev4.Reference{}, &protocolv4.DeliveryAuthorization{}); !errors.Is(err, ErrReadInProgress) {
		t.Fatal("cursor bypassed claim", err)
	}
	if n, err := o.Write(context.Background(), []byte("new")); n != 3 || err != nil || o.AcceptedBytes() != 3 {
		t.Fatal("owner borrowed earlier acceptance", n, err, o.AcceptedBytes())
	}
	deliverOwnedInput(t, f, peer, "reply", true)
	var response [8]byte
	r, err := o.ReadInto(context.Background(), response[:])
	if err != nil || r.Progress.Filled != 5 || r.ReadTerminal != protocolv4.V4ReadTerminalEof || string(response[:5]) != "reply" {
		t.Fatal(r, err)
	}
	if err := o.Release(); err != nil {
		t.Fatal(err)
	}
	if o.admission != nil || o.flow != nil || o.queue != nil || o.handle != (OpenHandle{}) || o.reservation != (resourcev4.Reference{}) || o.AcceptedBytes() != 3 {
		t.Fatal("released capability retained transport graph or erased progress")
	}
	if _, err := o.Write(context.Background(), []byte("late")); !errors.Is(err, ErrStreamOwned) {
		t.Fatal(err)
	}
	if _, err := q.Write(context.Background(), []byte("next")); err != nil {
		t.Fatal("release reset or sealed original queue", err)
	}
}

func TestStreamOwnershipRejectsExistingReadAndPreparedWrite(t *testing.T) {
	f, q, _, h, ref := ownedFixture(t, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _, _ = f.flows[0].receive.ReadInto(ctx, make([]byte, 1)) }()
	waitReadAdmitted(t, f.flows[0].receive)
	_, err := f.local.admission.OwnStream(h, ref)
	cancel()
	<-done
	if !errors.Is(err, ErrStreamOwnershipBusy) || ref.Check() != nil {
		t.Fatal("claim stole existing read or reservation", err)
	}
	f.run(t)
	end := time.Now().Add(time.Second)
	for !f.service.running.Load() && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	op, err := q.PrepareWrite([]byte("prepared"), WriteOptions{TimeoutMS: 30000, HardDeadline: streamTestDeadline(t, f.local.engine)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.admission.OwnStream(h, ref); !errors.Is(err, ErrStreamOwnershipBusy) || ref.Check() != nil {
		t.Fatal("claim stole never-started writer", err)
	}
	op.Cancel()
	o := ownFixtureStream(t, f, h, ref)
	if _, err := q.PrepareWrite([]byte("outside"), WriteOptions{TimeoutMS: 30000, HardDeadline: streamTestDeadline(t, f.local.engine)}); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("ordinary PrepareWrite bypassed owner", err)
	}
	owned, err := o.PrepareWrite([]byte("inside"), WriteOptions{TimeoutMS: 30000, HardDeadline: streamTestDeadline(t, f.local.engine)})
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Release(); !errors.Is(err, ErrStreamOwnershipBusy) {
		t.Fatal("prepared ownership refunded", err)
	}
	o.Revoke()
	if err := owned.Start(); err == nil {
		t.Fatal("revoked prepared operation started")
	}
	if err := o.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamOwnershipRevocationPreservesPartialWritesAndActualTails(t *testing.T) {
	f, q, _, h, ref := ownedFixture(t, 2)
	o := ownFixtureStream(t, f, h, ref)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	writes := make(chan queuedWriteResult, 1)
	reads := make(chan error, 1)
	go func() { n, err := o.WriteAll(ctx, []byte("data")); writes <- queuedWriteResult{n, err} }()
	go func() { _, err := o.ReadInto(ctx, make([]byte, 4)); reads <- err }()
	waitSendQueueWriters(t, q, 1)
	waitReadAdmitted(t, f.flows[0].receive)
	before := f.root.Snapshot().Charged
	if err := o.Release(); !errors.Is(err, ErrStreamOwnershipBusy) {
		t.Fatal("released actual methods", err)
	}
	o.Revoke()
	written, readErr := <-writes, <-reads
	if written.n != 2 || !errors.Is(written.err, ErrStreamOwned) || !errors.Is(readErr, ErrStreamOwned) || o.AcceptedBytes() != 2 || f.root.Snapshot().Charged != before {
		t.Fatal("revocation erased progress or refunded tails", written, readErr, o.AcceptedBytes())
	}
	if err := o.Cancel(); err != nil {
		t.Fatal("revoked owner lost its cleanup authority", err)
	}
	if err := o.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamOwnershipPinsAliasesBeforeTheOriginalIOGate(t *testing.T) {
	f, _, _, h, ref := ownedFixture(t, 8)
	o := ownFixtureStream(t, f, h, ref)
	if _, _, _, _, err := o.begin(); err != nil {
		t.Fatal(err)
	}
	o.Revoke()
	if err := o.Release(); !errors.Is(err, ErrStreamOwnershipBusy) {
		t.Fatal("pre-gate method tail lost its graph", err)
	}
	o.end()
	if err := o.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamOwnershipRevokesOriginalCursorWait(t *testing.T) {
	f, _, peer, h, ref := ownedFixture(t, 8)
	o := ownFixtureStream(t, f, h, ref)
	deliverOwnedInput(t, f, peer, "ab", false)
	target, _ := exactCursorTarget(4, 4)
	c, _ := testReaderCursor(t, f.flows[0].receive, target, testAuthorization{})
	c.owner = o // Only the mechanics fixture substitutes its synthetic guard.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.ReadExactly(ctx); done <- err }()
	waitCursorFilled(t, c, 2)
	if err := o.Release(); !errors.Is(err, ErrStreamOwnershipBusy) {
		t.Fatal("active cursor released full ownership", err)
	}
	o.Revoke()
	if err := <-done; !errors.Is(err, ErrStreamOwned) {
		t.Fatal("cursor missed revocation wake", err)
	}
	if c.owner != nil || c.flow != nil || c.Progress().TransferredBytes != 2 {
		t.Fatal("cursor retained owner graph or reset consumed prefix")
	}
	if err := o.Release(); err != nil {
		t.Fatal(err)
	}
}
