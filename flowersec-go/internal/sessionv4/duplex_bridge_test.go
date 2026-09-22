package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type bridgeFixture struct {
	*serviceFixture
	options           DuplexOptions
	bridge            *DuplexBridge
	h                 [2]OpenHandle
	queues            [2]*SendQueue
	peers             [2]*StreamFlow
	writers           [2]*serviceTestWriter
	reservation       resourcev4.Reference
	ownership, chunks [2]resourcev4.Reference
}

func newBridgeFixture(t *testing.T, capacity, timeout uint64) *bridgeFixture {
	t.Helper()
	f := &bridgeFixture{options: DuplexOptions{ChunkBytes: 4, TimeoutMS: timeout, CleanupTimeoutMS: 35, RuntimeBytes: 256 * 1024}}
	charge, _ := DuplexBridgeCharge(f.options)
	copyCharge, _ := CopyCharge(f.options.ChunkBytes)
	extra := []resourcev4.Vector{charge, StreamOwnershipCharge(), StreamOwnershipCharge(), copyCharge, copyCharge, {}, {}, {}, {}}
	f.serviceFixture = newServiceFixtureResources(t, 2, [3]uint32{2}, capacity, 2, testAuthorization{}, true, extra)
	f.reservation = f.reserve(t, charge)
	t.Cleanup(f.reservation.Release)
	for i := range 2 {
		f.writers[i] = &serviceTestWriter{frames: make(chan []byte, 16)}
		f.queues[i], f.peers[i] = f.open(t, BusinessStream, 64, f.writers[i])
		f.h[i] = OpenHandle{f.local.admission, f.flows[i].receive.scope}
		f.ownership[i], f.chunks[i] = f.reserve(t, StreamOwnershipCharge()), f.reserve(t, copyCharge)
		t.Cleanup(f.ownership[i].Release)
		t.Cleanup(f.chunks[i].Release)
	}
	f.options.HardDeadline = streamTestDeadline(t, f.local.engine)
	t.Cleanup(func() {
		f.local.admission.Close()
		if f.bridge != nil {
			select {
			case <-f.bridge.Done():
				_, _ = f.bridge.Wait(context.Background())
			case <-time.After(3 * time.Second):
				t.Error("bridge retained actual lifecycle worker")
			}
		}
	})
	return f
}

func (f *bridgeFixture) construct(t *testing.T, ctx context.Context) *DuplexBridge {
	t.Helper()
	var err error
	f.bridge, err = NewDuplexBridge(ctx, f.h[0], f.h[1], f.options, f.reservation, f.ownership, f.chunks)
	if err != nil {
		t.Fatal(err)
	}
	return f.bridge
}

func (f *bridgeFixture) input(t *testing.T, i int, payload string, fin bool) {
	t.Helper()
	if _, err := f.peers[i].send.Write(context.Background(), []byte(payload), fin); err != nil {
		t.Fatal(err)
	}
	r, err := f.local.receiver.Receive(context.Background(), nextServiceFrame(t, f.peers[i].send.writer.writer.(*serviceTestWriter)))
	if err != nil {
		t.Fatal(err)
	}
	err = f.flows[i].Apply(r)
	r.Release()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *bridgeFixture) receiveFIN(t *testing.T, i int) string {
	t.Helper()
	for {
		r, err := f.peer.receiver.Receive(context.Background(), nextServiceFrame(t, f.writers[i]))
		if err != nil {
			t.Fatal(err)
		}
		frame, _ := r.Body()
		fin, _ := frame.Field("fin").Bool()
		err = f.peers[i].Apply(r)
		r.Release()
		if err != nil {
			t.Fatal(err)
		}
		if fin {
			break
		}
	}
	var dst [64]byte
	n, terminal, err := f.peers[i].receive.TryRead(dst[:])
	if err != nil || terminal != protocolv4.V4ReadTerminalEof {
		t.Fatal(n, terminal, err)
	}
	return string(dst[:n])
}

func waitBridge(t *testing.T, d *DuplexBridge) (DuplexObservation, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := d.Wait(ctx)
	if !r.Final || r.Result == nil {
		t.Fatal("bridge did not publish stable result", r, err)
	}
	return r, err
}

func TestDuplexBridgeHalfCloseKeepsReversePumpAndRequiresBothDrained(t *testing.T) {
	f := newBridgeFixture(t, 8, 3000)
	f.options.CleanupTimeoutMS = 500
	f.run(t)
	d := f.construct(t, context.Background())
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if err := d.Start(); err != nil {
			t.Fatal(err)
		}
	}
	f.input(t, 0, "request", true)
	if got := f.receiveFIN(t, 1); got != "request" {
		t.Fatal(got)
	}
	p := d.Progress()
	if p.Final || p.Outcome != "" || p.AToB.SourceReadBytes != 7 || p.AToB.DestinationAcceptedBytes != 7 || p.BToA.SourceReadBytes != 0 {
		t.Fatal(p)
	}
	// A's EOF only closes B's send direction. B can still produce its response.
	f.input(t, 1, "reply", true)
	if got := f.receiveFIN(t, 0); got != "reply" {
		t.Fatal(got)
	}
	select {
	case <-d.ready:
		t.Fatal("FIN replaced authenticated drainage")
	default:
	}
	for i := range 2 {
		if _, err := f.peer.admission.PublishDrained(context.Background(), OpenHandle{f.peer.admission, f.h[i].scope}, f.peer.maintenance); err != nil {
			t.Fatal(err)
		}
		applyTerminalWire(t, f.local, f.peer.control.Bytes())
		f.peer.control.Reset()
		if i == 0 {
			select {
			case <-d.ready:
				t.Fatal("one Finish completed bridge")
			default:
			}
		}
		if _, err := f.local.admission.PublishDrained(context.Background(), f.h[i], f.local.maintenance); err != nil {
			t.Fatal(err)
		}
		applyTerminalWire(t, f.peer, f.local.control.Bytes())
		f.local.control.Reset()
	}
	r, err := waitBridge(t, d)
	if err != nil || r.Result.Outcome != protocolv4.V4DuplexOutcomeNormal || r.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(r, err)
	}
	for _, direction := range []protocolv4.V4DuplexDirectionResult{r.Result.AToB, r.Result.BToA} {
		if direction.SourceStatus != protocolv4.V4StreamStatusEof || direction.SendResult.SendDrained == nil || !*direction.SendResult.SendDrained || direction.SendResult.NativeSendFinished != nil {
			t.Fatal(direction)
		}
	}
	<-d.Done()
	r2, err := d.Wait(context.Background())
	if err != nil || r2.Result != r.Result || d.owners[0] != nil || d.owners[1] != nil || d.deadline != nil || d.operationContext != nil || d.reservation != (resourcev4.Reference{}) {
		t.Fatal("final result changed or retained transport graph", err)
	}
}

func TestDuplexBridgeCanceledWaitPreservesProgressAndBoundedObserver(t *testing.T) {
	f := newBridgeFixture(t, 2, 1000)
	d := f.construct(t, context.Background())
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		waitReadAdmitted(t, f.flows[i].receive)
	}
	before := f.root.Snapshot()
	ctx, cancel := context.WithCancel(context.Background())
	waited := make(chan DuplexObservation, 1)
	go func() { r, _ := d.Wait(ctx); waited <- r }()
	until := time.After(time.Second)
	for {
		d.mu.Lock()
		waiting := d.waiting
		d.mu.Unlock()
		if waiting {
			break
		}
		select {
		case <-until:
			t.Fatal("waiter was not admitted")
		default:
			runtime.Gosched()
		}
	}
	if r, err := d.Wait(context.Background()); !errors.Is(err, ErrStreamOwnershipBusy) || r.Result != nil || r.Final {
		t.Fatal(r, err)
	}
	cancel()
	if r := <-waited; r.Result != nil || r.Final || !r.Started || r.Outcome != "" {
		t.Fatal(r)
	}
	if f.root.Snapshot().References != before.References {
		t.Fatal("canceled observer retained budget")
	}
	f.input(t, 0, "abcdefgh", true)
	waitSendQueueWriters(t, f.queues[1], 1)
	p := d.Progress().AToB
	if p.SourceReadBytes != 4 || p.DestinationAcceptedBytes != 2 || p.PendingTailBytes != 2 || p.Complete {
		t.Fatal(p)
	}
	d.Abort()
	r, err := waitBridge(t, d)
	if !errors.Is(err, ErrDuplexAborted) || r.Result.Outcome != protocolv4.V4DuplexOutcomeAborted || r.Result.AToB.Progress.SourceReadBytes != 4 || r.Result.AToB.Progress.DestinationAcceptedBytes != 2 || string(r.Result.AToB.Progress.UnacceptedTail) != "cd" {
		t.Fatal(r.Result, err)
	}
	if r.CleanupStatus.Status != protocolv4.V4CleanupStateCleanupIncomplete {
		t.Fatal(r.CleanupStatus)
	}
	r.Result.AToB.Progress.UnacceptedTail[0] = 'X'
	r2, err := d.Wait(context.Background())
	if !errors.Is(err, ErrDuplexAborted) || r.Result != r2.Result || string(r2.Result.AToB.Progress.UnacceptedTail) != "Xd" {
		t.Fatal("Wait copied/rebuilt result owner", r2, err)
	}
}

func TestDuplexBridgeNeverStartedStillExpiresAndKeepsUndeliveredCharge(t *testing.T) {
	f := newBridgeFixture(t, 8, 25)
	d := f.construct(t, context.Background())
	select {
	case <-d.ready:
	case <-time.After(time.Second):
		t.Fatal("unstarted owner did not expire")
	}
	if err := d.Start(); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal(err)
	}
	if p := d.Progress(); p.Started || !p.Final || p.Outcome != protocolv4.V4DuplexOutcomeFailed || p.AToB.SourceReadBytes != 0 {
		t.Fatal(p)
	}
	f.local.admission.Close()
	<-d.Done()
	for _, state := range d.copies {
		if state.storage != nil || state.final.SourceTerminal == "" || state.reservation.Check() != nil {
			t.Fatal("unobserved final result lost charge or kept unused chunk")
		}
	}
	if d.reservation.Check() != nil {
		t.Fatal("unobserved result metadata lost charge")
	}
	r, err := waitBridge(t, d)
	if !errors.Is(err, timev4.ErrExpired) || r.AToB.SourceReadBytes != 0 || d.reservation != (resourcev4.Reference{}) {
		t.Fatal(r, err)
	}
}

func TestDuplexBridgeRejectsAliasAndBusyEndpointBeforeIO(t *testing.T) {
	for _, duplicate := range []bool{true, false} {
		f := newBridgeFixture(t, 8, 1000)
		b := f.h[1]
		var release func()
		if duplicate {
			b = f.h[0]
		} else {
			f.flows[1].receive.pool.mu.Lock()
			f.flows[1].receive.readPending = true
			f.flows[1].receive.pool.mu.Unlock()
			release = func() {
				f.flows[1].receive.pool.mu.Lock()
				f.flows[1].receive.readPending = false
				f.flows[1].receive.pool.mu.Unlock()
			}
		}
		_, err := NewDuplexBridge(context.Background(), f.h[0], b, f.options, f.reservation, f.ownership, f.chunks)
		if release != nil {
			release()
		}
		if duplicate && !errors.Is(err, cryptov4.ErrConfiguration) || !duplicate && !errors.Is(err, ErrStreamOwnershipBusy) {
			t.Fatal(err)
		}
		for i := range 2 {
			if _, err := f.queues[i].Write(context.Background(), []byte("usable")); err != nil {
				t.Fatal("construction failure fenced original stream", err)
			}
			if _, terminal, err := f.flows[i].receive.TryRead(make([]byte, 1)); err != nil || terminal != protocolv4.V4ReadTerminalOpen {
				t.Fatal(terminal, err)
			}
		}
	}
}

func TestDuplexBridgeOriginalFailureSurvivesOppositeAbort(t *testing.T) {
	f := newBridgeFixture(t, 2, 1000)
	d := f.construct(t, context.Background())
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	f.input(t, 0, "abcdefgh", true)
	waitSendQueueWriters(t, f.queues[1], 1)
	f.queues[1].Stop(cryptov4.ErrAuthentication)
	r, err := waitBridge(t, d)
	if !errors.Is(err, cryptov4.ErrAuthentication) || r.Result.Outcome != protocolv4.V4DuplexOutcomeFailed || r.Result.AToB.Progress.SourceReadBytes != 4 || string(r.Result.AToB.Progress.UnacceptedTail) != "cd" {
		t.Fatal(r.Result, err)
	}
}

func TestDuplexBridgeLateProviderRetainsBothCleanupFactsAndCharge(t *testing.T) {
	f := newBridgeFixture(t, 8, 1000)
	w := f.writers[1]
	w.entered, w.release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(w.release) }) })
	f.run(t)
	d := f.construct(t, context.Background())
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	f.input(t, 0, "data", true)
	<-w.entered
	d.Abort()
	r, err := waitBridge(t, d)
	if !errors.Is(err, ErrDuplexAborted) || r.Result.AToB.Progress.DestinationAcceptedBytes != 4 || r.CleanupStatus.Status != protocolv4.V4CleanupStateCleanupIncomplete {
		t.Fatal(r, err)
	}
	f.local.admission.Close()
	select {
	case <-d.workerDone[0]:
	case <-time.After(time.Second):
		t.Fatal("one late endpoint blocked independent cleanup")
	}
	select {
	case <-d.Done():
		t.Fatal("live provider refunded actual task")
	default:
	}
	if p := d.CleanupStatus(); p.CoreCleanup != protocolv4.V4CoreCleanupPending {
		t.Fatal(p)
	}
	before := f.root.Snapshot().Charged
	once.Do(func() { close(w.release) })
	select {
	case <-d.Done():
	case <-time.After(time.Second):
		t.Fatal("late provider did not release original owner")
	}
	if d.CleanupStatus().Status != protocolv4.V4CleanupStateComplete || f.root.Snapshot().Charged[resourcev4.Tasks] >= before[resourcev4.Tasks] {
		t.Fatal("actual exit failed to return worker charge")
	}
	r2, err := d.Wait(context.Background())
	if !errors.Is(err, ErrDuplexAborted) || r2.Result != r.Result || r.Result.CleanupStatus.Status != protocolv4.V4CleanupStateCleanupIncomplete || r2.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal("late cleanup changed fixed result", r2, err)
	}
}

func TestPersistentCopyEarlyFailureFreezesAndDropsUnusedBacking(t *testing.T) {
	_, _, root, ref, _ := copyFixture(t, 8, 4)
	state, err := prepareCopy(4, ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.runOwned(context.Background(), nil, nil); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal(err)
	}
	if p := state.progress(); !p.Complete || p.SourceReadBytes != 0 || state.final.SourceTerminal != protocolv4.V4ReadTerminalUnknown || state.storage != nil {
		t.Fatal(p)
	}
	if root.Snapshot().Reservations != 4 {
		t.Fatal("SDK return refunded unhanded result")
	}
	state.release()
	if root.Snapshot().Reservations != 3 || state.storage != nil {
		t.Fatal("failed persistent copy retained storage")
	}
}

func TestDuplexBridgeOperationContextAbortsBothDirections(t *testing.T) {
	for _, start := range []bool{false, true} {
		f := newBridgeFixture(t, 2, 1000)
		ctx, cancel := context.WithCancel(context.Background())
		d := f.construct(t, ctx)
		if start {
			if err := d.Start(); err != nil {
				t.Fatal(err)
			}
			for i := range 2 {
				waitReadAdmitted(t, f.flows[i].receive)
			}
			f.input(t, 0, "data", true)
			waitSendQueueWriters(t, f.queues[1], 1)
		}
		cancel()
		r, err := waitBridge(t, d)
		if !errors.Is(err, context.Canceled) || r.Result.Outcome != protocolv4.V4DuplexOutcomeAborted {
			t.Fatal(r, err)
		}
		if start && (r.Result.AToB.Progress.SourceReadBytes != 4 || r.Result.AToB.Progress.DestinationAcceptedBytes != 2 || string(r.Result.AToB.Progress.UnacceptedTail) != "ta") {
			t.Fatal(r.Result)
		}
	}
}

func TestDuplexBridgeAbortFencesOriginalGatesBeforeSupervisor(t *testing.T) {
	f := newBridgeFixture(t, 8, 1000)
	d := f.construct(t, context.Background())
	// Pin the supervisor's first Revoke gate, but leave both actual I/O gates
	// available. The short Abort transition must already revoke their lifetime.
	owner := d.owners[0]
	owner.mu.Lock()
	d.Abort()
	_, _, readErr := f.flows[0].receive.tryReadOwned(make([]byte, 1), owner)
	_, writeErr := f.queues[0].writeOwned(context.Background(), []byte("late"), nil, owner)
	owner.mu.Unlock()
	if !errors.Is(readErr, context.Canceled) || !errors.Is(writeErr, context.Canceled) {
		t.Fatal("Abort relied on delayed supervisor", readErr, writeErr)
	}
	if r, err := waitBridge(t, d); !errors.Is(err, ErrDuplexAborted) || r.Result.AToB.Progress.SourceReadBytes != 0 || owner.AcceptedBytes() != 0 {
		t.Fatal(r, err)
	}
}

func TestDuplexBridgeLiveProgressRemainsCoherentDuringAcceptance(t *testing.T) {
	f := newBridgeFixture(t, 2, 1000)
	d := f.construct(t, context.Background())
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	f.input(t, 0, "abcdefgh", true)
	waitSendQueueWriters(t, f.queues[1], 1)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var lastRead, lastTaken uint64
		for {
			p := d.Progress().AToB
			if p.SourceReadBytes < lastRead || p.DestinationAcceptedBytes < lastTaken || p.SourceReadBytes-p.DestinationAcceptedBytes != p.PendingTailBytes || p.PendingTailBytes > 4 {
				t.Error("torn or regressed progress", p)
				return
			}
			lastRead, lastTaken = p.SourceReadBytes, p.DestinationAcceptedBytes
			select {
			case <-stop:
				return
			default:
				runtime.Gosched()
			}
		}
	}()
	f.run(t)
	if got := f.receiveFIN(t, 1); got != "abcdefgh" {
		t.Fatal(got)
	}
	d.Abort()
	r, err := waitBridge(t, d)
	close(stop)
	<-done
	if !errors.Is(err, ErrDuplexAborted) || r.Result.AToB.Progress.SourceReadBytes != 8 || r.Result.AToB.Progress.DestinationAcceptedBytes != 8 || len(r.Result.AToB.Progress.UnacceptedTail) != 0 {
		t.Fatal(r, err)
	}
}

type opaqueBridgeContext struct {
	done       chan struct{}
	canceled   atomic.Bool
	valueCalls atomic.Int32
}

func (c *opaqueBridgeContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *opaqueBridgeContext) Done() <-chan struct{}       { return c.done }
func (c *opaqueBridgeContext) Err() error {
	if c.canceled.Load() {
		return context.Canceled
	}
	return nil
}
func (c *opaqueBridgeContext) Value(any) any { c.valueCalls.Add(1); return nil }

func TestDuplexBridgeCustomContextUsesExistingSupervisorOnly(t *testing.T) {
	f := newBridgeFixture(t, 8, 1000)
	ctx := &opaqueBridgeContext{done: make(chan struct{})}
	d := f.construct(t, ctx)
	if ctx.valueCalls.Load() != 0 {
		t.Fatal("constructor invoked parent context propagation")
	}
	owner := d.owners[0]
	owner.mu.Lock()
	ctx.canceled.Store(true)
	close(ctx.done)
	_, _, err := f.flows[0].receive.tryReadOwned(make([]byte, 1), owner)
	owner.mu.Unlock()
	if !errors.Is(err, context.Canceled) {
		t.Fatal("original custom context did not fence gate", err)
	}
	if r, err := waitBridge(t, d); !errors.Is(err, context.Canceled) || r.Result.Outcome != protocolv4.V4DuplexOutcomeAborted || ctx.valueCalls.Load() != 0 {
		t.Fatal(r, err)
	}
}

func TestDuplexBridgeNormalIncompleteKeepsOriginalCleanupLifetime(t *testing.T) {
	for _, ending := range []string{"publication", "abort", "deadline"} {
		t.Run(ending, func(t *testing.T) {
			f := newBridgeFixture(t, 8, 350)
			f.run(t)
			d := f.construct(t, context.Background())
			owner := d.owners[0]
			if err := d.Start(); err != nil {
				t.Fatal(err)
			}
			f.input(t, 0, "a", true)
			if f.receiveFIN(t, 1) != "a" {
				t.Fatal("request mismatch")
			}
			f.input(t, 1, "b", true)
			if f.receiveFIN(t, 0) != "b" {
				t.Fatal("response mismatch")
			}
			for i := range 2 {
				if _, err := f.peer.admission.PublishDrained(context.Background(), OpenHandle{f.peer.admission, f.h[i].scope}, f.peer.maintenance); err != nil {
					t.Fatal(err)
				}
				applyTerminalWire(t, f.local, f.peer.control.Bytes())
				f.peer.control.Reset()
			}
			// Both Finish calls can succeed while the original local terminal
			// publication return still owns a real cleanup responsibility.
			r, err := waitBridge(t, d)
			if !errors.Is(err, ErrDuplexCleanupIncomplete) || r.Result.Outcome != protocolv4.V4DuplexOutcomeNormal || r.CleanupStatus.Status != protocolv4.V4CleanupStateCleanupIncomplete {
				t.Fatal(r, err)
			}
			if ending == "publication" {
				for i := range 2 {
					if _, err := f.local.admission.PublishDrained(context.Background(), f.h[i], f.local.maintenance); err != nil {
						t.Fatal(err)
					}
					applyTerminalWire(t, f.peer, f.local.control.Bytes())
					f.local.control.Reset()
				}
			} else {
				if ending == "abort" {
					d.Abort()
				}
				select {
				case <-owner.revokeDone:
				case <-time.After(time.Second):
					t.Fatal("incomplete publication detached original cancellation/deadline")
				}
				f.local.admission.Close()
			}
			select {
			case <-d.Done():
			case <-time.After(time.Second):
				t.Fatal("late cleanup did not exit")
			}
			r2, err := d.Wait(context.Background())
			if !errors.Is(err, ErrDuplexCleanupIncomplete) || r2.Result != r.Result || r.Result.Outcome != protocolv4.V4DuplexOutcomeNormal || r.Result.CleanupStatus.Status != protocolv4.V4CleanupStateCleanupIncomplete || r2.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
				t.Fatal("late cleanup rewrote original result", r2, err)
			}
		})
	}
}

func TestDuplexBridgeConcurrentStartAndAbortCannotDuplicatePump(t *testing.T) {
	f := newBridgeFixture(t, 2, 1000)
	f.input(t, 0, "abcdefgh", true)
	d := f.construct(t, context.Background())
	var group sync.WaitGroup
	start := make(chan struct{})
	for i := range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if i%3 == 0 {
				d.Abort()
			} else {
				_ = d.Start()
			}
		}()
	}
	close(start)
	group.Wait()
	r, err := waitBridge(t, d)
	if !errors.Is(err, ErrDuplexAborted) || r.Result.Outcome != protocolv4.V4DuplexOutcomeAborted {
		t.Fatal(r, err)
	}
	p := r.Result.AToB.Progress
	if p.SourceReadBytes > 4 || p.DestinationAcceptedBytes > 2 || p.Validate(protocolv4.TransferContext{ChunkBytes: 4}) != nil {
		t.Fatal("competing Start created more than one pump", p)
	}
	for range 3 {
		if err := d.Start(); !errors.Is(err, ErrDuplexAborted) {
			t.Fatal(err)
		}
	}
}

func TestDuplexBridgePublicationRechecksCancellationAfterEndpointGate(t *testing.T) {
	f := newBridgeFixture(t, 8, 3000)
	f.options.CleanupTimeoutMS = 1000
	f.run(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := f.construct(t, ctx)
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	f.input(t, 0, "a", true)
	f.receiveFIN(t, 1)
	f.input(t, 1, "b", true)
	f.receiveFIN(t, 0)
	for i := range 2 {
		if _, err := f.peer.admission.PublishDrained(context.Background(), OpenHandle{f.peer.admission, f.h[i].scope}, f.peer.maintenance); err != nil {
			t.Fatal(err)
		}
		applyTerminalWire(t, f.local, f.peer.control.Bytes())
		f.peer.control.Reset()
	}
	until := time.After(time.Second)
	for d.Progress().Outcome != protocolv4.V4DuplexOutcomeNormal {
		select {
		case <-until:
			t.Fatal("both Finish calls did not complete")
		default:
			runtime.Gosched()
		}
	}
	// Exercise the actual publication gate while the supervisor cannot observe
	// parent cancellation. The exchange has real EOF/DRAINED facts above; only
	// the cleanup-expiry wake is supplied directly at this mechanics seam.
	d.mu.Lock()
	owner := d.owners[0]
	owner.mu.Lock()
	published := make(chan struct{})
	go func() {
		d.incomplete = true
		d.publishLocked([2]*cryptov4.Engine{f.local.engine, f.local.engine}, false)
		d.mu.Unlock()
		close(published)
	}()
	cancel()
	owner.mu.Unlock()
	<-published
	r, err := waitBridge(t, d)
	if !errors.Is(err, context.Canceled) || r.Result.Outcome != protocolv4.V4DuplexOutcomeAborted || r.Result.AToB.Progress.SourceReadBytes != 1 || r.Result.BToA.Progress.SourceReadBytes != 1 {
		t.Fatal("publication omitted original cancellation gate", r, err)
	}
}
