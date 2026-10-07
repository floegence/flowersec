package rpcv4

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type managementTestSink struct {
	mu         sync.Mutex
	wire       [][]byte
	fail       error
	beforeGate func()
}

func (s *managementTestSink) TryAcceptManagement(ctx context.Context, wire []byte, gate ManagementPublicationGate) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.fail != nil {
		return 0, s.fail
	}
	transfer := func() error {
		s.wire = append(s.wire, append([]byte(nil), wire...))
		return nil
	}
	if gate != nil {
		if s.beforeGate != nil {
			s.beforeGate()
		}
		if err := gate(transfer); err != nil {
			return 0, err
		}
	} else {
		_ = transfer()
	}
	return uint64(len(s.wire)), nil
}
func managementWireTarget() ExecutionTarget {
	return ExecutionTarget{Service: ExecutionService{"tenant", "audience", "service"}, Caller: ExecutionPrincipal{Authority: [32]byte{9}, Subject: "caller"}, Operation: [32]byte{1}, RequestDigest: [32]byte{2}, ContractDigest: [32]byte{3}}
}
func newManagementWireFixture(t *testing.T) (*ExecutionManagementWire, *managementTestSink, ExecutionAccess) {
	t.Helper()
	wire, sink, access, _ := newManagementWireFixtureClock(t, executionClock(t))
	return wire, sink, access
}
func newManagementWireFixtureClock(t *testing.T, clock *timev4.Clock) (*ExecutionManagementWire, *managementTestSink, ExecutionAccess, *resourcev4.Root) {
	t.Helper()
	root := executionRoot(t)
	sink := &managementTestSink{}
	c := ExecutionManagementWireConfig{Clock: clock, Sink: sink, RuntimeBytes: 4096}
	charge, err := ExecutionManagementWireCharge(c.RuntimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{31}, Backing: [16]byte{32}, Kind: 12}
	ref, err := root.Reserve(owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := NewExecutionManagementWire(c, ref)
	if err != nil {
		t.Fatal(err)
	}
	owner.Instance = [16]byte{33}
	owner.Backing = [16]byte{34}
	authority, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		wire.Close()
		authority.Release()
		ref.Release()
		if !wire.CleanupComplete() {
			t.Error("management channel retained actual work")
		}
		if root.Snapshot().Reservations != 0 {
			t.Error("management leaked reservation", root.Snapshot())
		}
	})
	return wire, sink, managementAccess{ref: authority}, root
}
func managementTestResponse(t *testing.T, w *ExecutionManagementWire, serial uint64, cancel bool, result protocolv4.ManagementResult) []byte {
	t.Helper()
	var buffer [managementEnvelopeBytes]byte
	n, err := w.bodies.EncodeResult(buffer[514:], result, cancel)
	if err != nil {
		t.Fatal(err)
	}
	n, _, err = w.encodeEnvelope(buffer[:], cancel, true, serial, 0, buffer[514:514+n])
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer[:n]...)
}

// v4.go_management.serial_lifetime
func TestExecutionManagementPublicationGateAndLateResponses(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	ctx := context.Background()
	target := managementWireTarget()
	sink.fail = ErrCapacity
	if serial, err := w.TryRequest(ctx, false, target, 1000, access); serial != 0 || !errors.Is(err, ErrCapacity) {
		t.Fatal(serial, err)
	}
	if w.highwater != 0 || len(sink.wire) != 0 {
		t.Fatal("failed publication consumed a serial")
	}
	sink.fail = nil
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if serial, err := w.TryRequest(canceled, false, target, 1000, access); serial != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(serial, err)
	}
	for i := uint64(1); i <= 2; i++ {
		serial, err := w.TryRequest(ctx, i == 2, target, 1000, access)
		if err != nil || serial != i {
			t.Fatal(serial, err)
		}
	}
	if _, err := w.TryRequest(ctx, false, target, 1000, access); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if err := w.Abandon(1); err != nil {
		t.Fatal(err)
	}
	if _, err := w.TryRequest(ctx, false, target, 1000, access); !errors.Is(err, ErrCapacity) {
		t.Fatal("abandon refunded incomplete response", err)
	}
	second := managementTestResponse(t, w, 2, true, protocolv4.ManagementResult{Status: "ok", CancelKind: "requested", Observation: protocolv4.ManagementObservation{Found: true, State: 2, Dispatched: true, WorkActive: true, CancelRequested: true}})
	response, serial, disposition, err := w.AcceptResponse(second)
	if err != nil || serial != 2 || disposition != ManagementResponseDelivered || !response.Observation.CancelRequested || !response.Cancel.Observation.CancelRequested {
		t.Fatal(response, serial, disposition, err)
	}
	first := managementTestResponse(t, w, 1, false, protocolv4.ManagementResult{Status: "unavailable"})
	if _, _, disposition, err = w.AcceptResponse(first); err != nil || disposition != ManagementResponseDiscarded {
		t.Fatal(disposition, err)
	}
	if _, _, disposition, err = w.AcceptResponse(second); err != nil || disposition != ManagementResponseDiscarded {
		t.Fatal("completed duplicate", disposition, err)
	}
	future := managementTestResponse(t, w, 3, false, protocolv4.ManagementResult{Status: "unavailable"})
	if _, _, _, err = w.AcceptResponse(future); !errors.Is(err, ErrManagementSerial) {
		t.Fatal("unsubmitted response", err)
	}
	if serial, err = w.TryRequest(ctx, false, target, 1000, access); err != nil || serial != 3 {
		t.Fatal(serial, err)
	}
}

func TestExecutionManagementResponseValidationPreservesOwner(t *testing.T) {
	w, _, access := newManagementWireFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	response := managementTestResponse(t, w, 1, false, protocolv4.ManagementResult{Status: "not_found", Observation: protocolv4.ManagementObservation{Reason: "not_registered"}})
	malformed := append([]byte(nil), response...)
	malformed[len(malformed)-1] = 255
	if _, _, _, err := w.AcceptResponse(malformed); err == nil {
		t.Fatal("accepted malformed result")
	}
	if w.pending[0].serial != 1 {
		t.Fatal("malformed result released owner")
	}
	mismatch := managementTestResponse(t, w, 1, true, protocolv4.ManagementResult{Status: "unavailable"})
	if _, _, _, err := w.AcceptResponse(mismatch); !errors.Is(err, ErrManagementBinding) {
		t.Fatal(err)
	}
	if w.pending[0].serial != 1 {
		t.Fatal("wrong method released owner")
	}
	if _, _, _, err := w.AcceptResponse(response); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionManagementResolverFailureDoesNotDesynchronize(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	resolver := ExecutionManagementResolverFunc(func(context.Context, ExecutionTarget, bool) (*VolatileExecutions, ExecutionAccess, error) {
		return nil, nil, ErrOwner
	})
	for serial := uint64(1); serial <= 4; serial++ {
		_, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access)
		if err != nil {
			t.Fatal(err)
		}
		request := sink.wire[len(sink.wire)-1]
		reply, err := w.HandleRequest(context.Background(), resolver, request)
		if err != nil {
			t.Fatal(serial, err)
		}
		if err = reply.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
		response := sink.wire[len(sink.wire)-1]
		result, got, _, err := w.AcceptResponse(response)
		if err != nil || got != serial || result.Status != "unavailable" {
			t.Fatal(result, got, err)
		}
	}
}

func TestExecutionManagementCloseWaitsForAdmittedResolver(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	entered, exit, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = w.HandleRequest(context.Background(), ExecutionManagementResolverFunc(func(context.Context, ExecutionTarget, bool) (*VolatileExecutions, ExecutionAccess, error) {
			close(entered)
			<-exit
			return nil, nil, ErrOwner
		}), sink.wire[0])
	}()
	<-entered
	w.Close()
	if w.CleanupComplete() {
		t.Error("refunded a running resolver")
	}
	close(exit)
	<-done
	if !w.CleanupComplete() {
		t.Fatal("resolver exit did not complete cleanup")
	}
}

func TestExecutionManagementReaderAdmissionPrecedesWorkerOrder(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	for i := 0; i < 2; i++ {
		if _, err := w.TryRequest(context.Background(), i == 1, managementWireTarget(), 1000, access); err != nil {
			t.Fatal(err)
		}
	}
	var jobs [2]ManagementJob
	for i := range jobs {
		var err error
		jobs[i], err = w.BeginRequest(sink.wire[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, i := range []int{1, 0} {
		reply, err := jobs[i].Run(context.Background(), ExecutionManagementResolverFunc(nil))
		if err != nil {
			t.Fatal("scheduler changed inbound ordering", err)
		}
		if _, err = jobs[i].Run(context.Background(), ExecutionManagementResolverFunc(nil)); !errors.Is(err, ErrOwner) {
			t.Fatal("job ran twice", err)
		}
		if err = reply.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
		response, serial, _, err := w.AcceptResponse(sink.wire[len(sink.wire)-1])
		if err != nil || serial != uint64(i+1) || response.Status != "unavailable" {
			t.Fatal(response, serial, err)
		}
	}
}

func TestExecutionManagementPartialHeaderKeepsExactOriginalAdmission(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	header, _, _, err := w.decodeEnvelope(sink.wire[0])
	if err != nil {
		t.Fatal(err)
	}
	job, err := w.BeginRequestHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	original := w.replies[job.index].deadline
	if original == nil || original.Cap() != 1000 || w.replies[job.index].running {
		t.Fatal("header lost bounded original owner")
	}
	if err = job.Admit(sink.wire[0]); err != nil {
		t.Fatal(err)
	}
	if w.replies[job.index].deadline != original {
		t.Fatal("body refreshed deadline")
	}
	if err = job.Admit(sink.wire[0]); !errors.Is(err, ErrOwner) {
		t.Fatal("admitted body twice", err)
	}
	w.Close()
	if !w.CleanupComplete() {
		t.Fatal("unstarted job retained after close")
	}
}

// The same original clock governs worker completion, scheduler retry and the
// sending ring gate. Advancing this admitted source needs no wall-clock sleep.
func newManagementExpiryFixture(t *testing.T) (*ExecutionManagementWire, *managementTestSink, ExecutionAccess, *atomic.Uint64, ExecutionManagementResolver) {
	t.Helper()
	tick := &atomic.Uint64{}
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 10000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: tick.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.InstallTrusted(mark, timev4.Interval{LowerMS: 25, UpperMS: 25}); err != nil {
		t.Fatal(err)
	}
	w, sink, access, root := newManagementWireFixtureClock(t, clock)
	target := managementWireTarget()
	cfg := VolatileExecutionConfig{Root: root, Owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{35}, Backing: [16]byte{36}, Kind: 7}, Clock: clock, Service: target.Service, CallerAuthorities: [][32]byte{target.Caller.Authority}, Records: 1, Active: 1, TaskCharge: resourcev4.Vector{resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, RuntimeBytes: 4096, WorkRuntimeBytes: 4096, ResultRuntimeBytes: 4096}
	charge, err := VolatileExecutionsCharge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := root.Reserve(cfg.Owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	history, err := NewVolatileExecutions(cfg, ref)
	if err != nil {
		ref.Release()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		history.Close()
		ref.Release()
		if !history.CleanupComplete() {
			t.Error("management history retained actual work")
		}
	})
	resolver := ExecutionManagementResolverFunc(func(context.Context, ExecutionTarget, bool) (*VolatileExecutions, ExecutionAccess, error) {
		return history, access, nil
	})
	return w, sink, access, tick, resolver
}

func assertManagementUnavailableEnvelope(t *testing.T, w *ExecutionManagementWire, sink *managementTestSink, serial uint64) {
	t.Helper()
	if len(sink.wire) != 2 {
		t.Fatal("finite reply did not transfer exactly once", len(sink.wire))
	}
	header, body, cancel, err := w.decodeEnvelope(sink.wire[1])
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.bodies.DecodeResult(body, cancel)
	if err != nil || !header.IsResponse() || header.Fields().ControlSerial != serial || result.Status != "unavailable" {
		t.Fatal("finite reply lost original serial or result", header.Fields(), result, err)
	}
	if w.closed {
		t.Fatal("request expiry closed the management generation")
	}
}

func TestExecutionManagementCompletedExpiryRemainsSchedulerReadable(t *testing.T) {
	w, sink, access, tick, _ := newManagementExpiryFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	job, err := w.BeginRequest(sink.wire[0])
	if err != nil {
		t.Fatal(err)
	}
	reply, err := job.Run(context.Background(), ExecutionManagementResolverFunc(func(context.Context, ExecutionTarget, bool) (*VolatileExecutions, ExecutionAccess, error) {
		// Even a business failure completing at the original cap must converge
		// before the scheduler observes the completed worker.
		tick.Store(975)
		return nil, nil, ErrOwner
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := job.RemainingMS(); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("completed finite reply was not readable by scheduler", err)
	}
	finite, err := job.Unavailable()
	if err != nil || finite != reply || w.replies[job.index].deadline == nil || w.replies[job.index].access != nil {
		t.Fatal("scheduler replaced completed reply ownership", finite, err)
	}
	if err := finite.Publish(context.Background()); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("expired original reply acquired publication authority", err)
	}
	if len(sink.wire) != 1 || w.replies[job.index].serial != job.serial {
		t.Fatal("expiry lost the original reply or submitted new bytes")
	}
}

func TestExecutionManagementSelectedReplyBackpressureExpiry(t *testing.T) {
	w, sink, access, tick, resolver := newManagementExpiryFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	job, err := w.BeginRequest(sink.wire[0])
	if err != nil {
		t.Fatal(err)
	}
	reply, err := job.Run(context.Background(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	original := w.replies[job.index].deadline
	if original == nil || w.replies[job.index].access == nil || w.replies[job.index].timedOut {
		t.Fatal("ordinary result was not available before expiry")
	}
	sink.fail = ErrCapacity
	if err := reply.Publish(context.Background()); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if w.replies[job.index].serial != job.serial || w.replies[job.index].deadline != original || w.replies[job.index].publishing || len(sink.wire) != 1 {
		t.Fatal("backpressure consumed or replaced selected reply")
	}
	tick.Store(975)
	if _, err := job.RemainingMS(); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("selected reply stopped observing original cap", err)
	}
	finite, err := job.Unavailable()
	if err != nil || finite != reply {
		t.Fatal("scheduler changed selected owner", finite, err)
	}
	sink.fail = nil
	if err := finite.Publish(context.Background()); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("expired original reply acquired publication authority", err)
	}
	if len(sink.wire) != 1 || w.replies[job.index].serial != job.serial {
		t.Fatal("expiry lost the original reply or submitted new bytes")
	}
}

func TestExecutionManagementPublishGateCrossingExpiryRetainsReply(t *testing.T) {
	w, sink, access, tick, resolver := newManagementExpiryFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	job, err := w.BeginRequest(sink.wire[0])
	if err != nil {
		t.Fatal(err)
	}
	reply, err := job.Run(context.Background(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := job.RemainingMS(); err != nil {
		t.Fatal("reply expired before selection", err)
	}
	gates := 0
	sink.beforeGate = func() {
		gates++
		tick.Store(975)
	}
	if err := reply.Publish(context.Background()); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("final gate failed to preserve original deadline", err)
	}
	if gates != 1 {
		t.Fatal("finite failure retried the expired success gate", gates)
	}
	if len(sink.wire) != 1 || w.replies[job.index].serial != job.serial {
		t.Fatal("expired gate published bytes or lost original ownership")
	}
	if err := reply.Publish(context.Background()); !errors.Is(err, timev4.ErrExpired) || len(sink.wire) != 1 {
		t.Fatal("expired reply renewed publication authority", err, len(sink.wire))
	}
}

func TestExecutionManagementExpiryPublicationRetainsRunningProvider(t *testing.T) {
	w, sink, access, tick, _ := newManagementExpiryFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	job, err := w.BeginRequest(sink.wire[0])
	if err != nil {
		t.Fatal(err)
	}
	entered, exit, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer func() {
		release.Do(func() { close(exit) })
		<-done
	}()
	var workerErr error
	go func() {
		defer close(done)
		_, workerErr = job.Run(context.Background(), ExecutionManagementResolverFunc(func(context.Context, ExecutionTarget, bool) (*VolatileExecutions, ExecutionAccess, error) {
			close(entered)
			<-exit
			return nil, nil, ErrOwner
		}))
	}()
	<-entered
	tick.Store(975)
	if _, err := job.RemainingMS(); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal(err)
	}
	reply, err := job.Unavailable()
	if err != nil {
		t.Fatal(err)
	}
	if err := reply.Publish(context.Background()); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("expired provider acquired publication authority", err)
	}
	if len(sink.wire) != 1 {
		t.Fatal("expired provider submitted bytes")
	}
	w.mu.Lock()
	original := w.replies[job.index]
	w.mu.Unlock()
	if original.serial != job.serial || !original.running || original.published || !original.timedOut {
		t.Fatal("finite publication refunded the active provider position")
	}
	w.Close()
	if w.CleanupComplete() {
		t.Fatal("channel close refunded the late provider tail")
	}
	release.Do(func() { close(exit) })
	<-done
	if !errors.Is(workerErr, ErrManagementClosed) || !w.CleanupComplete() || len(sink.wire) != 1 {
		t.Fatal("late completion changed finite reply or stranded cleanup", workerErr, w.CleanupComplete(), len(sink.wire))
	}
}
