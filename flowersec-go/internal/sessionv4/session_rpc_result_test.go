package sessionv4

import (
	"bytes"
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
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func deferredCallerFixture(t *testing.T) (*serviceDispatchFixture, *RPCServices, rpcv4.ContractRoute, *Environment) {
	t.Helper()
	f, r, route := shortCallerFixture(t, 16)
	config := EnvironmentConfig{Services: true, ResultOwners: 16, Positions: 1, Clock: f.trust.clock, RuntimeBytes: 65536}
	charge, err := EnvironmentCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvironment(config, f.f.reserve(t, 1, charge), f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}))
	if err != nil {
		t.Fatal(err)
	}
	_, authority, err := f.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	floorCharge, _ := protocolv4.DeliverySubscriptionFloorCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: 4096})
	r.deliveryFloor, err = authority.ReserveDeliveryFloor(f.f.reserve(t, 1, floorCharge))
	if err != nil {
		t.Fatal(err)
	}
	// Only the delivered host link is fixture-supplied. Result admission,
	// authority, Network input, future service and Environment cleanup are real.
	f.plan.mu.Lock()
	f.plan.host = newEnvironmentSession(e, 0, context.Background())
	f.plan.mu.Unlock()
	t.Cleanup(func() {
		e.Close()
		f.publisher.Close()
		f.receiver.Close()
		r.AdvanceCalls()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := e.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := e.Retire(); err != nil {
			t.Error(err)
		}
	})
	return f, r, route, e
}

func beginDeferredCall(t *testing.T, f *serviceDispatchFixture, r *RPCServices, route rpcv4.ContractRoute, decode UnaryResultDecoder) (*UnaryCall, protocolv4.ApplicationHeader) {
	t.Helper()
	var wire [512]byte
	n, h, err := f.codec.Encode(wire[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: 3, DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	call, err := r.BeginDeferredUnary(context.Background(), route, h, wire[:n], []byte("req"), ApplicationShort, decode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(call.Close)
	return call, h
}

func resultTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestDeferredResultStatusIsDormantAndSurvivesIOClose(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	before := f.f.root.Snapshot().ResultOwners
	var calls atomic.Int32
	call, h := beginDeferredCall(t, f, r, route, func(_ context.Context, input []byte) (any, error) { calls.Add(1); return input, nil })
	finishShortResponse(t, f, h, 1, []byte("owned result"))
	r.AdvanceCalls()
	status, err := call.WaitStatus(resultTestContext(t))
	if err != nil || !status.Complete || !status.Available || status.Decoded || calls.Load() != 0 {
		t.Fatal(status, calls.Load(), err)
	}
	if f.network.Snapshot().OutgoingGeneral != 0 {
		t.Fatal("complete input retained K")
	}
	_, authority, err := f.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	authority.Close(nil)
	f.publisher.Close()
	f.receiver.Close()
	value, status, err := call.TakeResult(resultTestContext(t))
	if err != nil || !status.Delivered || !status.Outcome.ApplicationInputDelivered || calls.Load() != 1 {
		t.Fatal(value, status, err)
	}
	payload := value.([]byte)
	if !bytes.Equal(payload, []byte("owned result")) {
		t.Fatal(payload)
	}
	if f.f.root.Snapshot().ResultOwners != before+1 {
		t.Fatal("decoder released the local result-owner position")
	}
	call.Close()
	call.advanceResult()
	if !bytes.Equal(payload, []byte("owned result")) {
		t.Fatal("cleanup wiped application-owned alias")
	}
}

func TestDeferredEncodedTakeWinsWithoutApplicationCodec(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	var calls atomic.Int32
	call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { calls.Add(1); return nil, nil })
	finishShortResponse(t, f, h, 1, []byte("encoded"))
	r.AdvanceCalls()
	payload, status, err := call.TakeEncodedResult(resultTestContext(t))
	if err != nil || string(payload) != "encoded" || !status.Delivered || status.Outcome.ApplicationInputDelivered || calls.Load() != 0 {
		t.Fatal(string(payload), status, err)
	}
	if _, _, err := call.TakeResult(resultTestContext(t)); !errors.Is(err, ErrUnaryResultDelivered) {
		t.Fatal(err)
	}
	if _, _, err := call.TakeEncodedResult(resultTestContext(t)); !errors.Is(err, ErrUnaryResultDelivered) {
		t.Fatal(err)
	}
	call.Close()
	if string(payload) != "encoded" {
		t.Fatal("Close wiped delivered encoded bytes")
	}
}

func TestDeferredTakeCancellationJoinsOneDecoderAndPreservesOwnedInput(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var calls atomic.Int32
	var retained []byte
	call, h := beginDeferredCall(t, f, r, route, func(_ context.Context, input []byte) (any, error) {
		calls.Add(1)
		retained = input
		close(entered)
		<-release
		return input, nil
	})
	finishShortResponse(t, f, h, 1, []byte("one input"))
	r.AdvanceCalls()
	ctx, cancel := context.WithCancel(resultTestContext(t))
	first := make(chan error, 1)
	go func() { _, _, err := call.TakeResult(ctx); first <- err }()
	awaitApplicationTask(t, entered)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := call.TakeEncodedResult(resultTestContext(t)); !errors.Is(err, ErrUnaryInputDelivered) {
		t.Fatal(err)
	}
	// Input is already application-owned; later independent trust rejection
	// cannot revoke this callback or cause another decoding attempt.
	f.trust.trust.rejected.Store(true)
	f.trust.namespace.NotifyTrust()
	once.Do(func() { close(release) })
	value, status, err := call.TakeResult(resultTestContext(t))
	if err != nil || string(value.([]byte)) != "one input" || !status.Delivered || calls.Load() != 1 {
		t.Fatal(value, status, err)
	}
	call.Close()
	if string(retained) != "one input" {
		t.Fatal("callback input was not owned")
	}
}

func TestDeferredPrivateInputStillRequiresOriginalAuthorization(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	var calls atomic.Int32
	call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { calls.Add(1); return nil, nil })
	finishShortResponse(t, f, h, 1, []byte("private"))
	r.AdvanceCalls()
	f.trust.trust.rejected.Store(true)
	f.trust.namespace.NotifyTrust()
	call.advanceResult()
	status, err := call.WaitStatus(resultTestContext(t))
	if err != nil || !status.Complete || status.Available {
		t.Fatal(status, err)
	}
	if _, _, err := call.TakeResult(resultTestContext(t)); !errors.Is(err, ErrUnaryPayloadUnavailable) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid private input reached application")
	}
}

func TestDeferredCloseRetainsActualDecoderTail(t *testing.T) {
	f, r, route, e := deferredCallerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	call, h := beginDeferredCall(t, f, r, route, func(_ context.Context, input []byte) (any, error) { close(entered); <-release; return input, nil })
	finishShortResponse(t, f, h, 1, []byte("tail"))
	r.AdvanceCalls()
	wait := make(chan error, 1)
	go func() { _, _, err := call.TakeResult(resultTestContext(t)); wait <- err }()
	awaitApplicationTask(t, entered)
	before := f.f.root.Snapshot().ResultOwners
	e.Close()
	if err := <-wait; !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal(err)
	}
	call.advanceResult()
	if f.f.root.Snapshot().ResultOwners != before {
		t.Fatal("Close refunded running callback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := e.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	if err := e.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

func TestDeferredDecoderFailuresAreNormalizedAndNeverRepeated(t *testing.T) {
	for _, mode := range []string{"error", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			f, r, route, _ := deferredCallerFixture(t)
			var calls atomic.Int32
			call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) {
				calls.Add(1)
				switch mode {
				case "panic":
					panic("application value")
				case "goexit":
					runtime.Goexit()
				}
				return nil, errors.New("application error")
			})
			finishShortResponse(t, f, h, 1, []byte("data"))
			r.AdvanceCalls()
			_, status, err := call.TakeResult(resultTestContext(t))
			if !errors.Is(err, ErrUnaryDecodeFailed) || !status.Delivered || !status.Outcome.ApplicationInputDelivered {
				t.Fatal(status, err)
			}
			if _, _, err := call.TakeResult(resultTestContext(t)); !errors.Is(err, ErrUnaryResultDelivered) || calls.Load() != 1 {
				t.Fatal(calls.Load(), err)
			}
		})
	}
}

func TestDeferredDecoderCannotWaitForItself(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	var call *UnaryCall
	var h protocolv4.ApplicationHeader
	call, h = beginDeferredCall(t, f, r, route, func(ctx context.Context, input []byte) (any, error) {
		if _, _, err := call.TakeResult(ctx); !errors.Is(err, ErrCompletionDependency) {
			return nil, errors.New("self dependency accepted")
		}
		return input, nil
	})
	finishShortResponse(t, f, h, 1, []byte("data"))
	r.AdvanceCalls()
	if _, _, err := call.TakeResult(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

func TestDeferredCanceledQueuedDecoderReturnsToOriginalDormantResult(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	blocking, err := f.f.executor.ReserveCompletion(f.f.reserve(t, 1, f.f.executor.CompletionCharge()), f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := blocking.Submit(func() error { close(entered); <-release; return nil })
	if err != nil {
		t.Fatal(err)
	}
	awaitApplicationTask(t, entered)
	var calls atomic.Int32
	call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { calls.Add(1); return nil, nil })
	finishShortResponse(t, f, h, 1, []byte("still private"))
	r.AdvanceCalls()
	ctx, cancel := context.WithCancel(resultTestContext(t))
	waiting := make(chan error, 1)
	go func() { _, _, err := call.TakeResult(ctx); waiting <- err }()
	var task *CompletionTask
	deadline := time.Now().Add(3 * time.Second)
	for task == nil && time.Now().Before(deadline) {
		call.mu.Lock()
		task = call.deferred.task
		call.mu.Unlock()
		runtime.Gosched()
	}
	if task == nil {
		t.Fatal("typed request was not queued")
	}
	cancel()
	if err := <-waiting; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	if err := worker.Wait(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if err := task.Wait(resultTestContext(t)); !errors.Is(err, errCompletionNotEligible) {
		t.Fatal(err)
	}
	call.advanceResult()
	payload, status, err := call.TakeEncodedResult(resultTestContext(t))
	if err != nil || string(payload) != "still private" || !status.Delivered || calls.Load() != 0 {
		t.Fatal(string(payload), status, calls.Load(), err)
	}
}

func TestDeferredWaitStatusHasBoundedObserversAndNoDecodeClaim(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	call, _ := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { return nil, nil })
	ctx, cancel := context.WithCancel(resultTestContext(t))
	defer cancel()
	waited := make(chan error, 4)
	for range 4 {
		go func() { _, err := call.WaitStatus(ctx); waited <- err }()
	}
	deadline := time.Now().Add(3 * time.Second)
	var waiters uint8
	for waiters != 4 && time.Now().Before(deadline) {
		call.mu.Lock()
		waiters = call.deferred.waiters
		call.mu.Unlock()
		runtime.Gosched()
	}
	if waiters != 4 {
		t.Fatal(waiters)
	}
	if _, err := call.WaitStatus(resultTestContext(t)); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	f.f.executor.mu.Lock()
	claims := f.f.executor.completionClaims
	f.f.executor.mu.Unlock()
	if claims != 0 {
		t.Fatal("status wait consumed decoder claim")
	}
	cancel()
	for range 4 {
		if err := <-waited; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

func TestPreparedDeferredResultStartsOnceAndDetachesSession(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	var calls atomic.Int32
	o, err := r.PrepareUnaryResult(context.Background(), route, []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, ApplicationShort, func(_ context.Context, input []byte) (any, error) { calls.Add(1); return input, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	first, second := o.Start(context.Background()), o.Start(context.Background())
	if first.Error != nil || first.Call == nil || second.Call != first.Call {
		t.Fatal(first, second)
	}
	finishShortResponse(t, f, o.header, 1, []byte("result"))
	r.AdvanceCalls()
	if !o.detached || o.services != nil || o.resultPlan != nil || calls.Load() != 0 {
		t.Fatal("prepared result retained Session or eagerly decoded")
	}
	if value, _, err := first.Call.TakeResult(resultTestContext(t)); err != nil || string(value.([]byte)) != "result" {
		t.Fatal(value, err)
	}
}

func beginProtectedDeferredCall(t *testing.T, f *serviceDispatchFixture, r *RPCServices, route rpcv4.ContractRoute, decode UnaryResultDecoder) (*UnaryCall, protocolv4.ApplicationHeader) {
	t.Helper()
	var wire [512]byte
	n, h, err := f.codec.Encode(wire[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: 3, DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	call, err := r.BeginDeferredShortUnary(context.Background(), route, h, wire[:n], []byte("req"), decode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(call.Close)
	return call, h
}

func TestProtectedDeferredResultsReuseOriginalFloorAtSaturatedRoot(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	saturateServiceRoot(t, f)
	before := f.f.root.Snapshot()
	for serial := uint64(1); serial <= 3; serial++ {
		call, h := beginProtectedDeferredCall(t, f, r, route, func(_ context.Context, input []byte) (any, error) { return input, nil })
		finishShortResponse(t, f, h, serial, []byte("short result"))
		r.AdvanceCalls()
		value, status, err := call.TakeResult(resultTestContext(t))
		if err != nil || !status.Delivered || string(value.([]byte)) != "short result" {
			t.Fatal(value, status, err)
		}
		call.mu.Lock()
		task := call.deferred.task
		call.mu.Unlock()
		if task != nil {
			if err := task.Wait(resultTestContext(t)); err != nil {
				t.Fatal(err)
			}
		}
		call.Close()
		call.advanceResult()
		if after := f.f.root.Snapshot(); after != before {
			t.Fatal("protected result did not return its actual original vector", before, after)
		}
	}
}

func TestProtectedDeferredResultSurvivesOriginalFloorRetirement(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	call, h := beginProtectedDeferredCall(t, f, r, route, func(_ context.Context, input []byte) (any, error) { return input, nil })
	finishShortResponse(t, f, h, 1, []byte("detached"))
	r.AdvanceCalls()
	for _, p := range r.shortCaller {
		p.CloseAfterUse()
	}
	r.completionFloor.Close()
	r.deliveryFloor.Close()
	if !r.completionFloor.CleanupComplete() {
		t.Fatal("detached Completion blocked Session floor cleanup")
	}
	for _, p := range r.shortCaller {
		if !p.CleanupComplete() {
			t.Fatal("independent result retained reusable Session floor")
		}
	}
	_, authority, err := f.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	authority.Close(nil)
	value, status, err := call.TakeResult(resultTestContext(t))
	if err != nil || string(value.([]byte)) != "detached" || !status.Delivered {
		t.Fatal(value, status, err)
	}
}

func TestConcurrentEncodedConsumersKeepOriginalWinnerFacts(t *testing.T) {
	f, r, route, e := deferredCallerFixture(t)
	call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { return nil, nil })
	finishShortResponse(t, f, h, 1, []byte("unique"))
	r.AdvanceCalls()
	e.mu.Lock()
	var results [4]struct {
		payload []byte
		err     error
	}
	var wg sync.WaitGroup
	ctx := resultTestContext(t)
	for j := range results {
		wg.Add(1)
		go func() { defer wg.Done(); results[j].payload, _, results[j].err = call.TakeEncodedResult(ctx) }()
	}
	deadline := time.Now().Add(time.Second)
	var count uint8
	for count != 4 && time.Now().Before(deadline) {
		call.mu.Lock()
		count = call.deferred.waiters
		call.mu.Unlock()
		runtime.Gosched()
	}
	e.mu.Unlock()
	wg.Wait()
	winners := 0
	for _, result := range results {
		if result.err == nil {
			winners++
			if string(result.payload) != "unique" {
				t.Fatal(result)
			}
		} else if !errors.Is(result.err, ErrUnaryResultDelivered) {
			t.Fatal(result.err)
		}
	}
	if winners != 1 {
		t.Fatal(winners)
	}
}
