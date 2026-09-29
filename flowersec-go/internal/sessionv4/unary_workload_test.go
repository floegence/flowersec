package sessionv4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func workloadFixture(t *testing.T, codec bool) (*serviceDispatchFixture, *RPCServices, *Environment, UnaryMethodDefinition, *unaryWorkload) {
	t.Helper()
	f, r, _, e := deferredCallerFixture(t)
	r.routes = f.routes
	method := UnaryMethodDefinition{Contract: f.policy.Digest, WorkClass: ApplicationShort, Decode: func(_ context.Context, input []byte) (any, error) { return string(input), nil }, DefaultResponseLimitBytes: 1024}
	if codec {
		method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 16, ScratchBytes: 16, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) { return input, nil }}
	}
	w, err := r.reserveUnaryWorkload(method, 8, 1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	method.workload = w
	t.Cleanup(func() {
		w.seal()
		waitWorkload(t, r, e, func() bool { return w.cleaned })
	})
	return f, r, e, method, w
}

func waitWorkload(t *testing.T, r *RPCServices, e *Environment, ready func() bool) {
	t.Helper()
	ctx := resultTestContext(t)
	for {
		r.AdvanceCalls()
		e.advanceResults()
		r.advanceWorkloads()
		r.mu.Lock()
		done := ready()
		r.mu.Unlock()
		if done {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("workload retained original resources", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

// Fill both the byte budget and remaining root reference slab. A protected
// use must consume its admitted owners and aliases all the way through Take.
func saturateWorkloadRoot(t *testing.T, f *serviceDispatchFixture) {
	t.Helper()
	snapshot := f.f.root.Snapshot()
	fill := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: snapshot.Limit[resourcev4.SDKBytes] - snapshot.Charged[resourcev4.SDKBytes]})
	var aliases []resourcev4.Reference
	for {
		ref, err := fill.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		aliases = append(aliases, ref)
	}
	t.Cleanup(func() {
		for _, alias := range aliases {
			alias.Release()
		}
		fill.Release()
	})
}

func TestUnaryWorkloadUsesOriginalCapacityAtFullRoot(t *testing.T) {
	for _, encoded := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "codec"}[encoded], func(t *testing.T) {
			f, r, e, method, w := workloadFixture(t, encoded)
			saturateWorkloadRoot(t, f)
			before := f.f.root.Snapshot()
			for serial := uint64(1); serial <= 2; serial++ {
				op, err := r.PrepareMethod(context.Background(), method, []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
				if err != nil {
					t.Fatal("preadmitted preparation failed", err)
				}
				t.Cleanup(op.Close)
				if op.workload != &w.slots[0] || f.network.Snapshot().OutgoingGeneral != 0 {
					t.Fatal("Prepare did not retain the dormant original position")
				}
				start := op.Start(context.Background())
				if start.Error != nil || start.Call == nil {
					t.Fatal("preadmitted Start failed", start.Error)
				}
				finishShortResponse(t, f, op.header, serial, []byte("result"))
				r.AdvanceCalls()
				if f.network.Snapshot().OutgoingGeneral != 0 {
					t.Fatal("completed response retained live Network K")
				}
				if _, err := r.PrepareMethod(context.Background(), method, []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000}); !errors.Is(err, resourcev4.ErrCapacity) {
					t.Fatal("undelivered result reproduced workload capacity", err)
				}
				value, status, err := op.TakeResult(resultTestContext(t))
				if err != nil || value != "result" || !status.Delivered {
					t.Fatal(value, status, err)
				}
				op.Close()
				waitWorkload(t, r, e, func() bool { return !w.slots[0].used })
				if after := f.f.root.Snapshot(); after != before {
					t.Fatal("original workload capacity changed across a use", before, after)
				}
			}
		})
	}
}

func TestUnaryWorkloadConstructorUnwindsAllPositions(t *testing.T) {
	for _, failure := range []string{"result", "completion"} {
		t.Run(failure, func(t *testing.T) {
			f, r, route := shortCallerFixture(t, 2)
			resultSlots := uint32(4)
			if failure == "result" {
				resultSlots = 2
			}
			_, _, _, e := deferredCallerForServiceFixture(t, f, r, route, resultSlots)
			r.routes = f.routes
			before, positions, network := f.f.root.Snapshot(), e.OperationsSnapshot(), f.network.Snapshot()
			method := UnaryMethodDefinition{Contract: f.policy.Digest, Decode: synchronousResult}
			w, err := r.reserveUnaryWorkload(method, 8, 1024, 2)
			if w != nil || !errors.Is(err, cryptov4.ErrCapacity) {
				t.Fatal("incomplete target was admitted", w, err)
			}
			if f.f.root.Snapshot() != before || e.OperationsSnapshot() != positions || f.network.Snapshot() != network {
				t.Fatal("failed target retained partial resources", before, f.f.root.Snapshot())
			}
			for _, slot := range r.workloadSlots {
				if slot != nil {
					t.Fatal("failed target retained an operation position")
				}
			}
		})
	}
}

func TestUnaryWorkloadLargerLegalCallsUseGeneralCapacity(t *testing.T) {
	_, r, _, method, w := workloadFixture(t, false)
	for _, tc := range []struct {
		input string
		limit uint32
	}{
		{"larger request", 1024},
		{"req", 2048},
	} {
		op, err := r.PrepareMethod(context.Background(), method, []byte(tc.input), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: tc.limit})
		if err != nil {
			t.Fatal(err)
		}
		if op.workload != nil || op.header.Fields().PayloadBytes != uint32(len(tc.input)) || op.header.Fields().ResponseLimitBytes != tc.limit || w.slots[0].used {
			t.Fatal("workload changed the legal request envelope")
		}
		op.Close()
	}
}

func TestUnaryWorkloadSealKeepsReturnedPreparation(t *testing.T) {
	f, r, e, method, w := workloadFixture(t, false)
	op, err := r.PrepareMethod(context.Background(), method, []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	w.seal()
	r.advanceWorkloads()
	if _, err := r.PrepareMethod(context.Background(), method, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000}); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("sealed binding created work", err)
	}
	start := op.Start(context.Background())
	if start.Error != nil {
		t.Fatal("binding close revoked returned operation", start.Error)
	}
	finishShortResponse(t, f, op.header, 1, []byte("result"))
	r.AdvanceCalls()
	if _, _, err := op.TakeEncodedResult(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	op.Close()
	waitWorkload(t, r, e, func() bool { return w.cleaned })
}

func TestUnaryWorkloadKeepsActualDecoderTail(t *testing.T) {
	f, r, e, method, w := workloadFixture(t, false)
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	method.Decode = func(_ context.Context, input []byte) (any, error) {
		close(entered)
		<-release
		return string(input), nil
	}
	op, err := r.PrepareMethod(context.Background(), method, []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if start := op.Start(context.Background()); start.Error != nil {
		t.Fatal(start.Error)
	}
	finishShortResponse(t, f, op.header, 1, []byte("result"))
	r.AdvanceCalls()
	go func() {
		defer close(exited)
		_, _, _ = op.TakeResult(context.Background())
	}()
	awaitApplicationTask(t, entered)
	op.Close()
	r.advanceWorkloads()
	r.mu.Lock()
	retained := w.slots[0].used
	r.mu.Unlock()
	if !retained || w.slots[0].completion.checkAvailable() == nil {
		t.Fatal("observer close refunded a running decoder")
	}
	w.seal()
	r.advanceWorkloads()
	once.Do(func() { close(release) })
	awaitApplicationTask(t, exited)
	waitWorkload(t, r, e, func() bool { return w.cleaned })
}

func TestUnaryWorkloadSessionCloseDetachesCompletedResult(t *testing.T) {
	f, r, e, method, w := workloadFixture(t, false)
	op, err := r.PrepareMethod(context.Background(), method, []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if start := op.Start(context.Background()); start.Error != nil {
		t.Fatal(start.Error)
	}
	finishShortResponse(t, f, op.header, 1, []byte("independent"))
	r.AdvanceCalls()
	r.mu.Lock()
	r.channel = nil // The fixture owns the original publisher directly.
	r.mu.Unlock()
	r.Close()
	waitWorkload(t, r, e, func() bool { return w.cleaned })
	if f.f.root.Snapshot().ResultOwners == 0 {
		t.Fatal("Session retirement refunded the independent result")
	}
	value, status, err := op.TakeResult(resultTestContext(t))
	if err != nil || value != "independent" || !status.Delivered {
		t.Fatal("Session close erased the completed payload", value, status, err)
	}
}

func TestUnaryWorkloadTemporaryStartMissKeepsPreparedCapacity(t *testing.T) {
	f, r, e, method, w := workloadFixture(t, false)
	op, err := r.PrepareMethod(context.Background(), method, []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, AdmissionMode: 1, ExplicitAdmissionMode: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	r.mu.Lock()
	channel := r.channel
	r.channel = nil
	r.mu.Unlock()
	first := op.Start(context.Background())
	r.mu.Lock()
	r.channel = channel
	r.mu.Unlock()
	if !first.NotAdmitted || !errors.Is(first.Error, cryptov4.ErrNotReady) {
		t.Fatal(first)
	}
	w.seal()
	r.advanceWorkloads()
	if start := op.Start(context.Background()); start.Error != nil || start.Call == nil {
		t.Fatal("unsubmitted miss consumed future Start capacity", start)
	}
	finishShortResponse(t, f, op.header, 1, []byte("result"))
	r.AdvanceCalls()
	op.Close()
	waitWorkload(t, r, e, func() bool { return w.cleaned })
}
