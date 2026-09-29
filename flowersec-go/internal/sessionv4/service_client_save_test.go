package sessionv4

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

type referenceStoreFunc func(context.Context, protocolv4.OperationReference) (ReferenceSaveOutcome, error)

func (f referenceStoreFunc) SaveOperationReference(ctx context.Context, ref protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
	return f(ctx, ref)
}

func saveBinding(t *testing.T, f *serviceDispatchFixture, store referenceStoreFunc) ReferenceStoreBinding {
	t.Helper()
	return ReferenceStoreBinding{Domain: "test-domain", Store: store, Backing: f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Items: 1})}
}

func TestPrepareAndSaveConfirmsOriginalUnstartedHandle(t *testing.T) {
	f, r, _ := executionServiceClientFixture(t)
	var encodes, saves atomic.Int32
	method := UnaryMethodDefinition{Contract: f.policy.Digest, Decode: synchronousResult, DefaultResponseLimitBytes: 1024,
		Codec: SynchronousUnaryCodec{MaxEncodedBytes: 64, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) {
			encodes.Add(1)
			return append([]byte("encoded:"), input...), nil
		}}}
	client := bindServiceClientFixture(t, r, method)
	var saved protocolv4.OperationReference
	binding := saveBinding(t, f, func(ctx context.Context, ref protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
		application, err := checkApplicationContext(ctx)
		if err != nil || !application {
			t.Error("store escaped ordinary application executor", err)
		}
		saves.Add(1)
		saved = ref
		return ReferenceSaveConfirmed, nil
	})
	op, result, err := client.PrepareMethodAndSave(context.Background(), 0, []byte("input"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, AdmissionMode: 1, ExplicitAdmissionMode: true}, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	if result.Reference != saved || !saved.Valid() || !result.Attempted || result.Outcome != ReferenceSaveConfirmed || encodes.Load() != 1 || saves.Load() != 1 {
		t.Fatal(result, encodes.Load(), saves.Load())
	}
	if op.Snapshot().Started || op.Snapshot().Closed || len(f.sink.wire) != 0 {
		t.Fatal("save submitted or closed original preparation")
	}
	client.Close()
	if err := client.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	// A pure local try-now miss after handoff keeps exactly this preparation.
	r.mu.Lock()
	channel := r.channel
	r.channel = nil
	r.mu.Unlock()
	start := op.Start(context.Background())
	r.mu.Lock()
	r.channel = channel
	r.mu.Unlock()
	reference, err := op.Reference()
	if err != nil || !start.NotAdmitted || reference != saved || op.Snapshot().Closed || op.Snapshot().Started || encodes.Load() != 1 || saves.Load() != 1 {
		t.Fatal(start, reference, err)
	}
}

func TestPrepareAndSaveErrorsKeepReferenceAndClosePrivateOwner(t *testing.T) {
	failure := errors.New("durable provider refused")
	for _, mode := range []string{"unknown", "error", "panic", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f, _, client := executionServiceClientFixture(t)
			var captured *UnaryOperation
			binding := saveBinding(t, f, func(context.Context, protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
				client.mu.Lock()
				captured = client.calls[0].operation
				client.mu.Unlock()
				switch mode {
				case "error":
					return ReferenceSaveUnknown, failure
				case "panic":
					panic("provider panic")
				case "expired":
					f.trust.tick.Store(2000)
					return ReferenceSaveConfirmed, nil
				default:
					return ReferenceSaveUnknown, nil
				}
			})
			op, result, err := client.PrepareMethodAndSave(context.Background(), 0, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000}, binding)
			if op != nil || err == nil || !result.Attempted || !result.Reference.Valid() || captured == nil || !captured.Snapshot().Closed {
				t.Fatal(op, result, err)
			}
			if mode == "error" && !errors.Is(err, failure) {
				t.Fatal("lost provider failure", err)
			}
			if mode == "expired" && result.Outcome != ReferenceSaveConfirmed {
				t.Fatal("lost durable confirmation", result)
			}
			if mode != "expired" && result.Outcome != ReferenceSaveUnknown {
				t.Fatal(result)
			}
			if captured.Start(context.Background()).Error == nil || len(f.sink.wire) != 0 {
				t.Fatal("failed save retained Start rights")
			}
			client.Close()
			if err := client.WaitCleanup(resultTestContext(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPrepareAndSaveCancellationRetainsUncooperativeStoreTail(t *testing.T) {
	for _, closeBinding := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "binding_close"}[closeBinding], func(t *testing.T) {
			f, _, client := executionServiceClientFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			binding := saveBinding(t, f, func(context.Context, protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
				close(entered)
				<-release
				return ReferenceSaveConfirmed, nil
			})
			type outcome struct {
				op     *UnaryOperation
				result ReferenceSaveResult
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				op, result, err := client.PrepareMethodAndSave(ctx, 0, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000}, binding)
				done <- outcome{op, result, err}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("store did not enter")
			}
			client.mu.Lock()
			original := client.calls[0].operation
			client.mu.Unlock()
			if closeBinding {
				client.Close()
			} else {
				cancel()
			}
			select {
			case result := <-done:
				if result.op != nil || !errors.Is(result.err, context.Canceled) || !result.result.Reference.Valid() || !result.result.Attempted || result.result.Outcome != ReferenceSaveUnknown {
					t.Fatal(result)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("uncooperative store retained caller")
			}
			client.Close()
			client.advance()
			client.mu.Lock()
			active := client.active
			client.mu.Unlock()
			if active != 1 || original.Snapshot().CleanupComplete || !original.Snapshot().Closed {
				t.Fatal("store tail refunded before exit", active, original.Snapshot())
			}
			unblock()
			if err := client.WaitCleanup(resultTestContext(t)); err != nil {
				t.Fatal(err)
			}
			if original.Start(context.Background()).Error == nil || !original.Snapshot().CleanupComplete || len(f.sink.wire) != 0 {
				t.Fatal("late confirmation restored sending authority")
			}
		})
	}
}

func TestPrepareAndSaveRejectsBeforeEncoder(t *testing.T) {
	f, r, _ := executionServiceClientFixture(t)
	var encodes, saves atomic.Int32
	client := bindServiceClientFixture(t, r, UnaryMethodDefinition{Contract: f.policy.Digest, Decode: synchronousResult, DefaultResponseLimitBytes: 1024,
		Codec: SynchronousUnaryCodec{MaxEncodedBytes: 64, Encode: func(context.Context, []byte, []byte) ([]byte, error) { encodes.Add(1); return nil, nil }}})
	valid := saveBinding(t, f, func(context.Context, protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
		saves.Add(1)
		return ReferenceSaveConfirmed, nil
	})
	foreign := valid
	foreign.Backing = f.f.reserve(t, 2, resourcev4.Vector{resourcev4.Items: 1})
	wrongDomain := valid
	wrongDomain.Domain = "other-domain"
	badBacking := valid
	badBacking.Backing = resourcev4.Reference{}
	for _, binding := range []ReferenceStoreBinding{foreign, wrongDomain, badBacking, {}} {
		op, result, err := client.PrepareMethodAndSave(context.Background(), 0, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000}, binding)
		if op != nil || err == nil || result.Reference.Valid() || result.Attempted {
			t.Fatal(op, result, err)
		}
	}
	ctx := context.WithValue(context.Background(), cleanupOnlyContextKey{}, true)
	if _, _, err := client.PrepareMethodAndSave(ctx, 0, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000}, valid); !errors.Is(err, ErrApplicationDependency) {
		t.Fatal(err)
	}
	if encodes.Load() != 0 || saves.Load() != 0 {
		t.Fatal("invalid store entered application code")
	}
}

func TestPrepareAndSaveRejectsTransientAndObservationBeforeEncoder(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	var encodes, saves atomic.Int32
	for index := range definition.Methods {
		definition.Methods[index].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 64, Encode: func(context.Context, []byte, []byte) ([]byte, error) { encodes.Add(1); return nil, nil }}
	}
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	binding := saveBinding(t, f, func(context.Context, protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
		saves.Add(1)
		return ReferenceSaveConfirmed, nil
	})
	for shape := uint8(0); shape < 3; shape++ {
		op, result, err := client.prepareMethodAndSave(context.Background(), uint32(shape)+1, shape, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000}, binding)
		if err == nil || op != nil || result.Reference.Valid() || result.Attempted {
			t.Fatal(op, result, err)
		}
	}
	if encodes.Load() != 0 || saves.Load() != 0 {
		t.Fatal("non-execution save entered application code")
	}
}
