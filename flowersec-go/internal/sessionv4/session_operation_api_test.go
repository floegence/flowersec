package sessionv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func TestSessionOperationAPIUsesOriginalPreparedResultOwner(t *testing.T) {
	f, r, _, _ := deferredCallerFixture(t)
	r.routes = f.routes
	var encodes, decodes atomic.Int32
	method := UnaryMethodDefinition{Contract: f.policy.Digest, WorkClass: ApplicationShort,
		Codec:  SynchronousUnaryCodec{MaxEncodedBytes: 1024, Encode: func(_ context.Context, input, scratch []byte) ([]byte, error) { encodes.Add(1); return input, nil }},
		Decode: func(_ context.Context, input []byte) (any, error) { decodes.Add(1); return string(input), nil },
	}
	core := &SessionCore{plan: &SessionCorePlan{rpc: r}}
	session := &EnvironmentSession{core: core, delivered: true}
	input := []byte("original")
	op, err := session.PrepareUnary(context.Background(), method, input, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	clear(input)
	if op.Snapshot().Started || encodes.Load() != 1 || decodes.Load() != 0 {
		t.Fatal("prepare dispatched or decoded")
	}
	start := op.Start(context.Background())
	if start.Error != nil || start.Call == nil {
		t.Fatal(start)
	}
	if other := op.Start(context.Background()); other.Call != start.Call || other.Error != nil {
		t.Fatal("duplicate Start replaced owner", other)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	status, err := op.WaitResultStatus(canceled)
	if !errors.Is(err, context.Canceled) || status.Complete {
		t.Fatal(status, err)
	}
	finishShortResponse(t, f, op.header, 1, []byte("result"))
	r.AdvanceCalls()
	if !op.Snapshot().Result.Available || decodes.Load() != 0 {
		t.Fatal("status invoked decoder")
	}
	value, status, err := op.TakeResult(resultTestContext(t))
	if err != nil || value != "result" || !status.Delivered || decodes.Load() != 1 {
		t.Fatal(value, status, err)
	}
	if _, _, err := op.TakeEncodedResult(resultTestContext(t)); !errors.Is(err, ErrUnaryResultDelivered) {
		t.Fatal("independent encoded consume right", err)
	}
	op.Close()
	r.AdvanceCalls()
	if err := op.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if !op.Snapshot().CleanupComplete {
		t.Fatal("cleanup did not retain original fact")
	}
}

func TestSessionOperationAPIRejectsMissingExactRouteBeforeEncoder(t *testing.T) {
	f, r, _, _ := deferredCallerFixture(t)
	r.routes = f.routes
	var calls atomic.Int32
	_, err := r.PrepareMethod(context.Background(), UnaryMethodDefinition{Contract: [32]byte{255}, Decode: func(context.Context, []byte) (any, error) { return nil, nil }, Codec: SynchronousUnaryCodec{MaxEncodedBytes: 16, Encode: func(context.Context, []byte, []byte) ([]byte, error) { calls.Add(1); return nil, nil }}}, nil, rpcv4.UnaryPreparation{})
	if err == nil || calls.Load() != 0 {
		t.Fatal("unknown route entered codec", err)
	}
	core := &SessionCore{plan: &SessionCorePlan{rpc: r, closed: true}}
	if _, err := core.PrepareUnary(context.Background(), UnaryMethodDefinition{}, nil, rpcv4.UnaryPreparation{}); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal(err)
	}
}

func TestSessionOperationSelectsResponseLimitBeforeEncoding(t *testing.T) {
	f, r, _, _ := deferredCallerFixture(t)
	r.routes = f.routes
	var encodes atomic.Int32
	method := UnaryMethodDefinition{Contract: f.policy.Digest, WorkClass: ApplicationShort, Decode: synchronousResult,
		Codec: SynchronousUnaryCodec{MaxEncodedBytes: 16, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) { encodes.Add(1); return input, nil }}}
	for _, tc := range []struct {
		name                  string
		value, fallback, want uint32
		present, hasDefault   bool
	}{
		{"contract_maximum", 0, 0, f.policy.MaxResponseBytes, false, false},
		{"local_default", 0, 1024, 1024, false, true},
		{"explicit_override", 2048, 1024, 2048, false, true},
		{"explicit_zero", 0, 1024, 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := method
			selected.DefaultResponseLimitBytes, selected.ExplicitDefaultResponseLimit = tc.fallback, tc.hasDefault
			options := rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: tc.value, ExplicitResponseLimit: tc.present}
			before := encodes.Load()
			op, err := r.PrepareMethod(context.Background(), selected, []byte("request"), options)
			if tc.want < f.policy.MinResponseBytes {
				if err != rpcv4.ErrResponseLimitUnsupported || op != nil || encodes.Load() != before {
					t.Fatal("invalid explicit limit entered encoder", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer op.Close()
			selected.DefaultResponseLimitBytes = 17
			options.ResponseLimitBytes = 19
			if op.header.Fields().ResponseLimitBytes != tc.want || encodes.Load() != before+1 || len(f.sink.wire) != 0 {
				t.Fatal("preparation lost selection or submitted", op.header.Fields(), encodes.Load())
			}
		})
	}
	method.DefaultResponseLimitBytes = f.policy.MaxResponseBytes + 1
	before := f.f.root.Snapshot()
	calls := encodes.Load()
	if err := r.ValidateUnaryMethod(method); err != rpcv4.ErrResponseLimitUnsupported {
		t.Fatal("binding installed invalid local default", err)
	}
	op, err := r.PrepareMethod(context.Background(), method, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024})
	if err != rpcv4.ErrResponseLimitUnsupported || op != nil || encodes.Load() != calls || f.f.root.Snapshot() != before {
		t.Fatal("override bypassed default validation or retained charge", err)
	}
}
