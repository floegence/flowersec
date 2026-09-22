package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func TestServiceExecutionFloorReusesOriginalResourcesAtCapacity(t *testing.T) {
	for _, mode := range []uint8{0, 1} {
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			var calls atomic.Uint32
			f := newServiceDispatchFixtureContract(t, func(_ context.Context, r UnaryRequest, w *UnaryResponse) (uint32, error) {
				calls.Add(1)
				input, _, err := r.Input.Bytes()
				if err != nil {
					return 0, err
				}
				_, err = w.Write(input)
				return 0, err
			}, true, ApplicationShort, true, "service_unary_no_result_retention")
			saturateServiceRoot(t, f)
			before := f.f.root.Snapshot()
			for id := byte(1); id <= 3; id++ {
				f.executionRequest(t, id, []byte("protected execution"), mode)
				if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
					t.Fatal("original execution could not enter", err)
				}
				for _, reply := range f.executionReplies(t, 1) {
					if reply.header.IsSDKError() || !bytes.Equal(reply.body, []byte("protected execution")) {
						t.Fatal(reply.header.Kind(), reply.body)
					}
				}
				waitExecutorIdle(t, f.f.executor)
				f.dispatch.Advance()
				if err := f.dispatch.executionFloors[0].admission.CheckReady(); err != nil {
					t.Fatal("actual exit did not restore original admission", err)
				}
				if after := f.f.root.Snapshot(); after != before {
					t.Fatal("reused execution changed root accounting", before, after)
				}
			}
			if calls.Load() != 3 {
				t.Fatal(calls.Load())
			}
		})
	}
}

func TestServiceExecutionFloorKeepsRetainedResultAndProviderTail(t *testing.T) {
	f := newServiceDispatchFixtureProfile(t, func(_ context.Context, _ UnaryRequest, w *UnaryResponse) (uint32, error) {
		_, err := w.Write([]byte("retained"))
		return 0, err
	}, true, ApplicationShort, true)
	saturateServiceRoot(t, f)
	before := f.f.root.Snapshot()
	target := f.executionRequest(t, 1, nil, 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	waitExecutorIdle(t, f.f.executor)
	f.sink.held.Store(true)
	f.dispatch.Advance()
	if progressed, err := f.publisher.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	f.dispatch.Advance()
	var refs [5]resourcev4.Reference
	if err := resourcev4.CheckoutProtectedBatch(f.dispatch.shortExecution[:], refs[:]); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("provider tail returned output floor", err)
	}
	f.sink.held.Store(false)
	if progressed, err := f.publisher.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	fragment, err := protocolv4.DecodeRPCFragment(f.sink.wire)
	if err != nil || fragment.Kind != protocolv4.RPCData || !bytes.Equal(fragment.Payload, []byte("retained")) {
		t.Fatal("original response did not resume", fragment, err)
	}
	if progressed, err := f.publisher.Step(context.Background()); err != nil || progressed {
		t.Fatal(progressed, err)
	}
	f.dispatch.Advance()
	if err := f.dispatch.executionFloors[0].admission.CheckReady(); !errors.Is(err, rpcv4.ErrCapacity) {
		t.Fatal("retained result returned execution floor", err)
	}
	if got, err := f.history.Query(target, rpcv4.ExecutionContinuity{}, executionDispatchAccess{f.dispatch.reservation}); err != nil || !got.ResultAvailable || got.WorkActive {
		t.Fatal(got, err)
	}
	if after := f.f.root.Snapshot(); after != before {
		t.Fatal("retained output lost original backing", before, after)
	}
	f.trust.tick.Add(f.policy.ResultRetentionMS + 100)
	if err := f.history.Collect(); err != nil {
		t.Fatal(err)
	}
	if err := f.dispatch.executionFloors[0].admission.CheckReady(); err != nil {
		t.Fatal("actual expiry did not restore original floor", err)
	}
	if after := f.f.root.Snapshot(); after != before {
		t.Fatal("collection replaced protected charge", before, after)
	}
}
