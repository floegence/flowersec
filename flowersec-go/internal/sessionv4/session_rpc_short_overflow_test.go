package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func TestShortCallerOverlapUsesSpareGeneralCapacity(t *testing.T) {
	f, r, route := shortCallerFixture(t, 4)
	before := f.f.root.Snapshot()
	var decoded [2]string
	var calls [2]*UnaryCall
	var h protocolv4.ApplicationHeader
	for j := range calls {
		calls[j], h = beginShortCall(t, f, r, route, context.Background(), func(input rpcv4.InputBorrow) error {
			payload, _, err := input.Bytes()
			decoded[j] = string(payload)
			return err
		})
	}
	if r.localCall == nil || r.generalCalls[0] == nil || !r.localCall.protected || r.generalCalls[0].protected {
		t.Fatal("concurrent short calls did not retain distinct real vectors")
	}
	if after := f.f.root.Snapshot(); after.ResultOwners != before.ResultOwners+1 || after.Charged[resourcev4.SDKBytes] <= before.Charged[resourcev4.SDKBytes] {
		t.Fatal("second short call duplicated the floor without charging", before, after)
	}
	finishShortResponse(t, f, h, 1, []byte("floor"))
	finishShortResponse(t, f, h, 2, []byte("spare"))
	ctx := resultTestContext(t)
	if err := r.waitCalls(ctx); err != nil {
		t.Fatal(err)
	}
	for _, call := range calls {
		result, err := call.Wait(ctx)
		if err != nil || result.Error != nil || result.Reason != "" {
			t.Fatal(result, err)
		}
	}
	if decoded != ([2]string{"floor", "spare"}) || f.f.root.Snapshot() != before {
		t.Fatal("short overlap mixed results or retained resources", decoded, f.f.root.Snapshot())
	}
}

func TestShortCallerLargerLegalEnvelopeUsesGeneralVector(t *testing.T) {
	for _, field := range []string{"request", "response"} {
		t.Run(field, func(t *testing.T) {
			f, r, route := shortCallerFixture(t, 4)
			// Declare a smaller local floor without changing the installed wire
			// contract. Its preadmitted fixture backing remains conservative.
			if field == "request" {
				r.shortRequestBytes = 1
			} else {
				r.shortResponseBytes = 1
			}
			before := f.f.root.Snapshot()
			call, h := beginShortCall(t, f, r, route, context.Background(), func(rpcv4.InputBorrow) error { return nil })
			if r.localCall != nil || r.generalCalls[0] == nil || r.generalCalls[0].protected {
				t.Fatal("larger legal call used undersized protection")
			}
			for _, p := range r.shortCaller {
				if err := p.CheckAvailable(); err != nil {
					t.Fatal("larger call borrowed the separate floor", err)
				}
			}
			finishShortResponse(t, f, h, 1, []byte("full result"))
			ctx := resultTestContext(t)
			if err := r.waitCalls(ctx); err != nil {
				t.Fatal(err)
			}
			result, err := call.Wait(ctx)
			if err != nil || result.Error != nil || result.Reason != "" || f.f.root.Snapshot() != before {
				t.Fatal(result, err, f.f.root.Snapshot())
			}
		})
	}
}

func TestShortCallerCompletedUndeliveredResultDoesNotBlockSpareCall(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	var wire [512]byte
	n, h, err := f.codec.Encode(wire[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: 3, DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	decode := func(_ context.Context, payload []byte) (any, error) { return string(payload), nil }
	first, err := r.BeginDeferredShortUnary(context.Background(), route, h, wire[:n], []byte("req"), decode)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	finishShortResponse(t, f, h, 1, []byte("old result"))
	r.AdvanceCalls()
	if r.localCall != nil || r.shortCaller[4].CheckAvailable() == nil {
		t.Fatal("completed undelivered result lost its original floor ownership")
	}
	before := f.f.root.Snapshot()
	second, err := r.BeginDeferredShortUnary(context.Background(), route, h, wire[:n], []byte("req"), decode)
	if err != nil {
		t.Fatal("old result prevented an independently charged call", err)
	}
	defer second.Close()
	if r.localCall != nil || r.generalCalls[0] == nil || f.f.root.Snapshot().ResultOwners != before.ResultOwners+1 {
		t.Fatal("new call copied the protected result owner")
	}
	finishShortResponse(t, f, h, 2, []byte("new result"))
	r.AdvanceCalls()
	ctx := resultTestContext(t)
	for i, call := range []*UnaryCall{second, first} {
		payload, status, err := call.TakeEncodedResult(ctx)
		want := []string{"new result", "old result"}[i]
		if err != nil || !status.Delivered || string(payload) != want {
			t.Fatal("overlap changed old or new owned output", string(payload), status, err)
		}
	}
}

func TestShortCallerOverflowCannotBorrowCompletionFloorTwice(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, _ := beginShortCall(t, f, r, route, ctx, func(rpcv4.InputBorrow) error { return nil })
	before := f.f.root.Snapshot()
	var wire [512]byte
	n, h, err := f.codec.Encode(wire[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: 3, DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if second, err := r.BeginShortUnary(ctx, route, h, wire[:n], []byte("req"), func(rpcv4.InputBorrow) error { return nil }); second != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("overflow invented a Completion opportunity", second, err)
	}
	if f.f.root.Snapshot() != before || f.network.Snapshot().OutgoingGeneral != 1 {
		t.Fatal("failed overflow retained partial responsibility")
	}
	cancel()
	r.AdvanceCalls()
	if _, err := first.Wait(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}
