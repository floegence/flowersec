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
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func shortCallerFixture(t *testing.T, completionCapacity ...uint32) (*serviceDispatchFixture, *RPCServices, rpcv4.ContractRoute) {
	t.Helper()
	f := newServiceDispatchFixtureConfigured(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { return 0, nil }, false, ApplicationShort, completionCapacity...)
	return callerForServiceFixture(t, f)
}

func callerForServiceFixture(t *testing.T, f *serviceDispatchFixture) (*serviceDispatchFixture, *RPCServices, rpcv4.ContractRoute) {
	t.Helper()
	r := &RPCServices{referenceDomain: "test-domain", completionGraceMS: 5000, plan: f.plan, network: f.network, clock: f.trust.clock, runtimeBytes: 4096, shortRequestBytes: 8192, shortResponseBytes: 8192, channel: &RPCChannel{publisher: f.publisher}}
	r.referenceCodec, _ = protocolv4.NewOperationReferenceCodec()
	r.root = f.f.root
	r.owner = resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{119}, Backing: [16]byte{119}, Kind: 119}
	r.generalCalls = make([]*unaryInvocation, 32)
	r.operations = make([]*UnaryOperation, 32)
	charges, err := shortCallerCharges(4096, 8192, 8192)
	if err != nil {
		t.Fatal(err)
	}
	for index, minimum := range charges {
		charge, err := resourcev4.ProtectedCharge(minimum)
		if err != nil {
			t.Fatal(err)
		}
		ref := f.f.reserveOwner(t, 1, charge, index == 4)
		if index == 2 || index == 4 || index == 5 {
			anchor, e := ref.Borrow()
			if e != nil {
				t.Fatal(e)
			}
			var aliases []resourcev4.Reference
			if index == 4 {
				alias, e := ref.Borrow()
				if e != nil {
					t.Fatal(e)
				}
				aliases = []resourcev4.Reference{alias}
			}
			r.shortCaller[index], err = resourcev4.NewProtectedResultReservation(ref, minimum, anchor, aliases...)
			anchor.Release()
			for _, alias := range aliases {
				alias.Release()
			}
		} else {
			r.shortCaller[index], err = resourcev4.NewProtectedReservation(ref, minimum)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	backing := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 4096})
	r.completionFloor, err = f.f.executor.NewCompletionFloor(f.f.reserve(t, 1, f.f.executor.CompletionFloorCharge()), backing)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ := rpcv4.ContractRouteCharge(4096)
	route, err := f.routes.Capture(f.policy.Digest, f.f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(route.Release)
	t.Cleanup(func() {
		// The fixture owns the actual publisher/receiver directly; their existing
		// cleanup joins them. This test exercises original call and result owners,
		// while the separate duplex integration test owns a real RPCChannel.
		r.mu.Lock()
		r.channel = nil
		r.mu.Unlock()
		r.Close()
		f.sink.held.Store(false)
		f.publisher.Close()
		f.receiver.Close()
		_ = f.publisher.Retire()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := r.waitCalls(ctx); err != nil {
			t.Error(err)
		}
		if !r.completionFloor.CleanupComplete() {
			t.Error("call retained completion floor")
		}
		for _, p := range r.shortCaller {
			if !p.CleanupComplete() {
				t.Error("call retained actual tail")
			}
		}
	})
	return f, r, route
}

func beginShortCall(t *testing.T, f *serviceDispatchFixture, r *RPCServices, route rpcv4.ContractRoute, ctx context.Context, decode func(rpcv4.InputBorrow) error, deadlines ...uint64) (*UnaryCall, protocolv4.ApplicationHeader) {
	t.Helper()
	var wire [512]byte
	deadline := uint64(2000)
	if len(deadlines) != 0 {
		deadline = deadlines[0]
	}
	n, h, err := f.codec.Encode(wire[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: 3, DeadlineAtMS: deadline, ServiceContractDigest: f.policy.Digest, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	call, err := r.BeginShortUnary(ctx, route, h, wire[:n], []byte("req"), decode)
	if err != nil {
		t.Fatal(err)
	}
	return call, h
}

func finishShortResponse(t *testing.T, f *serviceDispatchFixture, h protocolv4.ApplicationHeader, serial uint64, payload []byte) {
	t.Helper()
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	receiveShortResponse(t, f, h, serial, payload)
}

func receiveShortResponse(t *testing.T, f *serviceDispatchFixture, h protocolv4.ApplicationHeader, serial uint64, payload []byte) {
	t.Helper()
	fields := h.Fields()
	fields.Kind, fields.DeadlineAtMS, fields.AdmissionMode, fields.ResponseLimitBytes = 0, 0, 0, 0
	fields.PayloadBytes = uint32(len(payload))
	var wire, encoded [512]byte
	kind := "transient_unary_response"
	if h.HasExecutionIdentity() {
		kind = "execution_unary_response"
	}
	n, _, err := f.codec.Encode(wire[:], kind, fields)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []protocolv4.RPCFragment{{Kind: protocolv4.RPCBegin, Serial: serial, ReplyTo: serial, Header: wire[:n]}, {Kind: protocolv4.RPCData, Serial: serial, Payload: payload}} {
		n, err := protocolv4.EncodeRPCFragment(encoded[:], fragment)
		if err != nil {
			t.Fatal(err)
		}
		if used, err := f.receiver.Feed(encoded[:n]); err != nil || used != n {
			t.Fatal(used, err)
		}
	}
}

func finishShortDecode(t *testing.T, r *RPCServices) {
	t.Helper()
	r.AdvanceCalls()
	r.mu.Lock()
	i := r.localCall
	r.mu.Unlock()
	if i == nil {
		return
	}
	i.mu.Lock()
	task := i.task
	i.mu.Unlock()
	if task != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := task.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	r.AdvanceCalls()
}

func TestShortCallerFullResultAndCompletionAtSaturatedRoot(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	saturateServiceRoot(t, f)
	before := f.f.root.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for serial := uint64(1); serial <= 3; serial++ {
		var decoded []byte
		call, h := beginShortCall(t, f, r, route, context.Background(), func(input rpcv4.InputBorrow) error {
			p, _, err := input.Bytes()
			decoded = bytes.Clone(p)
			return err
		})
		finishShortResponse(t, f, h, serial, []byte("original result"))
		finishShortDecode(t, r)
		outcome, err := call.Wait(ctx)
		if err != nil || outcome.Error != nil || outcome.Reason != "" || outcome.SDKErrorCode != 0 || !bytes.Equal(decoded, []byte("original result")) {
			t.Fatal(outcome, err, string(decoded))
		}
		if after := f.f.root.Snapshot(); after != before {
			t.Fatal("call changed protected quota", before, after)
		}
	}
}

func TestShortCallerDecoderTailSurvivesSessionClose(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	call, h := beginShortCall(t, f, r, route, context.Background(), func(input rpcv4.InputBorrow) error {
		close(entered)
		<-release
		p, _, err := input.Bytes()
		if err == nil && string(p) != "result" {
			return errors.New("original result changed")
		}
		return err
	})
	finishShortResponse(t, f, h, 1, []byte("result"))
	r.AdvanceCalls()
	awaitApplicationTask(t, entered)
	r.mu.Lock()
	r.channel = nil
	r.mu.Unlock()
	r.Close()
	if r.completionFloor.CleanupComplete() || f.f.root.Snapshot().ResultOwners != 1 {
		t.Fatal("Session close refunded live decoder")
	}
	var refs [6]resourcev4.Reference
	if err := resourcev4.CheckoutProtectedBatch(r.shortCaller[:], refs[:]); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("closed floor reused", err)
	}
	once.Do(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := r.waitCalls(ctx); err != nil {
		t.Fatal(err)
	}
	outcome, err := call.Wait(ctx)
	if err != nil || outcome.Error != nil {
		t.Fatal(outcome, err)
	}
	if f.f.root.Snapshot().ResultOwners != 0 {
		t.Fatal("actual decoder exit retained result owner")
	}
}

func TestShortCallerCancellationBeforePublicationReturnsOriginalFloor(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	call, _ := beginShortCall(t, f, r, route, ctx, func(rpcv4.InputBorrow) error { t.Error("canceled call decoded"); return nil })
	cancel()
	r.AdvanceCalls()
	wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	outcome, err := call.Wait(wait)
	if err != nil || !errors.Is(outcome.Error, context.Canceled) || f.network.Snapshot().OutgoingGeneral != 0 {
		t.Fatal(outcome, err, f.network.Snapshot())
	}
	if r.localCall != nil {
		t.Fatal("unpublished cancellation retained call")
	}
	if _, err := r.BeginShortUnary(ctx, route, protocolv4.ApplicationHeader{}, nil, nil, func(rpcv4.InputBorrow) error { return nil }); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal(err)
	}
}

func TestShortCallerRetainsRequestTailAfterNetworkAndDecoderFinish(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	saturateServiceRoot(t, f)
	before := f.f.root.Snapshot()
	call, h := beginShortCall(t, f, r, route, context.Background(), func(input rpcv4.InputBorrow) error { _, _, err := input.Bytes(); return err })
	if ok, err := f.publisher.Step(context.Background()); err != nil || !ok {
		t.Fatal(ok, err)
	}
	// Complete BEGIN's provider observation, then leave the accepted DATA's
	// own provider completion outstanding after peer/result completion.
	if ok, err := f.publisher.Step(context.Background()); err != nil || !ok {
		t.Fatal(ok, err)
	}
	f.sink.held.Store(true)
	receiveShortResponse(t, f, h, 1, []byte("result"))
	finishShortDecode(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if outcome, err := call.Wait(ctx); err != nil || outcome.Error != nil {
		t.Fatal(outcome, err)
	}
	if f.network.Snapshot().OutgoingGeneral != 0 {
		t.Fatal("complete input retained network slot")
	}
	var refs [6]resourcev4.Reference
	if err := resourcev4.CheckoutProtectedBatch(r.shortCaller[:], refs[:]); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("new call reused live request provider tail", err)
	}
	if r.localCall == nil || f.f.root.Snapshot() != before {
		t.Fatal("old provider responsibility was dropped")
	}
	f.sink.held.Store(false)
	if _, err := f.publisher.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.AdvanceCalls()
	if r.localCall != nil || f.f.root.Snapshot() != before {
		t.Fatal("actual provider exit did not restore original floor")
	}
}

func TestShortCallerQueuedDecoderRechecksOriginalEntryGate(t *testing.T) {
	for _, gate := range []string{"lease", "endpoint", "context", "services"} {
		t.Run(gate, func(t *testing.T) {
			f, r, route := shortCallerFixture(t, 3)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			reservation, err := f.f.executor.ReserveCompletion(f.f.reserve(t, 1, f.f.executor.CompletionCharge()), f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}))
			if err != nil {
				t.Fatal(err)
			}
			blocker, err := reservation.Submit(func() error { close(entered); <-release; return nil })
			if err != nil {
				t.Fatal(err)
			}
			awaitApplicationTask(t, entered)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call, h := beginShortCall(t, f, r, route, ctx, func(rpcv4.InputBorrow) error { t.Error("closed gate disclosed application input"); return nil })
			finishShortResponse(t, f, h, 1, []byte("private result"))
			r.AdvanceCalls()
			if r.localCall.task == nil {
				t.Fatal("decoder was not queued behind original Completion worker")
			}
			switch gate {
			case "lease":
				f.plan.lease.Revoke()
			case "endpoint":
				f.plan.lease.authorization.Close(ErrApplicationAuthorization)
			case "context":
				cancel()
			case "services":
				r.mu.Lock()
				r.channel = nil // This component fixture owns its publisher separately.
				r.mu.Unlock()
				r.Close()
			}
			once.Do(func() { close(release) })
			wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := blocker.Wait(wait); err != nil {
				t.Fatal(err)
			}
			_ = r.localCall.task.Wait(wait)
			r.AdvanceCalls()
			outcome, err := call.Wait(wait)
			if err != nil || outcome.Error == nil || outcome.ApplicationInputDelivered {
				t.Fatal("queued decoder bypassed entry gate", outcome, err)
			}
		})
	}
}

func TestShortCallerCompleteInputDisarmsDeadlineBeforeDelayedDecode(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	r.completionGraceMS = 100
	call, h := beginShortCall(t, f, r, route, context.Background(), func(input rpcv4.InputBorrow) error { _, _, err := input.Bytes(); return err }, 1500)
	finishShortResponse(t, f, h, 1, []byte("complete before deadline"))
	f.trust.tick.Store(400) // Original receive deadline has passed, authorization remains valid.
	finishShortDecode(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	outcome, err := call.Wait(ctx)
	if err != nil || outcome.Error != nil || outcome.Reason != "" || !outcome.ApplicationInputDelivered {
		t.Fatal("complete response was given an implicit TTL", outcome, err)
	}
}

func TestShortCallerReceivesWithinOriginalFiniteGrace(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	call, h := beginShortCall(t, f, r, route, context.Background(), func(input rpcv4.InputBorrow) error { _, _, err := input.Bytes(); return err }, 1500)
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	f.trust.tick.Store(400) // Business deadline 1500 has passed; receive grace is still valid.
	finishShortResponse(t, f, h, 1, []byte("in flight result"))
	finishShortDecode(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	outcome, err := call.Wait(ctx)
	if err != nil || outcome.Error != nil || outcome.Reason != "" || !outcome.ApplicationInputDelivered {
		t.Fatal("business deadline removed finite receive grace", outcome, err)
	}
}

func TestShortCallerCompletionDeadlineKeepsLateNetworkResponsibility(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	r.completionGraceMS = 100
	call, h := beginShortCall(t, f, r, route, context.Background(), func(rpcv4.InputBorrow) error { t.Error("expired result decoded"); return nil }, 1500)
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	f.trust.tick.Store(400)
	r.AdvanceCalls()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	outcome, err := call.Wait(ctx)
	if err != nil || !errors.Is(outcome.Error, timev4.ErrExpired) || outcome.Reason != "result_abandoned" || outcome.ApplicationInputDelivered {
		t.Fatal("receive deadline did not settle local result", outcome, err)
	}
	if f.network.Snapshot().OutgoingGeneral != 1 || r.localCall == nil {
		t.Fatal("expiry refunded the original late-response association")
	}
	finishShortResponse(t, f, h, 1, []byte("late response"))
	r.AdvanceCalls()
	if f.network.Snapshot().OutgoingGeneral != 0 || r.localCall != nil {
		t.Fatal("late response did not release the original responsibility")
	}
}
