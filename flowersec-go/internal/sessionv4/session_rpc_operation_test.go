package sessionv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func prepareCallerOperation(t *testing.T, r *RPCServices, route rpcv4.ContractRoute, options rpcv4.UnaryPreparation, payload []byte) *UnaryOperation {
	t.Helper()
	o, err := r.PrepareUnary(route, payload, options, ApplicationShort, true, func(input rpcv4.InputBorrow) error { _, _, err := input.Bytes(); return err })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	return o
}

func TestPreparedUnarySingleFlightAndImmutableInput(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	payload := []byte("original input")
	o := prepareCallerOperation(t, r, route, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, payload)
	copy(payload, []byte("changed input!"))
	var results [12]UnaryStartResult
	var wg sync.WaitGroup
	for j := range results {
		wg.Add(1)
		go func() { defer wg.Done(); results[j] = o.Start(context.Background()) }()
	}
	wg.Wait()
	for _, result := range results {
		if result.Error != nil || result.Call == nil || result.Call != results[0].Call || result.NotAdmitted {
			t.Fatal(result)
		}
	}
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.network.Snapshot().OutgoingGeneral != 1 {
		t.Fatal("duplicate Start allocated another original association")
	}
	data := f.sink.wire
	if !bytes.Contains(data, []byte("original input")) || bytes.Contains(data, payload) {
		t.Fatal("prepared bytes changed", data)
	}
	wait, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.Wait(wait); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	finishShortResponse(t, f, o.header, 1, []byte("result"))
	finishShortDecode(t, r)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	result, err := o.Wait(ctx)
	if err != nil || result.Error != nil || !result.ApplicationInputDelivered {
		t.Fatal(result, err)
	}
	if !o.detached || o.services != nil {
		t.Fatal("completed operation retained Session graph")
	}
	if retry := o.Start(wait); retry.Call != results[0].Call || retry.Error != nil {
		t.Fatal("repeated Start replaced original", retry)
	}
}

func TestPreparedTryNowMissKeepsOnlyOriginalPreparedRights(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	o := prepareCallerOperation(t, r, route, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024, AdmissionMode: 1}, []byte("request"))
	r.mu.Lock()
	channel := r.channel
	r.channel = nil
	r.mu.Unlock()
	first := o.Start(context.Background())
	if !first.NotAdmitted || !errors.Is(first.Error, cryptov4.ErrNotReady) || first.Call != nil {
		t.Fatal(first)
	}
	if o.started || f.network.Snapshot().OutgoingGeneral != 0 || len(f.sink.wire) != 0 {
		t.Fatal("local miss created publication rights")
	}
	r.mu.Lock()
	r.channel = channel
	r.mu.Unlock()
	second := o.Start(context.Background())
	if second.Error != nil || second.Call == nil {
		t.Fatal(second)
	}
	finishShortResponse(t, f, o.header, 1, []byte("result"))
	finishShortDecode(t, r)
}

func TestPreparedQueuedFailureCannotStartAgain(t *testing.T) {
	_, r, route := shortCallerFixture(t)
	o := prepareCallerOperation(t, r, route, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, nil)
	r.mu.Lock()
	channel := r.channel
	r.channel = nil
	r.mu.Unlock()
	first := o.Start(context.Background())
	r.mu.Lock()
	r.channel = channel
	r.mu.Unlock()
	second := o.Start(context.Background())
	if !errors.Is(first.Error, cryptov4.ErrNotReady) || first.NotAdmitted || second.Call != nil || second.Error != first.Error {
		t.Fatal(first, second)
	}
}

func TestPreparedLifetimeAndExactGuaranteeRejection(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	before := f.f.root.Snapshot()
	for _, options := range []rpcv4.UnaryPreparation{
		{DeadlineAtMS: 2000, ResponseLimitBytes: 1024, RequireDurable: true},
		{DeadlineAtMS: 2000, ResponseLimitBytes: 1024, RequireExecution: true},
		{DeadlineAtMS: ^uint64(0), ResponseLimitBytes: 1024},
	} {
		o, err := r.PrepareUnary(route, nil, options, ApplicationShort, true, func(rpcv4.InputBorrow) error { return nil })
		if err == nil || o != nil {
			t.Fatal("unsupported preparation accepted", o, err)
		}
		if after := f.f.root.Snapshot(); after != before {
			t.Fatal("preparation failure leaked", before, after)
		}
	}
	o := prepareCallerOperation(t, r, route, rpcv4.UnaryPreparation{DeadlineAtMS: 1500, ResponseLimitBytes: 1024}, nil)
	f.trust.tick.Store(400)
	r.AdvanceCalls()
	if !o.closed || !o.detached || !errors.Is(o.failure, timev4.ErrExpired) {
		t.Fatal("prepared lifetime renewed", o.failure)
	}
	if result := o.Start(context.Background()); result.Call != nil || result.Error == nil {
		t.Fatal(result)
	}
}

func TestUnaryRequestPublicationRechecksOriginalGates(t *testing.T) {
	for _, reason := range []string{"registration", "deadline", "binding_release"} {
		t.Run(reason, func(t *testing.T) {
			f, r, route := shortCallerFixture(t)
			call, h := beginShortCall(t, f, r, route, context.Background(), func(rpcv4.InputBorrow) error { return nil }, 1500)
			switch reason {
			case "registration":
				if err := f.routes.SetRegistered(f.policy.Digest, false); err != nil {
					t.Fatal(err)
				}
			case "deadline":
				f.trust.tick.Store(400)
			case "binding_release":
				route.Release()
			}
			if _, err := f.publisher.Step(context.Background()); err != nil {
				t.Fatal(err)
			}
			if reason == "binding_release" {
				finishShortResponse(t, f, h, 1, []byte("reply"))
				finishShortDecode(t, r)
			} else {
				if len(f.sink.wire) != 0 || f.network.Snapshot().OutgoingGeneral != 0 {
					t.Fatal("unauthorized bytes or serial escaped")
				}
				r.AdvanceCalls()
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			outcome, err := call.Wait(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if reason == "binding_release" {
				if outcome.Error != nil {
					t.Fatal(outcome)
				}
			} else if outcome.Error == nil || outcome.ApplicationInputDelivered {
				t.Fatal(outcome)
			}
		})
	}
}

func TestExecutionUnaryPreparedIdentityAndOriginalResponse(t *testing.T) {
	f := newServiceDispatchFixtureProfile(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { return 0, nil }, false, ApplicationShort, true)
	f, r, route := callerForServiceFixture(t, f)
	options := rpcv4.UnaryPreparation{DeadlineAtMS: 2000, AdmissionNotAfterMS: 1800, ResponseLimitBytes: 1024, Offer: protocolv4.AdmissionOfferBounds{Digest: f.policy.Digest, NotBeforeMS: 1000, NotAfterMS: 1600}}
	o := prepareCallerOperation(t, r, route, options, []byte("execution request"))
	h := o.header
	fields := h.Fields()
	if !h.HasExecutionIdentity() || binary.BigEndian.Uint64(fields.OperationID[:8]) != 1600 || fields.RequestDigest == ([32]byte{}) {
		t.Fatal("wrong fixed execution identity")
	}
	digest, err := protocolv4.ComputeExecutionRequestDigest(h, f.contract, []byte("execution request"))
	if err != nil || digest != fields.RequestDigest {
		t.Fatal("digest does not bind complete immutable request", err)
	}
	first := o.Start(context.Background())
	if first.Error != nil || first.Call == nil {
		t.Fatal(first)
	}
	finishShortResponse(t, f, h, 1, []byte("execution result"))
	finishShortDecode(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := o.Wait(ctx)
	if err != nil || result.Error != nil || result.Header.Fields().OperationID != fields.OperationID || !result.ApplicationInputDelivered {
		t.Fatal(result, err)
	}
}
