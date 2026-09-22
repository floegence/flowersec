package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func TestUnaryAbandonBeforePublicationKeepsOriginalStart(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	o, err := r.PrepareUnaryResult(context.Background(), route, []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, ApplicationShort, func(_ context.Context, input []byte) (any, error) { return input, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	before := f.f.root.Snapshot()
	if status, err := o.AbandonResult(); !errors.Is(err, ErrUnaryNotStarted) || status.Abandoned || status.Request != o.header {
		t.Fatal(status, err)
	}
	if f.f.root.Snapshot() != before || o.started || o.closed {
		t.Fatal("not_started consumed prepared rights")
	}
	first := o.Start(context.Background())
	if first.Error != nil || first.Call == nil {
		t.Fatal(first)
	}
	before = f.f.root.Snapshot()
	if status, err := o.AbandonResult(); !errors.Is(err, ErrUnaryNotStarted) || status.Submission.HeaderAccepted || status.Abandoned {
		t.Fatal(status, err)
	}
	if f.f.root.Snapshot() != before {
		t.Fatal("unpublished abandonment changed original owner")
	}
	finishShortResponse(t, f, o.header, 1, []byte("result"))
	r.AdvanceCalls()
	if value, _, err := first.Call.TakeResult(resultTestContext(t)); err != nil || string(value.([]byte)) != "result" {
		t.Fatal(value, err)
	}
	if again := o.Start(context.Background()); again.Call != first.Call {
		t.Fatal("abandonment replaced Start", again)
	}
}

func TestUnaryAbandonCompleteInputDoesNotCreateStopOrLatePosition(t *testing.T) {
	for _, coordinated := range []bool{false, true} {
		t.Run(map[bool]string{false: "reader", true: "coordinator"}[coordinated], func(t *testing.T) {
			f, r, route, _ := deferredCallerFixture(t)
			var decodes atomic.Uint32
			call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { decodes.Add(1); return nil, nil })
			finishShortResponse(t, f, h, 1, []byte("private"))
			if coordinated {
				r.AdvanceCalls()
			}
			status, err := call.AbandonResult()
			if err != nil || !status.Abandoned || status.Available || status.Delivered || status.Request != h || !status.Submission.HeaderAccepted || status.Outcome.Header.Kind() != "transient_unary_response" {
				t.Fatal(status, err)
			}
			for range 2 {
				if again, err := call.AbandonResult(); err != nil || !again.Abandoned || again.Outcome.Reason != "result_abandoned" {
					t.Fatal(again, err)
				}
				if _, got, err := call.TakeResult(resultTestContext(t)); !errors.Is(err, ErrUnaryResultAbandoned) || !got.Abandoned {
					t.Fatal(got, err)
				}
				if _, got, err := call.TakeEncodedResult(resultTestContext(t)); !errors.Is(err, ErrUnaryResultAbandoned) || !got.Abandoned {
					t.Fatal(got, err)
				}
			}
			call.Close()
			r.AdvanceCalls()
			if progressed, err := f.publisher.Step(context.Background()); err != nil || progressed {
				t.Fatal("complete input manufactured a stop", progressed, err)
			}
			if f.network.Snapshot().OutgoingGeneral != 0 || decodes.Load() != 0 {
				t.Fatal("abandonment retained a network position or decoded")
			}
		})
	}
}

func TestUnaryAbandonIncompleteResponseRetainsOriginalLateOwner(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { t.Error("abandoned decoder entered"); return nil, nil })
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	before := f.f.root.Snapshot().ResultOwners
	if status, err := call.AbandonResult(); err != nil || !status.Abandoned || !status.Submission.MessageAccepted {
		t.Fatal(status, err)
	}
	if _, err := call.AbandonResult(); err != nil {
		t.Fatal(err)
	}
	r.AdvanceCalls()
	if f.f.root.Snapshot().ResultOwners != before || f.network.Snapshot().OutgoingGeneral != 1 {
		t.Fatal("local abandonment refunded actual late input")
	}
	if progressed, err := f.publisher.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	fragment, err := protocolv4.DecodeRPCFragment(f.sink.wire)
	if err != nil || fragment.Kind != protocolv4.RPCStopOutput {
		t.Fatal("wrong original stop boundary", fragment, err)
	}
	if progressed, err := f.publisher.Step(context.Background()); err != nil || progressed {
		t.Fatal("duplicate stop", progressed, err)
	}
	receiveShortResponse(t, f, h, 1, []byte("late private result"))
	r.AdvanceCalls()
	if f.network.Snapshot().OutgoingGeneral != 0 {
		t.Fatal("late input did not settle original K")
	}
	if status, err := call.WaitStatus(resultTestContext(t)); err != nil || !status.Abandoned || status.Outcome.Reason != "result_abandoned" {
		t.Fatal(status, err)
	}
}

func TestUnaryAbandonKeepsRealDecoderAndOwnedInput(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var inputAlias []byte
	call, h := beginDeferredCall(t, f, r, route, func(_ context.Context, input []byte) (any, error) {
		inputAlias = input
		close(entered)
		<-release
		return input, nil
	})
	finishShortResponse(t, f, h, 1, []byte("owned"))
	r.AdvanceCalls()
	result := make(chan error, 1)
	go func() { _, _, err := call.TakeResult(resultTestContext(t)); result <- err }()
	awaitApplicationTask(t, entered)
	before := f.f.root.Snapshot()
	if status, err := call.AbandonResult(); err != nil || !status.Abandoned || !status.DecoderRunning || !status.Outcome.ApplicationInputDelivered {
		t.Fatal(status, err)
	}
	if err := <-result; !errors.Is(err, ErrUnaryResultAbandoned) {
		t.Fatal("pending consumer lost abandonment", err)
	}
	call.advanceResult()
	if after := f.f.root.Snapshot(); after.ResultOwners != before.ResultOwners || after.Charged != before.Charged {
		t.Fatal("abandonment refunded running decoder", before, after)
	}
	if !bytes.Equal(inputAlias, []byte("owned")) {
		t.Fatal("abandonment wiped application input")
	}
	call.mu.Lock()
	task := call.deferred.task
	call.mu.Unlock()
	once.Do(func() { close(release) })
	awaitApplicationTask(t, task.Done())
	call.advanceResult()
	if _, status, err := call.TakeResult(resultTestContext(t)); !errors.Is(err, ErrUnaryResultAbandoned) || !status.Abandoned {
		t.Fatal(status, err)
	}
	if !bytes.Equal(inputAlias, []byte("owned")) {
		t.Fatal("actual decoder exit wiped application input")
	}
}

func TestUnaryAbandonAndEncodedHandoffHaveOneWinner(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { t.Error("encoded result decoded"); return nil, nil })
	finishShortResponse(t, f, h, 1, []byte("owned result"))
	r.AdvanceCalls()
	var wg sync.WaitGroup
	var payload []byte
	var takeErr, abandonErr error
	wg.Add(2)
	go func() { defer wg.Done(); payload, _, takeErr = call.TakeEncodedResult(resultTestContext(t)) }()
	go func() { defer wg.Done(); _, abandonErr = call.AbandonResult() }()
	wg.Wait()
	switch {
	case takeErr == nil:
		if !errors.Is(abandonErr, ErrUnaryResultDelivered) || !bytes.Equal(payload, []byte("owned result")) {
			t.Fatal(takeErr, abandonErr, payload)
		}
		if status, err := call.AbandonResult(); !errors.Is(err, ErrUnaryResultDelivered) || !status.Delivered || status.Abandoned {
			t.Fatal(status, err)
		}
	case abandonErr == nil:
		if !errors.Is(takeErr, ErrUnaryResultAbandoned) || len(payload) != 0 {
			t.Fatal(takeErr, abandonErr)
		}
	default:
		t.Fatal("no original handoff winner", takeErr, abandonErr)
	}
}

func TestUnaryAbandonPartialRequestSelectsOneAbort(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { t.Error("abandoned decoder entered"); return nil, nil })
	if progressed, err := f.publisher.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	if status, err := call.AbandonResult(); err != nil || !status.Abandoned || !status.Submission.HeaderAccepted || status.Submission.MessageAccepted {
		t.Fatal(status, err)
	}
	if _, err := call.AbandonResult(); err != nil {
		t.Fatal(err)
	}
	if progressed, err := f.publisher.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	fragment, err := protocolv4.DecodeRPCFragment(f.sink.wire)
	if err != nil || fragment.Kind != protocolv4.RPCAbort || fragment.Offset != 0 {
		t.Fatal("abandonment published a request suffix", fragment, err)
	}
	var payload [16]byte
	code, err := protocolv4.EnumValue("ApplicationSDKError", "code", "request_message_aborted")
	if err != nil {
		t.Fatal(err)
	}
	body, err := protocolv4.EncodeMap(payload[:], "ApplicationSDKError", []protocolv4.Field{{Name: "code", Number: code}})
	if err != nil {
		t.Fatal(err)
	}
	var header, wire [512]byte
	n, _, err := f.codec.EncodeSDKResponse(header[:], h, uint32(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []protocolv4.RPCFragment{{Kind: protocolv4.RPCBegin, Serial: 1, ReplyTo: 1, Header: header[:n]}, {Kind: protocolv4.RPCData, Serial: 1, Payload: body}} {
		n, err = protocolv4.EncodeRPCFragment(wire[:], fragment)
		if err != nil {
			t.Fatal(err)
		}
		if consumed, err := f.receiver.Feed(wire[:n]); err != nil || consumed != n {
			t.Fatal(consumed, err)
		}
	}
	if progressed, err := f.publisher.Step(context.Background()); err != nil || progressed {
		t.Fatal("abort was repeated", progressed, err)
	}
	r.AdvanceCalls()
	if status, err := call.WaitStatus(resultTestContext(t)); err != nil || !status.Abandoned || f.network.Snapshot().OutgoingGeneral != 0 {
		t.Fatal(status, err)
	}
}

func TestUnaryAbandonCompleteResponseWithdrawsUnstartedStop(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { t.Error("abandoned decoder entered"); return nil, nil })
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := call.AbandonResult(); err != nil {
		t.Fatal(err)
	}
	receiveShortResponse(t, f, h, 1, []byte("complete"))
	r.AdvanceCalls()
	if progressed, err := f.publisher.Step(context.Background()); err != nil || progressed {
		t.Fatal("complete input retained stop publication", progressed, err)
	}
	if f.network.Snapshot().OutgoingGeneral != 0 {
		t.Fatal("complete input retained late position")
	}
}

func TestUnaryAbandonRetainsAcceptedStopProviderTail(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	call, h := beginDeferredCall(t, f, r, route, func(context.Context, []byte) (any, error) { t.Error("abandoned decoder entered"); return nil, nil })
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	before := f.f.root.Snapshot().ResultOwners
	f.sink.held.Store(true)
	defer f.sink.held.Store(false)
	if _, err := call.AbandonResult(); err != nil {
		t.Fatal(err)
	}
	if progressed, err := f.publisher.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	receiveShortResponse(t, f, h, 1, []byte("complete"))
	r.AdvanceCalls()
	call.advanceResult()
	if call.ResultStatus().CleanupComplete || f.f.root.Snapshot().ResultOwners != before || f.network.Snapshot().OutgoingGeneral != 0 {
		t.Fatal("complete input refunded an accepted STOP provider tail")
	}
	f.sink.held.Store(false)
	if progressed, err := f.publisher.Step(context.Background()); err != nil || progressed {
		t.Fatal(progressed, err)
	}
	r.AdvanceCalls()
	call.advanceResult()
	if !call.ResultStatus().CleanupComplete {
		t.Fatal("actual provider exit did not finish original cleanup")
	}
}
