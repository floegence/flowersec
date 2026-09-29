package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func executionServiceClientFixture(t *testing.T) (*serviceDispatchFixture, *RPCServices, *UnaryServiceClient) {
	t.Helper()
	f := newServiceDispatchFixtureProfile(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { return 0, nil }, false, ApplicationShort, true)
	f, r, route := callerForServiceFixture(t, f)
	deferredCallerForServiceFixture(t, f, r, route)
	r.routes = f.routes
	client := bindServiceClientFixture(t, r, UnaryMethodDefinition{Contract: f.policy.Digest, Decode: synchronousResult, DefaultResponseLimitBytes: 1024})
	return f, r, client
}

func TestServiceClientExecutionReferenceSurvivesStartFailure(t *testing.T) {
	f, r, client := executionServiceClientFixture(t)
	r.mu.Lock()
	channel := r.channel
	r.channel = nil
	r.mu.Unlock()
	_, status, err := client.Call(context.Background(), []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, AdmissionMode: 1, ExplicitAdmissionMode: true})
	r.mu.Lock()
	r.channel = channel
	r.mu.Unlock()
	if !errors.Is(err, cryptov4.ErrNotReady) || !status.Reference.Valid() || status.Submission.HeaderAccepted || !status.CleanupComplete || !status.Closed {
		t.Fatal(status, err)
	}
	target := status.Reference.Target()
	if target.ContractDigest != f.policy.Digest || target.Operation != status.Request.Fields().OperationID || target.RequestDigest != status.Request.Fields().RequestDigest {
		t.Fatal("execution reference changed original request")
	}
}

func TestServiceClientExecutionReferenceSurvivesCanceledSubmission(t *testing.T) {
	f, r, client := executionServiceClientFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		status UnaryResultStatus
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		_, s, e := client.Call(ctx, []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
		done <- outcome{s, e}
	}()
	var operation *UnaryOperation
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		client.mu.Lock()
		operation = client.calls[0].operation
		client.mu.Unlock()
		if operation != nil && operation.Snapshot().Started {
			break
		}
		runtime.Gosched()
	}
	if operation == nil || !operation.Snapshot().Started {
		t.Fatal("execution call did not start")
	}
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := operation.Reference()
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	var result outcome
	select {
	case result = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancel retained convenience caller")
	}
	if !errors.Is(result.err, context.Canceled) || result.status.Reference != ref || !result.status.Submission.HeaderAccepted || !result.status.Closed {
		t.Fatal(result.status, result.err)
	}
	if !operation.Snapshot().Closed {
		t.Fatal("canceled scope did not close hidden owner")
	}
	f.publisher.Close()
	f.receiver.Close()
	r.AdvanceCalls()
	client.Close()
	if err := client.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

func TestServiceClientStreamFailureClosesOriginalCandidate(t *testing.T) {
	_, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	// Invalid startup geometry is a local failure before OPEN; the caller
	// must receive no handle and the private candidate must be closed.
	op, err := client.StreamMethod(context.Background(), 2, []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	var failure *StreamingStartFailure
	if op != nil || !errors.As(err, &failure) || failure.Reference.Valid() || !failure.CleanupComplete {
		t.Fatal(op, err)
	}
	client.Close()
	if err := client.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}
