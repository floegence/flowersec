package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func bindServiceClientFixture(t *testing.T, r *RPCServices, method UnaryMethodDefinition) *UnaryServiceClient {
	t.Helper()
	client, err := r.bindUnaryService(method)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestServiceClientClosePreservesTransferredOperationAndSharedSession(t *testing.T) {
	f, r, _, e := deferredCallerFixture(t)
	r.routes = f.routes
	method := UnaryMethodDefinition{Contract: f.policy.Digest, WorkClass: ApplicationShort, Decode: synchronousResult, DefaultResponseLimitBytes: 1024}
	client := bindServiceClientFixture(t, r, method)
	method.Contract, method.DefaultResponseLimitBytes = [32]byte{99}, 1
	op, err := client.Prepare(context.Background(), []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	if op.header.Fields().ResponseLimitBytes != 1024 || op.header.Fields().ServiceContractDigest != f.policy.Digest {
		t.Fatal("caller changed captured binding")
	}
	client.Close()
	if !client.advance() || client.CleanupStatus().Status != protocolv4.V4CleanupStateComplete {
		t.Fatal("independent operation retained closed client")
	}
	if _, err := client.Prepare(context.Background(), nil, rpcv4.UnaryPreparation{}); err != cryptov4.ErrClosed {
		t.Fatal("closed client prepared again", err)
	}
	if err := client.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if e.OperationsSnapshot().Closed {
		t.Fatal("client closed borrowed Environment")
	}
	if result := op.Start(context.Background()); result.Error != nil {
		t.Fatal("client revoked transferred handle", result.Error)
	}
	finishShortResponse(t, f, op.header, 1, []byte("result"))
	r.AdvanceCalls()
	value, _, err := op.TakeResult(resultTestContext(t))
	if err != nil || string(value.([]byte)) != "result" {
		t.Fatal(value, err)
	}
}

func TestServiceClientCloseWaitsForOriginalEncoderExit(t *testing.T) {
	f, r, _, e := deferredCallerFixture(t)
	r.routes = f.routes
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	method := UnaryMethodDefinition{Contract: f.policy.Digest, WorkClass: ApplicationShort, Decode: synchronousResult, DefaultResponseLimitBytes: 1024,
		Codec: SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) {
			close(entered)
			<-release
			return input, nil
		}}}
	client := bindServiceClientFixture(t, r, method)
	exited := make(chan error, 1)
	go func() {
		op, err := client.Prepare(context.Background(), []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
		if op != nil {
			op.Close()
			err = errors.New("late preparation escaped closed binding")
		}
		exited <- err
	}()
	<-entered
	before := f.f.root.Snapshot().Charged
	client.Close()
	if client.advance() || client.CleanupStatus().PendingCallbacks != 1 || e.OperationsSnapshot().ActiveServiceClients != 1 {
		t.Fatal("close erased live encoder ownership")
	}
	if f.f.root.Snapshot().Charged != before {
		t.Fatal("close refunded active encoder")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.WaitCleanup(ctx); err != context.Canceled {
		t.Fatal("canceled wait altered original cleanup", err)
	}
	finish()
	if err := <-exited; err == nil {
		t.Fatal("late encoder returned an operation")
	}
	if err := client.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	e.advanceServiceClients()
	if e.OperationsSnapshot().ActiveServiceClients != 0 {
		t.Fatal("exited binding slot retained")
	}
}

func TestServiceClientCloseCancelsConvenienceCallAndRetainsNetworkTail(t *testing.T) {
	f, r, _, _ := deferredCallerFixture(t)
	r.routes = f.routes
	client := bindServiceClientFixture(t, r, UnaryMethodDefinition{Contract: f.policy.Digest, WorkClass: ApplicationShort, Decode: synchronousResult, DefaultResponseLimitBytes: 1024})
	exited := make(chan error, 1)
	go func() {
		_, _, err := client.Call(context.Background(), []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
		exited <- err
	}()
	var operation *UnaryOperation
	limit := time.Now().Add(3 * time.Second)
	for time.Now().Before(limit) {
		client.mu.Lock()
		operation = client.calls[0].operation
		client.mu.Unlock()
		if operation != nil && operation.Snapshot().Started {
			break
		}
		runtime.Gosched()
	}
	if operation == nil || !operation.Snapshot().Started {
		t.Fatal("convenience call did not start")
	}
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !operation.Snapshot().Result.Submission.HeaderAccepted {
		t.Fatal("request not actually submitted")
	}
	client.Close()
	if err := <-exited; err == nil {
		t.Fatal("closed convenience call succeeded")
	}
	r.AdvanceCalls()
	if client.advance() {
		t.Fatal("client refunded original late response")
	}
	if r.closed || f.plan.closed {
		t.Fatal("client closed borrowed Session")
	}
	f.publisher.Close()
	f.receiver.Close()
	r.AdvanceCalls()
	if err := client.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

func TestServiceClientEnvironmentSlotsAreBoundedAndReusableAfterExit(t *testing.T) {
	f, r, _, e := deferredCallerFixture(t)
	r.routes = f.routes
	method := UnaryMethodDefinition{Contract: f.policy.Digest, WorkClass: ApplicationShort, Decode: synchronousResult, DefaultResponseLimitBytes: 1024}
	var clients [64]*UnaryServiceClient
	for j := range clients {
		clients[j] = bindServiceClientFixture(t, r, method)
	}
	before := f.f.root.Snapshot()
	if extra, err := r.bindUnaryService(method); err != cryptov4.ErrCapacity || extra != nil || f.f.root.Snapshot() != before {
		t.Fatal("binding overflow allocated or escaped fixed table", err)
	}
	clients[0].Close()
	e.advanceServiceClients()
	replacement := bindServiceClientFixture(t, r, method)
	if replacement == clients[0] || e.OperationsSnapshot().ActiveServiceClients != 64 {
		t.Fatal("binding reused old identity or lost accounting")
	}
}
