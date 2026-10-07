package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func serviceShapesFixture(t *testing.T) (*serviceDispatchFixture, *RPCServices, *Environment, ServiceDefinition) {
	t.Helper()
	f, r, _, e := deferredCallerFixture(t)
	cfg := rpcv4.ContractRoutesConfig{ContractNodes: 256, RuntimeBytes: 4096, Methods: make([]rpcv4.MethodRoutes, 3)}
	definition := ServiceDefinition{Namespace: f.policy.Namespace, Methods: make([]ServiceMethod, 3)}
	for j, name := range []string{"service_unary_transient", "service_stream_transient", "service_notify_observation"} {
		body := admissionMap(t, "ServiceContract", initialFixture(t, name), map[string]protocolv4.Field{"type_id": {Number: uint64(j + 1)}})
		codec, err := protocolv4.NewServiceContractCodec(256)
		if err != nil {
			t.Fatal(err)
		}
		contract, err := codec.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := contract.Digest()
		contract.Release()
		cfg.Methods[j].Contracts = [][]byte{body}
		m := ServiceMethod{Type: uint32(j + 1), Shape: uint8(j), Method: UnaryMethodDefinition{Contract: digest, WorkClass: ApplicationShort}}
		if j < 2 {
			m.Method.Decode, m.Method.DefaultResponseLimitBytes = synchronousResult, 1024
		}
		if j == 1 {
			m.StreamKind, m.StreamMetadata = "test/events", []byte("original")
		}
		definition.Methods[j] = m
	}
	charge, err := rpcv4.ContractRoutesCharge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := rpcv4.NewContractRoutes(cfg, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	r.routes = routes
	host := r.plan.host
	host.mu.Lock()
	host.core, host.delivered = &SessionCore{plan: &SessionCorePlan{rpc: r}}, true
	host.mu.Unlock()
	return f, r, e, definition
}

func TestServiceClientMixedShapesPrepareAndPartialInstall(t *testing.T) {
	f, r, e, definition := serviceShapesFixture(t)
	var encodes [3]atomic.Int32
	for j := range definition.Methods {
		definition.Methods[j].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) {
			encodes[j].Add(1)
			return append([]byte("encoded:"), input...), nil
		}}
	}
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: []UnaryMethodSelector{{Namespace: definition.Namespace, Type: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if e.OperationsSnapshot().BoundMethods != 3 {
		t.Fatal("mixed descriptors escaped aggregate accounting")
	}
	options := rpcv4.UnaryPreparation{DeadlineAtMS: 2000}
	if _, err := client.PrepareStreamingMethod(context.Background(), 2, nil, options); err != cryptov4.ErrNotReady {
		t.Fatal(err)
	}
	if _, err := client.PrepareNotifyMethod(context.Background(), 3, nil, options); err != cryptov4.ErrNotReady {
		t.Fatal(err)
	}
	if encodes[1].Load()+encodes[2].Load() != 0 {
		t.Fatal("uninstalled methods entered encoder")
	}
	var snapshots [2]UnaryContractSnapshot
	if err := client.Refresh(context.Background(), []uint32{2, 3}, snapshots[:]); err != nil {
		t.Fatal(err)
	}
	for _, s := range snapshots {
		if !s.Installed || s.Error != nil {
			t.Fatal(s)
		}
	}
	definition.Methods[1].StreamMetadata[0] = 'X'
	stream, err := client.PrepareStreamingMethod(context.Background(), 2, []byte("stream"), options)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	notify, err := client.PrepareNotifyMethod(context.Background(), 3, []byte("notify"), options)
	if err != nil {
		t.Fatal(err)
	}
	defer notify.Close()
	if encodes[1].Load() != 1 || encodes[2].Load() != 1 || len(f.sink.wire) != 0 {
		t.Fatal("preparation encoded twice or published")
	}
	if string(stream.owner.stream.metadata) != "original" {
		t.Fatal("binding retained mutable metadata")
	}
	for _, op := range []*UnaryOperation{stream.owner, notify.owner} {
		if op.header.HasExecutionIdentity() {
			t.Fatal("transient operation acquired execution identity")
		}
		if _, err := op.Reference(); !errors.Is(err, rpcv4.ErrExecutionUnsupported) {
			t.Fatal(err)
		}
		if op.header.Fields().PayloadBytes != 14 {
			t.Fatal("prepared header ignored encoder output", op.header.Fields())
		}
	}
	if notify.owner.resultPlan != nil {
		t.Fatal("notification allocated result plan")
	}
	if _, err := client.PrepareMethod(context.Background(), 2, nil, options); err != rpcv4.ErrMethod {
		t.Fatal("shape mismatch accepted", err)
	}
	client.Close()
	if !client.advance() {
		t.Fatal("transferred operations retained service client")
	}
	if stream.owner.Snapshot().Closed || notify.owner.Snapshot().Closed {
		t.Fatal("service close revoked transferred operations")
	}
	stream.Close()
	notify.Close()
	if err := stream.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if err := notify.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

func TestServiceClientMixedShapeValidationBeforeEncoding(t *testing.T) {
	_, r, _, definition := serviceShapesFixture(t)
	if _, err := r.bindUnaryMethods(context.Background(), definition, UnaryServiceBindOptions{}); err != rpcv4.ErrMethod {
		t.Fatal("unary binding accepted another shape", err)
	}
	for _, index := range []int{1, 2} {
		copy := definition
		copy.Methods = append([]ServiceMethod(nil), definition.Methods...)
		if index == 1 {
			copy.Methods[index].StreamKind = ""
		} else {
			copy.Methods[index].Method.Decode = synchronousResult
		}
		if _, err := r.bindMethods(context.Background(), copy, UnaryServiceBindOptions{}); err == nil {
			t.Fatal("invalid shape accepted", index)
		}
	}
}

func TestSessionNotifyConvenienceReturnsAfterSubmission(t *testing.T) {
	f, r, e, definition := notifyWorkloadFixture(t, false)
	publisher, sink := attachNotifyWorkloadPublisher(t, f, r, 0)
	client, workload := bindNotifyWorkload(t, r, e, definition)
	ctx := resultTestContext(t)
	done := make(chan struct {
		result NotificationResult
		err    error
	}, 1)
	go func() {
		result, err := client.NotifyMethod(ctx, f.policy.Type, []byte("notify"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
		done <- struct {
			result NotificationResult
			err    error
		}{result: result, err: err}
	}()

	until := time.Now().Add(3 * time.Second)
	for sink.accepted.Load() == 0 && time.Now().Before(until) {
		if _, err := publisher.Step(ctx); err != nil {
			t.Fatal(err)
		}
		runtime.Gosched()
	}
	if sink.accepted.Load() != 1 {
		t.Fatal("convenience notification header was not accepted by the original publisher")
	}
	// The publisher preserves each accepted chunk's provider tail before
	// admitting the next chunk. Release the header tail, then retain the
	// complete message tail so NotifyMethod can return at submission time.
	sink.flush()
	for sink.accepted.Load() < 2 && time.Now().Before(until) {
		if _, err := publisher.Step(ctx); err != nil {
			t.Fatal(err)
		}
		runtime.Gosched()
	}
	if sink.accepted.Load() < 2 {
		t.Fatal("convenience notification was not fully accepted by the original publisher")
	}

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !result.result.MessageAccepted || result.result.Flushed || result.result.Terminal || result.result.CleanupComplete {
			t.Fatal("convenience notification did not return submission facts before physical cleanup", result.result)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !workload.slots[0].used {
		t.Fatal("convenience notification refunded its original workload before the publication tail was released")
	}

	sink.flush()
	if _, err := publisher.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if !workload.slots[0].used {
		t.Fatal("publication tail release bypassed the original workload coordinator")
	}

	client.Close()
	r.AdvanceCalls()
	e.advanceServiceClients()
	if err := client.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	waitWorkload(t, r, e, func() bool { return !workload.slots[0].used })
}

func TestSessionNotifyPreparedCodecPublishesOriginalOutput(t *testing.T) {
	ctx, services, fixtures, endpoints, _, _ := notificationRuntimeFixture(t)
	var policies [2]protocolv4.ServiceContractPolicy
	for j, r := range services {
		policies[j] = authorizeNotificationRuntime(t, r, fixtures[j])
	}
	observed := make(chan string, 2)
	sub, err := services[1].notifications.Subscribe(0, NotificationDropNewest, notificationStrings(func(_ context.Context, value string) error { observed <- value; return nil }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sub.Close()
		until := time.Now().Add(3 * time.Second)
		for !sub.Status().CleanupComplete && time.Now().Before(until) {
			services[1].notifications.Advance()
			runtime.Gosched()
		}
		if err := sub.Release(); err != nil {
			t.Error(err)
		}
	})
	if _, err := services[0].OpenNotifyChannel(ctx, streamTestDeadline(t, endpoints[0].engine)); err != nil {
		t.Fatal(err)
	}
	var encodes atomic.Int32
	method := UnaryMethodDefinition{Contract: policies[0].Digest, Codec: SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) {
		encodes.Add(1)
		return append([]byte("encoded:"), input...), nil
	}}}
	before := services[0].network.Snapshot()
	op, err := services[0].prepareNotifyMethod(ctx, method, []byte("value"), rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if start := op.Start(ctx); start.Error != nil {
		t.Fatal(start)
	}
	if start := op.Start(ctx); start.Error != nil {
		t.Fatal(start)
	}
	for {
		services[1].notifications.Advance()
		select {
		case value := <-observed:
			if value != "encoded:value" || encodes.Load() != 1 {
				t.Fatal(value, encodes.Load())
			}
			status, err := op.WaitSubmission(ctx)
			if err != nil || !status.MessageAccepted {
				t.Fatal(status, err)
			}
			op.Close()
			services[0].AdvanceCalls()
			if err := op.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if services[0].network.Snapshot() != before {
				t.Fatal("notification acquired response ownership")
			}
			return
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
			runtime.Gosched()
		}
	}
}
