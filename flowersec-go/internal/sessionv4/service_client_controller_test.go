package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func controllerServiceDefinition(f *serviceDispatchFixture) ServiceDefinition {
	return ServiceDefinition{Namespace: f.policy.Namespace, Methods: []ServiceMethod{{Type: f.policy.Type, Method: UnaryMethodDefinition{Contract: f.policy.Digest, Decode: synchronousResult, DefaultResponseLimitBytes: 1024}}}}
}

func closeControllerService(t *testing.T, client *UnaryServiceClient) {
	t.Helper()
	client.Close()
	if err := client.WaitCleanup(resultTestContext(t)); err != nil {
		t.Error(err)
	}
}

func TestControllerServiceNewCallsFollowCurrentAndTransferredHandleSurvivesClose(t *testing.T) {
	f, services, controller, sessions, fixtures := controllerReselectionFixture(t)
	definition := controllerServiceDefinition(f)
	var encodes atomic.Int32
	definition.Methods[0].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) { encodes.Add(1); return input, nil }}
	client, err := controller.BindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeControllerService(t, client) })
	first, err := client.Prepare(context.Background(), []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Close)
	header := first.header
	controller.mu.Lock()
	controller.current = sessions[1]
	controller.mu.Unlock()
	services[0].draining.Store(true)
	client.advance()
	second, err := client.Prepare(context.Background(), []byte("next"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	if first.services != services[0] || second.services != services[1] || encodes.Load() != 2 {
		t.Fatal("new work lost original route selection", encodes.Load())
	}
	second.Close()
	closeControllerService(t, client)
	if controller.Snapshot().Closed {
		t.Fatal("service closed borrowed Controller")
	}
	if start := first.Start(context.Background()); start.Error != nil {
		t.Fatal(start.Error)
	}
	if first.header != header || first.controller.session != sessions[1] || encodes.Load() != 2 {
		t.Fatal("reselection changed immutable preparation")
	}
	finishShortResponse(t, fixtures[1], first.header, 1, []byte("response"))
	advanceControllerServices(services)
	value, status, err := first.TakeResult(resultTestContext(t))
	if err != nil || !status.Delivered || string(value.([]byte)) != "response" {
		t.Fatal(value, status, err)
	}
	if len(fixtures[0].sink.wire) != 0 {
		t.Fatal("retired route published original request")
	}
}

func TestControllerServiceMissingCurrentIsLocalAndAuthorityChangeSealsBinding(t *testing.T) {
	f, _, controller, sessions, _ := controllerReselectionFixture(t)
	definition := controllerServiceDefinition(f)
	var encodes atomic.Int32
	definition.Methods[0].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) { encodes.Add(1); return input, nil }}
	client, err := controller.BindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeControllerService(t, client) })
	controller.mu.Lock()
	controller.current = nil
	controller.mu.Unlock()
	if op, err := client.Prepare(context.Background(), nil, rpcv4.UnaryPreparation{}); op != nil || !errors.Is(err, cryptov4.ErrNotReady) || encodes.Load() != 0 {
		t.Fatal(op, err)
	}
	snapshot := client.Contract(0)
	if !snapshot.Installed || snapshot.Digest != f.policy.Digest || !errors.Is(snapshot.Error, cryptov4.ErrNotReady) {
		t.Fatal(snapshot)
	}
	controller.mu.Lock()
	controller.current = sessions[1]
	controller.mu.Unlock()
	// The authorized application mapping is immutable in production. Changing
	// this fixture's original lease models a differently mapped replacement.
	lease, _, err := f.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	lease.mu.Lock()
	original := lease.execution
	lease.execution.authority[0] ^= 1
	lease.mu.Unlock()
	_, err = client.Prepare(context.Background(), nil, rpcv4.UnaryPreparation{})
	lease.mu.Lock()
	lease.execution = original
	lease.mu.Unlock()
	if !errors.Is(err, ErrApplicationAuthorization) || encodes.Load() != 0 {
		t.Fatal("target mismatch reached encoder", err)
	}
	if _, err := client.Prepare(context.Background(), nil, rpcv4.UnaryPreparation{}); err != cryptov4.ErrClosed {
		t.Fatal("binding reopened after target mismatch", err)
	}
}

func TestControllerServiceCloseRetainsBlockedCodecAndCancelsLateHandoff(t *testing.T) {
	f, _, controller, _, _ := controllerReselectionFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	definition := controllerServiceDefinition(f)
	definition.Methods[0].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) { close(entered); <-release; return input, nil }}
	client, err := controller.BindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeControllerService(t, client) })
	finished := make(chan error, 1)
	go func() {
		op, err := client.Prepare(context.Background(), []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
		if op != nil {
			op.Close()
			err = errors.New("late preparation escaped Close")
		}
		finished <- err
	}()
	<-entered
	before := f.f.root.Snapshot().Charged
	client.Close()
	if client.advance() || client.CleanupStatus().PendingCallbacks != 1 || f.f.root.Snapshot().Charged != before {
		t.Fatal("blocked codec released original ownership")
	}
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("closed binding returned a handle")
	}
	if err := client.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

func controllerStaticRoutes(t *testing.T, f *serviceDispatchFixture, body []byte) (*rpcv4.ContractRoutes, [32]byte) {
	t.Helper()
	codec, _ := protocolv4.NewServiceContractCodec(256)
	contract, err := codec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := contract.Digest()
	contract.Release()
	config := rpcv4.ContractRoutesConfig{ContractNodes: 256, RuntimeBytes: 4096, Methods: []rpcv4.MethodRoutes{{Contracts: [][]byte{body}}}}
	charge, err := rpcv4.ContractRoutesCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := rpcv4.NewContractRoutes(config, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	return routes, digest
}

func TestControllerServiceUpdateUsesNewRegistryAndPreservesPreparedSnapshot(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "bounded"}[bounded], func(t *testing.T) {
			f, services, controller, sessions, _ := controllerReselectionFixture(t)
			definition := controllerServiceDefinition(f)
			if bounded {
				definition.Methods[0].Acceptance, _ = protocolv4.BoundedContractAcceptance(protocolv4.ContractRange{Field: "max_response_bytes", Lower: 1024, Upper: 1048576})
			}
			client, err := controller.BindMethods(context.Background(), definition, UnaryServiceBindOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeControllerService(t, client) })
			old, err := client.Prepare(context.Background(), []byte("old"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(old.Close)
			body := admissionMap(t, "ServiceContract", initialFixture(t, "service_unary_transient"), map[string]protocolv4.Field{"max_response_bytes": {Number: 2048}})
			routes, digest := controllerStaticRoutes(t, f, body)
			services[1].routes = routes
			controller.mu.Lock()
			controller.current = sessions[1]
			controller.mu.Unlock()
			snapshot, err := client.UpdateContract(context.Background(), 0, digest)
			if err != nil || snapshot.Digest != digest || snapshot.Generation != 2 {
				t.Fatal(snapshot, err)
			}
			next, err := client.Prepare(context.Background(), []byte("new"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
			if err != nil {
				t.Fatal(err)
			}
			next.Close()
			if old.header.Fields().ServiceContractDigest != f.policy.Digest || next.header.Fields().ServiceContractDigest != digest || next.header.Fields().ResponseLimitBytes != 1024 {
				t.Fatal("update rewrote preparation or default")
			}
			if !bytes.Equal(client.methods[0].canonical, body) {
				t.Fatal("snapshot lost canonical body")
			}
			bad := admissionMap(t, "ServiceContract", body, map[string]protocolv4.Field{"min_response_limit_bytes": {Number: 2048}, "max_response_bytes": {Number: 4096}})
			services[2].routes, digest = controllerStaticRoutes(t, f, bad)
			controller.mu.Lock()
			controller.current = sessions[2]
			controller.mu.Unlock()
			if _, err = client.UpdateContract(context.Background(), 0, digest); err == nil {
				t.Fatal("invalid local default installed")
			}
			if !bytes.Equal(client.methods[0].canonical, body) {
				t.Fatal("failed candidate changed snapshot")
			}
		})
	}
}

func TestControllerServiceBindingDetachesOnlyCopiedSnapshotSessionScope(t *testing.T) {
	f, services, controller, sessions, _ := controllerReselectionFixture(t)
	limit := f.f.root.Snapshot().Limit
	account, err := f.f.root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: [16]byte{201}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	services[0].accounts[0], services[0].accountCount = account, 1
	client, err := controller.BindMethods(context.Background(), controllerServiceDefinition(f), UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeControllerService(t, client) })
	if usage, err := account.Usage(); err != nil || usage != (resourcev4.Vector{}) {
		t.Fatal("binding retained retired Session scope", usage, err)
	}
	account.Close()
	controller.mu.Lock()
	controller.current = sessions[1]
	controller.mu.Unlock()
	op, err := client.Prepare(context.Background(), []byte("new"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal("old Session scope revoked independent binding", err)
	}
	op.Close()
}

func TestControllerServiceUpdateRejectsChangedSchemaAndUnapprovedBoundedFields(t *testing.T) {
	for _, change := range []string{"request_schema_revision", "request_max_bytes"} {
		t.Run(change, func(t *testing.T) {
			f, services, controller, sessions, _ := controllerReselectionFixture(t)
			definition := controllerServiceDefinition(f)
			definition.Methods[0].Acceptance, _ = protocolv4.BoundedContractAcceptance(protocolv4.ContractRange{Field: "max_response_bytes", Lower: 1024, Upper: 1048576})
			client, err := controller.BindMethods(context.Background(), definition, UnaryServiceBindOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeControllerService(t, client) })
			field := protocolv4.Field{Number: 777}
			if change == "request_schema_revision" {
				field = protocolv4.Field{Kind: protocolv4.TextString, Text: "other.v2"}
			}
			body := admissionMap(t, "ServiceContract", initialFixture(t, "service_unary_transient"), map[string]protocolv4.Field{change: field})
			routes, digest := controllerStaticRoutes(t, f, body)
			services[1].routes = routes
			controller.mu.Lock()
			controller.current = sessions[1]
			controller.mu.Unlock()
			if _, err := client.UpdateContract(context.Background(), 0, digest); !errors.Is(err, protocolv4.ErrContractPolicyRejected) {
				t.Fatal("unapproved field installed", err)
			}
			if got := client.Contract(0); got.Digest != f.policy.Digest || got.Generation != 1 {
				t.Fatal(got)
			}
		})
	}
}

func TestControllerServiceMixedShapesKeepOriginalPreparedSession(t *testing.T) {
	f, services, controller, sessions, _ := controllerReselectionFixture(t)
	config := rpcv4.ContractRoutesConfig{ContractNodes: 256, RuntimeBytes: 4096}
	definition := ServiceDefinition{Namespace: f.policy.Namespace}
	for j, name := range []string{"service_unary_transient", "service_stream_transient", "service_notify_observation"} {
		body := admissionMap(t, "ServiceContract", initialFixture(t, name), map[string]protocolv4.Field{"type_id": {Number: uint64(j + 1)}})
		codec, _ := protocolv4.NewServiceContractCodec(256)
		contract, err := codec.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := contract.Digest()
		contract.Release()
		config.Methods = append(config.Methods, rpcv4.MethodRoutes{Contracts: [][]byte{body}})
		method := ServiceMethod{Type: uint32(j + 1), Shape: uint8(j), Method: UnaryMethodDefinition{Contract: digest}}
		if j < 2 {
			method.Method.Decode = synchronousResult
			method.Method.DefaultResponseLimitBytes = 1024
		}
		if j == 1 {
			method.StreamKind = "test/events"
		}
		definition.Methods = append(definition.Methods, method)
	}
	charge, err := rpcv4.ContractRoutesCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := rpcv4.NewContractRoutes(config, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	services[0].routes, services[1].routes = routes, routes
	client, err := controller.BindMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: []UnaryMethodSelector{{Namespace: definition.Namespace, Type: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeControllerService(t, client) })
	controller.mu.Lock()
	controller.current = sessions[1]
	controller.mu.Unlock()
	if _, err := client.PrepareNotifyMethod(context.Background(), 3, nil, rpcv4.UnaryPreparation{}); err != cryptov4.ErrNotReady {
		t.Fatal("uninstalled descriptor prepared", err)
	}
	var statuses [2]UnaryContractSnapshot
	if err := client.Refresh(context.Background(), []uint32{2, 3}, statuses[:]); err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if !status.Installed || status.Error != nil {
			t.Fatal(status)
		}
	}
	stream, err := client.PrepareStreamingMethod(context.Background(), 2, []byte("stream"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stream.Close)
	notify, err := client.PrepareNotifyMethod(context.Background(), 3, []byte("notice"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(notify.Close)
	controller.mu.Lock()
	controller.current = sessions[0]
	controller.mu.Unlock()
	closeControllerService(t, client)
	if stream.owner.services != services[1] || stream.owner.stream.core != sessions[1].core || notify.owner.services != services[1] || stream.owner.controllerManaged || notify.owner.controllerManaged {
		t.Fatal("non-unary preparation acquired reselection")
	}
	if stream.owner.Snapshot().Closed || notify.owner.Snapshot().Closed {
		t.Fatal("service closed transferred shape handle")
	}
}

func TestControllerServiceConvenienceCallClosesItsOriginalScope(t *testing.T) {
	f, services, controller, _, _ := controllerReselectionFixture(t)
	client, err := controller.BindMethods(context.Background(), controllerServiceDefinition(f), UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeControllerService(t, client) })
	finished := make(chan error, 1)
	go func() {
		_, _, err := client.Call(context.Background(), []byte("call"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
		finished <- err
	}()
	ctx := resultTestContext(t)
	for {
		client.mu.Lock()
		op := client.calls[0].operation
		client.mu.Unlock()
		if op != nil && op.Snapshot().Started {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("call did not start")
		}
		runtime.Gosched()
	}
	client.Close()
	if err := <-finished; err == nil {
		t.Fatal("closed convenience call succeeded")
	}
	for range 4 {
		advanceControllerServices(services)
		controller.advanceDispatches()
		client.advance()
	}
	if err := client.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if controller.Snapshot().Closed {
		t.Fatal("convenience scope closed Controller")
	}
}
