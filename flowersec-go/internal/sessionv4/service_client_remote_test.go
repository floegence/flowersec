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
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type remoteServiceFixture struct {
	executorFixture *executorFixture
	session         *EnvironmentSession
	rpc             *RPCServices
	environment     *Environment
	definition      ServiceDefinition
	server          *rpcv4.ContractRoutes
	publisher       *rpcv4.Publisher
	receiver        *rpcv4.Receiver
	sink            *queryIntegrationSink
	plan            *SessionPlan
	variant         [32]byte
	deadlines       []uint64
	batches         int
	responseBytes   []uint32
}

// The actual query framing, fixed executor, authorization, route installation
// and cleanup are exercised. Only the already authenticated host/core link is
// fixture supplied; native handshake qualification belongs to carrier tests.
func newRemoteServiceFixture(t *testing.T, count int) *remoteServiceFixture {
	return newRemoteServiceShapeFixture(t, count, false)
}

func newRemoteServiceShapeFixture(t *testing.T, count int, execution bool) *remoteServiceFixture {
	return newRemoteServiceWindowFixture(t, count, execution, 1000)
}

func newRemoteServiceWindowFixture(t *testing.T, count int, execution bool, offerWindow uint64) *remoteServiceFixture {
	return newRemoteServiceMixedWindowFixture(t, count, execution, offerWindow, false)
}

func newRemoteServiceMixedWindowFixture(t *testing.T, count int, execution bool, offerWindow uint64, firstTransient bool) *remoteServiceFixture {
	t.Helper()
	var limit resourcev4.Vector
	for j := range limit {
		limit[j] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 512, ReferenceSlots: 2048})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("remote service retained resources", root.Snapshot())
		}
	})
	f := &executorFixture{root: root, config: ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, CompletionRunning: 1, CompletionReserved: 2, QueryOwners: 8, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}}
	charge, err := ApplicationExecutorCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.executor.Close(); awaitQuery(t, f.executor.Done()) })
	trust := newSessionAdmissionTrustFixture(t, root, f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128}), resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{83}, Backing: [16]byte{1}, Kind: 83})
	authority, err := protocolv4.NewEndpointAuthorization(trust.subscriptions[0], trust.authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authority.Close(nil) })
	x := &remoteServiceFixture{sink: &queryIntegrationSink{}, executorFixture: f}
	cfg := rpcv4.ContractRoutesConfig{Methods: make([]rpcv4.MethodRoutes, count), ContractNodes: 256, RuntimeBytes: 4096, Clock: trust.clock}
	var selectors []ContractQueryMethod
	for j := range count {
		methodExecution := execution && (!firstTransient || j != 0)
		fixture := "service_unary_transient"
		if methodExecution {
			fixture = "service_unary_execution"
		}
		body := admissionMap(t, "ServiceContract", initialFixture(t, fixture), map[string]protocolv4.Field{"type_id": {Number: uint64(j + 1)}})
		codec, _ := protocolv4.NewServiceContractCodec(256)
		contract, err := codec.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := contract.Policy()
		if err != nil {
			t.Fatal(err)
		}
		contract.Release()
		x.definition.Namespace = policy.Namespace
		x.definition.Methods = append(x.definition.Methods, ServiceMethod{Type: policy.Type, Method: UnaryMethodDefinition{Contract: policy.Digest, WorkClass: ApplicationShort, DefaultResponseLimitBytes: 1024, Decode: synchronousResult}})
		selectors = append(selectors, ContractQueryMethod{Namespace: policy.Namespace, Type: policy.Type})
		cfg.Methods[j].Contracts = [][]byte{body}
		if methodExecution {
			cfg.Methods[j].OfferWindowMS = offerWindow
		}
		if j == 0 {
			body = admissionMap(t, "ServiceContract", body, map[string]protocolv4.Field{"max_response_bytes": {Number: 2048}})
			contract, err = codec.Decode(body)
			if err != nil {
				t.Fatal(err)
			}
			x.variant, _ = contract.Digest()
			contract.Release()
			cfg.Methods[j].Contracts = append(cfg.Methods[j].Contracts, body)
		}
	}
	charge, err = rpcv4.ContractRoutesCharge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	clientRoutes, err := rpcv4.NewContractRoutes(cfg, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clientRoutes.Close)
	x.server, err = rpcv4.NewContractRoutes(cfg, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.server.Close)
	for j, m := range x.definition.Methods {
		if execution && (!firstTransient || j != 0) {
			wire, err := protocolv4.EncodeMap(make([]byte, 256), "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: m.Method.Contract[:]}, {Name: "not_before_ms", Number: 1000}, {Name: "not_after_ms", Number: 1000 + offerWindow}})
			if err != nil {
				t.Fatal(err)
			}
			if err = x.server.RegisterOffer(m.Method.Contract, wire); err != nil {
				t.Fatal(err)
			}
		}
		if err := x.server.Advertise(m.Method.Contract); err != nil {
			t.Fatal(err)
		}
	}
	nc := rpcv4.NetworkConfig{Session: testSessionContract(t, protocolv4.DHProfileX25519, "services", 4096, 4, 0, 5000).Contract, Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}}, RuntimeBytes: 4096}
	charge, err = rpcv4.NetworkCharge(nc)
	if err != nil {
		t.Fatal(err)
	}
	network, err := rpcv4.NewNetwork(nc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(network.Close)
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{92}, Backing: [16]byte{92}, Kind: 92}
	ic := rpcv4.ServiceInputsConfig{GeneralOutstanding: 32, InputRuntimeBytes: 4096, HashRuntimeBytes: 512, RuntimeBytes: 4096, Root: root, Owner: owner}
	charge, err = rpcv4.ServiceInputsCharge(ic)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := network.NewServiceInputs(x.server, ic, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inputs.Close)
	charge, _ = rpcv4.PublisherCharge(4096)
	x.publisher, err = network.NewPublisher([16]byte{1}, x.sink, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ = rpcv4.ReceiverCharge(4096)
	x.receiver, err = network.NewReceiver(x.publisher, inputs, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		x.receiver.Close()
		x.publisher.Close()
		if err := x.publisher.Retire(); err != nil {
			t.Error(err)
		}
	})
	charge, _ = rpcv4.ContractQueryServiceCharge(4096)
	service, err := network.NewContractQueryService(x.server, trust.clock, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	x.plan = applicationTestPlan(t, f, SessionPlanConfig{ContractQueries: true, ContractQueryMethods: selectors, RuntimeBytes: 4096, AuthorizeApplication: func(_ context.Context, request AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		lease, err := request.ReserveLease(request.Binding(), nil, func(context.Context) error { return nil })
		if err == nil {
			for _, m := range selectors {
				if err = lease.SetContractQueryAccess(m, rpcv4.QueryTargetAllowed); err != nil {
					break
				}
			}
		}
		return AuthorizeApplicationResult{Lease: lease}, err
	}})
	if err = x.plan.InstallContractQueries(service); err != nil {
		t.Fatal(err)
	}
	charge, _ = rpcv4.ContractQueryClientCharge(4096)
	queryClient, err := network.NewContractQueryClient(trust.clock, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(queryClient.Close)
	if err = x.plan.InstallOutgoingContractQueries(queryClient); err != nil {
		t.Fatal(err)
	}
	x.plan.claimed = true
	if err = x.plan.authorize(context.Background(), ApplicationBinding{Artifact: trust.session.ArtifactDigest, Attempt: trust.attempt}, authority.Check); err != nil {
		t.Fatal(err)
	}
	if err = x.plan.lease.bindAuthorization(authority); err != nil {
		t.Fatal(err)
	}
	ec := EnvironmentConfig{Services: true, ResultOwners: 16, Positions: 1, ContractQueryAcquisitions: 4, Clock: trust.clock, RuntimeBytes: 4096}
	charge, err = EnvironmentCharge(ec)
	if err != nil {
		t.Fatal(err)
	}
	x.environment, err = NewEnvironment(ec, f.reserve(t, 1, charge), f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 64}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		x.sink.held.Store(false)
		x.receiver.Close()
		x.publisher.Close()
		x.environment.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := x.environment.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := x.environment.Retire(); err != nil {
			t.Error(err)
		}
	})
	x.session = &EnvironmentSession{environment: x.environment, application: x.plan, delivered: true}
	x.rpc = &RPCServices{network: network, operations: make([]*UnaryOperation, 32), generalCalls: make([]*unaryInvocation, 32), workloadSlots: make([]*unaryWorkloadSlot, 32), plan: x.plan, root: root, owner: owner, clock: trust.clock, routes: clientRoutes, runtimeBytes: 4096, shortResponseBytes: 8192, channel: &RPCChannel{publisher: x.publisher}}
	x.session.core = &SessionCore{plan: &SessionCorePlan{rpc: x.rpc, config: SessionCoreConfig{Clock: trust.clock, DispatchTimeoutMS: 4000, Session: testSessionContract(t, protocolv4.DHProfileX25519, "services", 4096, 4, 0, 5000)}}}
	x.plan.host = x.session
	return x
}

func (x *remoteServiceFixture) pump(t *testing.T, done <-chan struct{}) {
	t.Helper()
	ctx := resultTestContext(t)
	codec, _ := protocolv4.NewApplicationHeaderCodec()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			t.Fatal("remote service acquisition stalled")
		default:
		}
		before := x.sink.writes
		_, err := x.publisher.Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if before != x.sink.writes {
			frame, err := protocolv4.DecodeRPCFragment(x.sink.wire)
			if err != nil {
				t.Fatal(err)
			}
			if frame.Kind == protocolv4.RPCBegin {
				h, err := codec.Decode(frame.Header)
				if err != nil {
					t.Fatal(err)
				}
				if h.Kind() == "query_contracts_request" {
					x.batches++
					x.deadlines = append(x.deadlines, h.Fields().DeadlineAtMS)
				}
				if h.Kind() == "query_contracts_response" {
					x.responseBytes = append(x.responseBytes, h.Fields().PayloadBytes)
				}
			}
			if _, err = x.receiver.Feed(x.sink.wire); err != nil {
				t.Fatal(err)
			}
		}
		runtime.Gosched()
	}
}

func (x *remoteServiceFixture) run(t *testing.T, action func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); action() }()
	x.pump(t, done)
}

// Bind may return after receiving its final response but before the fixture's
// next publisher visit confirms that response's provider tail. Settle that
// original write before holding a later query; the sink's global hold switch
// must not retroactively block the completed Bind response.
func (x *remoteServiceFixture) holdNextPublication(t *testing.T, ctx context.Context) {
	t.Helper()
	before := x.sink.writes
	if progressed, err := x.publisher.Step(ctx); err != nil || progressed || x.sink.writes != before {
		t.Fatal("previous query still had unpublished fragments", progressed, err)
	}
	x.sink.held.Store(true)
}

func TestRemoteServiceBatchesShareDeadlineAndInstallExactVariants(t *testing.T) {
	x := newRemoteServiceFixture(t, 9)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if x.batches != 2 || len(x.deadlines) != 2 || x.deadlines[0] != x.deadlines[1] {
		t.Fatal("initial batches restarted original deadline", x.batches, x.deadlines)
	}
	for _, m := range x.definition.Methods {
		if s := client.Contract(m.Type); !s.Installed || s.Digest != m.Method.Contract || s.Generation != 1 || s.Error != nil {
			t.Fatal(s)
		}
	}
	if x.environment.OperationsSnapshot().ActiveQueries != 0 {
		t.Fatal("Bind completed before final query cleanup")
	}
	var update UnaryContractSnapshot
	x.run(t, func() { update, err = client.UpdateContract(context.Background(), 1, x.variant) })
	if err != nil || update.Digest != x.variant || update.Generation != 2 {
		t.Fatal(update, err)
	}
	if client.methods[0].definition.Method.DefaultResponseLimitBytes != 1024 {
		t.Fatal("remote update replaced response default")
	}
	fullBytes := x.responseBytes[len(x.responseBytes)-1]
	x.run(t, func() { update, err = client.UpdateContract(context.Background(), 1, x.variant) })
	if err != nil || update.Error != nil || update.Generation != 2 {
		t.Fatal(update, err)
	}
	if n := x.responseBytes[len(x.responseBytes)-1]; n >= fullBytes {
		t.Fatal("owned canonical baseline was not sent conditionally", n, fullBytes)
	}
}

func TestRemoteServiceCloseRetainsPhysicalQueryTail(t *testing.T) {
	x := newRemoteServiceFixture(t, 2)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote, InitialMethods: []UnaryMethodSelector{{Namespace: x.definition.Namespace, Type: 1}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	var output [1]UnaryContractSnapshot
	ctx := resultTestContext(t)
	x.holdNextPublication(t, ctx)
	done := make(chan struct{})
	go func() { defer close(done); err = client.Refresh(context.Background(), []uint32{2}, output[:]) }()
	before := x.sink.writes
	for x.sink.writes == before {
		if _, e := x.publisher.Step(ctx); e != nil {
			t.Fatal(e)
		}
		select {
		case <-ctx.Done():
			t.Fatal("query never published")
		default:
		}
		runtime.Gosched()
	}
	client.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Close did not cancel refresh wait")
	}
	if err == nil && output[0].Error == nil {
		t.Fatal("closed refresh installed a snapshot")
	}
	if client.advance() {
		t.Fatal("physical publication tail was refunded")
	}
	if s := x.environment.OperationsSnapshot(); s.BoundMethods != 2 || s.ActiveQueries != 1 {
		t.Fatal("physical tail escaped accounting", s)
	}
	x.sink.held.Store(false)
	x.receiver.Close()
	x.publisher.Close()
	if err := client.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteServiceJoinCancellationDoesNotCancelOriginalQuery(t *testing.T) {
	x := newRemoteServiceShapeFixture(t, 1, true)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	var original [1]UnaryContractSnapshot
	done := make(chan struct{})
	go func() { defer close(done); err = client.Refresh(context.Background(), []uint32{1}, original[:]) }()
	ctx := resultTestContext(t)
	for {
		client.mu.Lock()
		active := client.methods[0].update.active
		client.mu.Unlock()
		if active {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("refresh not active")
		default:
		}
		runtime.Gosched()
	}
	var joined [1]UnaryContractSnapshot
	joinCtx, cancel := context.WithCancel(ctx)
	joinDone := make(chan struct{})
	var joinErr error
	go func() { defer close(joinDone); joinErr = client.Refresh(joinCtx, []uint32{1}, joined[:]) }()
	for {
		client.mu.Lock()
		waiters := client.methods[0].update.waiters
		client.mu.Unlock()
		if waiters == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("refresh did not join")
		default:
		}
		runtime.Gosched()
	}
	cancel()
	<-joinDone
	if joinErr != nil || !errors.Is(joined[0].Error, context.Canceled) {
		t.Fatal(joined, joinErr)
	}
	if s, err := client.UpdateContract(ctx, 1, x.variant); err != ErrContractUpdateInProgress || s.Error != ErrContractUpdateInProgress {
		t.Fatal(s, err)
	}
	x.pump(t, done)
	if err != nil || original[0].Error != nil || !original[0].Installed {
		t.Fatal(original, err)
	}
	if x.batches != 2 {
		t.Fatal("join published an additional query", x.batches)
	}
}

func TestRemoteServiceCloseRejectsLateInstallationBeforeCodec(t *testing.T) {
	x := newRemoteServiceFixture(t, 2)
	var encodes atomic.Int32
	x.definition.Methods[1].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(_ context.Context, b, _ []byte) ([]byte, error) { encodes.Add(1); return b, nil }}
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote, InitialMethods: []UnaryMethodSelector{{Namespace: x.definition.Namespace, Type: 1}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if _, err = client.PrepareMethod(context.Background(), 2, nil, rpcv4.UnaryPreparation{}); err != cryptov4.ErrClosed || encodes.Load() != 0 {
		t.Fatal(err, encodes.Load())
	}
}

func TestRemoteServiceInitialSubsetRefreshAndPartialRefusal(t *testing.T) {
	x := newRemoteServiceFixture(t, 3)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote, InitialMethods: []UnaryMethodSelector{{Namespace: x.definition.Namespace, Type: 1}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if s := client.Contract(2); s.Installed || s.Digest != ([32]byte{}) || s.Error != cryptov4.ErrNotReady {
		t.Fatal(s)
	}
	if _, err = client.PrepareMethod(context.Background(), 2, nil, rpcv4.UnaryPreparation{}); err != cryptov4.ErrNotReady {
		t.Fatal(err)
	}
	if _, err = client.UpdateContract(context.Background(), 2, x.variant); err != cryptov4.ErrNotReady {
		t.Fatal(err)
	}
	if err = x.plan.lease.SetContractQueryAccess(ContractQueryMethod{Namespace: x.definition.Namespace, Type: 3}, rpcv4.QueryTargetDenied); err != nil {
		t.Fatal(err)
	}
	var output [2]UnaryContractSnapshot
	x.run(t, func() { err = client.Refresh(context.Background(), []uint32{2, 3}, output[:]) })
	if err != nil || !output[0].Installed || output[0].Error != nil || output[1].Installed || output[1].Error != ErrContractDenied {
		t.Fatal(output, err)
	}
	if !client.Contract(1).Installed {
		t.Fatal("partial failure erased installed method")
	}
	if x.batches != 2 {
		t.Fatal("Refresh did not batch", x.batches)
	}
}

func TestRemoteServiceFailedInitialSetNeverDeliversClient(t *testing.T) {
	x := newRemoteServiceFixture(t, 2)
	if err := x.plan.lease.SetContractQueryAccess(ContractQueryMethod{Namespace: x.definition.Namespace, Type: 2}, rpcv4.QueryTargetDenied); err != nil {
		t.Fatal(err)
	}
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if client != nil || err != ErrContractDenied {
		t.Fatal("partial Bind escaped", client, err)
	}
	// Failed delivery closes the original client; its cancellation observer
	// still owns the descriptor until the observer's actual exit is observed.
	deadline := time.Now().Add(3 * time.Second)
	for {
		x.environment.advanceServiceClients()
		s := x.environment.OperationsSnapshot()
		if s.BoundMethods == 0 && s.ActiveServiceClients == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(s)
		}
		runtime.Gosched()
	}
}

func TestRemoteServiceAcquisitionClaimsCountBeforeCandidateWork(t *testing.T) {
	x := newRemoteServiceFixture(t, 1)
	var claims [4]*contractQueryClaim
	for j := range claims {
		var err error
		claims[j], err = x.environment.reserveContractQuery()
		if err != nil {
			t.Fatal(err)
		}
		defer claims[j].release()
	}
	if _, err := x.environment.reserveContractQuery(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	if s := x.environment.OperationsSnapshot(); s.ActiveQueries != 4 {
		t.Fatal(s)
	}
	client, err := x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	if err != cryptov4.ErrCapacity || client != nil || x.sink.writes != 0 {
		t.Fatal("query claim overflow", client, err)
	}
}

func TestRemoteServiceBoundedRefreshUsesAdvertisementAndPreservesExactBinding(t *testing.T) {
	x := newRemoteServiceFixture(t, 1)
	bounded := x.definition
	bounded.Methods = append([]ServiceMethod(nil), x.definition.Methods...)
	bounded.Methods[0].Acceptance, _ = protocolv4.BoundedContractAcceptance(protocolv4.ContractRange{Field: "max_response_bytes", Lower: 1024, Upper: 1048576})
	var exactClient, boundedClient *UnaryServiceClient
	var err error
	x.run(t, func() {
		exactClient, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(exactClient.Close)
	x.run(t, func() {
		boundedClient, err = x.session.BindMethods(context.Background(), bounded, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(boundedClient.Close)
	if err = x.server.Advertise(x.variant); err != nil {
		t.Fatal(err)
	}
	var statuses [1]UnaryContractSnapshot
	before := x.batches
	x.run(t, func() { err = exactClient.Refresh(context.Background(), []uint32{1}, statuses[:]) })
	if err != nil || statuses[0].Error != nil || statuses[0].Digest != x.definition.Methods[0].Method.Contract {
		t.Fatal("advertisement replaced exact approval", statuses, err)
	}
	if x.batches != before {
		t.Fatal("exact transient refresh published an unnecessary query")
	}
	x.run(t, func() { err = boundedClient.Refresh(context.Background(), []uint32{1}, statuses[:]) })
	if err != nil || statuses[0].Error != nil || statuses[0].Digest != x.variant || statuses[0].Generation != 2 {
		t.Fatal("bounded advertisement not installed", statuses, err)
	}
}

func TestRemoteServiceRequiredGuaranteeFailsBeforeQuery(t *testing.T) {
	x := newRemoteServiceFixture(t, 1)
	x.definition.Methods[0].Method.RequireDurable = true
	client, err := x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	if client != nil || err != protocolv4.ErrRequiredGuaranteeUnavailable || x.sink.writes != 0 {
		t.Fatal(client, err, x.sink.writes)
	}
	if s := x.environment.OperationsSnapshot(); s.ActiveServiceClients != 0 || s.BoundMethods != 0 {
		t.Fatal(s)
	}
}

func TestRemoteServiceExecutionOfferRenewsWithoutChangingCapturedWindow(t *testing.T) {
	x := newRemoteServiceShapeFixture(t, 1, true)
	x.definition.Methods[0].Method.RequireDurable = true
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if s := client.Contract(1); !s.Installed || !s.OfferReady || s.OfferPending || s.Error != nil {
		t.Fatal(s)
	}
	first, child, _, method, err := client.enter(context.Background(), 1, 0, nil, rpcv4.UnaryPreparation{})
	if err != nil {
		t.Fatal(err)
	}
	if child.Err() != nil {
		t.Fatal(child.Err())
	}
	old := method.Method.bindingOffer
	client.leave(first)
	digest := x.definition.Methods[0].Method.Contract
	wire, err := protocolv4.EncodeMap(make([]byte, 256), "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}, {Name: "not_before_ms", Number: 1050}, {Name: "not_after_ms", Number: 2050}})
	if err != nil {
		t.Fatal(err)
	}
	if err = x.server.RegisterOffer(digest, wire); err != nil {
		t.Fatal(err)
	}
	var output [1]UnaryContractSnapshot
	x.run(t, func() { err = client.Refresh(context.Background(), []uint32{1}, output[:]) })
	if err != nil || output[0].Error != nil || !output[0].OfferReady || output[0].Generation != 1 {
		t.Fatal(output, err)
	}
	client.mu.Lock()
	next := client.methods[0].offer
	client.mu.Unlock()
	if old.NotAfterMS != 2000 || next.NotAfterMS != 2050 {
		t.Fatal("Offer did not retain original distinct bounds", old, next)
	}
	if _, err = x.rpc.routes.CapturePreparationOffer(digest, old); err != nil {
		t.Fatal("renewal erased prepared Offer", err)
	}
	if _, err = x.rpc.routes.CapturePreparationOffer(digest, next); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteServiceTotalDeadlineStopsFurtherBatches(t *testing.T) {
	x := newRemoteServiceFixture(t, 9)
	x.session.core.plan.config.DispatchTimeoutMS = 1
	ctx := resultTestContext(t)
	_, err := x.session.BindMethods(ctx, x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	if err == nil {
		t.Fatal("expired Bind delivered")
	}
	if !errors.Is(err, timev4.ErrExpired) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if x.sink.writes != 0 {
		t.Fatal("Bind advanced beyond its original deadline")
	}
}
