package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Query framing and authorization use the real remote fixture. The two source
// links share the already authenticated identity, clock and resource root, but
// use separate registries. No connection acquisition is needed by this test.
func candidateRemoteFixture(t *testing.T, count int) (*remoteServiceFixture, *UnaryServiceClient, *ConnectionController, *controllerAttempt) {
	t.Helper()
	x := newRemoteServiceShapeFixture(t, count, true)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote, InitialMethods: []UnaryMethodSelector{{Namespace: x.definition.Namespace, Type: 1}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	_, identity, err := x.session.controllerRPCIdentity()
	if err != nil {
		t.Fatal(err)
	}
	oldRPC := x.rpc
	old := &EnvironmentSession{environment: x.environment, delivered: true, core: &SessionCore{plan: &SessionCorePlan{rpc: oldRPC, config: x.session.core.plan.config}}}
	cfg := rpcv4.ContractRoutesConfig{Methods: make([]rpcv4.MethodRoutes, count), ContractNodes: 256, RuntimeBytes: 4096, Clock: oldRPC.clock}
	for i := range client.methods {
		m := &client.methods[i]
		cfg.Methods[i] = rpcv4.MethodRoutes{Contracts: [][]byte{m.canonical}, OfferWindowMS: 1000}
	}
	charge, err := rpcv4.ContractRoutesCharge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := rpcv4.NewContractRoutes(cfg, x.executorFixture.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	x.rpc = &RPCServices{plan: oldRPC.plan, root: oldRPC.root, owner: oldRPC.owner, clock: oldRPC.clock, routes: routes, runtimeBytes: oldRPC.runtimeBytes, shortResponseBytes: oldRPC.shortResponseBytes, channel: oldRPC.channel}
	x.session.core.plan.rpc = x.rpc
	controller := &ConnectionController{environment: x.environment, current: old, config: ControllerConfig{Clock: oldRPC.clock}}
	deadline, err := timev4.NewAge(oldRPC.clock, 4000, 5000)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(context.Canceled) })
	a := &controllerAttempt{ctx: ctx, cancel: cancel, deadline: deadline, candidate: x.session, previous: old}
	controller.attempt = a
	client.mu.Lock()
	client.source = controllerDispatch{controller: controller, routing: identity}
	client.services = nil
	client.mu.Unlock()
	t.Cleanup(func() { controller.finishCandidateContracts(a) })
	return x, client, controller, a
}

func prepareRemoteCandidatePlan(t *testing.T, c *ConnectionController, a *controllerAttempt) {
	t.Helper()
	// Required methods are declared before the source recipe freezes, even
	// when this contract-only candidate needs no local workload positions.
	if err := c.prepareWorkloadPlan(a, &SourceConnectConfig{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.workloads.close(a.candidate) })
}

func TestCandidateRemoteContractsRemainPrivateUntilPublication(t *testing.T) {
	x, client, controller, a := candidateRemoteFixture(t, 11)
	methods := make([]ServiceDependencyMethod, 0, 11)
	for i := uint32(1); i <= 11; i++ {
		selection := ServiceDependencyMethod{Method: UnaryMethodSelector{Namespace: x.definition.Namespace, Type: i}}
		if i == 11 {
			selection.DispatchRequirement = OnUse
		}
		methods = append(methods, selection)
	}
	invocationDeclarations(t, x.executorFixture, []ServiceDependency{{Alias: "files", Client: client, Methods: methods}})
	prepareRemoteCandidatePlan(t, controller, a)
	client.mu.Lock()
	oldOffer := client.methods[0].offer
	client.mu.Unlock()
	// Advertise a later exact window on candidate. Current must keep its
	// previously authenticated Offer until the current switch wins.
	digest := x.definition.Methods[0].Method.Contract
	wire, _ := protocolv4.EncodeMap(make([]byte, 256), "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}, {Name: "not_before_ms", Number: 1100}, {Name: "not_after_ms", Number: 2100}})
	if err := x.server.RegisterOffer(digest, wire); err != nil {
		t.Fatal(err)
	}
	var err error
	x.run(t, func() { err = controller.prepareCandidateContracts(a, x.session) })
	if !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal(err)
	}
	x.run(t, func() { err = controller.prepareCandidateContracts(a, x.session) })
	if !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal(err)
	}
	if err = controller.prepareCandidateContracts(a, x.session); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	if client.methods[0].offer != oldOffer || client.methods[1].installed || client.methods[10].candidateContract.attempt != nil {
		client.mu.Unlock()
		t.Fatal("candidate leaked installation or queried optional method")
	}
	for i := 0; i < 10; i++ {
		if !client.methods[i].candidateContract.matches(x.rpc, client.methods[i].generation) {
			client.mu.Unlock()
			t.Fatal("missing independent candidate", i)
		}
	}
	client.mu.Unlock()
	if x.batches != 3 || x.deadlines[1] != x.deadlines[2] {
		t.Fatal("candidate exceeded batch size or renewed deadline", x.batches, x.deadlines)
	}
	controller.mu.Lock()
	controller.current, a.result.CurrentSwitched = x.session, true
	controller.mu.Unlock()
	controller.finishCandidateContracts(a)
	client.mu.Lock()
	defer client.mu.Unlock()
	if !client.methods[1].installed || client.methods[1].generation != 1 || client.methods[10].installed || client.methods[0].offer.NotAfterMS != 2100 || client.methods[0].generation != 1 {
		t.Fatal("publication did not install exactly the qualified set")
	}
}

func TestCandidateRemoteDenialPreservesCurrentAndClearsStaging(t *testing.T) {
	x, client, controller, a := candidateRemoteFixture(t, 2)
	client.mu.Lock()
	before := client.methods[0].offer
	client.mu.Unlock()
	invocationDeclarations(t, x.executorFixture, []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: x.definition.Namespace, Type: 1}}, {Method: UnaryMethodSelector{Namespace: x.definition.Namespace, Type: 2}}}}})
	prepareRemoteCandidatePlan(t, controller, a)
	if err := x.plan.lease.SetContractQueryAccess(ContractQueryMethod{Namespace: x.definition.Namespace, Type: 2}, rpcv4.QueryTargetDenied); err != nil {
		t.Fatal(err)
	}
	var err error
	x.run(t, func() { err = controller.prepareCandidateContracts(a, x.session) })
	if !errors.Is(err, ErrContractDenied) {
		t.Fatal(err)
	}
	controller.finishCandidateContracts(a)
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.methods[0].offer != before || client.methods[0].candidateContract.attempt != nil || client.methods[1].installed || controller.current != a.previous {
		t.Fatal("denial changed current or retained candidate")
	}
}

func TestCandidateRemoteCancellationRejectsLateQueryResult(t *testing.T) {
	x, client, controller, a := candidateRemoteFixture(t, 1)
	invocationDeclarations(t, x.executorFixture, []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: x.definition.Namespace, Type: 1}}}}})
	prepareRemoteCandidatePlan(t, controller, a)
	client.mu.Lock()
	before := client.methods[0].offer
	client.mu.Unlock()
	done := make(chan struct{})
	var failure error
	go func() {
		failure = controller.prepareCandidateContracts(a, x.session)
		close(done)
	}()
	ctx := resultTestContext(t)
	for {
		client.mu.Lock()
		query := client.methods[0].update.query
		client.mu.Unlock()
		if query != nil {
			break
		}
		select {
		case <-done:
			t.Fatal("candidate exited before issuing original query", failure)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
			runtime.Gosched()
		}
	}
	a.cancel(context.Canceled)
	x.pump(t, done)
	if !errors.Is(failure, context.Canceled) {
		t.Fatal(failure)
	}
	controller.finishCandidateContracts(a)
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.methods[0].offer != before || client.methods[0].candidateContract.attempt != nil || controller.current != a.previous {
		t.Fatal("canceled candidate changed an installation fact")
	}
}

func TestExplicitUpdateSupersedesOnlyItsOriginalCandidateTarget(t *testing.T) {
	x, client, controller, a := candidateRemoteFixture(t, 2)
	invocationDeclarations(t, x.executorFixture, []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: x.definition.Namespace, Type: 1}}, {Method: UnaryMethodSelector{Namespace: x.definition.Namespace, Type: 2}}}}})
	prepareRemoteCandidatePlan(t, controller, a)
	done, joined := make(chan struct{}), make(chan struct{})
	var failure error
	var result UnaryContractSnapshot
	go func() { failure = controller.prepareCandidateContracts(a, x.session); close(done) }()
	ctx := resultTestContext(t)
	for {
		client.mu.Lock()
		started := client.methods[0].update.query != nil
		client.mu.Unlock()
		if started {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		runtime.Gosched()
	}
	go func() {
		result = client.joinRemote(ctx, 1, x.definition.Methods[0].Method.Contract)
		close(joined)
	}()
	for {
		client.mu.Lock()
		superseded := client.methods[0].update.superseded
		client.mu.Unlock()
		if superseded {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		runtime.Gosched()
	}
	x.pump(t, done)
	x.pump(t, joined)
	if !errors.Is(failure, cryptov4.ErrNotReady) || result.Error != errRenewalSuperseded {
		t.Fatal("explicit update did not retain priority after original cleanup", failure, result)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.methods[0].candidateContract.attempt != nil || client.methods[1].candidateContract.attempt != a {
		t.Fatal("explicit update retained its canceled target or canceled another target")
	}
}
