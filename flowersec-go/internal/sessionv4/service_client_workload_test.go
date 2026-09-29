package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func workloadBindOptions(method uint32) UnaryServiceBindOptions {
	return UnaryServiceBindOptions{Workloads: []ServiceMethodWorkload{{Type: method, Calls: 1, RequestBytes: 8}}}
}

func closeWorkloadClient(t *testing.T, c *UnaryServiceClient, r *RPCServices, e *Environment) {
	t.Helper()
	c.Close()
	r.AdvanceCalls()
	e.advanceServiceClients()
	if err := c.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	r.advanceWorkloads()
}

func TestServiceWorkloadBindConsumesActualTargetAtFullRoot(t *testing.T) {
	f, r, _, e := deferredCallerFixture(t)
	r.routes = f.routes
	r.shortResponseBytes = 512
	definition := controllerServiceDefinition(f)
	if _, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{}); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("unqualified larger short default was accepted", err)
	}
	options := workloadBindOptions(f.policy.Type)
	client, err := r.bindMethods(context.Background(), definition, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWorkloadClient(t, client, r, e) })
	w := client.methods[0].definition.Method.workload
	if w == nil || w.responseBytes != 1024 || e.OperationsSnapshot().ProtectedResults != 2 {
		t.Fatal("Bind returned without its actual method target")
	}
	options.Workloads[0].Calls = 2
	options.Workloads[0].ResponseLimitBytes = 2048
	saturateWorkloadRoot(t, f)
	op, err := client.Prepare(context.Background(), []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil || op.workload != &w.slots[0] {
		t.Fatal("Bind recipe was not consumed", err)
	}
	t.Cleanup(op.Close)
	client.Close()
	if start := op.Start(context.Background()); start.Error != nil {
		t.Fatal("binding close revoked its transferred prepared operation", start.Error)
	}
	finishShortResponse(t, f, op.header, 1, []byte("result"))
	r.AdvanceCalls()
	value, status, err := op.TakeResult(resultTestContext(t))
	if err != nil || string(value.([]byte)) != "result" || !status.Delivered {
		t.Fatal(value, status, err)
	}
	op.Close()
	waitWorkload(t, r, e, func() bool { return w.cleaned })
}

func TestServiceWorkloadBindFailureUnwindsEarlierMethodTargets(t *testing.T) {
	f, r, e, definition, _ := serviceMethodsFixture(t, 2)
	var occupied [14]environmentResultProtection
	if err := e.protectResults(e.reservation, occupied[:]); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, position := range occupied {
			position.close()
		}
	}()
	before, positions := f.f.root.Snapshot(), e.OperationsSnapshot()
	options := workloadBindOptions(1)
	options.Workloads = append(options.Workloads, ServiceMethodWorkload{Type: 2, Calls: 1, RequestBytes: 8})
	client, err := r.bindMethods(context.Background(), definition, options)
	if client != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("partial target escaped Bind", client, err)
	}
	if f.f.root.Snapshot() != before || e.OperationsSnapshot() != positions {
		t.Fatal("failed Bind retained metadata or an earlier method target", before, f.f.root.Snapshot())
	}
}

func TestServiceWorkloadContractUpdateReusesQualifiedEnvelope(t *testing.T) {
	f, r, e, definition, variants := serviceMethodsFixture(t, 1)
	client, err := r.bindMethods(context.Background(), definition, workloadBindOptions(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWorkloadClient(t, client, r, e) })
	w := client.methods[0].definition.Method.workload
	old, err := client.Prepare(context.Background(), []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(old.Close)
	before := f.f.root.Snapshot()
	status, err := client.UpdateContract(context.Background(), 1, variants[0])
	if err != nil || status.Digest != variants[0] {
		t.Fatal(status, err)
	}
	if client.methods[0].definition.Method.workload != w || w.closed || f.f.root.Snapshot() != before {
		t.Fatal("compatible update duplicated or revoked the admitted target")
	}
	if old.header.Fields().ServiceContractDigest != definition.Methods[0].Method.Contract {
		t.Fatal("update changed a returned request")
	}
	old.Close()
	waitWorkload(t, r, e, func() bool { return !w.slots[0].used })
	next, err := client.Prepare(context.Background(), []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	if next.workload != &w.slots[0] || next.header.Fields().ServiceContractDigest != variants[0] || next.header.Fields().ResponseLimitBytes != 1024 {
		t.Fatal("new digest lost the original explicit default or reusable target")
	}
	if _, err := client.UpdateContract(context.Background(), 1, variants[1]); !errors.Is(err, rpcv4.ErrResponseLimitUnsupported) {
		t.Fatal("workload overrode an invalid explicit method default", err)
	}
}

func TestServiceWorkloadLargerCandidatePreservesOldOnCapacityFailure(t *testing.T) {
	f, r, e, definition, variants := serviceMethodsFixture(t, 1)
	original := definition.Methods[0].Method.Contract
	definition.Methods[0].Method.Contract = variants[0]
	definition.Methods[0].Method.DefaultResponseLimitBytes = 0
	client, err := r.bindMethods(context.Background(), definition, workloadBindOptions(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWorkloadClient(t, client, r, e) })
	old := client.methods[0].definition.Method.workload
	if old.responseBytes != 2048 {
		t.Fatal("recipe did not select the exact contract maximum", old.responseBytes)
	}
	op, err := client.Prepare(context.Background(), []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	before := f.f.root.Snapshot()
	fill := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: before.Limit[resourcev4.SDKBytes] - before.Charged[resourcev4.SDKBytes]})
	filled := f.f.root.Snapshot()
	_, err = client.UpdateContract(context.Background(), 1, original)
	if !errors.Is(err, resourcev4.ErrCapacity) || client.methods[0].definition.Method.workload != old || old.closed || client.Contract(1).Digest != variants[0] || f.f.root.Snapshot() != filled {
		t.Fatal("failed larger candidate changed the original target", err)
	}
	fill.Release()
	if _, err = client.UpdateContract(context.Background(), 1, original); err != nil {
		t.Fatal(err)
	}
	next := client.methods[0].definition.Method.workload
	if next == old || next.responseBytes != 1048576 || !old.closed || old.cleaned || f.f.root.Snapshot().ResultOwners != before.ResultOwners+1 {
		t.Fatal("new target failed to retain real overlap")
	}
	op.Close()
	waitWorkload(t, r, e, func() bool { return old.cleaned })
}

func TestServiceWorkloadRemoteBindQualifiesBeforeHandoff(t *testing.T) {
	x := newRemoteServiceFixture(t, 1)
	options := workloadBindOptions(1)
	options.ContractSource = ServiceContractsRemote
	options.Workloads[0].ResponseLimitBytes = 2048
	var client *UnaryServiceClient
	var err error
	x.run(t, func() { client, err = x.session.BindMethods(context.Background(), x.definition, options) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWorkloadClient(t, client, x.rpc, x.environment) })
	w := client.methods[0].definition.Method.workload
	if x.batches != 1 || w == nil || w.responseBytes != 2048 || client.Contract(1).Error != nil {
		t.Fatal("remote binding handed off without exact snapshot qualification")
	}
	x.run(t, func() { _, err = client.UpdateContract(context.Background(), 1, x.variant) })
	if err != nil || client.methods[0].definition.Method.workload != w || w.closed {
		t.Fatal("remote compatible update duplicated the target", err)
	}
}

func TestServiceWorkloadRemoteBindDoesNotDeliverPartialTarget(t *testing.T) {
	x := newRemoteServiceFixture(t, 2)
	options := workloadBindOptions(1)
	options.ContractSource = ServiceContractsRemote
	options.Workloads = append(options.Workloads, ServiceMethodWorkload{Type: 2, Calls: 2, RequestBytes: 8})
	var client *UnaryServiceClient
	var err error
	x.run(t, func() { client, err = x.session.BindMethods(context.Background(), x.definition, options) })
	if client != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("remote Bind exposed an incompletely qualified client", client, err)
	}
	for _, slot := range x.rpc.workloadSlots {
		if slot != nil {
			t.Fatal("failed remote Bind retained an unused method target")
		}
	}
}

func TestServiceWorkloadControllerStagesRealReplacementCapacity(t *testing.T) {
	f, services, controller, sessions, fixtures := controllerReselectionFixture(t)
	definition := controllerServiceDefinition(f)
	client, err := controller.BindMethods(context.Background(), definition, workloadBindOptions(f.policy.Type))
	if err != nil {
		t.Fatal(err)
	}
	e := controller.environment
	t.Cleanup(func() {
		client.Close()
		controller.advanceDispatches()
		for _, r := range services {
			r.AdvanceCalls()
		}
		e.advanceResults()
		e.advanceServiceClients()
	})
	oldWorkload := client.methods[0].definition.Method.workload
	old, err := client.Prepare(context.Background(), []byte("old"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(old.Close)
	if start := old.Start(context.Background()); start.Error != nil {
		t.Fatal(start.Error)
	}
	finishShortResponse(t, f, old.header, 1, []byte("old result"))
	services[0].AdvanceCalls()
	controller.advanceDispatches()
	deadline, err := timev4.NewAge(f.trust.clock, 4000, 5000)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	a := &controllerAttempt{ctx: ctx, cancel: cancel, deadline: deadline, previous: sessions[0], candidate: sessions[1]}
	controller.mu.Lock()
	controller.attempt = a
	controller.mu.Unlock()
	before := f.f.root.Snapshot().ResultOwners
	prepareControllerWorkloadFixture(t, f, controller, a, sessions[1])
	if err := controller.prepareCandidateWorkloads(a, sessions[1]); err != nil {
		t.Fatal(err)
	}
	if client.methods[0].definition.Method.workload != oldWorkload || oldWorkload.closed || f.f.root.Snapshot().ResultOwners != before+1 {
		t.Fatal("private replacement changed current or omitted overlap")
	}
	controller.mu.Lock()
	controller.current, a.result.CurrentSwitched = sessions[1], true
	controller.mu.Unlock()
	controller.finishCandidateContracts(a)
	if client.methods[0].definition.Method.workload.services != services[1] || !oldWorkload.closed || oldWorkload.cleaned {
		t.Fatal("publication did not transfer the candidate target")
	}
	next, err := client.Prepare(context.Background(), []byte("new"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil || next.workload == nil || next.workload.workload.services != services[1] {
		t.Fatal("new preparation lost replacement capacity", err)
	}
	t.Cleanup(next.Close)
	if start := next.Start(context.Background()); start.Error != nil {
		t.Fatal(start.Error)
	}
	finishShortResponse(t, fixtures[1], next.header, 1, []byte("new result"))
	advanceControllerServices(services)
	for _, operation := range []*UnaryOperation{old, next} {
		if _, _, err := operation.TakeResult(resultTestContext(t)); err != nil {
			t.Fatal(err)
		}
		operation.Close()
	}
	controller.advanceDispatches()
	waitWorkload(t, services[0], e, func() bool { return oldWorkload.cleaned })
}

func TestServiceWorkloadControllerFailedCandidateUnwinds(t *testing.T) {
	f, services, controller, sessions, _ := controllerReselectionFixture(t)
	client, err := controller.BindMethods(context.Background(), controllerServiceDefinition(f), workloadBindOptions(f.policy.Type))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWorkloadClient(t, client, services[0], controller.environment) })
	current := client.methods[0].definition.Method.workload
	deadline, err := timev4.NewAge(f.trust.clock, 4000, 5000)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	a := &controllerAttempt{ctx: ctx, cancel: cancel, deadline: deadline, previous: sessions[0], candidate: sessions[1]}
	controller.mu.Lock()
	controller.attempt = a
	controller.mu.Unlock()
	before := f.f.root.Snapshot()
	prepareControllerWorkloadFixture(t, f, controller, a, sessions[1])
	if err := controller.prepareCandidateWorkloads(a, sessions[1]); err != nil {
		t.Fatal(err)
	}
	candidate := client.methods[0].candidateWorkload.workload
	if candidate == nil || candidate == current {
		t.Fatal("replacement did not reserve independent original positions")
	}
	controller.mu.Lock()
	a.finished = true
	controller.attempt = nil
	controller.mu.Unlock()
	controller.finishCandidateContracts(a)
	a.workloads.close(sessions[1])
	services[1].advanceWorkloads()
	if !candidate.cleaned || current.closed || client.methods[0].definition.Method.workload != current || f.f.root.Snapshot() != before {
		t.Fatal("failed candidate altered current or retained idle capacity")
	}
	controller.mu.Lock()
	a.result.CurrentSwitched = true // A stale attempt cannot regain installation rights.
	controller.mu.Unlock()
	controller.finishCandidateContracts(a)
	if client.methods[0].definition.Method.workload != current {
		t.Fatal("stale candidate replaced current after cleanup")
	}
}
