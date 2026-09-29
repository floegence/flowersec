package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func occupyOrdinaryServiceCalls(t *testing.T, client *UnaryServiceClient) {
	t.Helper()
	for range 32 {
		slot, _, _, _, err := client.enter(context.Background(), 0, 0, []byte("outside declared request"), rpcv4.UnaryPreparation{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.leave(slot) })
		if slot.workload != nil {
			t.Fatal("a larger request consumed a declared call opportunity")
		}
	}
	if _, _, _, _, err := client.enter(context.Background(), 0, 0, []byte("outside declared request"), rpcv4.UnaryPreparation{}); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("ordinary calls exceeded their finite positions", err)
	}
}

func TestServiceWorkloadCallScopeSurvivesOrdinarySaturation(t *testing.T) {
	f, r, _, e := deferredCallerFixture(t)
	r.routes = f.routes
	client, err := r.bindMethods(context.Background(), controllerServiceDefinition(f), workloadBindOptions(f.policy.Type))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWorkloadClient(t, client, r, e) })
	occupyOrdinaryServiceCalls(t, client)
	saturateWorkloadRoot(t, f)
	before := f.f.root.Snapshot()
	op, slot, child, err := client.prepare(context.Background(), 0, []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000}, true)
	if err != nil {
		t.Fatal("declared call lost its scope to ordinary traffic", err)
	}
	defer client.leave(slot)
	defer op.Close()
	if client.active != 33 || slot.workload == nil || op.workload == nil {
		t.Fatal("the actual caller did not consume its independent target")
	}
	if started := op.Start(child); started.Error != nil {
		t.Fatal(started.Error)
	}
	finishShortResponse(t, f, op.header, 1, []byte("result"))
	r.AdvanceCalls()
	value, status, err := op.TakeResult(resultTestContext(t))
	if err != nil || !status.Delivered || string(value.([]byte)) != "result" {
		t.Fatal(value, status, err)
	}
	if f.f.root.Snapshot() != before {
		t.Fatal("declared call acquired unadmitted backing")
	}
}

func TestServiceWorkloadCallScopeKeepsBackingUntilCallerExit(t *testing.T) {
	f, r, _, e := deferredCallerFixture(t)
	r.routes = f.routes
	client, err := r.bindMethods(context.Background(), controllerServiceDefinition(f), workloadBindOptions(f.policy.Type))
	if err != nil {
		t.Fatal(err)
	}
	slot, child, _, _, err := client.enter(context.Background(), 0, 0, []byte("req"), rpcv4.UnaryPreparation{})
	if err != nil {
		t.Fatal(err)
	}
	w := client.methods[0].definition.Method.workload
	client.Close()
	r.advanceWorkloads()
	if child.Err() == nil || w.cleaned || client.advance() || client.CleanupStatus().PendingCallbacks != 1 {
		t.Fatal("Close refunded a caller that has not left preparation")
	}
	client.leave(slot)
	r.advanceWorkloads()
	if !w.cleaned || !client.advance() {
		t.Fatal("actual caller exit retained an idle scope")
	}
	closeWorkloadClient(t, client, r, e)
}

func TestServiceWorkloadCallScopesRetainOldGeneration(t *testing.T) {
	f, services, controller, sessions, fixtures := controllerReselectionFixture(t)
	client, err := controller.BindMethods(context.Background(), controllerServiceDefinition(f), workloadBindOptions(f.policy.Type))
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
		for _, r := range services {
			r.advanceWorkloads()
		}
	})
	old, oldSlot, _, err := client.prepare(context.Background(), 0, []byte("old"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.leave(oldSlot)
	defer old.Close()
	oldWorkload := oldSlot.workload.workload
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
	prepareControllerWorkloadFixture(t, f, controller, a, sessions[1])
	if err := controller.prepareCandidateWorkloads(a, sessions[1]); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	controller.current = sessions[1]
	a.result.CurrentSwitched, a.finished = true, true
	controller.attempt = nil
	controller.mu.Unlock()
	controller.finishCandidateContracts(a)
	old.Close()
	controller.advanceDispatches()
	services[0].advanceWorkloads()
	if !oldWorkload.closed || oldWorkload.cleaned {
		t.Fatal("replacement lost the old caller's actual scope")
	}
	occupyOrdinaryServiceCalls(t, client)
	saturateWorkloadRoot(t, f)
	op, slot, child, err := client.prepare(context.Background(), 0, []byte("new"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000}, true)
	if err != nil {
		t.Fatal("old generation occupied the new target", err)
	}
	defer client.leave(slot)
	defer op.Close()
	if slot.workload == nil || slot.workload.workload == oldWorkload || slot.session != sessions[1] || op.workload == nil || op.workload.workload != slot.workload.workload {
		t.Fatal("replacement did not consume its own complete vector")
	}
	if started := op.Start(child); started.Error != nil {
		t.Fatal(started.Error)
	}
	finishShortResponse(t, fixtures[1], op.header, 1, []byte("result"))
	services[1].AdvanceCalls()
	controller.advanceDispatches()
	if value, status, err := op.TakeResult(resultTestContext(t)); err != nil || !status.Delivered || string(value.([]byte)) != "result" {
		t.Fatal(value, status, err)
	}
}
