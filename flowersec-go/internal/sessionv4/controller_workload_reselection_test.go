package sessionv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func stageControllerWorkloadReplacement(t *testing.T, f *serviceDispatchFixture, c *ConnectionController, next *EnvironmentSession) *controllerAttempt {
	t.Helper()
	deadline, err := timev4.NewAge(f.trust.clock, 4000, 5000)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(context.Canceled) })
	c.mu.Lock()
	a := &controllerAttempt{ctx: ctx, cancel: cancel, deadline: deadline, previous: c.current, candidate: next}
	c.attempt = a
	c.mu.Unlock()
	prepareControllerWorkloadFixture(t, f, c, a, next)
	if err := c.prepareCandidateWorkloads(a, next); err != nil {
		t.Fatal(err)
	}
	return a
}

// These routing tests use already authenticated component Sessions. Admit the
// same immutable replacement recipe and real target backing that full source
// construction would acquire before publishing the replacement candidate.
func prepareControllerWorkloadFixture(t *testing.T, f *serviceDispatchFixture, c *ConnectionController, a *controllerAttempt, next *EnvironmentSession) {
	t.Helper()
	r := next.dependencyServices()
	if r == nil {
		t.Fatal("missing candidate RPC services")
	}
	routes := rpcv4.ContractRoutesConfig{ContractNodes: 256}
	var digests [][32]byte
	for _, client := range c.environment.serviceClients {
		if client == nil || client.source.controller != c {
			continue
		}
		for i := range client.methods {
			method := &client.methods[i]
			if method.workload.Calls == 0 {
				continue
			}
			digest := method.definition.Method.Contract
			found := false
			for _, previous := range digests {
				found = found || previous == digest
			}
			if !found {
				digests = append(digests, digest)
				routes.Methods = append(routes.Methods, rpcv4.MethodRoutes{Contracts: [][]byte{append([]byte(nil), method.canonical...)}})
			}
		}
	}
	config := SourceConnectConfig{Root: r.root, Owner: r.owner, Scope: corePlanTestScope(t, r.root, r.root.Snapshot().Limit, 200),
		Admission: SessionAdmissionConfig{Application: f.plan, RPC: &RPCServicesConfig{Routes: routes, Session: testSessionContract(t, protocolv4.DHProfileX25519, "services", 4096, 4, 0, 5000).Contract}}}
	t.Cleanup(func() { a.workloads.close(next) })
	if err := c.prepareWorkloadPlan(a, &config); err != nil {
		t.Fatal(err)
	}
	r.initialWorkloads = make([]*unaryWorkload, len(config.Admission.RPC.Workloads))
	for index, target := range config.Admission.RPC.Workloads {
		w, err := r.qualifyUnaryWorkload(target.Method, target.Workload, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.initialIndex, w.replacement = index, target.replacement
		r.initialWorkloads[index] = w
		if err := w.reserveController(c); err != nil {
			t.Fatal(err)
		}
	}
}

func publishControllerWorkloadReplacement(c *ConnectionController, a *controllerAttempt) {
	c.mu.Lock()
	c.current, a.result.CurrentSwitched = a.candidate, true
	c.mu.Unlock()
	c.finishCandidateContracts(a)
}

func cleanupControllerWorkloadClient(t *testing.T, c *ConnectionController, services []*RPCServices, client *UnaryServiceClient) {
	t.Helper()
	t.Cleanup(func() {
		client.Close()
		for range 4 {
			c.advanceDispatches()
			advanceControllerServices(services)
			c.environment.advanceResults()
			c.environment.advanceServiceClients()
			for _, r := range services {
				r.advanceWorkloads()
			}
		}
		if err := client.WaitCleanup(resultTestContext(t)); err != nil {
			t.Error(err)
		}
	})
}

func TestControllerWorkloadReselectionConsumesSelectedTargetAtFullRoot(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_start", true: "tentative_route"}[started], func(t *testing.T) {
			f, services, c, sessions, fixtures := controllerReselectionFixture(t)
			definition := controllerServiceDefinition(f)
			var encodes atomic.Int32
			definition.Methods[0].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 16, ScratchBytes: 16, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) { encodes.Add(1); return input, nil }}
			client, err := c.BindMethods(context.Background(), definition, workloadBindOptions(f.policy.Type))
			if err != nil {
				t.Fatal(err)
			}
			cleanupControllerWorkloadClient(t, c, services, client)
			op, err := client.Prepare(context.Background(), []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(op.Close)
			original := op.workload.workload
			header := op.header
			var first *UnaryCall
			if started {
				result := op.Start(context.Background())
				if result.Error != nil {
					t.Fatal(result.Error)
				}
				first = result.Call
			}
			a := stageControllerWorkloadReplacement(t, f, c, sessions[1])
			target := client.methods[0].candidateWorkload.workload
			if target == nil || target == original || target.lineage != original.lineage || !target.installed.Load() {
				t.Fatal("candidate lacks original binding target")
			}
			publishControllerWorkloadReplacement(c, a)
			saturateWorkloadRoot(t, f)
			full := f.f.root.Snapshot()
			if started {
				c.advanceDispatches()
			} else {
				result := op.Start(context.Background())
				if result.Error != nil {
					t.Fatal("Start lost preadmitted selected target", result.Error)
				}
				first = result.Call
			}
			current := first.currentCall()
			if current.invocation == nil || current.invocation.services != services[1] || target.slots[0].activeCall.Load() != current.invocation || current.request != header || encodes.Load() != 1 || op.reselections != 1 {
				t.Fatal("reselection replaced request or used ordinary backing", current.ResultStatus())
			}
			if started && (current == first || !first.deferred.closed || first.deferred.cleaned) {
				t.Fatal("old forwarding/result tail was refunded or not sealed")
			}
			if f.f.root.Snapshot().Charged != full.Charged {
				t.Fatal("reselection allocated or refunded original target")
			}
			finishShortResponse(t, fixtures[1], op.header, 1, []byte("result"))
			advanceControllerServices(services)
			value, status, err := op.TakeResult(resultTestContext(t))
			if err != nil || !status.Delivered || string(value.([]byte)) != "result" {
				t.Fatal(value, status, err)
			}
			if result := c.Dispatch(context.Background(), op); result.Call != first || result.Error != nil || encodes.Load() != 1 {
				t.Fatal("Dispatch repeated original Start", result)
			}
			op.Close()
			advanceControllerServices(services)
			c.environment.advanceResults()
			c.advanceDispatches()
		})
	}
}

func TestControllerWorkloadReselectionCannotBorrowAnotherBinding(t *testing.T) {
	f, services, c, sessions, _ := controllerReselectionFixture(t, 2)
	definition := controllerServiceDefinition(f)
	first, err := c.BindMethods(context.Background(), definition, workloadBindOptions(f.policy.Type))
	if err != nil {
		t.Fatal(err)
	}
	cleanupControllerWorkloadClient(t, c, services, first)
	other, err := c.BindMethods(context.Background(), definition, workloadBindOptions(f.policy.Type))
	if err != nil {
		t.Fatal(err)
	}
	cleanupControllerWorkloadClient(t, c, services, other)
	op, err := first.Prepare(context.Background(), []byte("old"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	a := stageControllerWorkloadReplacement(t, f, c, sessions[1])
	publishControllerWorkloadReplacement(c, a)
	occupied, err := first.Prepare(context.Background(), []byte("new"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(occupied.Close)
	otherTarget := other.methods[0].definition.Method.workload
	if otherTarget.lineage == op.workload.workload.lineage {
		t.Fatal("independent bindings share workload identity")
	}
	saturateWorkloadRoot(t, f)
	result := op.Start(context.Background())
	if result.Call != nil || !errors.Is(result.Error, resourcev4.ErrCapacity) || otherTarget.slots[0].used || otherTarget.slots[0].activeCall.Load() != nil {
		t.Fatal("reselection consumed unrelated binding capacity", result)
	}
}

func TestControllerWorkloadReselectionCannotConsumeUninstalledCandidate(t *testing.T) {
	f, services, c, sessions, _ := controllerReselectionFixture(t)
	client, err := c.BindMethods(context.Background(), controllerServiceDefinition(f), workloadBindOptions(f.policy.Type))
	if err != nil {
		t.Fatal(err)
	}
	cleanupControllerWorkloadClient(t, c, services, client)
	op, err := client.Prepare(context.Background(), []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	m := &client.methods[0]
	candidate, err := client.prepareWorkloadCandidate(m, m.definition.Method.Contract, services[1])
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.finish()
	if candidate.next.installed.Load() {
		t.Fatal("private qualification published target")
	}
	switchControllerFixture(c, sessions[1])
	saturateWorkloadRoot(t, f)
	result := op.Start(context.Background())
	if result.Call != nil || !errors.Is(result.Error, resourcev4.ErrCapacity) || candidate.next.slots[0].used {
		t.Fatal("uninstalled candidate supplied dispatch capacity", result)
	}
}

func TestControllerWorkloadReselectionKeepsAllThreeOriginalTails(t *testing.T) {
	f, services, c, sessions, fixtures := controllerReselectionFixture(t, 3)
	client, err := c.BindMethods(context.Background(), controllerServiceDefinition(f), workloadBindOptions(f.policy.Type))
	if err != nil {
		t.Fatal(err)
	}
	cleanupControllerWorkloadClient(t, c, services, client)
	op, err := client.Prepare(context.Background(), []byte("req"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	start := op.Start(context.Background())
	if start.Error != nil {
		t.Fatal(start.Error)
	}
	var targets [3]*unaryWorkload
	targets[0] = op.workload.workload
	for index := 1; index < 3; index++ {
		a := stageControllerWorkloadReplacement(t, f, c, sessions[index])
		targets[index] = client.methods[0].candidateWorkload.workload
		publishControllerWorkloadReplacement(c, a)
		if index == 2 {
			saturateWorkloadRoot(t, f)
		}
		c.advanceDispatches()
		if start.Call.currentCall().invocation.services != services[index] || op.reselections != uint8(index) {
			t.Fatal("bounded original route could not consume its complete target", start.Call.ResultStatus())
		}
	}
	advanceControllerServices(services)
	for _, w := range targets {
		if w.cleaned {
			t.Fatal("an original tentative tail was refunded")
		}
	}
	first, second := start.Call, start.Call.redirected()
	if second == nil || second.redirected() == nil || first.deferred.cleaned || second.deferred.cleaned {
		t.Fatal("forwarding owner was discarded before original handle exit")
	}
	finishShortResponse(t, fixtures[2], op.header, 1, []byte("third result"))
	advanceControllerServices(services)
	value, status, err := op.TakeResult(resultTestContext(t))
	if err != nil || !status.Delivered || string(value.([]byte)) != "third result" {
		t.Fatal(value, status, err)
	}
	op.Close()
	for range 4 {
		advanceControllerServices(services)
		c.environment.advanceResults()
		c.advanceDispatches()
		for _, r := range services {
			r.advanceWorkloads()
		}
	}
	if err := op.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if !targets[0].cleaned || !targets[1].cleaned || targets[2].closed {
		t.Fatal("route cleanup did not retain only current's unused target")
	}
}
