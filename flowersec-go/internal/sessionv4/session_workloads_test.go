package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// Material geometry is signed as services before any provider or preparation
// exists. This exercises the real original consumer/accepted admission gates.
func sessionWorkloadFixture(t *testing.T) (*admissionIntegrationFixture, *Environment) {
	t.Helper()
	f := admissionIntegrationProfile(t, context.Background(), "live_authority", "services")
	ef := &executorFixture{root: f.root, config: ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, Ready: 4, ResidentReady: 2, CompletionRunning: 1, CompletionReserved: 4, QueryOwners: 4, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}}
	charge, err := ApplicationExecutorCharge(ef.config)
	if err != nil {
		t.Fatal(err)
	}
	ef.executor, err = NewApplicationExecutor(ef.config, ef.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ef.executor.Close(); awaitApplicationTask(t, ef.executor.Done()) })
	accounts := []resourcev4.Account{f.scope.Tenant, f.scope.Session}
	plan := applicationTestPlan(t, ef, SessionPlanConfig{Services: true, ContractQueries: true, RuntimeBytes: 4096, AuthorizeApplication: func(context.Context, AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		return AuthorizeApplicationResult{}, ErrApplicationAuthorization
	}}, accounts...)
	c := rpcServicesTestConfig(ef, f.trust.clock, f.trust.session.Contract)
	c.Accounts = accounts
	wire := initialFixture(t, "service_unary_transient")
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := contract.Policy()
	contract.Release()
	if err != nil {
		t.Fatal(err)
	}
	c.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{wire}}}
	c.Workloads = []SessionMethodWorkload{{Namespace: policy.Namespace, Method: ServiceMethod{Type: policy.Type, Method: UnaryMethodDefinition{Contract: policy.Digest, WorkClass: ApplicationShort, DefaultResponseLimitBytes: 1024, Decode: func(_ context.Context, b []byte) (any, error) { return string(b), nil }}}, Workload: ServiceMethodWorkload{Type: policy.Type, Calls: 1, RequestBytes: 8}}}
	f.config.Application, f.config.RPC = plan, &c
	core := &f.config.Core
	core.MaxScopes = 16
	core.Open.Active, core.Open.Terminal = 12, 32
	core.Open.PerClass = [3]uint32{2, 10, 0}
	core.Open.PerOpener = [2][3]uint32{{2, 5, 0}, {2, 5, 0}}
	core.Open.Protected = [2][3]uint32{{0, 5, 0}, {0, 5, 0}}
	core.Open.Lifetime = [2][3]uint64{{1024, 1024, 0}, {1024, 1024, 0}}
	core.SendWorkers = [3]uint32{1, 1, 0}
	core.Streams = c.Bootstrap
	ec := EnvironmentConfig{Services: true, ResultOwners: 4, Positions: 1, Clock: f.trust.clock, RuntimeBytes: 65536}
	charge, err = EnvironmentCharge(ec)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvironment(ec, ef.reserve(t, 1, charge), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.Close()
		if err := e.WaitCleanup(resultTestContext(t)); err != nil {
			t.Error(err)
		}
		if err := e.Retire(); err != nil {
			t.Error(err)
		}
	})
	return f, e
}

func hostWorkloadPlan(t *testing.T, f *admissionIntegrationFixture, e *Environment) {
	t.Helper()
	host := newEnvironmentSession(e, 0, context.Background())
	if err := f.config.Application.claimPreparation(host); err != nil {
		t.Fatal(err)
	}
	f.config.applicationHost = host
}

func TestSessionWorkloadOriginalAdmissionAccountsAndTransfer(t *testing.T) {
	for _, controller := range []bool{false, true} {
		t.Run(map[bool]string{false: "consumer", true: "controller"}[controller], func(t *testing.T) {
			f, e := sessionWorkloadFixture(t)
			want, count, err := SessionAdmissionRequirements(f.config)
			if err != nil {
				t.Fatal(err)
			}
			before := f.root.Snapshot()
			var h *sessionHeadroom
			var original *unaryWorkload
			var receive *ReceivePool
			if controller {
				h, err = reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
				if err != nil {
					t.Fatal(err)
				}
				defer h.close()
				original = h.workloads
				receive = h.receivePool
				if receive == nil {
					t.Fatal("original receive pool was not prepared before Acquire")
				}
				if original == nil || original.services != nil || original.slots[0].authority != nil || original.slots[0].authorityBacking.Check() != nil || e.OperationsSnapshot().ProtectedResults != 2 {
					t.Fatal("pre-Acquire promises missing or authority manufactured")
				}
				if original.slots[0].completion.checkAvailable() != nil || h.completionFloor.checkAvailable() != nil {
					t.Fatal("future Completion not reserved")
				}
				f.config.headroom = h
			}
			hostWorkloadPlan(t, f, e)
			a := f.reserve(t, context.Background())
			expected, _ := before.Charged.Add(want)
			after := f.root.Snapshot()
			if after.Charged != expected || after.Reservations != before.Reservations+count {
				t.Fatal("requirements omitted or duplicated backing", before, after, want, count)
			}
			if receive != nil && a.core.receivePool != receive {
				t.Fatal("admission replaced pre-Acquire receive backing")
			}
			r := a.application.rpc
			w := r.initialWorkloads[0]
			if w == nil || w.services != r || w.slots[0].authority == nil || w.slots[0].authorityBacking != (resourcev4.Reference{}) || original != nil && original != w {
				t.Fatal("original admitted workload not transferred")
			}
			if f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 || a.claimed || a.committed || a.activated {
				t.Fatal("resource construction disclosed credentials or crossed TxA")
			}
			if h != nil {
				h.close()
				if f.root.Snapshot() != after {
					t.Fatal("headroom released adopted ownership")
				}
			}
			target := f.config.RPC.Workloads[0]
			claimed, err := r.qualifyUnaryWorkload(target.Method, target.Workload, nil)
			if err != nil || claimed != w || r.initialWorkloads[0] != nil {
				t.Fatal("Bind qualification ignored factory target", err)
			}
			claimed.releaseUnpublished()
			if r.initialWorkloads[0] != w || w.closed || f.root.Snapshot() != after {
				t.Fatal("failed Bind lost original promise")
			}
		})
	}
}

func TestSessionWorkloadRejectedBeforeCredentialAdoption(t *testing.T) {
	for _, kind := range []string{"result_capacity", "completion_capacity", "missing_contract", "duplicate_method", "partial_targets", "standalone"} {
		t.Run(kind, func(t *testing.T) {
			f, e := sessionWorkloadFixture(t)
			switch kind {
			case "result_capacity":
				f.config.RPC.Workloads[0].Workload.Calls = 4
			case "completion_capacity":
				f.config.RPC.Workloads[0].Workload.Calls = 3
			case "missing_contract":
				f.config.RPC.Workloads[0].Method.Method.Contract[0] ^= 1
			case "duplicate_method":
				f.config.RPC.Workloads = append(f.config.RPC.Workloads, f.config.RPC.Workloads[0])
			case "partial_targets":
				first := &f.config.RPC.Workloads[0]
				first.Workload.Calls = 2
				second := *first
				second.Method.Type++
				second.Workload.Type, second.Workload.Calls = second.Method.Type, 1
				wire := admissionMap(t, "ServiceContract", f.config.RPC.Routes.Methods[0].Contracts[0], map[string]protocolv4.Field{"type": {Number: uint64(second.Method.Type)}})
				codec, err := protocolv4.NewServiceContractCodec(256)
				if err != nil {
					t.Fatal(err)
				}
				contract, err := codec.Decode(wire)
				if err != nil {
					t.Fatal(err)
				}
				second.Method.Method.Contract, err = contract.Digest()
				contract.Release()
				if err != nil {
					t.Fatal(err)
				}
				f.config.RPC.Routes.Methods = append(f.config.RPC.Routes.Methods, rpcv4.MethodRoutes{Contracts: [][]byte{wire}})
				f.config.RPC.Workloads = append(f.config.RPC.Workloads, second)
			}
			before, positions := f.root.Snapshot(), e.OperationsSnapshot()
			if kind == "standalone" {
				if _, err := f.config.Application.InstallRPCServices(*f.config.RPC); !errors.Is(err, cryptov4.ErrConfiguration) {
					t.Fatal(err)
				}
			} else {
				hostWorkloadPlan(t, f, e)
				a, err := NewSessionAdmissionReservation(context.Background(), f.config, f.prepared, f.trust.subscriptions[0], f.root, admissionResourceKey(f.owner, 202), f.environment, f.preauth, f.scope, nil, nil)
				if a != nil || err == nil {
					t.Fatal("incomplete target was admitted", a, err)
				}
			}
			if f.root.Snapshot() != before || e.OperationsSnapshot() != positions || f.config.Application.rpc != nil || f.config.Application.rpcPreparing || f.config.Application.claimed || f.config.Application.closed {
				t.Fatal("failed preparation retained ownership or consumed plan", before, f.root.Snapshot())
			}
			if _, err := f.trust.subscriptions[0].CheckOriginalFor(f.environment, f.trust.session, protocolv4.ClientToServer, f.trust.candidate); err != nil {
				t.Fatal("failure consumed credential owner", err)
			}
		})
	}
}

func TestSessionWorkloadHeadroomRejectsChangedRecipeAndCloses(t *testing.T) {
	f, e := sessionWorkloadFixture(t)
	before, positions := f.root.Snapshot(), e.OperationsSnapshot()
	h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	f.config.RPC.Workloads[0].Workload.RequestBytes++
	hostWorkloadPlan(t, f, e)
	f.config.headroom = h
	reserved := f.root.Snapshot()
	a, err := NewSessionAdmissionReservation(context.Background(), f.config, f.prepared, f.trust.subscriptions[0], f.root, admissionResourceKey(f.owner, 202), f.environment, f.preauth, f.scope, nil, nil)
	if a != nil || !errors.Is(err, cryptov4.ErrConfiguration) || h.claimed || f.root.Snapshot() != reserved {
		t.Fatal("changed recipe consumed headroom", err)
	}
	h.close()
	if f.root.Snapshot() != before || e.OperationsSnapshot() != positions {
		t.Fatal("headroom leaked original future owners", before, f.root.Snapshot())
	}
}

func TestSessionWorkloadAcceptedAdmissionUsesOriginalVerifiedSubscriptions(t *testing.T) {
	f, environment := sessionWorkloadFixture(t)
	_, entrance, _, fsb := acceptedVerifiedFlightFrom(t, f)
	hostWorkloadPlan(t, f, environment)
	c := f.config
	c.Core.MessageCarrier = false
	c.Initial.Role = protocolv4.ServerToClient
	a, err := NewAcceptedSessionAdmissionReservation(context.Background(), c, entrance, AcceptedAdmissionMaterial{Activation: f.trust.activation, Authority: f.trust.authority, FSB: fsb, ClientCertificate: f.trust.certificates[0], Subscriptions: f.trust.subscriptions[1], Attempt: f.trust.attempt}, f.root, admissionResourceKey(f.owner, 213), f.environment, f.preauth, f.scope)
	if a != nil {
		t.Cleanup(func() {
			a.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := a.WaitCleanup(ctx); err != nil {
				t.Error(err)
				return
			}
			if err := a.Retire(); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	w := a.application.rpc.initialWorkloads[0]
	if w == nil || w.slots[0].authority == nil || a.claimed || a.committed || a.activated || environment.OperationsSnapshot().ProtectedResults != 2 {
		t.Fatal("accepted owner crossed durable admission or lost target")
	}
}

func TestSessionWorkloadSnapshotFreezesOriginalRecipe(t *testing.T) {
	f, _ := sessionWorkloadFixture(t)
	c := f.config.RPC
	snapshot := captureRPCServicesConfig(c)
	c.Workloads[0].Namespace = "changed"
	c.Workloads[0].Workload.RequestBytes++
	c.Workloads[0].Method.Method.Contract[0] ^= 1
	if snapshot.Workloads[0].Namespace == c.Workloads[0].Namespace || snapshot.Workloads[0].Workload == c.Workloads[0].Workload || snapshot.Workloads[0].Method.Method.Contract == c.Workloads[0].Method.Method.Contract {
		t.Fatal("asynchronous preparation retained mutable workload recipe")
	}
}

func TestSessionWorkloadHeadroomTransfersAtFullByteBudget(t *testing.T) {
	f, e := sessionWorkloadFixture(t)
	h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	w := h.workloads
	snapshot := f.root.Snapshot()
	fill, err := f.root.Reserve(admissionResourceKey(f.owner, 230), resourcev4.Vector{resourcev4.SDKBytes: snapshot.Limit[resourcev4.SDKBytes] - snapshot.Charged[resourcev4.SDKBytes]})
	if err != nil {
		t.Fatal(err)
	}
	defer fill.Release()
	full := f.root.Snapshot()
	f.config.headroom = h
	hostWorkloadPlan(t, f, e)
	a := f.reserve(t, context.Background())
	if a.application.rpc.initialWorkloads[0] != w || f.root.Snapshot().Charged != full.Charged {
		t.Fatal("headroom required new bytes or replaced original target")
	}
}

func TestSessionWorkloadHeadroomPartialFailureReturnsWholePromise(t *testing.T) {
	for _, calls := range []uint16{3, 4} {
		t.Run(string(rune('0'+calls)), func(t *testing.T) {
			f, e := sessionWorkloadFixture(t)
			f.config.RPC.Workloads[0].Workload.Calls = calls
			before, positions := f.root.Snapshot(), e.OperationsSnapshot()
			h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
			if h != nil || !errors.Is(err, cryptov4.ErrCapacity) {
				t.Fatal("partial headroom accepted", err)
			}
			if f.root.Snapshot() != before || e.OperationsSnapshot() != positions || f.config.Application.rpcPreparing {
				t.Fatal("pre-Acquire failure leaked reservations")
			}
		})
	}
}
