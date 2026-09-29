package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func sessionStreamWorkloadFixture(t *testing.T) (*admissionIntegrationFixture, *Environment) {
	t.Helper()
	f, environment := sessionWorkloadFixture(t)
	wire := initialFixture(t, "service_stream_transient")
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
	c := f.config.RPC
	c.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{wire}}}
	c.Workloads = []SessionMethodWorkload{{Namespace: policy.Namespace, Method: ServiceMethod{Type: policy.Type, Shape: 1, StreamKind: "test/events", StreamMetadata: []byte("fixed"), Method: UnaryMethodDefinition{Contract: policy.Digest, DefaultResponseLimitBytes: 1024, Decode: func(_ context.Context, b []byte) (any, error) { return string(b), nil }}}, Workload: ServiceMethodWorkload{Type: policy.Type, Calls: 1, RequestBytes: 8}}}
	return f, environment
}

func TestSessionStreamWorkloadOriginalAdmissionAccountsAndTransfer(t *testing.T) {
	for _, headroom := range []bool{false, true} {
		t.Run(map[bool]string{false: "consumer", true: "controller"}[headroom], func(t *testing.T) {
			f, environment := sessionStreamWorkloadFixture(t)
			want, count, err := SessionAdmissionRequirements(f.config)
			if err != nil {
				t.Fatal(err)
			}
			before := f.root.Snapshot()
			var h *sessionHeadroom
			var original *unaryWorkload
			if headroom {
				h, err = reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, environment)
				if err != nil {
					t.Fatal(err)
				}
				defer h.close()
				original = h.workloads
				if original == nil || original.stream == nil || original.stream.core != nil || original.slots[0].transport.plan != nil || original.slots[0].transport.receive.pool != h.receivePool {
					t.Fatal("streaming backing was not admitted before Acquire")
				}
				f.config.headroom = h
			}
			hostWorkloadPlan(t, f, environment)
			a := f.reserve(t, context.Background())
			w := a.application.rpc.initialWorkloads[0]
			after := f.root.Snapshot()
			expected, err := before.Charged.Add(want)
			if err != nil || after.Charged != expected || after.Reservations != before.Reservations+count {
				t.Fatal("streaming requirements omitted or duplicated original owners", before, after, want, count)
			}
			if w == nil || w.stream == nil || w.stream.core != nil || original != nil && original != w || w.slots[0].transport.receive.pool != a.core.receivePool || w.slots[0].authority == nil {
				t.Fatal("admission replaced streaming responsibility")
			}
			if f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 || a.claimed || a.committed || a.activated {
				t.Fatal("workload crossed the original credential/spend boundary")
			}
			if h != nil {
				h.close()
				if f.root.Snapshot() != after {
					t.Fatal("headroom closed the adopted streaming owners")
				}
			}
		})
	}
}

func TestSessionStreamWorkloadRejectsChangedOriginalGeometry(t *testing.T) {
	for _, change := range []string{"kind", "metadata", "transport"} {
		t.Run(change, func(t *testing.T) {
			f, e := sessionStreamWorkloadFixture(t)
			before, positions := f.root.Snapshot(), e.OperationsSnapshot()
			h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
			if err != nil {
				t.Fatal(err)
			}
			defer h.close()
			switch change {
			case "kind":
				f.config.RPC.Workloads[0].Method.StreamKind = "test/other"
			case "metadata":
				f.config.RPC.Workloads[0].Method.StreamMetadata[0] ^= 1
			case "transport":
				f.config.Core.Streams.QueueBytes++
			}
			f.config.headroom = h
			hostWorkloadPlan(t, f, e)
			reserved := f.root.Snapshot()
			a, err := NewSessionAdmissionReservation(context.Background(), f.config, f.prepared, f.trust.subscriptions[0], f.root, admissionResourceKey(f.owner, 202), f.environment, f.preauth, f.scope, nil, nil)
			if a != nil || !errors.Is(err, cryptov4.ErrConfiguration) || h.claimed || f.root.Snapshot() != reserved {
				t.Fatal("changed geometry consumed or replaced original backing", err)
			}
			h.close()
			if f.root.Snapshot() != before || e.OperationsSnapshot() != positions {
				t.Fatal("failed geometry check leaked original backing")
			}
		})
	}
}

func TestSessionStreamWorkloadHeadroomTransfersAtFullBytes(t *testing.T) {
	f, e := sessionStreamWorkloadFixture(t)
	h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	w := h.workloads
	before := f.root.Snapshot()
	fill, err := f.root.Reserve(admissionResourceKey(f.owner, 231), resourcev4.Vector{resourcev4.SDKBytes: before.Limit[resourcev4.SDKBytes] - before.Charged[resourcev4.SDKBytes]})
	if err != nil {
		t.Fatal(err)
	}
	defer fill.Release()
	full := f.root.Snapshot()
	f.config.headroom = h
	hostWorkloadPlan(t, f, e)
	a := f.reserve(t, context.Background())
	if a.application.rpc.initialWorkloads[0] != w || f.root.Snapshot().Charged != full.Charged {
		t.Fatal("streaming admission requested another byte vector")
	}
}

func TestSessionStreamWorkloadRejectsIncompleteTransportBeforeAcquire(t *testing.T) {
	for _, field := range []string{"opening", "receive", "credit"} {
		t.Run(field, func(t *testing.T) {
			f, e := sessionStreamWorkloadFixture(t)
			switch field {
			case "opening":
				f.config.Core.Open.Opening = 1
			case "receive":
				f.config.Core.Streams.ReceivePoolBytes = f.config.Core.Streams.ReceiveBytes
			case "credit":
				f.config.Core.Streams.InitialReceiveLimit = 1
			}
			before, positions := f.root.Snapshot(), e.OperationsSnapshot()
			if _, _, err := SessionAdmissionRequirements(f.config); err == nil {
				t.Fatal("requirements accepted an incomplete streaming transport")
			}
			h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
			if h != nil || err == nil || f.root.Snapshot() != before || e.OperationsSnapshot() != positions {
				t.Fatal("incomplete streaming transport retained partial admission", err)
			}
		})
	}
}
