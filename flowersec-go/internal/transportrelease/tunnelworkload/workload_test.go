package tunnelworkload

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

func TestRunColdRequiresIndependentCleanupDeadline(t *testing.T) {
	_, err := RunCold(context.Background(), &Endpoint{}, 1, 1, 1, time.Second, 0)
	if err == nil || !errors.Is(err, errInvalidTunnelColdWorkload) {
		t.Fatalf("RunCold cleanup deadline error = %v", err)
	}
}

func TestReleaseCoordinatorPairTimeoutCoversColdPhase(t *testing.T) {
	plan := transportrelease.ProfilePlan{
		Cold: transportrelease.ColdPlan{
			OperationDeadlineSeconds: 53,
			PhaseDeadlineSeconds:     55,
		},
	}
	config, err := releaseCoordinatorConfig(plan)
	if err != nil {
		t.Fatal(err)
	}
	if config.PairTimeout != 55*time.Second {
		t.Fatalf("release pair timeout = %s, want cold phase deadline", config.PairTimeout)
	}
}

func TestTopologiesNameEveryWebSocketRawQUICPair(t *testing.T) {
	want := map[Topology][2]carrier.Kind{
		TopologyWW: {carrier.KindWebSocket, carrier.KindWebSocket},
		TopologyQQ: {carrier.KindQUIC, carrier.KindQUIC},
		TopologyWQ: {carrier.KindWebSocket, carrier.KindQUIC},
		TopologyQW: {carrier.KindQUIC, carrier.KindWebSocket},
	}
	if len(Topologies()) != len(want) {
		t.Fatalf("topologies = %v", Topologies())
	}
	for topology, carriers := range want {
		client, server, err := topology.Carriers()
		if err != nil {
			t.Fatal(err)
		}
		if client != carriers[0] || server != carriers[1] {
			t.Fatalf("%s carriers = %s/%s, want %s/%s", topology, client, server, carriers[0], carriers[1])
		}
	}
	if _, _, err := Topology("WT").Carriers(); err == nil {
		t.Fatal("accepted topology outside the frozen WW/QQ/WQ/QW matrix")
	}
}

func TestProductionTunnelTopologiesRunColdRPCBulkAndCleanup(t *testing.T) {
	plan := transportrelease.ProfilePlan{
		ID: "focused-v1",
		Cold: transportrelease.ColdPlan{
			Operations: 2, MaxInflight: 1, StartRatePerSecond: 20,
			OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 20,
		},
		RPC: transportrelease.RPCPlan{
			Operations: 4, RequestBytes: 128, ResponseBytes: 128, Workers: 2,
			OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 10,
		},
		Bulk: transportrelease.BulkPlan{
			WarmupBytesPerDirection: 1024, ScoreBytesPerDirection: 4096,
			PhaseDeadlineSeconds: 10,
		},
		CleanupDeadlineSeconds: 10,
	}
	for _, topology := range Topologies() {
		t.Run(string(topology), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			endpoint, err := OpenEndpointAt(ctx, topology, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			result, err := Run(ctx, endpoint, plan)
			if err != nil {
				t.Fatal(err)
			}
			if result.Topology != topology || len(result.Cold) != plan.Cold.Operations || len(result.RPC) != plan.RPC.Operations {
				t.Fatalf("incomplete workload result: %+v", result)
			}
			if result.Bulk.BytesPerDirection != plan.Bulk.ScoreBytesPerDirection || result.CleanupDuration <= 0 {
				t.Fatalf("incomplete bulk/cleanup result: %+v", result)
			}
		})
	}
}

func TestOpenEndpointAtRejectsNonConcreteAddress(t *testing.T) {
	for _, address := range []string{"", "0.0.0.0", "not-an-ip", "224.0.0.1"} {
		if _, err := OpenEndpointAt(context.Background(), TopologyWW, address); err == nil {
			t.Fatalf("accepted listen address %q", address)
		}
	}
}
