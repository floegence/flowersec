package tunnelworkload

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/gorilla/websocket"
)

type terminalCloseSession struct {
	flowersession.SessionV2
	closeErr   error
	terminated chan struct{}
}

func (session *terminalCloseSession) Termination() <-chan struct{} { return session.terminated }
func (session *terminalCloseSession) Close() error                 { return session.closeErr }

func TestPairCloseAcceptsTerminalSessionCloseErrorsAfterTermination(t *testing.T) {
	terminated := make(chan struct{})
	close(terminated)
	pair := &Pair{
		Client: &terminalCloseSession{closeErr: context.DeadlineExceeded, terminated: terminated},
		Server: &terminalCloseSession{closeErr: context.Canceled, terminated: terminated},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pair.Close(ctx); err != nil {
		t.Fatalf("Pair.Close terminal errors = %v", err)
	}
}

func TestPairCloseAcceptsPeerTunnelBridgeCloseAfterTermination(t *testing.T) {
	terminated := make(chan struct{})
	close(terminated)
	pair := &Pair{
		Client: &terminalCloseSession{
			closeErr:   &websocket.CloseError{Code: 4000, Text: "tunnel bridge closed"},
			terminated: terminated,
		},
	}
	if err := pair.Close(context.Background()); err != nil {
		t.Fatalf("Pair.Close peer tunnel bridge close = %v", err)
	}
}

func TestPairCloseRetainsUnexpectedSessionCloseErrors(t *testing.T) {
	terminated := make(chan struct{})
	close(terminated)
	want := errors.New("unexpected close failure")
	pair := &Pair{Client: &terminalCloseSession{closeErr: want, terminated: terminated}}
	if err := pair.Close(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Pair.Close error = %v, want %v", err, want)
	}
}

func TestPairClosePrefersCompletedTerminationOverExpiredCleanupContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 64 {
		terminated := make(chan struct{})
		close(terminated)
		pair := &Pair{Client: &terminalCloseSession{terminated: terminated}}
		if err := pair.Close(ctx); err != nil {
			t.Fatalf("Pair.Close completed termination = %v", err)
		}
	}
}

func TestCloseTunnelOwnersCancelsEndpointBeforeWaitingForPairTermination(t *testing.T) {
	terminated := make(chan struct{})
	pair := &Pair{
		Client: &terminalCloseSession{terminated: terminated},
		Server: &terminalCloseSession{terminated: terminated},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := closeTunnelOwners(ctx, pair, func(context.Context) error {
		close(terminated)
		return nil
	}); err != nil {
		t.Fatalf("close tunnel owners with dependent termination: %v", err)
	}
}

func TestRunColdRequiresIndependentCleanupDeadline(t *testing.T) {
	_, err := RunCold(context.Background(), &Endpoint{}, 1, 1, 1, time.Second, 0)
	if err == nil || !errors.Is(err, errInvalidTunnelColdWorkload) {
		t.Fatalf("RunCold cleanup deadline error = %v", err)
	}
}

func TestRunColdStopsSchedulingAndPreservesFirstProductFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, err := RunCold(ctx, &Endpoint{}, 3, 1, 2, time.Second, time.Second)
	elapsed := time.Since(started)
	if !errors.Is(err, errEndpointClosed) || !strings.Contains(err.Error(), "tunnel cold connection 1") {
		t.Fatalf("RunCold first failure = %v", err)
	}
	if strings.Contains(err.Error(), "tunnel cold connection 2") || elapsed >= 400*time.Millisecond {
		t.Fatalf("RunCold scheduled after first failure: elapsed=%s error=%v", elapsed, err)
	}
	if ctx.Err() != nil {
		t.Fatalf("RunCold canceled its caller context: %v", ctx.Err())
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
	if config.PairTimeout != 55*time.Second || config.AdmissionResponseTimeout != 30*time.Second || config.ActivationTimeout != 30*time.Second {
		t.Fatalf("release coordinator timeouts = pair %s response %s activation %s", config.PairTimeout, config.AdmissionResponseTimeout, config.ActivationTimeout)
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

func TestProductionTunnelWQCleanupFitsFrozenDeadline(t *testing.T) {
	plan := transportrelease.ProfilePlan{
		ID: "cleanup-contract-v1",
		Cold: transportrelease.ColdPlan{
			Operations: 1, MaxInflight: 1, StartRatePerSecond: 1,
			OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 6,
		},
		RPC: transportrelease.RPCPlan{
			Operations: 1, RequestBytes: 128, ResponseBytes: 128, Workers: 1,
			OperationDeadlineSeconds: 2, PhaseDeadlineSeconds: 4,
		},
		Bulk: transportrelease.BulkPlan{
			WarmupBytesPerDirection: 1024, ScoreBytesPerDirection: 4096,
			PhaseDeadlineSeconds: 5,
		},
		CleanupDeadlineSeconds: 2,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpoint, err := OpenEndpointAt(ctx, TopologyWQ, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(ctx, endpoint, plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.CleanupDuration <= 0 || result.CleanupDuration > 2*time.Second {
		t.Fatalf("WQ cleanup duration = %s, want within frozen 2s deadline", result.CleanupDuration)
	}
}

func TestOpenEndpointAtRejectsNonConcreteAddress(t *testing.T) {
	for _, address := range []string{"", "0.0.0.0", "not-an-ip", "224.0.0.1"} {
		if _, err := OpenEndpointAt(context.Background(), TopologyWW, address); err == nil {
			t.Fatalf("accepted listen address %q", address)
		}
	}
}
