package transporttest

import (
	"context"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier"
)

func TestProductionControllerArtifactCurrentPinConnects(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			endpoint, err := OpenProductDirectEndpoint(ctx, kind)
			if err != nil {
				t.Fatal(err)
			}
			defer endpoint.Close()
			source, err := NewProductControllerArtifactSource(endpoint, []ControllerArtifactPlan{ControllerPlanCurrentPin})
			if err != nil {
				t.Fatal(err)
			}
			lease, sourceErr := source.Acquire(ctx)
			if sourceErr != nil {
				t.Fatal(sourceErr)
			}
			client, err := flowersec.Connect(ctx, lease, endpoint.ProductControllerConnectorOptions())
			if err != nil {
				t.Fatalf("current pin connect failed: %v", err)
			}
			defer client.Close()
			server, err := source.WaitServer(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
		})
	}
}

func TestProductionControllerEstablishedSessionSurvivesPinPolicyExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint, err := OpenProductDirectEndpoint(ctx, carrier.KindWebSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	source, err := NewProductControllerArtifactSource(endpoint, []ControllerArtifactPlan{ControllerPlanExpiringPin})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := flowersec.NewConnectionController(source, flowersec.ConnectionControllerOptions{
		Connector: endpoint.ProductControllerConnectorOptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	controller.Start(ctx)
	defer controller.Close(context.Background())
	deadline := time.Now().Add(3 * time.Second)
	for controller.Snapshot().State != flowersec.ConnectionConnected && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if controller.Snapshot().State != flowersec.ConnectionConnected {
		snapshot := controller.Snapshot()
		t.Fatalf("controller did not establish before pin expiry: %s failure=%v", snapshot, snapshot.Failure)
	}
	server, err := source.WaitServer(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	time.Sleep(5 * time.Second)
	if _, err := controller.CurrentSession().ProbeLiveness(ctx); err != nil {
		t.Fatalf("established session was disconnected when artifact pin expired: %v", err)
	}
	if got := controller.Snapshot().State; got != flowersec.ConnectionConnected {
		t.Fatalf("controller state after pin expiry = %s, want connected", got)
	}
}
