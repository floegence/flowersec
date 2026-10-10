package interopharness

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func TestPreparedMaterialOwnsPositionWithinOriginalDeployment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	serverReporter, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := serverReporter.Close(); err != nil {
			t.Error(err)
		}
	})
	server, err := NewServer(ctx, serverReporter, ServerOptions{Carrier: "websocket", Handlers: manualEchoPlan})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := server.Material().JSON()
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reporter.Close(); err != nil {
			t.Error(err)
		}
	})
	reporter.Capacity = &sessionv4.EngineeringHostCapacity{Sessions: 3, Materials: 3}
	base, err := NewClient(ctx, reporter, wire, server.TrustPEM, server.Origin, manualEchoPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !base.Runtime.ownsEnvironment || !base.Runtime.ownsExecutor {
		t.Fatal("original deployment did not retain ownership of its Environment and executor")
	}
	first, err := base.PrepareMaterial(ctx, server.Material(), server.Origin, manualEchoPlan)
	if err != nil {
		t.Fatal(err)
	}
	_, _, policy, err := directRoute(server.Material().Route)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := server.IssueAuthority(policy, server.Address)
	if err != nil {
		t.Fatal(err)
	}
	second, err := base.PrepareMaterial(ctx, server.MaterialFor(issued), server.Origin, manualEchoPlan)
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range []*Client{first, second} {
		r := child.Runtime
		if r.Environment != base.Runtime.Environment || r.Executor != base.Runtime.Executor || r.Authority.Root != base.Runtime.Authority.Root || r.Authority.Store != base.Runtime.Authority.Store || r.Authority.Clock != base.Runtime.Authority.Clock || r.Authority.Verification != base.Runtime.Authority.Verification || r.ownsEnvironment || r.ownsExecutor {
			t.Fatal("prepared position replaced or owned a shared deployment resource")
		}
		if r.Authority.Scope[0].Session == base.Runtime.Authority.Scope[0].Session || r.Plans[0] == base.Runtime.Plans[0] || r.Leases[0] == base.Runtime.Leases[0] || r.Handlers[0] == base.Runtime.Handlers[0] {
			t.Fatal("prepared position reused another original position owner")
		}
		cost := resourcev4.Vector{resourcev4.Items: r.Authority.SessionLimit[resourcev4.Items] + 1}
		ref, err := r.Authority.Root.Reserve(r.Authority.Owner(), cost, r.Authority.Scope[0].Session)
		ref.Release()
		if !errors.Is(err, resourcev4.ErrCapacity) {
			t.Fatalf("position inherited the aggregate root limit: %v", err)
		}
	}
	if first.Runtime.Authority.Scope[0].Session == second.Runtime.Authority.Scope[0].Session || first.Runtime.Authority.ArtifactDigest == second.Runtime.Authority.ArtifactDigest {
		t.Fatal("independent signed positions lost their original scopes or material")
	}
	first.Runtime.Reporter.CloseOwners()
	if err := first.Runtime.Reporter.WaitOwners(ctx); err != nil {
		t.Fatal("prepared child's registered physical owners did not retire", err)
	}
	if err := first.Runtime.Reporter.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-base.Runtime.Executor.Done():
		t.Fatal("closing a child shut down the shared executor")
	default:
	}
	if err := second.Runtime.Handlers[0].Retire(); err == nil {
		t.Fatal("closing a child retired its sibling's live handler", err)
	}
	second.Runtime.Reporter.CloseOwners()
	if err := second.Runtime.Reporter.WaitOwners(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Runtime.Reporter.Close(); err != nil {
		t.Fatal(err)
	}
	base.Runtime.Reporter.CloseOwners()
	if err := base.Runtime.Reporter.WaitOwners(ctx); err != nil {
		t.Fatal("original deployment did not retire after its positions", err)
	}
}
