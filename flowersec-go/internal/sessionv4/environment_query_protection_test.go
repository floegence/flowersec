package sessionv4

import (
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func TestContractQueryProtectionRetainsCompleteAcquisitionThroughInstallation(t *testing.T) {
	x := newRemoteServiceShapeFixture(t, 1, true)
	p, err := x.rpc.prepareContractQueryProtection(x.environment, x.session)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var ordinary [3]*contractQueryClaim
	for i := range ordinary {
		ordinary[i], err = x.environment.reserveContractQuery()
		if err != nil {
			t.Fatal(err)
		}
		defer ordinary[i].release()
	}
	if _, err = x.environment.reserveContractQuery(); err != cryptov4.ErrCapacity {
		t.Fatal("ordinary work consumed protection", err)
	}
	for range 3 {
		claim, _, err := p.reserve(x.session)
		if err != nil {
			t.Fatal(err)
		}
		defer claim.release()
		target := ServiceContractTarget{Namespace: x.definition.Namespace, Type: 1, Wanted: x.definition.Methods[0].Method.Contract, HasWanted: true, MaxOfferWindowMS: 1000}
		q, err := x.session.beginServiceContractQueryUntil(context.Background(), []ServiceContractTarget{target}, nil, claim, []protocolv4.ContractQueryKnown{nil})
		if err != nil {
			t.Fatal(err)
		}
		var snapshots *ContractQuerySnapshots
		x.run(t, func() {
			if err = q.Wait(context.Background()); err == nil {
				snapshots, err = q.Take()
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		defer snapshots.Close()
		awaitQuery(t, q.registration.done)
		if q.call.CleanupComplete() {
			t.Fatal("Q2 returned before consumer installation exit")
		}
		if _, _, err = p.reserve(x.session); err != cryptov4.ErrCapacity {
			t.Fatal("protected output was recycled", err)
		}
		if s := x.environment.OperationsSnapshot(); s.ActiveQueries != 4 {
			t.Fatal("Environment position returned early", s)
		}
		snapshots.Close()
		claim.release()
		x.run(t, func() { err = q.WaitCleanup(resultTestContext(t)) })
		if err != nil {
			t.Fatal(err)
		}
		if s := x.environment.OperationsSnapshot(); s.ActiveQueries != 3 {
			t.Fatal(s)
		}
	}
	p.Close()
}

func TestContractQueryProtectionSharesEnvironmentAcrossRealSessionVectors(t *testing.T) {
	x := newRemoteServiceWindowFixture(t, 1, true, 400000)
	f := x.executorFixture
	config := rpcv4.NetworkConfig{Session: testSessionContract(t, protocolv4.DHProfileX25519, "services", 4096, 4, 0, 5000).Contract, Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}}, RuntimeBytes: 4096}
	charge, err := rpcv4.NetworkCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	network, err := rpcv4.NewNetwork(config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(network.Close)
	charge, _ = rpcv4.ContractQueryClientCharge(4096)
	queries, err := network.NewContractQueryClient(x.rpc.clock, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(queries.Close)
	plan := applicationTestPlan(t, f, SessionPlanConfig{ContractQueries: true, RuntimeBytes: 4096, AuthorizeApplication: func(ctx context.Context, request AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		lease, err := request.ReserveLease(request.Binding(), nil, func(context.Context) error { return nil })
		return AuthorizeApplicationResult{Lease: lease}, err
	}})
	charge, _ = rpcv4.ContractQueryServiceCharge(4096)
	service, err := network.NewContractQueryService(x.server, x.rpc.clock, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	if err = plan.InstallContractQueries(service); err != nil {
		t.Fatal(err)
	}
	if err = plan.InstallOutgoingContractQueries(queries); err != nil {
		t.Fatal(err)
	}
	plan.claimed = true
	session := &EnvironmentSession{environment: x.environment, application: plan, delivered: true, core: &SessionCore{}}
	rpc := &RPCServices{plan: plan, root: x.rpc.root, owner: x.rpc.owner, clock: x.rpc.clock, runtimeBytes: 4096, channel: &RPCChannel{publisher: x.publisher}}
	rpc.owner.Instance[1], rpc.owner.Backing[1] = 2, 2
	p, err := x.rpc.prepareContractQueryProtection(x.environment, x.session)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	q, err := x.environment.ensureContractQuerySource(rpc, session)
	if err != nil || q != p {
		t.Fatal("second Environment position allocated", q, err)
	}
	x.environment.mu.Lock()
	sources := 0
	for _, source := range p.sources {
		if source != nil {
			sources++
		}
	}
	x.environment.mu.Unlock()
	if sources != 2 {
		t.Fatal(sources)
	}
	first, _, err := p.reserve(x.session)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = p.reserve(session); err != cryptov4.ErrCapacity {
		t.Fatal("two protected J positions", err)
	}
	first.release()
	second, _, err := p.reserve(session)
	if err != nil {
		t.Fatal(err)
	}
	second.release()
	if s := x.environment.OperationsSnapshot(); s.ActiveQueries != 0 {
		t.Fatal(s)
	}
}

func TestContractQueryProtectionWaitsForTransferredOutputAfterClose(t *testing.T) {
	x := newRemoteServiceShapeFixture(t, 1, true)
	p, err := x.rpc.prepareContractQueryProtection(x.environment, x.session)
	if err != nil {
		t.Fatal(err)
	}
	claim, ref, err := p.reserve(x.session)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ := ContractQuerySnapshotsCharge(8)
	owned, err := ref.Take(charge)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Release()
	p.Close()
	claim.release()
	x.environment.mu.Lock()
	x.environment.collectContractQueryProtectionLocked()
	retained := x.environment.queryProtection == p
	x.environment.mu.Unlock()
	if !retained || p.output.CleanupComplete() {
		t.Fatal("actual output backing was refunded")
	}
	owned.Release()
	x.environment.mu.Lock()
	x.environment.collectContractQueryProtectionLocked()
	retained = x.environment.queryProtection == p
	x.environment.mu.Unlock()
	if retained {
		t.Fatal("returned output kept idle protection")
	}
}

func TestContractQueryProtectionCannotDisplaceOrdinaryClaims(t *testing.T) {
	x := newRemoteServiceFixture(t, 1)
	var claims [4]*contractQueryClaim
	for i := range claims {
		var err error
		claims[i], err = x.environment.reserveContractQuery()
		if err != nil {
			t.Fatal(err)
		}
		defer claims[i].release()
	}
	before := x.rpc.root.Snapshot()
	if _, err := x.rpc.prepareContractQueryProtection(x.environment, x.session); err != cryptov4.ErrCapacity {
		t.Fatal(err)
	}
	if after := x.rpc.root.Snapshot(); after != before {
		t.Fatal("failed protection retained partial backing", before, after)
	}
	if s := x.environment.OperationsSnapshot(); s.ActiveQueries != 4 {
		t.Fatal(s)
	}
}
