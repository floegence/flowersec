package sessionv4

import (
	"context"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func managedRenewalOptions() UnaryServiceBindOptions {
	return UnaryServiceBindOptions{ContractSource: ServiceContractsRemote, OfferRefresh: ServiceOfferRefreshManaged, RenewalPolicy: ContractRenewalPolicy{BatchMS: 2000, JoinMS: 10000, SuspensionMS: 60000, TimeErrorMS: 4000, SourceRemainingMS: 400000}}
}

func bindManagedTestService(t *testing.T, x *remoteServiceFixture, options UnaryServiceBindOptions) *UnaryServiceClient {
	t.Helper()
	var client *UnaryServiceClient
	var err error
	x.run(t, func() { client, err = x.session.BindMethods(context.Background(), x.definition, options) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestManagedContractRenewalPublishesCompleteProtection(t *testing.T) {
	x := newRemoteServiceWindowFixture(t, 3, true, 400000)
	c := bindManagedTestService(t, x, managedRenewalOptions())
	x.environment.mu.Lock()
	p := x.environment.queryProtection
	protected := p != nil && p.managed && !p.closed && p.sourceLocked(x.session) != nil
	x.environment.mu.Unlock()
	if !protected {
		t.Fatal("managed client delivered without complete protection")
	}
	for _, method := range []uint32{1, 2, 3} {
		if snapshot := c.Contract(method); !snapshot.ManagedRenewal || !snapshot.OfferReady || snapshot.RenewalError != nil {
			t.Fatal(snapshot)
		}
	}
	var ordinary [3]*contractQueryClaim
	for j := range ordinary {
		var err error
		ordinary[j], err = x.environment.reserveContractQuery()
		if err != nil {
			t.Fatal(err)
		}
		defer ordinary[j].release()
	}
	if _, err := x.environment.reserveContractQuery(); err != cryptov4.ErrCapacity {
		t.Fatal("protected position consumed", err)
	}
}

func TestManagedContractRenewalRejectsUnqualifiedDelivery(t *testing.T) {
	for _, test := range []struct {
		name   string
		window uint64
		policy ContractRenewalPolicy
	}{
		{"short-offer", 1000, managedRenewalOptions().RenewalPolicy},
		{"missing-source", 400000, ContractRenewalPolicy{BatchMS: 2000}},
		{"missing-batch", 400000, ContractRenewalPolicy{SourceRemainingMS: 400000}},
	} {
		t.Run(test.name, func(t *testing.T) {
			x := newRemoteServiceWindowFixture(t, 1, true, test.window)
			options := managedRenewalOptions()
			options.RenewalPolicy = test.policy
			var c *UnaryServiceClient
			var err error
			x.run(t, func() { c, err = x.session.BindMethods(context.Background(), x.definition, options) })
			if err != errContractRenewalQualification || c != nil {
				t.Fatal(c, err)
			}
			x.environment.mu.Lock()
			p := x.environment.queryProtection
			x.environment.mu.Unlock()
			if p != nil {
				t.Fatal("failed qualification created protection")
			}
		})
	}
}

func TestManagedContractRenewalTransientCreatesNoProtection(t *testing.T) {
	x := newRemoteServiceFixture(t, 2)
	options := managedRenewalOptions()
	options.RenewalPolicy = ContractRenewalPolicy{}
	c := bindManagedTestService(t, x, options)
	x.environment.mu.Lock()
	p := x.environment.queryProtection
	x.environment.mu.Unlock()
	if p != nil || c.Contract(1).ManagedRenewal {
		t.Fatal("transient snapshot created renewal work")
	}
	var output [2]UnaryContractSnapshot
	var err error
	x.run(t, func() { err = c.Refresh(context.Background(), []uint32{1, 2}, output[:]) })
	if err != nil || x.batches != 1 {
		t.Fatal("transient Refresh queried", err, x.batches)
	}
}

func TestManagedContractRenewalCoordinatorRenewsAndReleasesLastBinding(t *testing.T) {
	x := newRemoteServiceWindowFixture(t, 2, true, 400000)
	c := bindManagedTestService(t, x, managedRenewalOptions())
	// Model the same installed window entering its advance interval without
	// aging this fixture's deliberately short independent authority envelope.
	// Actual framing, EDF dispatch, installation and cleanup run unchanged.
	c.mu.Lock()
	for j := range c.methods {
		c.methods[j].offer.NotAfterMS = 1300
	}
	c.mu.Unlock()
	x.environment.signalMaterials()
	x.run(t, func() {
		ctx := resultTestContext(t)
		for {
			c.mu.Lock()
			renewed := c.methods[0].offer.NotAfterMS == 401000 && c.methods[1].offer.NotAfterMS == 401000
			c.mu.Unlock()
			if renewed || ctx.Err() != nil {
				return
			}
			runtime.Gosched()
		}
	})
	c.mu.Lock()
	renewed := c.methods[0].offer.NotAfterMS == 401000 && c.methods[1].offer.NotAfterMS == 401000
	c.mu.Unlock()
	if !renewed || x.batches != 2 {
		t.Fatal("coordinator did not renew original targets", x.batches)
	}
	c.Close()
	if err := c.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	ctx := resultTestContext(t)
	for {
		x.environment.mu.Lock()
		released := x.environment.queryProtection == nil
		x.environment.mu.Unlock()
		if released {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("last binding retained idle protection")
		}
		runtime.Gosched()
	}
}

func TestManagedContractRenewalLaterExecutionInstallAndGrowthQualification(t *testing.T) {
	x := newRemoteServiceWindowFixture(t, 9, true, 400000)
	options := managedRenewalOptions()
	options.InitialMethods = []UnaryMethodSelector{{Namespace: x.definition.Namespace, Type: 1}}
	options.RenewalPolicy = ContractRenewalPolicy{BatchMS: 100000, SourceRemainingMS: 400000}
	c := bindManagedTestService(t, x, options)
	var output [8]UnaryContractSnapshot
	var err error
	x.run(t, func() { err = c.Refresh(context.Background(), []uint32{2, 3, 4, 5, 6, 7, 8, 9}, output[:]) })
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; j < 7; j++ {
		if output[j].Error != nil || !output[j].Installed {
			t.Fatal(j, output[j])
		}
	}
	if output[7].Error != errContractRenewalQualification || c.Contract(9).Installed {
		t.Fatal("unqualified set growth installed", output[7])
	}
	if s := c.Contract(1); s.Error != nil || !s.ManagedRenewal {
		t.Fatal("growth failure damaged old responsibility", s)
	}
}

func TestManagedContractRenewalRejectedBindPreservesPreviousResponsibility(t *testing.T) {
	x := newRemoteServiceWindowFixture(t, 2, true, 400000)
	// Failed growth cannot weaken an existing binding's window or protection.
	c := bindManagedTestService(t, x, managedRenewalOptions())
	c.mu.Lock()
	old := c.methods[1].offer
	c.mu.Unlock()
	options := managedRenewalOptions()
	options.RenewalPolicy.SourceRemainingMS = 299999
	var rejected *UnaryServiceClient
	var err error
	x.run(t, func() { rejected, err = x.session.BindMethods(context.Background(), x.definition, options) })
	if rejected != nil || err != errContractRenewalQualification {
		t.Fatal(rejected, err)
	}
	c.mu.Lock()
	unchanged := c.methods[1].offer == old
	c.mu.Unlock()
	if !unchanged {
		t.Fatal("failed new client changed previous Offer")
	}
	if s := c.Contract(2); s.Error != nil || !s.ManagedRenewal {
		t.Fatal(s)
	}
}

func TestManagedContractRenewalFirstLateExecutionProtectsBeforeInstall(t *testing.T) {
	x := newRemoteServiceMixedWindowFixture(t, 2, true, 400000, true)
	options := managedRenewalOptions()
	options.InitialMethods = []UnaryMethodSelector{{Namespace: x.definition.Namespace, Type: 1}}
	c := bindManagedTestService(t, x, options)
	x.environment.mu.Lock()
	p := x.environment.queryProtection
	x.environment.mu.Unlock()
	if p != nil || c.Contract(2).Installed {
		t.Fatal("on-use descriptor created protection")
	}
	var output [1]UnaryContractSnapshot
	var err error
	x.run(t, func() { err = c.Refresh(context.Background(), []uint32{2}, output[:]) })
	if err != nil || output[0].Error != nil || !c.Contract(2).ManagedRenewal {
		t.Fatal(output, err)
	}
	x.environment.mu.Lock()
	p = x.environment.queryProtection
	x.environment.mu.Unlock()
	if p == nil {
		t.Fatal("first execution installed without protection")
	}
	if c.Contract(1).ManagedRenewal {
		t.Fatal("transient started renewal")
	}
}

func TestManagedContractRenewalDeniedTargetKeepsOriginalRound(t *testing.T) {
	x := newRemoteServiceWindowFixture(t, 1, true, 400000)
	c := bindManagedTestService(t, x, managedRenewalOptions())
	if err := x.plan.lease.SetContractQueryAccess(ContractQueryMethod{Namespace: x.definition.Namespace, Type: 1}, rpcv4.QueryTargetDenied); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.methods[0].offer.NotAfterMS = 1300
	c.mu.Unlock()
	x.environment.signalMaterials()
	x.run(t, func() {
		ctx := resultTestContext(t)
		for {
			c.mu.Lock()
			failed := c.methods[0].renewal.lastError != nil
			c.mu.Unlock()
			if failed || ctx.Err() != nil {
				return
			}
			runtime.Gosched()
		}
	})
	c.mu.Lock()
	state := c.methods[0].renewal
	offer := c.methods[0].offer
	c.mu.Unlock()
	if state.lastError != ErrContractDenied || state.nextAttemptMS == 0 || offer.NotAfterMS != 1300 {
		t.Fatal(state, offer)
	}
	x.environment.renewalMu.Lock()
	p := x.environment.queryProtection
	deadline := p.round.deadline
	x.environment.renewalMu.Unlock()
	if deadline == nil {
		t.Fatal("failed attempt abandoned original round")
	}
	for range 3 {
		x.environment.advanceManagedContractRenewal()
	}
	x.environment.renewalMu.Lock()
	same := p.round.deadline == deadline
	x.environment.renewalMu.Unlock()
	if !same || x.batches != 2 {
		t.Fatal("retry restarted deadline or ignored backoff", x.batches)
	}
}
