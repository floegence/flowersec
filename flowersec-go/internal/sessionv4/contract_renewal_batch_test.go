package sessionv4

import (
	"context"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func prepareRenewalTestBatch(t *testing.T, x *remoteServiceFixture, client *UnaryServiceClient) (*contractQueryProtection, []contractRenewalEntry, contractRenewalBudget) {
	t.Helper()
	p, err := x.rpc.prepareContractQueryProtection(x.environment, x.session)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var entries []contractRenewalEntry
	for i := range client.methods {
		m := &client.methods[i]
		entries = append(entries, contractRenewalEntry{client: client, method: m, group: contractRenewalGroup{session: x.session}, namespace: client.namespace, typeID: m.definition.Type, digest: m.definition.Method.Contract, offer: m.offer, sourceRemainingMS: 400000})
	}
	budget, err := qualifyContractRenewal(entries, contractRenewalTiming{BatchMS: 2000, JoinMS: 10000, SuspensionMS: 60000, TimeErrorMS: 4000})
	if err != nil {
		t.Fatal(err)
	}
	return p, entries, budget
}

func TestContractRenewalBatchUsesCoordinatorAndPreservesMethodPartialSuccess(t *testing.T) {
	x := newRemoteServiceWindowFixture(t, 3, true, 400000)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	p, entries, budget := prepareRenewalTestBatch(t, x, client)
	for _, entry := range entries {
		wire, err := protocolv4.EncodeMap(make([]byte, 256), "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: entry.digest[:]}, {Name: "not_before_ms", Number: 1050}, {Name: "not_after_ms", Number: 401050}})
		if err != nil {
			t.Fatal(err)
		}
		if err = x.server.RegisterOffer(entry.digest, wire); err != nil {
			t.Fatal(err)
		}
	}
	if err = x.plan.lease.SetContractQueryAccess(ContractQueryMethod{Namespace: x.definition.Namespace, Type: 2}, rpcv4.QueryTargetDenied); err != nil {
		t.Fatal(err)
	}
	deadline, err := x.rpc.contractAcquisitionDeadline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = p.startRenewalBatch(entries, budget, deadline); err != nil {
		t.Fatal(err)
	}
	var statuses [3]UnaryContractSnapshot
	x.run(t, func() { err = client.Refresh(context.Background(), []uint32{1, 2, 3}, statuses[:]) })
	if err != nil || statuses[0].Error != nil || statuses[1].Error != ErrContractDenied || statuses[2].Error != nil {
		t.Fatal(statuses, err)
	}
	if x.batches != 2 {
		t.Fatal("explicit Refresh did not join original batch", x.batches)
	}
	client.mu.Lock()
	if client.methods[0].offer.NotAfterMS != 401050 || client.methods[1].offer.NotAfterMS != 401000 || client.methods[2].offer.NotAfterMS != 401050 {
		t.Error("partial renewal overwrote another method")
	}
	client.mu.Unlock()
	ctx := resultTestContext(t)
	for {
		x.environment.mu.Lock()
		active := p.batch.active
		x.environment.mu.Unlock()
		if !active {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		runtime.Gosched()
	}
	if _, _, err = p.reserve(x.session); err != nil {
		t.Fatal("completed batch not reusable", err)
	} else {
		x.environment.mu.Lock()
		claim := x.environment.queryClaims[p.index]
		x.environment.mu.Unlock()
		claim.release()
	}
}

func TestContractRenewalBatchCloseCancelsInstallationAndRetainsQuery(t *testing.T) {
	x := newRemoteServiceWindowFixture(t, 1, true, 400000)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if err != nil {
		t.Fatal(err)
	}
	p, entries, budget := prepareRenewalTestBatch(t, x, client)
	deadline, err := x.rpc.contractAcquisitionDeadline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx := resultTestContext(t)
	x.holdNextPublication(t, ctx)
	if err = p.startRenewalBatch(entries, budget, deadline); err != nil {
		t.Fatal(err)
	}
	before := x.sink.writes
	for x.sink.writes == before {
		if _, err = x.publisher.Step(ctx); err != nil {
			t.Fatal(err)
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		runtime.Gosched()
	}
	client.Close()
	if client.advance() {
		t.Fatal("active renewal owner exited before provider")
	}
	p.Close()
	if _, _, err = p.reserve(x.session); err != cryptov4.ErrClosed {
		t.Fatal(err)
	}
	x.sink.held.Store(false)
	x.receiver.Close()
	x.publisher.Close()
	if err = client.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestContractRenewalExplicitUpdateSupersedesOnlyItsCandidate(t *testing.T) {
	x := newRemoteServiceWindowFixture(t, 2, true, 400000)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	p, entries, budget := prepareRenewalTestBatch(t, x, client)
	for _, digest := range [][32]byte{x.variant, entries[1].digest} {
		wire, err := protocolv4.EncodeMap(make([]byte, 256), "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}, {Name: "not_before_ms", Number: 1050}, {Name: "not_after_ms", Number: 401050}})
		if err != nil {
			t.Fatal(err)
		}
		if err = x.server.RegisterOffer(digest, wire); err != nil {
			t.Fatal(err)
		}
	}
	deadline, err := x.rpc.contractAcquisitionDeadline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = p.startRenewalBatch(entries, budget, deadline); err != nil {
		t.Fatal(err)
	}
	var update UnaryContractSnapshot
	done := make(chan struct{})
	go func() { defer close(done); update, err = client.UpdateContract(context.Background(), 1, x.variant) }()
	ctx := resultTestContext(t)
	for {
		client.mu.Lock()
		superseded := client.methods[0].update.superseded
		client.mu.Unlock()
		if superseded {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		runtime.Gosched()
	}
	x.pump(t, done)
	if err != nil || update.Digest != x.variant || update.Generation != 2 {
		t.Fatal(update, err)
	}
	client.mu.Lock()
	second := client.methods[1].offer
	client.mu.Unlock()
	if second.NotAfterMS != 401050 {
		t.Fatal("explicit update canceled unrelated renewal", second)
	}
	if x.batches != 3 {
		t.Fatal("replacement created an extra query", x.batches)
	}
}

func TestContractRenewalInsufficientOfferKeepsInstalledWindow(t *testing.T) {
	x := newRemoteServiceShapeFixture(t, 1, true)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	p, entries, budget := prepareRenewalTestBatch(t, x, client)
	deadline, err := x.rpc.contractAcquisitionDeadline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = p.startRenewalBatch(entries, budget, deadline); err != nil {
		t.Fatal(err)
	}
	var result [1]UnaryContractSnapshot
	x.run(t, func() { err = client.Refresh(context.Background(), []uint32{1}, result[:]) })
	if err != nil || result[0].Error != errContractRenewalQualification || !result[0].Installed {
		t.Fatal(result, err)
	}
	if current := client.Contract(1); current.Error != nil || !current.OfferReady || current.Generation != 1 {
		t.Fatal("failed managed qualification destroyed explicit short Offer", current)
	}
}
