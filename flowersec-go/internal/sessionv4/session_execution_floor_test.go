package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func rpcExecutionFloorFixture(t *testing.T) (*executorFixture, *SessionPlan, RPCServicesConfig, resourcev4.Account) {
	t.Helper()
	f, p, c := rpcServicesPlanFixture(t, true)
	tenant := c.Accounts[0]
	c.Session = testSessionContract(t, protocolv4.DHProfileX25519, "execution", 65536, 16, 0, 5000, 1<<20).Contract
	body := bytes.Replace(initialFixture(t, "service_unary_no_result_retention"), []byte{0x0d, 0x01}, []byte{0x0d, 0x00}, 1)
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	defer contract.Release()
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	c.ResultRead = rpcv4.QueryBinding{Type: 3, Contract: policy.Digest}
	c.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{body}, OfferWindowMS: 1000}}
	c.Methods = []UnaryRegistration{{Method: 0, Namespace: policy.Namespace, Type: policy.Type, WorkClass: ApplicationShort, Handler: func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { return 0, nil }}}
	owner := c.Owner
	owner.Instance, owner.Backing = [16]byte{201}, [16]byte{201}
	hc := rpcv4.VolatileExecutionConfig{Root: f.root, Owner: owner, Accounts: []resourcev4.Account{tenant}, Clock: c.Clock, Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}, CallerAuthorities: [][32]byte{{8}}, Records: 4, Active: 1, TaskCharge: f.executor.TaskCharge(), RuntimeBytes: 4096, WorkRuntimeBytes: 4096, ResultRuntimeBytes: 4096}
	charge, err := rpcv4.VolatileExecutionsCharge(hc)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(owner, charge, tenant)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	history, err := rpcv4.NewVolatileExecutions(hc, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(history.Close)
	owner.Instance, owner.Backing = [16]byte{202}, [16]byte{202}
	rc := rpcv4.ServiceRegistryConfig{Root: f.root, Owner: owner, Accounts: []resourcev4.Account{tenant}, Entries: 1, RuntimeBytes: 4096}
	charge, err = rpcv4.ServiceRegistryCharge(rc)
	if err != nil {
		t.Fatal(err)
	}
	ref, err = f.root.Reserve(owner, charge, tenant)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	c.ExecutionRegistry, err = rpcv4.NewServiceRegistry(rc, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.ExecutionRegistry.Close)
	binding := rpcv4.ServiceBinding{Authority: rpcv4.ServiceAuthority{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}, History: history}
	if err = c.ExecutionRegistry.Bind(binding); err != nil {
		t.Fatal(err)
	}
	c.ExecutionServices = []rpcv4.ServiceBinding{binding}
	return f, p, c, tenant
}

func TestRPCExecutionFloorSharesOneBatchAndPreservesOriginalScopes(t *testing.T) {
	f, p, c, tenant := rpcExecutionFloorFixture(t)
	before := f.root.Snapshot()
	total, count, err := RPCServicesRequirements(c)
	if err != nil {
		t.Fatal(err)
	}
	var batch rpcServicesBatch
	if err := prepareRPCServicesBatch(&batch, p, c, nil); err != nil {
		t.Fatal(err)
	}
	defer batch.release()
	var requests [rpcServicesOwnerCapacity]resourcev4.Request
	var refs [rpcServicesOwnerCapacity]resourcev4.Reference
	for i := 0; i < batch.count; i++ {
		requests[i], err = batch.request(i)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = f.root.ReserveBatch(requests[:batch.count], refs[:batch.count]); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	start, err := executionChargeStart(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs[start : start+5] {
		if err = ref.CheckAllocationScope(f.root, c.Owner, c.Accounts); err != nil {
			t.Fatal("output lost original Session scope", err)
		}
	}
	for _, ref := range refs[start+5 : start+9] {
		if err = ref.CheckAllocationScope(f.root, c.Owner, []resourcev4.Account{tenant}); err != nil {
			t.Fatal("history lost original shared scope", err)
		}
		if err = ref.CheckAllocationScope(f.root, c.Owner, c.Accounts); err == nil {
			t.Fatal("retained history was attached to Session scope")
		}
	}
	r, err := batch.adopt(refs[:batch.count])
	if err != nil {
		t.Fatal(err)
	}
	expected, err := before.Charged.Add(total)
	if err != nil {
		t.Fatal(err)
	}
	after := f.root.Snapshot()
	if after.Charged != expected || after.Reservations != before.Reservations+count {
		t.Fatal("execution used a second allocation budget", before, after)
	}
	if len(r.dispatch.executionFloors) != 1 || r.dispatch.executionFloors[0].admission.CheckReady() != nil {
		t.Fatal("incomplete original execution admission")
	}
}

func TestRPCExecutionHistoryCapacityFailureUnwindsWholeBatch(t *testing.T) {
	f, p, c, tenant := rpcExecutionFloorFixture(t)
	history := c.ExecutionServices[0].History
	charges, err := history.ShortAdmissionCharges(c.ShortResponseBytes, c.InvocationRuntimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	var refs [4]resourcev4.Reference
	for i, charge := range charges {
		owner := c.Owner
		owner.Instance, owner.Backing = [16]byte{210, byte(i)}, [16]byte{210, byte(i)}
		refs[i], err = f.root.Reserve(owner, charge, tenant)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(refs[i].Release)
	}
	pending, err := history.ReserveShortAdmission(c.ShortResponseBytes, c.InvocationRuntimeBytes, p.reservation, refs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pending.Close)
	before := f.root.Snapshot()
	if r, err := p.InstallRPCServices(c); r != nil || !errors.Is(err, rpcv4.ErrCapacity) {
		t.Fatal("history capacity did not reject Session assembly", err)
	}
	if after := f.root.Snapshot(); after != before || p.closed || p.claimed || p.rpcPreparing || p.services != nil || p.rpc != nil {
		t.Fatal("failed original promise partially consumed Session", before, after)
	}
	pending.Close()
	if _, err = p.InstallRPCServices(c); err != nil {
		t.Fatal("capacity failure consumed original plan", err)
	}
}
