package rpcv4

import (
	"bytes"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func queryTargets(t *testing.T, target protocolv4.ContractQueryTarget, known *protocolv4.ServiceContract) protocolv4.ContractQueryTargets {
	t.Helper()
	c, err := protocolv4.NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	_, targets, err := c.EncodeTargets(make([]byte, 2048), []protocolv4.ContractQueryTarget{target}, []*protocolv4.ServiceContract{known})
	if err != nil {
		t.Fatal(err)
	}
	return targets
}

func newQueryRead(t *testing.T, f *rpcFixture, r *ContractRoutes, targets protocolv4.ContractQueryTargets) *ContractQueryRead {
	t.Helper()
	charge, err := ContractQueryReadCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	read, err := r.NewQueryRead(targets, f.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(read.Close)
	return read
}

func snapshotRead(t *testing.T, read *ContractQueryRead, targets protocolv4.ContractQueryTargets, known *protocolv4.ServiceContract) (protocolv4.ContractSnapshotInfo, []byte) {
	t.Helper()
	codec, err := protocolv4.NewContractSnapshotCodec()
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, targets.ResponseBytes())
	n, err := read.Encode(&codec.ContractSnapshotEncoder, wire)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 8192)
	set, err := codec.Decode(targets, wire[:n], []*protocolv4.ServiceContract{known}, []uint64{1000}, [][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	item, err := set.Item(0)
	if err != nil {
		t.Fatal(err)
	}
	return item, body[:item.ContractBytes]
}

// v4.go_contract_query.registry_selectors
func TestContractQueryReadExactSelectorsAndCurrentAdvertisement(t *testing.T) {
	_, first, _ := inputFixture(t, false, nil)
	defer first.Release()
	var body [8192]byte
	n, err := first.CopyCanonical(body[:])
	if err != nil {
		t.Fatal(err)
	}
	// Change a numeric policy while preserving the immutable method shape.
	marker := []byte{0x0a, 0x1a, 0, 0x10, 0, 0}
	if bytes.Count(body[:n], marker) != 1 {
		t.Fatal("fixture maximum changed")
	}
	secondWire := bytes.Replace(body[:n], marker, []byte{0x0a, 0x19, 4, 0}, 1)
	codec, err := protocolv4.NewServiceContractCodec(768)
	if err != nil {
		t.Fatal(err)
	}
	second, err := codec.Decode(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	p1, _ := first.Policy()
	p2, _ := second.Policy()
	f := newRPCFixture(t, first, 1)
	c := ContractRoutesConfig{Methods: []MethodRoutes{{Contracts: [][]byte{body[:n], secondWire}}}, ContractNodes: 768, RuntimeBytes: 4096}
	charge, err := ContractRoutesCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewContractRoutes(c, f.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	if err = r.Advertise(p2.Digest); err != nil {
		t.Fatal(err)
	}
	base := protocolv4.ContractQueryTarget{Namespace: p1.Namespace, Type: p1.Type}
	tests := []struct {
		name   string
		target protocolv4.ContractQueryTarget
		known  *protocolv4.ServiceContract
		access QueryTargetAccess
		status string
		digest [32]byte
	}{
		{"current", base, nil, QueryTargetAllowed, "available_full", p2.Digest},
		{"wanted old", protocolv4.ContractQueryTarget{Namespace: p1.Namespace, Type: p1.Type, HasWanted: true, Wanted: p1.Digest}, nil, QueryTargetAllowed, "available_full", p1.Digest},
		{"known current", protocolv4.ContractQueryTarget{Namespace: p1.Namespace, Type: p1.Type, HasKnown: true, Known: p2.Digest}, second, QueryTargetAllowed, "available_unchanged", p2.Digest},
		{"known old does not select old", protocolv4.ContractQueryTarget{Namespace: p1.Namespace, Type: p1.Type, HasKnown: true, Known: p1.Digest}, first, QueryTargetAllowed, "available_full", p2.Digest},
		{"unknown wanted never substitutes current", protocolv4.ContractQueryTarget{Namespace: p1.Namespace, Type: p1.Type, HasWanted: true, Wanted: [32]byte{99}}, nil, QueryTargetAllowed, "unavailable", [32]byte{}},
		{"denied current", base, nil, QueryTargetDenied, "denied", [32]byte{}},
		{"unknown permission", base, nil, QueryTargetUnavailable, "unavailable", [32]byte{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targets := queryTargets(t, test.target, test.known)
			read := newQueryRead(t, f, r, targets)
			if err = read.Resolve(0, test.access); err != nil {
				t.Fatal(err)
			}
			item, _ := snapshotRead(t, read, targets, test.known)
			if item.Status != test.status || item.Policy.Digest != test.digest || item.HasOffer {
				t.Fatal(item)
			}
		})
	}
}

// v4.go_contract_query.registry_lifetime
func TestContractQueryReadRetainsCapturedBodyButRechecksFutureAvailability(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	f := newRPCFixture(t, contract, 1)
	a := installServiceInputs(t, f, 1048576)
	r := a.routes
	policy, _ := contract.Policy()
	if err := r.Advertise(policy.Digest); err != nil {
		t.Fatal(err)
	}
	targets := queryTargets(t, protocolv4.ContractQueryTarget{Namespace: policy.Namespace, Type: policy.Type}, nil)
	read := newQueryRead(t, f, r, targets)
	if err := read.Resolve(0, QueryTargetAllowed); err != nil {
		t.Fatal(err)
	}
	if err := r.SetRegistered(policy.Digest, false); err != nil {
		t.Fatal(err)
	}
	next := newQueryRead(t, f, r, targets)
	if err := next.Resolve(0, QueryTargetAllowed); err != nil {
		t.Fatal(err)
	}
	if item, _ := snapshotRead(t, next, targets, nil); item.Status != "unavailable" {
		t.Fatal("withdrawn method still advertised", item)
	}
	next.Close()
	a.Close()
	r.Close()
	if r.CleanupComplete() {
		t.Fatal("captured query body refunded")
	}
	if item, body := snapshotRead(t, read, targets, nil); item.Status != "available_full" || len(body) == 0 {
		t.Fatal("original snapshot body lost", item)
	}
	read.Close()
	if !r.CleanupComplete() {
		t.Fatal("released query retained registry")
	}
}

func TestContractAdvertisementsCannotWithdrawUnexpiredExecutionPromises(t *testing.T) {
	f := newOfferFixture(t, true, timev4.Interval{LowerMS: 25, UpperMS: 25})
	r := f.registry
	if err := r.Advertise(f.digest); !errors.Is(err, ErrMethod) {
		t.Fatal("execution advertised without Offer", err)
	}
	if err := r.RegisterOffer(f.digest, offerBytes(t, f.digest, 0, 100)); err != nil {
		t.Fatal(err)
	}
	if err := r.Advertise(f.digest); err != nil {
		t.Fatal(err)
	}
	if err := r.SetRegistered(f.digest, false); !errors.Is(err, ErrOwner) {
		t.Fatal("unexpired promise withdrawn", err)
	}
	f.ticks.Store(75)
	if _, err := r.RetireOffers(); err != nil {
		t.Fatal(err)
	}
	if err := r.SetRegistered(f.digest, false); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterOffer(f.digest, offerBytes(t, f.digest, 100, 200)); !errors.Is(err, ErrMethod) {
		t.Fatal("withdrawn registration regained windows", err)
	}
}

func TestContractQueryReadExecutionWindowAndAuthorizationRemainCurrent(t *testing.T) {
	f := newOfferFixture(t, true, timev4.Interval{LowerMS: 25, UpperMS: 25})
	r := f.registry
	if err := r.RegisterOffer(f.digest, offerBytes(t, f.digest, 0, 100)); err != nil {
		t.Fatal(err)
	}
	if err := r.Advertise(f.digest); err != nil {
		t.Fatal(err)
	}
	_, known, _ := inputFixture(t, true, nil)
	defer known.Release()
	policy, _ := known.Policy()
	target := protocolv4.ContractQueryTarget{Namespace: policy.Namespace, Type: policy.Type, HasWanted: true, Wanted: policy.Digest, HasKnown: true, Known: policy.Digest}
	targets := queryTargets(t, target, known)
	read := newQueryRead(t, f.rpc, r, targets)
	if err := read.Resolve(0, QueryTargetAllowed); err != nil {
		t.Fatal(err)
	}
	if item, _ := snapshotRead(t, read, targets, known); item.Status != "available_unchanged" || !item.HasOffer || item.Offer.NotAfterMS != 100 {
		t.Fatal(item)
	}
	read.Close()
	denied := newQueryRead(t, f.rpc, r, targets)
	if err := denied.Resolve(0, QueryTargetDenied); err != nil {
		t.Fatal(err)
	}
	if item, _ := snapshotRead(t, denied, targets, known); item.Status != "denied" || item.HasOffer {
		t.Fatal("known bypassed current permission", item)
	}
	denied.Close()
	// Expiry is checked at read time even before explicit window retirement.
	f.ticks.Store(75)
	expired := newQueryRead(t, f.rpc, r, targets)
	if err := expired.Resolve(0, QueryTargetAllowed); err != nil {
		t.Fatal(err)
	}
	if item, _ := snapshotRead(t, expired, targets, known); item.Status != "unavailable" || item.HasOffer {
		t.Fatal("query revived expired Offer", item)
	}
}

func TestContractQueryReadNoPartialSnapshotOrDuplicateTargetStep(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	f := newRPCFixture(t, contract, 1)
	a := installServiceInputs(t, f, 1048576)
	codec, err := protocolv4.NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	_, targets, err := codec.EncodeTargets(make([]byte, 2048), []protocolv4.ContractQueryTarget{{Namespace: "acme/files", Type: 1}, {Namespace: "acme/other", Type: 1}}, []*protocolv4.ServiceContract{nil, nil})
	if err != nil {
		t.Fatal(err)
	}
	read := newQueryRead(t, f, a.routes, targets)
	if err := read.Resolve(1, QueryTargetAllowed); !errors.Is(err, ErrAssociation) {
		t.Fatal("target order changed", err)
	}
	if err := read.Resolve(0, QueryTargetDenied); err != nil {
		t.Fatal(err)
	}
	if err := read.Resolve(0, QueryTargetAllowed); !errors.Is(err, ErrAssociation) {
		t.Fatal("original denial replaced", err)
	}
	out := bytes.Repeat([]byte{77}, 18432)
	if _, err := read.Encode(nil, out); !errors.Is(err, ErrOwner) || out[0] != 77 {
		t.Fatal("partial snapshot escaped", err)
	}
	if err := read.Resolve(1, QueryTargetUnavailable); err != nil {
		t.Fatal(err)
	}
	encoder, err := protocolv4.NewContractSnapshotCodec()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := read.Encode(&encoder.ContractSnapshotEncoder, out); err != nil {
		t.Fatal(err)
	}
}

func TestContractRoutesRejectChangingImmutableMethodShape(t *testing.T) {
	_, transient, _ := inputFixture(t, false, nil)
	defer transient.Release()
	_, execution, _ := inputFixture(t, true, nil)
	defer execution.Release()
	var bodies [2][8192]byte
	a, _ := transient.CopyCanonical(bodies[0][:])
	b, _ := execution.CopyCanonical(bodies[1][:])
	f := newRPCFixture(t, transient, 1)
	c := ContractRoutesConfig{Methods: []MethodRoutes{{Contracts: [][]byte{bodies[0][:a], bodies[1][:b]}}}, ContractNodes: 768, RuntimeBytes: 4096}
	charge, err := ContractRoutesCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewContractRoutes(c, f.reserve(charge)); !errors.Is(err, ErrAssociation) {
		t.Fatal("method semantics changed inside immutable definition", err)
	}
}
