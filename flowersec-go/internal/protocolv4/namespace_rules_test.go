package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"sort"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type namespaceFixture struct {
	rules                             *NamespaceRules
	r                                 *cborTextReference
	capacity, publication, delegation []byte
	head, state                       *cborRefValue
	now                               timev4.Interval
	resources                         *resourcev4.Root
	resourceSequence                  uint64
}

func namespaceNumber(n uint64) *cborRefValue { return &cborRefValue{major: 0, n: n} }
func namespaceBytes(b []byte) *cborRefValue  { return &cborRefValue{major: 2, data: bytes.Clone(b)} }
func namespaceArray(items ...*cborRefValue) *cborRefValue {
	return &cborRefValue{major: 4, items: items}
}

func (f *namespaceFixture) set(t *testing.T, schema string, root *cborRefValue, name string, value *cborRefValue) {
	t.Helper()
	*oracleField(t, f.r.cborReference, schema, root, name) = *value
}

func (f *namespaceFixture) seed(t *testing.T, id string) *cborRefValue {
	t.Helper()
	seed := oracleSeed(t, id)
	root, _, err := f.r.decode(oracleBytes(t, seed.Hex), seed.Schema, shapeContext(seed.Limits).limits, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func newNamespaceFixture(t *testing.T) *namespaceFixture {
	t.Helper()
	f := &namespaceFixture{r: newCBORTextReference(t), now: timev4.Interval{LowerMS: 1100, UpperMS: 1200}}
	c := f.seed(t, "namespace_capacity_fields")
	f.set(t, "NamespaceCapacity", c, "max_state_encoded_bytes", namespaceNumber(4096))
	f.capacity = c.encode(nil)
	f.publication = f.seed(t, "publication_policy").encode(nil)
	var err error
	f.rules, err = NewNamespaceRules(f.capacity, f.publication)
	if err != nil {
		t.Fatal(err)
	}
	f.head, f.state = f.seed(t, "freshness_head_fields"), f.seed(t, "revocation_state_fields")
	d := f.seed(t, "head_delegation_fields")
	key := ed25519.NewKeyFromSeed(bytes.Clone([]byte{71, 23, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}))
	f.set(t, "HeadSignerDelegation", d, "signer_public_key", namespaceBytes(key.Public().(ed25519.PublicKey)))
	clear(key)
	for _, object := range []struct {
		schema string
		root   *cborRefValue
	}{{"FreshnessHead", f.head}, {"RevocationState", f.state}, {"HeadSignerDelegation", d}} {
		f.set(t, object.schema, object.root, "namespace_capacity_digest", namespaceBytes(f.rules.capacityDigest[:]))
	}
	for _, name := range []string{"schema_revision", "tenant_id", "revocation_authority_id", "namespace_capacity_digest", "authority_generation", "publication_policy_id", "publication_policy_revision"} {
		f.set(t, "RevocationState", f.state, name, oracleField(t, f.r.cborReference, "FreshnessHead", f.head, name))
	}
	for _, name := range []string{"revoked_issuers", "revoked_certificates", "revoked_leases"} {
		f.set(t, "RevocationState", f.state, name, namespaceArray())
	}
	segment, err := f.r.namedMap("CohortPolicySegment", map[string]*cborRefValue{"first_cohort": namespaceNumber(0), "last_cohort": namespaceNumber(100), "certificate_impact_ms": namespaceNumber(1000), "connection_impact_ms": namespaceNumber(10000)})
	if err != nil {
		t.Fatal(err)
	}
	f.set(t, "RevocationState", f.state, "cohort_policy_segments", namespaceArray(segment))
	f.delegation = d.encode(nil)
	digest, err := cborSingleMapHash("head_signer_delegation_digest", "HeadSignerDelegation", "full", f.delegation)
	if err != nil {
		t.Fatal(err)
	}
	f.set(t, "FreshnessHead", f.head, "signer_delegation_digest", namespaceBytes(digest))
	return f
}

func (f *namespaceFixture) bindHead(t *testing.T, seq uint64, floors [2]uint64) (*NamespaceHead, []byte) {
	t.Helper()
	floor := namespaceArray(namespaceNumber(floors[0]), namespaceNumber(floors[1]))
	f.set(t, "RevocationState", f.state, "credential_revocation_floors", floor)
	f.set(t, "FreshnessHead", f.head, "credential_revocation_floors", floor)
	f.set(t, "FreshnessHead", f.head, "head_sequence", namespaceNumber(seq))
	state := f.state.encode(nil)
	digest, err := cborSingleMapHash("revocation_state_digest", "RevocationState", "full", state)
	if err != nil {
		t.Fatal(err)
	}
	f.set(t, "FreshnessHead", f.head, "state_encoded_bytes", namespaceNumber(uint64(len(state))))
	f.set(t, "FreshnessHead", f.head, "state_digest", namespaceBytes(digest))
	signed := signRuntimeFixture(t, "FreshnessHead", f.head.encode(nil), DecodeContext{})
	head, err := f.rules.BindHead(signed, f.delegation, valueUint(signed.document.Root(), "FreshnessHead", "authority_generation"), 900, 100000)
	if err != nil {
		t.Fatal(err)
	}
	return head, state
}

func (f *namespaceFixture) bindState(t *testing.T, seq uint64, floors [2]uint64) *NamespaceState {
	t.Helper()
	head, input := f.bindHead(t, seq, floors)
	cost, err := f.rules.StateCharge()
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewRevocationWorkspace(f.rules, f.reserve(t, cost))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	s, err := w.Bind(head, input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Release)
	return s
}

func TestRuntimeNamespaceOriginalHeadAndDeadline(t *testing.T) {
	f := newNamespaceFixture(t)
	h, _ := f.bindHead(t, 1, [2]uint64{})
	if err := h.CheckTime(f.now); err != nil {
		t.Fatal(err)
	}
	if !f.rules.Matches(f.capacity, f.publication) {
		t.Fatal("original mapping changed")
	}
	f.capacity[len(f.capacity)-1] ^= 1
	if f.rules.Matches(f.capacity, f.publication) {
		t.Fatal("mapping replacement accepted")
	}
	if h.CheckTime(timev4.Interval{LowerMS: 1099, UpperMS: 1200}) != timev4.ErrPending || h.CheckTime(timev4.Interval{LowerMS: 1000, UpperMS: 1099}) != timev4.ErrFutureTimestamp {
		t.Fatal("original lower-bound classification lost")
	}
	if h.CheckTime(timev4.Interval{LowerMS: h.next - 1, UpperMS: h.next}) != timev4.ErrExpired {
		t.Fatal("expiry is not strict")
	}
	end, err := h.Deadline(5000, f.rules.signerLife, 10000, f.now)
	if err != nil || end != h.issued+5000 {
		t.Fatal("staleness is not anchored to the original Head", end, err)
	}
	if _, err := h.Deadline(5000, f.rules.signerLife-1, 10000, f.now); err != CBORFailure("revocation_policy_incompatible") {
		t.Fatal("short actual delegation replaced the fixed publication envelope", err)
	}
	if _, err := h.Deadline(math.MaxUint64, f.rules.signerLife, 10000, f.now); err != CBORFailure("revocation_overflow") {
		t.Fatal("deadline overflow accepted", err)
	}
	for _, bad := range []struct {
		field string
		value *cborRefValue
	}{{"signer_public_key", namespaceBytes(make([]byte, 32))}, {"delegation_id", namespaceBytes(bytes.Repeat([]byte{8}, 16))}, {"authority_generation", namespaceNumber(h.generation + 1)}} {
		d, _, err := f.r.decode(f.delegation, "HeadSignerDelegation", nil, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		f.set(t, "HeadSignerDelegation", d, bad.field, bad.value)
		signed := signRuntimeFixture(t, "FreshnessHead", h.bytes, DecodeContext{})
		if got, err := f.rules.BindHead(signed, d.encode(nil), h.generation, 900, 100000); err == nil || got != nil {
			t.Fatal("delegation substitution accepted", bad.field)
		}
	}
}

func TestRuntimeNamespaceHeadFrontiersAndPinnedState(t *testing.T) {
	f := newNamespaceFixture(t)
	first := f.bindState(t, 1, [2]uint64{})
	second := f.bindState(t, 2, [2]uint64{1, 0})
	later, _ := f.bindHead(t, 3, [2]uint64{2, 0})
	now := timev4.Interval{LowerMS: 2200, UpperMS: 2201}
	if err := second.head.Follows(first.head, now); err != nil {
		t.Fatal(err)
	}
	if err := later.Follows(second.head, now); err != nil {
		t.Fatal(err)
	}
	if err := first.CheckSuccessor(second, nil); err != nil {
		t.Fatal("selected complete state cannot finish after a newer Head", err)
	}
	if second.head.Follows(later, now) != CBORFailure("revocation_head_rollback") {
		t.Fatal("old network Head accepted")
	}
	if later.CheckTime(timev4.Interval{LowerMS: 2199, UpperMS: 2200}) != timev4.ErrPending {
		t.Fatal("immature frontier adopted")
	}
	rollback, _ := f.bindHead(t, 4, [2]uint64{0, 1})
	if rollback.Follows(later, timev4.Interval{LowerMS: 12000, UpperMS: 12001}) != CBORFailure("revocation_floor_rollback") {
		t.Fatal("one frontier compensated for another")
	}
	equivocation, _ := f.bindHead(t, 3, [2]uint64{1, 0})
	if equivocation.Follows(later, now) != CBORFailure("revocation_head_equivocation") {
		t.Fatal("same sequence changed bytes")
	}
	if _, err := f.rules.cohortEnd(math.MaxUint64); err != CBORFailure("revocation_overflow") {
		t.Fatal("cohort overflow accepted", err)
	}
}

func TestRuntimeNamespaceStateOwnershipAndMalformedContent(t *testing.T) {
	f := newNamespaceFixture(t)
	head, input := f.bindHead(t, 1, [2]uint64{})
	cost, _ := f.rules.StateCharge()
	short := cost
	short[resourcev4.SDKBytes]--
	if _, err := NewRevocationWorkspace(f.rules, f.reserve(t, short)); err != resourcev4.ErrCapacity {
		t.Fatal("partial envelope reservation accepted", err)
	}
	w, _ := NewRevocationWorkspace(f.rules, f.reserve(t, cost))
	t.Cleanup(func() { _ = w.Close() })
	bad := bytes.Clone(input)
	bad[len(bad)-1] ^= 1
	if s, err := w.Bind(head, bad); err == nil || s != nil {
		t.Fatal("wrong state digest accepted")
	}
	s, err := w.Bind(head, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Bind(head, input); err != CBORFailure("decoder_busy") {
		t.Fatal("occupied backing reused", err)
	}
	s.Release()
	next, err := w.Bind(head, input)
	if err != nil {
		t.Fatal(err)
	}
	s.Release()
	if w.current != next {
		t.Fatal("stale release reclaimed new state")
	}
	next.Release()
	segments := oracleField(t, f.r.cborReference, "RevocationState", f.state, "cohort_policy_segments")
	other, _ := f.r.namedMap("CohortPolicySegment", map[string]*cborRefValue{"first_cohort": namespaceNumber(50), "last_cohort": namespaceNumber(70), "connection_impact_ms": namespaceNumber(10)})
	segments.items = append(segments.items, other)
	sort.Slice(segments.items, func(i, j int) bool {
		return bytes.Compare(segments.items[i].encode(nil), segments.items[j].encode(nil)) < 0
	})
	head, input = f.bindHead(t, 2, [2]uint64{})
	if _, err := w.Bind(head, input); err != CBORFailure("revocation_segment_overlap") {
		t.Fatal("overlapping class ranges accepted", err)
	}
}
