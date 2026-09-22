package protocolv4

import (
	"bytes"
	"sort"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type endpointCredentialFixture struct {
	f                 *namespaceFixture
	originals         [7]*SignedMap
	parent, candidate *cborRefValue
}

func newEndpointCredentialFixture(t *testing.T, tunnel, separate bool) *endpointCredentialFixture {
	t.Helper()
	f := newNamespaceFixture(t)
	x := &endpointCredentialFixture{f: f, parent: f.seed(t, "artifact_transport_fields")}
	names := []string{"parent", "client", "server", "client-grant", "client-relay", "server-grant", "server-relay"}
	authority := func(i int) string {
		if separate {
			return names[i]
		}
		return f.rules.authority
	}
	common := func(schema string, root *cborRefValue, i int) {
		for field, value := range map[string]*cborRefValue{
			"tenant_id": namespaceText(f.rules.tenant), "revocation_authority_id": namespaceText(authority(i)), "namespace_capacity_digest": namespaceBytes(f.rules.capacityDigest[:]),
			"revocation_epoch": namespaceNumber(0), "revocation_policy_id": namespaceText("online"), "revocation_policy_revision": namespaceNumber(1),
		} {
			f.set(t, schema, root, field, value)
		}
		generation := "revocation_authority_generation"
		if schema == "GrantNamespace" {
			generation = "generation"
		}
		f.set(t, schema, root, generation, oracleField(t, f.r.cborReference, "RevocationState", f.state, "authority_generation"))
	}
	common("Artifact", x.parent, 0)
	for field, value := range map[string]uint64{"issued_at_ms": 1050, "initiation_not_after_ms": 1500, "session_not_after_ms": 5000} {
		f.set(t, "Artifact", x.parent, field, namespaceNumber(value))
	}
	count := 3
	if tunnel {
		count = 7
	}
	for _, i := range []int{1, 2, 4, 6} {
		if i >= count {
			continue
		}
		cert := f.seed(t, "certificate_fields")
		common("IdentityCertificate", cert, i)
		role := uint64(2)
		if i < 3 {
			role = uint64(i - 1)
		}
		for field, value := range map[string]uint64{"role": role, "issued_at_ms": 1050, "expires_at_ms": 2000} {
			f.set(t, "IdentityCertificate", cert, field, namespaceNumber(value))
		}
		x.originals[i] = signRuntimeFixture(t, "IdentityCertificate", cert.encode(nil), DecodeContext{})
	}
	for i, name := range []string{"client_identity_digest", "server_identity_digest"} {
		digest, _ := x.originals[i+1].Digest("certificate_digest")
		f.set(t, "Artifact", x.parent, name, namespaceBytes(digest[:]))
	}
	index := 0
	if tunnel {
		index = 1
	}
	x.candidate = oracleField(t, f.r.cborReference, "Artifact", x.parent, "candidates").items[index]
	f.set(t, "Artifact", x.parent, "candidates", namespaceArray(x.candidate))
	refs := map[string]*cborRefValue{}
	for i := 0; i < count; i++ {
		mask := uint64(3)
		if tunnel {
			mask = 7
		}
		if i == 3 || i == 4 {
			mask = 5
		}
		if i == 5 || i == 6 {
			mask = 6
		}
		name := authority(i)
		if ref := refs[name]; ref != nil {
			old := oracleField(t, f.r.cborReference, "RevocationNamespaceRef", ref, "role_mask")
			old.n |= mask
		} else {
			refs[name] = f.mapValue(t, "RevocationNamespaceRef", map[string]*cborRefValue{
				"tenant_id": namespaceText(f.rules.tenant), "revocation_authority_id": namespaceText(name),
				"namespace_capacity_digest": namespaceBytes(f.rules.capacityDigest[:]), "generation": oracleField(t, f.r.cborReference, "RevocationState", f.state, "authority_generation"), "role_mask": namespaceNumber(mask),
			})
		}
	}
	var list []*cborRefValue
	for _, ref := range refs {
		list = append(list, ref)
	}
	sort.Slice(list, func(i, j int) bool { return bytes.Compare(list[i].encode(nil), list[j].encode(nil)) < 0 })
	f.set(t, "Candidate", x.candidate, "revocation_namespace_refs", namespaceArray(list...))
	x.originals[0] = signRuntimeFixture(t, "Artifact", x.parent.encode(nil), DecodeContext{})
	if tunnel {
		parentDigest, _ := x.originals[0].Digest("artifact_digest")
		route, err := f.r.projectCandidate(x.candidate)
		if err != nil {
			t.Fatal(err)
		}
		routeDigest, _ := cborSingleMapHash("route_digest", "Route", "full", route.encode(nil))
		contract := oracleField(t, f.r.cborReference, "Artifact", x.parent, "session_contract")
		contractDigest, _ := cborSingleMapHash("session_contract_digest", "SessionContract", "full", contract.encode(nil))
		for side, i := range []int{3, 5} {
			grant := f.seed(t, "grant_fields")
			ns := oracleField(t, f.r.cborReference, "Grant", grant, "namespace")
			common("GrantNamespace", ns, i)
			f.set(t, "GrantNamespace", ns, "role_mask", namespaceNumber(uint64(5+side)))
			parent := oracleField(t, f.r.cborReference, "Grant", grant, "parent_ref")
			for _, name := range []string{"tenant_id", "revocation_authority_id", "namespace_capacity_digest", "revocation_policy_id", "revocation_policy_revision", "lease_id", "revocation_epoch", "issued_at_ms", "initiation_not_after_ms", "session_not_after_ms"} {
				f.set(t, "GrantParentRef", parent, name, oracleField(t, f.r.cborReference, "Artifact", x.parent, name))
			}
			f.set(t, "GrantParentRef", parent, "authority_generation", oracleField(t, f.r.cborReference, "Artifact", x.parent, "revocation_authority_generation"))
			f.set(t, "GrantParentRef", parent, "artifact_issuer_key_id", oracleField(t, f.r.cborReference, "Artifact", x.parent, "issuer_key_id"))
			f.set(t, "GrantParentRef", parent, "artifact_digest", namespaceBytes(parentDigest[:]))
			f.set(t, "Grant", grant, "identity_digests", namespaceArray(oracleField(t, f.r.cborReference, "Artifact", x.parent, "client_identity_digest"), oracleField(t, f.r.cborReference, "Artifact", x.parent, "server_identity_digest")))
			relayDigest, _ := x.originals[i+1].Digest("certificate_digest")
			for field, value := range map[string]*cborRefValue{"route_descriptor": route, "route_digest": namespaceBytes(routeDigest), "session_contract_digest": namespaceBytes(contractDigest), "relay_identity_digest": namespaceBytes(relayDigest[:]), "issued_at_ms": namespaceNumber(1100), "not_after_ms": namespaceNumber(2000)} {
				f.set(t, "Grant", grant, field, value)
			}
			f.set(t, "GrantLimits", oracleField(t, f.r.cborReference, "Grant", grant, "limits"), "max_envelope_bytes", namespaceNumber(8+oracleField(t, f.r.cborReference, "SessionContract", contract, "max_frame").n))
			var legs []*cborRefValue
			for role, name := range []string{"client_leg", "server_leg"} {
				leg := oracleField(t, f.r.cborReference, "Candidate", x.candidate, name)
				legs = append(legs, f.mapValue(t, "GrantLegRef", map[string]*cborRefValue{"leg_id": oracleField(t, f.r.cborReference, "Leg", leg, "leg_id"), "logical_role": namespaceNumber(uint64(role))}))
			}
			f.set(t, "Grant", grant, "legs", namespaceArray(legs...))
			x.originals[i] = signRuntimeFixture(t, "Grant", grant.encode(nil), DecodeContext{})
		}
	}
	return x
}

func (x *endpointCredentialFixture) bind(role Direction) (*EndpointCredentials, error) {
	var grant, relay *SignedMap
	if x.originals[3] != nil {
		grant, relay = x.originals[3+2*int(role)], x.originals[4+2*int(role)]
	}
	return BindEndpointCredentials(role, x.originals[0], 0, x.originals[1], x.originals[2], grant, relay)
}

func (x *endpointCredentialFixture) policy(t *testing.T, id string, revision, stale, signer uint64) *CredentialPolicy {
	t.Helper()
	value := x.f.mapValue(t, "CredentialRevocationPolicy", map[string]*cborRefValue{"revocation_policy_id": namespaceText(id), "revocation_policy_revision": namespaceNumber(revision), "max_staleness_ms": namespaceNumber(stale), "max_head_signer_lifetime_ms": namespaceNumber(signer)})
	p, err := NewCredentialPolicy(value.encode(nil))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEndpointCredentialClosureRoleLocalOriginals(t *testing.T) {
	for _, tunnel := range []bool{false, true} {
		for _, separate := range []bool{false, true} {
			x := newEndpointCredentialFixture(t, tunnel, separate)
			for _, role := range []Direction{ClientToServer, ServerToClient} {
				closure, err := x.bind(role)
				if err != nil {
					t.Fatal(tunnel, separate, role, err)
				}
				want := 3
				if tunnel {
					want = 5
				}
				if closure.CredentialCount() != want || closure.Deadline() != 2000 {
					t.Fatal("wrong dependency closure")
				}
				if tunnel {
					parent, grant := closure.Credential(0).Scope(), closure.Credential(3).Scope()
					if grant.ParentIssuer != parent.Issuer || grant.ParentAuthority != parent.Authority || grant.ParentCapacityDigest != parent.CapacityDigest || grant.ParentGeneration != parent.Generation || grant.ParentCohort != parent.Cohort {
						t.Fatal("grant issuer trust lost original parent authority context")
					}
				}
				if !separate {
					want = 1
				}
				if closure.NamespaceCount() != want {
					t.Fatal("wrong local namespace count", closure.NamespaceCount())
				}
				for i := 0; i < closure.NamespaceCount(); i++ {
					ref, _ := closure.Namespace(i)
					if separate && ((role == ClientToServer && (ref.Authority == "server-grant" || ref.Authority == "server-relay")) || (role == ServerToClient && (ref.Authority == "client-grant" || ref.Authority == "client-relay"))) {
						t.Fatal("remote private subscription included")
					}
				}
			}
		}
	}
	if cost, err := EndpointCredentialsBackingBytes(); err != nil || cost == 0 {
		t.Fatal(cost, err)
	}
}

func TestCredentialFreshnessProjectionsDoNotShareTheirMinimum(t *testing.T) {
	f := newNamespaceFixture(t)
	n, tick, _ := liveNamespaceFixture(t, f, 4000, false)
	var first, second credentialProjection
	if left, err := first.project(n.clock, 1700); err != nil || left != 500 {
		t.Fatal(left, err)
	}
	if left, err := second.project(n.clock, 1500); err != nil || left != 300 {
		t.Fatal(left, err)
	}
	tick.Store(100)
	mark, _ := n.clock.Monotonic()
	if err := n.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1200, UpperMS: 1250}); err != nil {
		t.Fatal(err)
	}
	// A renewed second namespace can stop controlling the minimum. The first
	// namespace still has its original monotonic deadline despite clock refinement.
	if _, err := second.project(n.clock, 1900); err != nil {
		t.Fatal(err)
	}
	if left, err := first.project(n.clock, 1700); err != nil || left != 400 {
		t.Fatal("other namespace renewal reset this original projection", left, err)
	}
}

func TestDetachedCredentialSurvivesSecretOwnerErasure(t *testing.T) {
	x := newEndpointCredentialFixture(t, false, false)
	closure, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	parent := closure.Credential(0)
	permission := IssuerPermission{Schema: "Artifact", Issuer: parent.scope.Issuer, Key: parent.key, SigningStart: 1000, SigningEnd: 1100}
	wire, _ := x.originals[0].Bytes()
	x.originals[0].Release()
	if !bytes.Equal(wire, make([]byte, len(wire))) {
		t.Fatal("source secret backing not erased")
	}
	state := x.f.bindState(t, 1, [2]uint64{})
	if _, err := state.CheckDetachedCredential(parent, permission, x.f.now); err != nil {
		t.Fatal(err)
	}
	x.f.set(t, "RevocationState", x.f.state, "revoked_leases", namespaceArray(x.f.mapValue(t, "RevokedLeaseEntry", map[string]*cborRefValue{
		"issuer_key_id": namespaceBytes(parent.scope.Issuer[:]), "lease_id": namespaceBytes(parent.lease[:]), "artifact_digest": namespaceBytes(parent.facts.Digest[:]), "cohort": namespaceNumber(parent.scope.Cohort), "latest_impact_not_after_ms": namespaceNumber(parent.scope.ExpiresMS),
	})))
	revoked := x.f.bindState(t, 2, [2]uint64{})
	if _, err := revoked.CheckDetachedCredential(parent, permission, x.f.now); err != CBORFailure("revocation_lease_rejected") {
		t.Fatal("detached original escaped revocation", err)
	}
	if parent.CheckAdmission(timev4.Interval{LowerMS: 1600, UpperMS: 1700}) != timev4.ErrExpired {
		t.Fatal("admission extended")
	}
	if _, err := state.CheckDetachedCredential(parent, permission, timev4.Interval{LowerMS: 1600, UpperMS: 1700}); err != nil {
		t.Fatal("admission end killed Session", err)
	}
}

func TestEndpointCredentialClosureRejectsAlteredDependencies(t *testing.T) {
	for _, change := range []string{"missing", "generation", "capacity", "mask", "identity", "extra"} {
		t.Run(change, func(t *testing.T) {
			x := newEndpointCredentialFixture(t, false, true)
			refs := oracleField(t, x.f.r.cborReference, "Candidate", x.candidate, "revocation_namespace_refs")
			switch change {
			case "missing":
				refs.items = refs.items[1:]
			case "generation":
				oracleField(t, x.f.r.cborReference, "RevocationNamespaceRef", refs.items[0], "generation").n++
			case "capacity":
				oracleField(t, x.f.r.cborReference, "RevocationNamespaceRef", refs.items[0], "namespace_capacity_digest").data = bytes.Repeat([]byte{3}, 32)
			case "mask":
				oracleField(t, x.f.r.cborReference, "RevocationNamespaceRef", refs.items[0], "role_mask").n = 1
			case "identity":
				oracleField(t, x.f.r.cborReference, "Artifact", x.parent, "server_identity_digest").data = bytes.Repeat([]byte{3}, 32)
			case "extra":
				oracleField(t, x.f.r.cborReference, "RevocationNamespaceRef", refs.items[0], "revocation_authority_id").data = []byte("extra")
			}
			sort.Slice(refs.items, func(i, j int) bool { return bytes.Compare(refs.items[i].encode(nil), refs.items[j].encode(nil)) < 0 })
			x.originals[0] = signRuntimeFixture(t, "Artifact", x.parent.encode(nil), DecodeContext{})
			if _, err := x.bind(ClientToServer); err == nil {
				t.Fatal("changed dependency accepted")
			}
		})
	}
	x := newEndpointCredentialFixture(t, true, true)
	if _, err := BindEndpointCredentials(ClientToServer, x.originals[0], 0, x.originals[1], x.originals[2], x.originals[5], x.originals[6]); err == nil {
		t.Fatal("remote hop substituted")
	}
}

func TestEndpointCredentialPoliciesAndCurrentNamespace(t *testing.T) {
	x := newEndpointCredentialFixture(t, false, false)
	closure, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	p := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
	requirements, err := closure.ResolvePolicies([]*CredentialPolicy{p, p, p})
	if err != nil || requirements.StalenessMS != 5000 {
		t.Fatal(requirements, err)
	}
	n, _, trust := liveNamespaceFixture(t, x.f, 4000, false)
	bindings := make([]CredentialValidation, 3)
	for i := range bindings {
		c := closure.Credential(i)
		bindings[i] = CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: c.scope.Schema, Issuer: c.scope.Issuer, Key: c.key, SigningStart: 1000, SigningEnd: 1100}, Policy: p}
	}
	for _, original := range x.originals[:3] {
		original.Release()
	}
	valid, err := closure.CheckCurrent(bindings, 10000)
	if err != nil || valid.DeadlineMS != 2000 {
		t.Fatal(valid, err)
	}
	trust.rejected.Store(true)
	if _, err := closure.CheckCurrent(bindings, 10000); err != CBORFailure("independent_trust_rejected") {
		t.Fatal("current rejection bypassed", err)
	}
	if _, err := closure.ResolvePolicies([]*CredentialPolicy{p, x.policy(t, "online", 1, 6000, x.f.rules.signerLife), p}); err != CBORFailure("credential_policy_equivocation") {
		t.Fatal(err)
	}
	if _, err := closure.ResolvePolicies([]*CredentialPolicy{p, x.policy(t, "other", 1, 5000, x.f.rules.signerLife), p}); err != CBORFailure("credential_policy_reference") {
		t.Fatal(err)
	}
	closure.credentials[1].facts.PolicyID = "different" // Model a separately signed reference for this isolated policy test.
	if _, err := closure.ResolvePolicies([]*CredentialPolicy{p, x.policy(t, "different", 7, 1, x.f.rules.signerLife), p}); err != CBORFailure("credential_policy_reference") {
		t.Fatal(err)
	}
	if _, err := closure.ResolvePolicies([]*CredentialPolicy{p, x.policy(t, "different", 1, 1, x.f.rules.signerLife), p}); err != CBORFailure("credential_policy_parent_envelope") {
		t.Fatal(err)
	}
	if err := x.f.rules.CheckPublication(CredentialRequirements{1, x.f.rules.signerLife - 1}); err != CBORFailure("revocation_policy_incompatible") {
		t.Fatal(err)
	}
}

func TestEndpointAuthorizationCurrentTrustAndOriginalAdmission(t *testing.T) {
	for _, source := range []string{"live_authority", "preauthorized_pool"} {
		x := newEndpointCredentialFixture(t, false, false)
		x.f.now = timev4.Interval{LowerMS: 1200, UpperMS: 1250}
		closure, err := x.bind(ClientToServer)
		if err != nil {
			t.Fatal(err)
		}
		_, activation, _ := x.f.activationOriginal(t, source, x.originals[0])
		n, tick, trust := liveNamespaceFixture(t, x.f, 4000, false)
		trust.activation = activation.trust
		p := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
		bindings := make([]CredentialValidation, closure.count)
		for i, c := range closure.credentials[:closure.count] {
			bindings[i] = CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: c.scope.Schema, Issuer: c.scope.Issuer, Key: c.key, SigningStart: 1000, SigningEnd: 1100}, Policy: p}
		}
		subscriptions, err := closure.Subscribe(bindings, 10000, x.f.reserve(t, CredentialSubscriptionsCharge()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(subscriptions.Close)
		a, err := NewEndpointAuthorization(subscriptions, activation)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Close(nil) })
		if result, err := a.CheckAdmission(); err != nil || result.DeadlineMS != 2000 {
			t.Fatal(result, err)
		}
		for _, original := range x.originals[:3] {
			original.Release()
		}
		bindings[0].Namespace = nil // Caller mutation cannot replace the retained owners.
		tick.Store(300)
		if err := a.Check(); err != nil {
			t.Fatal("ended admission killed admitted Session", err)
		}
		if remaining, err := a.RemainingMS(); err != nil || remaining != 450 {
			t.Fatal("freshness projection changed original time", remaining, err)
		}
		trust.rejected.Store(true)
		if err := a.Check(); err != CBORFailure("independent_trust_rejected") {
			t.Fatal(err)
		}
		trust.rejected.Store(false)
		if err := a.Check(); err != CBORFailure("independent_trust_rejected") {
			t.Fatal("terminal authorization revived", err)
		}
	}
}

func TestEndpointCredentialRejectsSignedGrantSubstitution(t *testing.T) {
	for _, field := range []string{"parent", "contract", "relay", "envelope"} {
		t.Run(field, func(t *testing.T) {
			x := newEndpointCredentialFixture(t, true, false)
			wire, _ := x.originals[3].Bytes()
			root, _, err := x.f.r.decode(wire, "Grant", nil, 1<<16)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "parent":
				parent := oracleField(t, x.f.r.cborReference, "Grant", root, "parent_ref")
				x.f.set(t, "GrantParentRef", parent, "artifact_digest", namespaceBytes(bytes.Repeat([]byte{8}, 32)))
			case "contract":
				x.f.set(t, "Grant", root, "session_contract_digest", namespaceBytes(bytes.Repeat([]byte{8}, 32)))
			case "relay":
				x.f.set(t, "Grant", root, "relay_identity_digest", namespaceBytes(bytes.Repeat([]byte{8}, 32)))
			case "envelope":
				limits := oracleField(t, x.f.r.cborReference, "Grant", root, "limits")
				oracleField(t, x.f.r.cborReference, "GrantLimits", limits, "max_envelope_bytes").n--
			}
			x.originals[3] = signRuntimeFixture(t, "Grant", root.encode(nil), DecodeContext{})
			if _, err := x.bind(ClientToServer); err == nil {
				t.Fatal("signed replacement accepted")
			}
		})
	}
}
