package protocolv4

import (
	"context"
	"testing"
	"time"
)

// InstallMatureDirectIssueNamespace performs a fresh independently signed
// online bootstrap on the same resource Environment after closing the previous
// owner. It never edits an authenticated live State or treats elapsed TTL as a
// floor. The issuer authorization and original immutable mapping stay exact.
func InstallMatureDirectIssueNamespace(t *testing.T, h *DirectIssueSQLiteTestHarness, cover bool) {
	t.Helper()
	f := h.fixture.f
	old := f.owner
	old.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := old.namespace.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	n := f.namespace
	maturity, err := old.rules.mature(1, h.Facts.Scope.Cohort)
	if err != nil {
		t.Fatal(err)
	}
	// Add a little proven interval margin without shortening original impact.
	now := maturity + 200
	f.tick.Store(now - n.now.LowerMS)
	f.set(t, "issued_at_ms", namespaceNumber(now))
	f.set(t, "not_after_ms", namespaceNumber(now+8000))
	n.rules = old.rules
	delegation, _, err := n.r.decode(n.delegation, "HeadSignerDelegation", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]uint64{"issued_at_ms": now, "not_before_ms": now, "not_after_ms": now + min(uint64(2000), n.rules.signerLife)} {
		n.set(t, "HeadSignerDelegation", delegation, field, namespaceNumber(value))
	}
	n.delegation = delegation.encode(nil)
	f.set(t, "head_delegations", namespaceArray(delegation))
	digest, err := cborSingleMapHash("head_signer_delegation_digest", "HeadSignerDelegation", "full", n.delegation)
	if err != nil {
		t.Fatal(err)
	}
	n.set(t, "FreshnessHead", n.head, "signer_delegation_digest", namespaceBytes(digest))
	n.set(t, "FreshnessHead", n.head, "this_update_ms", namespaceNumber(now))
	n.set(t, "FreshnessHead", n.head, "next_update_ms", namespaceNumber(now+min(uint64(1000), n.rules.headValidity)))
	floors := [2]uint64{}
	if cover {
		floors[1] = h.Facts.Scope.Cohort + 1
	}
	// bindHead uses the fixture's fixed original trust span. Construct the same
	// signed Head against the new independent configuration's actual interval.
	floor := namespaceArray(namespaceNumber(floors[0]), namespaceNumber(floors[1]))
	n.set(t, "RevocationState", n.state, "credential_revocation_floors", floor)
	n.set(t, "FreshnessHead", n.head, "credential_revocation_floors", floor)
	n.set(t, "FreshnessHead", n.head, "head_sequence", namespaceNumber(2))
	f.state = n.state.encode(nil)
	stateDigest, err := cborSingleMapHash("revocation_state_digest", "RevocationState", "full", f.state)
	if err != nil {
		t.Fatal(err)
	}
	n.set(t, "FreshnessHead", n.head, "state_digest", namespaceBytes(stateDigest))
	n.set(t, "FreshnessHead", n.head, "state_encoded_bytes", namespaceNumber(uint64(len(f.state))))
	signed := signRuntimeFixture(t, "FreshnessHead", n.head.encode(nil), DecodeContext{})
	f.head, err = n.rules.BindHead(signed, n.delegation, h.Facts.Scope.Generation, now, now+8000)
	if err != nil {
		t.Fatal(err)
	}
	limits := NamespaceTrustLimits{Configurations: 4, ConfigBytes: 32768, MapNodes: 8192, RuntimeBytes: 65536}
	charge, err := NamespaceTrustCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	borrow, err := h.Environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = NewNamespaceTrustAnchor(old.root, limits, old.clock, n.reserve(t, charge), borrow)
	borrow.Release()
	if err != nil {
		t.Fatal(err)
	}
	bl := NamespaceBootstrapLimits{ResponseBytes: 32768, ResponseNodes: 8192, StateBytes: 4096, DurationMS: 4000, FetchDurationMS: 4000, FetchAttempts: 2, Subscribers: 8, RuntimeBytes: 65536}
	cost, err := NamespaceBootstrapCharge(bl)
	if err != nil {
		t.Fatal(err)
	}
	f.operation, err = NewNamespaceOnlineBootstrap(context.Background(), f.owner, bl, n.namespaceAllocation(t), n.reserve(t, cost))
	if err != nil {
		t.Fatal(err)
	}
	f.alter = func(v *cborRefValue) {
		n.set(t, "TrustBootstrapResponse", v, "issued_at_ms", namespaceNumber(now))
		n.set(t, "TrustBootstrapResponse", v, "not_after_ms", namespaceNumber(now+1000))
	}
	if _, err = f.operation.Run(context.Background(), f.provider); err != nil {
		t.Fatal(err)
	}
	if err = f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	h.Config.Trust = [3]*NamespaceTrustStore{f.owner, f.owner, f.owner}
	t.Cleanup(func() {
		// The initial helper already owns cleanup of the replacement. The old
		// immutable history remains charged until the original Environment ends.
		n.resources.Close()
		if err := old.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
}

func TestDirectIssueRetirementRequiresActualFullStateFloor(t *testing.T) {
	for _, cover := range []bool{false, true} {
		t.Run(map[bool]string{false: "mature_without_floor", true: "mature_complete_floor"}[cover], func(t *testing.T) {
			h := NewDirectIssueSQLiteTestHarness(t)
			InstallMatureDirectIssueNamespace(t, h, cover)
			c := h.Config
			policy, ref, err := NewDirectIssuePolicy(DirectIssuePolicyConfig{Trust: c.Trust[0], Clock: c.Clock, Issuer: c.IssuerKeyID, Audience: c.Audience, CryptoProfile: c.CryptoProfile, PolicyID: c.RevocationPolicyID, PolicyRevision: c.RevocationPolicyRevision}, h.Environment)
			if err != nil {
				t.Fatal(err)
			}
			defer ref.Release()
			proof, ready, err := policy.ProveRetirement(h.Facts)
			if err != nil || ready != cover {
				t.Fatal("wrong original maturity proof", ready, err)
			}
			if cover && (proof.Head == ([32]byte{}) || proof.State == ([32]byte{}) || proof.ConnectionFloor <= h.Facts.Scope.Cohort) {
				t.Fatal("missing actual signed pair")
			}
		})
	}
}
