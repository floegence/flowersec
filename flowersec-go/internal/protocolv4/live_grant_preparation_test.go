package protocolv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func liveGrantPreparationFixture(t *testing.T) *endpointCredentialFixture {
	t.Helper()
	x := newEndpointCredentialFixture(t, true, false)
	wire, err := x.originals[3].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := x.f.r.decode(wire, "Grant", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	x.f.set(t, "Grant", grant, "issued_at_ms", namespaceNumber(1050))
	x.originals[3] = signRuntimeFixture(t, "Grant", grant.encode(nil), DecodeContext{})
	return x
}

func TestLiveGrantPreparationWaitsForHeadRefreshAndKeepsOriginalDeadline(t *testing.T) {
	x := liveGrantPreparationFixture(t)
	complete, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	grant := complete.credentials[3]
	f := x.f
	f.set(t, "FreshnessHead", f.head, "next_update_ms", namespaceNumber(1300))
	n, tick, _ := liveNamespaceFixture(t, f, 4000, false)
	policy := x.policy(t, grant.facts.PolicyID, grant.facts.PolicyRevision, 5000, f.rules.signerLife)
	validation := CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: "Grant", Issuer: grant.scope.Issuer, Key: grant.key, SigningStart: 1000, SigningEnd: 1200}, Policy: policy}
	preparation := LiveGrantPreparation{Scope: grant.scope, Validation: validation}
	tick.Store(250)
	if pending, err := preparation.CheckPreparation(2000, n.reservation); err != nil || !pending {
		t.Fatal("stale but trusted Head did not remain pending", pending, err)
	}
	if _, err := preparation.Check(2000, n.reservation); err != timev4.ErrExpired {
		t.Fatal("pending preparation authorized use", err)
	}
	f.set(t, "FreshnessHead", f.head, "this_update_ms", namespaceNumber(1300))
	f.set(t, "FreshnessHead", f.head, "next_update_ms", namespaceNumber(1600))
	head, content := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(head); err != nil {
		t.Fatal("refreshed Head was rejected", err)
	}
	pin, err := n.Pending()
	if err != nil || pin == nil {
		t.Fatal("original refresh pin unavailable", pin, err)
	}
	if err := pin.Fetch(namespaceRead(content)); err != nil {
		t.Fatal("original refresh could not complete", err)
	}
	if pending, err := preparation.CheckPreparation(2000, n.reservation); err != nil || pending {
		t.Fatal("original preparation did not recover after refresh", pending, err)
	}
	if _, err := preparation.Check(2000, n.reservation); err != nil {
		t.Fatal("recovered preparation lost its original valid deadline", err)
	}
}

func TestLiveGrantPreparationKeepsAdapterErrorsAndRevocationTerminal(t *testing.T) {
	for _, stage := range []string{"head_expired", "head_adapter", "revoked"} {
		t.Run(stage, func(t *testing.T) {
			x := liveGrantPreparationFixture(t)
			complete, err := x.bind(ClientToServer)
			if err != nil {
				t.Fatal(err)
			}
			grant := complete.credentials[3]
			f := x.f
			f.set(t, "FreshnessHead", f.head, "next_update_ms", namespaceNumber(1300))
			if stage == "revoked" {
				impact := f.mapValue(t, "IssuerAuthorizationImpact", map[string]*cborRefValue{"authorization_digest": namespaceBytes(make([]byte, 32)), "max_affected_cohorts": namespaceArray(namespaceNumber(0), namespaceNumber(0)), "signing_not_before_ms": namespaceNumber(1000), "signing_not_after_ms": namespaceNumber(1200)})
				entry := f.mapValue(t, "RevokedIssuerEntry", map[string]*cborRefValue{"issuer_key_id": namespaceBytes(grant.scope.Issuer[:]), "authorizations": namespaceArray(impact)})
				f.set(t, "RevocationState", f.state, "revoked_issuers", namespaceArray(entry))
			}
			n, tick, trust := liveNamespaceFixture(t, f, 4000, false)
			policy := x.policy(t, grant.facts.PolicyID, grant.facts.PolicyRevision, 5000, f.rules.signerLife)
			validation := CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: "Grant", Issuer: grant.scope.Issuer, Key: grant.key, SigningStart: 1000, SigningEnd: 1200}, Policy: policy}
			preparation := LiveGrantPreparation{Scope: grant.scope, Validation: validation}
			want := error(timev4.ErrExpired)
			if stage == "head_adapter" {
				want = errors.New("trust adapter unavailable")
			}
			if stage == "head_expired" || stage == "head_adapter" {
				n.mu.Lock()
				trustStage := "head"
				n.trust = &preparationTrustFailure{testNamespaceTrust: trust, stage: trustStage, failure: want}
				n.mu.Unlock()
			} else {
				want = CBORFailure("revocation_issuer_rejected")
			}
			tick.Store(250)
			pending, err := preparation.CheckPreparation(2000, n.reservation)
			if pending || err != want {
				t.Fatal("terminal trust/revocation failure became pending", pending, err, want)
			}
		})
	}
}

func concreteLiveGrantPreparationFixture(t *testing.T, prepare ...func(*onlineBootstrapFixture)) (*onlineBootstrapFixture, *LiveNamespace, LiveGrantPreparation) {
	t.Helper()
	x := liveGrantPreparationFixture(t)
	complete, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	grant := complete.credentials[3]
	setup := []func(*onlineBootstrapFixture){func(f *onlineBootstrapFixture) {
		n, scope := f.namespace, grant.scope
		issuer := n.mapValue(t, "CredentialIssuerAuthorization", map[string]*cborRefValue{
			"authorization_id":              namespaceBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
			"tenant_id":                     namespaceText(scope.Tenant),
			"revocation_authority_id":       namespaceText(scope.Authority),
			"namespace_capacity_digest":     namespaceBytes(scope.CapacityDigest[:]),
			"authority_generation":          namespaceNumber(scope.Generation),
			"credential_kind":               namespaceNumber(2),
			"issuer_key_id":                 namespaceBytes(scope.Issuer[:]),
			"issuer_public_key":             namespaceBytes(grant.key[:]),
			"audience":                      namespaceText(scope.Audience),
			"signing_not_before_ms":         namespaceNumber(1000),
			"signing_not_after_ms":          namespaceNumber(5000),
			"first_cohort":                  namespaceNumber(0),
			"last_cohort":                   namespaceNumber(100),
			"max_credential_not_after_ms":   namespaceNumber(6000),
			"role":                          namespaceNumber(scope.Role & 3),
			"service":                       namespaceText(scope.Service),
			"parent_authority_id":           namespaceText(scope.ParentAuthority),
			"parent_capacity_digest":        namespaceBytes(scope.ParentCapacityDigest[:]),
			"parent_generation":             namespaceNumber(scope.ParentGeneration),
			"parent_artifact_issuer_key_id": namespaceBytes(scope.ParentIssuer[:]),
			"first_parent_cohort":           namespaceNumber(0),
			"last_parent_cohort":            namespaceNumber(100),
			"max_affected_cohorts":          namespaceArray(&cborRefValue{major: 7, n: 22}, namespaceNumber(100)),
		})
		policy := n.mapValue(t, "CredentialRevocationPolicy", map[string]*cborRefValue{
			"revocation_policy_id":        namespaceText(grant.facts.PolicyID),
			"revocation_policy_revision":  namespaceNumber(grant.facts.PolicyRevision),
			"max_staleness_ms":            namespaceNumber(5000),
			"max_head_signer_lifetime_ms": namespaceNumber(n.rules.signerLife),
		})
		f.set(t, "issuer_authorizations", namespaceArray(issuer))
		f.set(t, "credential_policies", namespaceArray(policy))
		f.set(t, "activation_delegations", namespaceArray())
		f.set(t, "once_authorities", namespaceArray())
		n.set(t, "FreshnessHead", n.head, "next_update_ms", namespaceNumber(1300))
		f.head, f.state = n.bindHead(t, 1, [2]uint64{})
	}}
	setup = append(setup, prepare...)
	f := onlineBootstrapConfigured(t, nil, setup...)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the original Head decoder and trust owner until fixture cleanup;
	// durableHead uses them to bind the refreshed Head through the live path.
	if n.trust != f.owner {
		t.Fatal("preparation did not retain the concrete trust owner")
	}
	validation, err := f.owner.ResolveCredential(grant)
	if err != nil {
		t.Fatal(err)
	}
	return f, n, LiveGrantPreparation{Scope: grant.scope, Validation: validation}
}

func TestLiveGrantPreparationConcreteTrustRefreshKeepsOriginalEnds(t *testing.T) {
	for _, tc := range []struct {
		name       string
		hardEnd    uint64
		deadline   uint64
		expiryTick uint64
	}{
		{name: "hard_end", hardEnd: 1600, deadline: 1600, expiryTick: 450},
		{name: "grant_expiry", hardEnd: 3000, deadline: 2000, expiryTick: 800},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, n, preparation := concreteLiveGrantPreparationFixture(t)
			if pending, err := preparation.CheckPreparation(tc.hardEnd, n.reservation); err != nil || pending {
				t.Fatal("fresh concrete preparation was not ready", pending, err)
			}
			f.tick.Store(250)
			if pending, err := preparation.CheckPreparation(tc.hardEnd, n.reservation); err != nil || !pending {
				t.Fatal("independently trusted stale Head did not suspend preparation", pending, err)
			}
			if _, err := preparation.Check(tc.hardEnd, n.reservation); err != timev4.ErrExpired {
				t.Fatal("strict concrete check accepted a stale Head", err)
			}
			f.namespace.set(t, "FreshnessHead", f.namespace.head, "this_update_ms", namespaceNumber(1300))
			f.namespace.set(t, "FreshnessHead", f.namespace.head, "next_update_ms", namespaceNumber(2400))
			head, content := durableHead(t, f, 2)
			if err := n.Observe(head); err != nil {
				t.Fatal("concrete refreshed Head was rejected", err)
			}
			pin, err := n.Pending()
			if err != nil || pin == nil {
				t.Fatal("concrete refresh pin unavailable", pin, err)
			}
			if err := pin.Fetch(namespaceRead(content)); err != nil {
				t.Fatal("concrete refreshed State was rejected", err)
			}
			if pending, err := preparation.CheckPreparation(tc.hardEnd, n.reservation); err != nil || pending {
				t.Fatal("same concrete preparation did not recover", pending, err)
			}
			if deadline, err := preparation.Check(tc.hardEnd, n.reservation); err != nil || deadline != tc.deadline {
				t.Fatal("Head refresh extended the original validity envelope", deadline, err, tc.deadline)
			}
			f.tick.Store(tc.expiryTick)
			if pending, err := preparation.CheckPreparation(tc.hardEnd, n.reservation); pending || err != timev4.ErrExpired {
				t.Fatal("expired original end became a freshness wait", pending, err)
			}
			if _, err := preparation.Check(tc.hardEnd, n.reservation); err != timev4.ErrExpired {
				t.Fatal("strict concrete check lost the original end", err)
			}
		})
	}
}

func TestLiveGrantPreparationConcreteTrustKeepsKnownRevocationTerminal(t *testing.T) {
	f, n, preparation := concreteLiveGrantPreparationFixture(t, func(f *onlineBootstrapFixture) {
		installBootstrapIssuerDenial(t, f, bootstrapIssuerEvidence(t, f), 1)
	})
	f.tick.Store(250)
	want := CBORFailure("revocation_issuer_rejected")
	if pending, err := preparation.CheckPreparation(2000, n.reservation); pending || err != want {
		t.Fatal("known concrete issuer revocation became a freshness wait", pending, err)
	}
	if _, err := preparation.Check(2000, n.reservation); err != want {
		t.Fatal("strict concrete check lost known issuer revocation", err)
	}
}

func TestLiveGrantPreparationConcreteTrustKeepsClockAdapterErrorsTerminal(t *testing.T) {
	for _, adapterFailure := range []error{errors.New("clock adapter unavailable"), timev4.ErrExpired} {
		t.Run(adapterFailure.Error(), func(t *testing.T) {
			var failed atomic.Bool
			f, n, preparation := concreteLiveGrantPreparationFixture(t, func(f *onlineBootstrapFixture) {
				clock, err := timev4.NewClock(f.owner.clock.Profile(), func() (timev4.Tick, error) {
					if failed.Load() {
						return timev4.Tick{}, adapterFailure
					}
					return timev4.Tick{Milliseconds: f.tick.Load(), Incarnation: [16]byte{2}}, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(clock.Close)
				mark, err := clock.Monotonic()
				if err != nil {
					t.Fatal(err)
				}
				if err := clock.InstallTrusted(mark, f.namespace.now); err != nil {
					t.Fatal(err)
				}
				f.owner.clock = clock
			})
			t.Cleanup(func() { failed.Store(false) })
			f.tick.Store(250)
			if pending, err := preparation.CheckPreparation(2000, n.reservation); err != nil || !pending {
				t.Fatal("concrete preparation did not reach the stale-Head wait", pending, err)
			}
			failed.Store(true)
			pending, err := preparation.CheckPreparation(2000, n.reservation)
			failed.Store(false)
			// Clock translates source failures into unavailable time and retires
			// the original anchor, including a source-provided expiry sentinel.
			if pending || err != timev4.ErrUnavailable {
				t.Fatal("clock adapter failure became a freshness wait", pending, err, adapterFailure)
			}
			if _, err := preparation.Check(2000, n.reservation); err != timev4.ErrUnavailable {
				t.Fatal("strict concrete check reused the failed clock anchor", err)
			}
		})
	}
}
