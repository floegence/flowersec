package protocolv4

import (
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func preparationCredential(t *testing.T, f *namespaceFixture, n *LiveNamespace, stale uint64) (*Credential, CredentialValidation) {
	t.Helper()
	signed, permission := f.certificate(t)
	c, err := signed.DetachCredential()
	if err != nil {
		t.Fatal(err)
	}
	x := &endpointCredentialFixture{f: f}
	p := x.policy(t, c.facts.PolicyID, c.facts.PolicyRevision, stale, f.rules.signerLife)
	return c, CredentialValidation{Namespace: n, Issuer: permission, Policy: p}
}

func TestMaterialPreparationWaitsForOriginalNamespaceRefresh(t *testing.T) {
	f := newNamespaceFixture(t)
	n, tick, _ := liveNamespaceFixture(t, f, 4000, false)
	c, v := preparationCredential(t, f, n, 150)
	check := func(want bool) {
		t.Helper()
		before := f.resources.Snapshot()
		pending, err := CheckMaterialPreparation(v, c, c.scope.ExpiresMS, n.reservation)
		if err != nil || pending != want {
			t.Fatal("preparation freshness", pending, err)
		}
		if after := f.resources.Snapshot(); after != before {
			t.Fatal("verification allocated new owner", before, after)
		}
	}
	check(false)
	tick.Store(60)
	check(true)
	if _, err := v.CheckMaterialCredential(c, c.scope.ExpiresMS, n.reservation); err != timev4.ErrExpired {
		t.Fatal("pending preparation granted admission", err)
	}
	f.set(t, "FreshnessHead", f.head, "this_update_ms", namespaceNumber(1160))
	head, content := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(head); err != nil {
		t.Fatal(err)
	}
	pin, err := n.Pending()
	if err != nil || pin == nil {
		t.Fatal("original refresh pin unavailable", err)
	}
	if err := pin.Fetch(namespaceRead(content)); err != nil {
		t.Fatal(err)
	}
	check(false)
	tick.Store(800)
	if pending, err := CheckMaterialPreparation(v, c, c.scope.ExpiresMS, n.reservation); pending || err != timev4.ErrExpired {
		t.Fatal("original credential expiry renewed", pending, err)
	}
}

type preparationTrustFailure struct {
	*testNamespaceTrust
	stage   string
	failure error
}

func (t *preparationTrustFailure) Policy(p *CredentialPolicy) error {
	if t.stage == "policy" {
		return t.failure
	}
	return t.testNamespaceTrust.Policy(p)
}
func (t *preparationTrustFailure) Head(h NamespaceHeadTrust) error {
	if t.stage == "head" {
		return t.failure
	}
	return t.testNamespaceTrust.Head(h)
}
func (t *preparationTrustFailure) Issuer(p IssuerPermission, s CredentialScope) error {
	if t.stage == "issuer" {
		return t.failure
	}
	return t.testNamespaceTrust.Issuer(p, s)
}

func TestMaterialPreparationNeverDefersKnownRejection(t *testing.T) {
	for _, stage := range []string{"policy", "head", "issuer", "revoked", "closed"} {
		t.Run(stage, func(t *testing.T) {
			f := newNamespaceFixture(t)
			// The active Head expires before this still-live credential.
			f.set(t, "FreshnessHead", f.head, "next_update_ms", namespaceNumber(1300))
			signed, permission := f.certificate(t)
			credential, err := signed.DetachCredential()
			if err != nil {
				t.Fatal(err)
			}
			if stage == "revoked" {
				entry := f.mapValue(t, "RevokedCertificateEntry", map[string]*cborRefValue{"certificate_digest": namespaceBytes(credential.facts.Digest[:]), "cohort": namespaceNumber(0), "expires_at_ms": namespaceNumber(2000)})
				f.set(t, "RevocationState", f.state, "revoked_certificates", namespaceArray(entry))
			}
			n, tick, trust := liveNamespaceFixture(t, f, 4000, false)
			x := &endpointCredentialFixture{f: f}
			v := CredentialValidation{Namespace: n, Issuer: permission, Policy: x.policy(t, credential.facts.PolicyID, credential.facts.PolicyRevision, 5000, f.rules.signerLife)}
			tick.Store(110)
			want := error(timev4.ErrPending)
			switch stage {
			case "revoked":
				want = CBORFailure("revocation_certificate_rejected")
			case "closed":
				want = context.Canceled
				n.Close(want)
			default:
				n.mu.Lock()
				n.trust = &preparationTrustFailure{testNamespaceTrust: trust, stage: stage, failure: want}
				n.mu.Unlock()
			}
			pending, err := CheckMaterialPreparation(v, credential, 2000, n.reservation)
			if stage == "closed" && err == resourcev4.ErrClosed && !pending {
				// Closing the namespace seals its resource owner before the next
				// preparation check. That gate may win before reading its cause.
				return
			}
			if pending || err != want {
				t.Fatal("known denial hidden by stale Head", pending, err, want)
			}
		})
	}
}

func TestMaterialPreparationDoesNotRenewArtifactInitiation(t *testing.T) {
	x := newEndpointCredentialFixture(t, false, false)
	f := x.f
	n, tick, _ := liveNamespaceFixture(t, f, 4000, false)
	c, err := x.originals[0].DetachCredential()
	if err != nil {
		t.Fatal(err)
	}
	v := CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: "Artifact", Issuer: c.scope.Issuer, Key: c.key, SigningStart: 1000, SigningEnd: 1100}, Policy: x.policy(t, c.facts.PolicyID, c.facts.PolicyRevision, 150, f.rules.signerLife)}
	tick.Store(310)
	if pending, err := CheckMaterialPreparation(v, c, c.scope.ExpiresMS, n.reservation); pending || err != timev4.ErrExpired {
		t.Fatal("ended initiation window classified as refreshable", pending, err)
	}
}
