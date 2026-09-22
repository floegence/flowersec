package protocolv4

import (
	"bytes"
	"context"
	"testing"
)

func bootstrapIssuerEvidence(t *testing.T, f *onlineBootstrapFixture) *cborRefValue {
	t.Helper()
	n := f.namespace
	original := oracleField(t, n.r.cborReference, "TrustConfig", f.config, "issuer_authorizations").items[0]
	digest, err := fullMapDigest("credential_issuer_authorization_digest", "CredentialIssuerAuthorization", original.encode(nil))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]*cborRefValue{"authorization_digest": namespaceBytes(digest[:])}
	for _, name := range []string{"signing_not_before_ms", "signing_not_after_ms"} {
		value := *oracleField(t, n.r.cborReference, "CredentialIssuerAuthorization", original, name)
		fields[name] = &value
	}
	originalImpact := oracleField(t, n.r.cborReference, "CredentialIssuerAuthorization", original, "max_affected_cohorts")
	impact := namespaceArray()
	for _, value := range originalImpact.items {
		copy := *value
		impact.items = append(impact.items, &copy)
	}
	fields["max_affected_cohorts"] = impact
	value, err := n.r.namedMap("IssuerAuthorizationImpact", fields)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func installBootstrapIssuerDenial(t *testing.T, f *onlineBootstrapFixture, evidence *cborRefValue, sequence uint64) {
	t.Helper()
	n := f.namespace
	issuer := oracleField(t, n.r.cborReference, "TrustConfig", f.config, "issuer_authorizations").items[0]
	id := oracleField(t, n.r.cborReference, "CredentialIssuerAuthorization", issuer, "issuer_key_id")
	entry, err := n.r.namedMap("RevokedIssuerEntry", map[string]*cborRefValue{"issuer_key_id": namespaceBytes(id.data), "authorizations": namespaceArray(evidence)})
	if err != nil {
		t.Fatal(err)
	}
	n.set(t, "RevocationState", n.state, "revoked_issuers", namespaceArray(entry))
	f.head, f.state = n.bindHead(t, sequence, [2]uint64{})
}

func TestNamespaceTrustOriginalIssuerImpactRequiredAtBootstrap(t *testing.T) {
	for _, change := range []string{"exact", "missing", "shorter", "window"} {
		t.Run(change, func(t *testing.T) {
			f := onlineBootstrap(t)
			evidence := bootstrapIssuerEvidence(t, f)
			switch change {
			case "missing":
				f.namespace.set(t, "IssuerAuthorizationImpact", evidence, "authorization_digest", namespaceBytes(bytes.Repeat([]byte{4}, 32)))
			case "shorter":
				f.namespace.set(t, "IssuerAuthorizationImpact", evidence, "max_affected_cohorts", namespaceArray(namespaceNumber(0), &cborRefValue{major: 7, n: 22}))
			case "window":
				f.namespace.set(t, "IssuerAuthorizationImpact", evidence, "signing_not_before_ms", namespaceNumber(1))
			}
			installBootstrapIssuerDenial(t, f, evidence, 1)
			n, err := f.operation.Run(context.Background(), f.provider)
			if change == "exact" {
				if err != nil || n == nil {
					t.Fatal(err)
				}
				// Trust may retain the original revoked permission as evidence,
				// but a new ID is not authority to extend that key's rights.
				f.advance(t, 2, 5500)
				issuer := oracleField(t, f.namespace.r.cborReference, "TrustConfig", f.config, "issuer_authorizations").items[0]
				f.namespace.set(t, "CredentialIssuerAuthorization", issuer, "authorization_id", namespaceBytes(bytes.Repeat([]byte{6}, 16)))
				if err := f.owner.Update(f.wire(t)); err != CBORFailure("revocation_issuer_rejected") {
					t.Fatal("revoked issuer got a new permission", err)
				}
			} else if err == nil || n != nil {
				t.Fatal("incomplete original issuer impact installed", change)
			}
		})
	}
}

func TestNamespaceTrustRetainsImpactOfRemovedCurrentPermission(t *testing.T) {
	f := onlineBootstrap(t)
	evidence := bootstrapIssuerEvidence(t, f)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	// Build the next original State with the historically known issuer, then
	// remove that permission from current trust without erasing its history.
	f.namespace.set(t, "IssuerAuthorizationImpact", evidence, "authorization_digest", namespaceBytes(bytes.Repeat([]byte{9}, 32)))
	installBootstrapIssuerDenial(t, f, evidence, 2)
	f.advance(t, 2, 5500)
	f.set(t, "issuer_authorizations", namespaceArray())
	if err := f.owner.Update(f.wire(t)); err != nil {
		t.Fatal(err)
	}
	signed := signRuntimeFixture(t, "FreshnessHead", f.head.bytes, DecodeContext{})
	c := f.owner.configurations[f.owner.count-1]
	head, err := f.owner.rules.BindHead(signed, f.namespace.delegation, c.generation, c.issued, c.end)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Observe(head); err != nil {
		t.Fatal(err)
	}
	pin, err := n.Pending()
	if err != nil || pin == nil {
		t.Fatal(err)
	}
	if err := pin.Fetch(namespaceRead(f.state)); err != CBORFailure("revocation_issuer_evidence_missing") {
		t.Fatal("removed permission lost original impact history", err)
	}
	if n.active.head.sequence != 1 {
		t.Fatal("invalid complete State replaced active")
	}
}

func TestNamespaceTrustPermanentRetirementRejectsNewPermissions(t *testing.T) {
	f := independentTrust(t)
	issuer := f.owner.configurations[0].issuers[0].permission.Issuer
	f.advance(t, 2, 5500)
	f.set(t, "retired_issuers", namespaceArray(namespaceBytes(issuer[:])))
	if err := f.owner.Update(f.wire(t)); err != nil {
		t.Fatal(err)
	}
	f.advance(t, 3, 6000)
	entry := oracleField(t, f.namespace.r.cborReference, "TrustConfig", f.config, "issuer_authorizations").items[0]
	f.namespace.set(t, "CredentialIssuerAuthorization", entry, "authorization_id", namespaceBytes(bytes.Repeat([]byte{8}, 16)))
	if err := f.owner.Update(f.wire(t)); err != CBORFailure("revocation_issuer_rejected") {
		t.Fatal("permanently retired key acquired a new delegation", err)
	}
}
