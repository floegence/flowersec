package protocolv4

import "bytes"

// lockForPublication returns with the original namespace (when installed) and
// trust gates held in that order. Namespace attachment can change nil to one
// owner once; history destruction cannot run while this update owns busy.
func (t *NamespaceTrustStore) lockForPublication() *LiveNamespace {
	for {
		t.mu.Lock()
		n := t.namespace
		t.mu.Unlock()
		if n != nil {
			n.mu.Lock()
		}
		t.mu.Lock()
		if t.namespace == n {
			return n
		}
		t.mu.Unlock()
		if n != nil {
			n.mu.Unlock()
		}
	}
}

func (t *NamespaceTrustStore) knownPermission(issuer [16]byte, digest [32]byte) bool {
	for i := 0; i < t.count; i++ {
		for _, entry := range t.configurations[i].issuers {
			if entry.permission.Issuer == issuer && entry.digest == digest {
				return true
			}
		}
		for _, entry := range t.configurations[i].activations {
			if entry.binding.Issuer == issuer && entry.binding.DelegationDigest == digest {
				return true
			}
		}
	}
	return false
}

func (t *NamespaceTrustStore) checkPermissionExtensions(next *trustConfiguration, namespace *LiveNamespace) error {
	var denied Value
	if namespace != nil && namespace.active != nil && namespace.active.head.generation == next.generation {
		denied = namespace.active.document.Root().Named("RevocationState", "revoked_issuers")
	}
	for _, kind := range []string{"issuer_authorizations", "activation_delegations"} {
		entries := next.signed.Field(kind)
		for i := 0; i < entries.Len(); i++ {
			var issuer [16]byte
			var digest [32]byte
			if kind == "issuer_authorizations" {
				issuer, digest = next.issuers[i].permission.Issuer, next.issuers[i].digest
			} else {
				issuer, digest = next.activations[i].binding.Issuer, next.activations[i].binding.DelegationDigest
			}
			if t.knownPermission(issuer, digest) {
				continue
			}
			if t.count > 0 && includesTrustID(t.configurations[t.count-1].retired, issuer) || denied.valid() && searchRevocation(denied, "RevokedIssuerEntry", []string{"issuer_key_id"}, issuer[:]).valid() {
				return CBORFailure("revocation_issuer_rejected")
			}
		}
	}
	return nil
}

// StateHistory is called while the original State owner pins the immutable
// document. Every independently known permission of a revoked issuer must be
// present, including permissions omitted from a newer trust configuration.
// Neither Head assertions nor shorter current permissions can replace them.
func (t *NamespaceTrustStore) StateHistory(state *NamespaceState) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return err
	}
	return t.stateHistoryLocked(state)
}

func (t *NamespaceTrustStore) stateHistoryLocked(state *NamespaceState) error {
	if state == nil || state.document == nil || state.head == nil || state.workspace.rules != t.rules {
		return CBORFailure("revocation_state_owner")
	}
	list := state.document.Root().Named("RevocationState", "revoked_issuers")
	for i := 0; i < t.count; i++ {
		config := &t.configurations[i]
		if config.generation != state.head.generation {
			continue
		}
		for j, entry := range config.issuers {
			if err := matchIssuerImpact(list, entry.permission.Issuer, entry.digest, config.signed.Field("issuer_authorizations").Index(j), "CredentialIssuerAuthorization"); err != nil {
				return err
			}
		}
		for j, entry := range config.activations {
			if err := matchIssuerImpact(list, entry.binding.Issuer, entry.binding.DelegationDigest, config.signed.Field("activation_delegations").Index(j), "ConnectionActivationDelegation"); err != nil {
				return err
			}
		}
	}
	return nil
}

func matchIssuerImpact(list Value, issuer [16]byte, digest [32]byte, original Value, schema string) error {
	denied := searchRevocation(list, "RevokedIssuerEntry", []string{"issuer_key_id"}, issuer[:])
	if !denied.valid() {
		return nil
	}
	entry := searchRevocation(denied.Named("RevokedIssuerEntry", "authorizations"), "IssuerAuthorizationImpact", []string{"authorization_digest"}, digest[:])
	if !entry.valid() {
		return CBORFailure("revocation_issuer_evidence_missing")
	}
	for _, field := range []string{"max_affected_cohorts", "signing_not_before_ms", "signing_not_after_ms"} {
		if !bytes.Equal(entry.Named("IssuerAuthorizationImpact", field).Encoded(), original.Named(schema, field).Encoded()) {
			return CBORFailure("revocation_issuer_evidence_changed")
		}
	}
	return nil
}
