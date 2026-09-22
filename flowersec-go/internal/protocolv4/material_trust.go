package protocolv4

// ActivationConfiguration is an exact independently authenticated delegation
// and once-authority mapping copied into caller-admitted storage. It grants no
// spend, winner or admission success; the original proof and parent binding
// must still pass the live namespace and durable admission gates.
type ActivationConfiguration struct {
	Rules            *NamespaceRules
	Key              [32]byte
	Delegation, Once []byte
}

func (t *NamespaceTrustStore) ResolveActivation(parent *Credential, signingKeyID string, delegationOut, onceOut []byte) (ActivationConfiguration, error) {
	if parent == nil || parent.scope.Schema != "Artifact" || signingKeyID == "" {
		return ActivationConfiguration{}, CBORFailure("activation_authority_owner")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return ActivationConfiguration{}, err
	}
	c := &t.configurations[t.count-1]
	scope := parent.scope
	if scope.Tenant != t.root.Tenant || scope.Authority != t.root.Authority || scope.CapacityDigest != t.rules.capacityDigest || scope.Generation != c.generation || includesTrustID(c.retired, scope.Issuer) {
		return ActivationConfiguration{}, CBORFailure("activation_delegation_namespace")
	}
	for i, entry := range c.activations {
		b := entry.binding
		if b.ParentIssuer != scope.Issuer || b.SigningKeyID != signingKeyID || includesTrustID(c.retired, b.Issuer) {
			continue
		}
		for j, mapping := range c.once {
			if mapping.issuer != scope.Issuer || mapping.spend != b.SpendAuthority || mapping.winner != b.WinnerAuthority {
				continue
			}
			delegation := c.signed.Field("activation_delegations").Index(i).Encoded()
			once := c.signed.Field("once_authorities").Index(j).Encoded()
			if len(delegationOut) < len(delegation) || len(onceOut) < len(once) {
				return ActivationConfiguration{}, CBORFailure("configuration_capacity")
			}
			d, o := copy(delegationOut, delegation), copy(onceOut, once)
			return ActivationConfiguration{Rules: t.rules, Key: b.Key, Delegation: delegationOut[:d:d], Once: onceOut[:o:o]}, nil
		}
	}
	return ActivationConfiguration{}, CBORFailure("activation_delegation_authority")
}
