package protocolv4

// CheckRegistry validates the complete original role dependency closure before
// irreversible admission. It does not resubscribe, copy State, or change the
// captured namespace when the registry has another entry with matching names.
func (s *CredentialSubscriptions) CheckRegistry(r *NamespaceRegistry) error {
	if s == nil || r == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closure == nil {
		return CBORFailure("revocation_subscription_owner")
	}
	for _, binding := range s.bindings[:s.closure.count] {
		if err := r.CheckNamespace(binding.Namespace); err != nil {
			return err
		}
	}
	return nil
}

func (p *CredentialPreparation) CheckRegistry(r *NamespaceRegistry) error {
	if p == nil || p.subscriptions == nil || p != &p.subscriptions.preparation {
		return CBORFailure("revocation_namespace_owner")
	}
	return p.subscriptions.CheckRegistry(r)
}
