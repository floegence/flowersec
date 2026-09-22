package rpcv4

// CheckMethodExecutionSupport validates every exact registered contract of a
// locally implemented method before its Session can advertise readiness. A
// contract update cannot silently acquire unsupported persistence semantics.
// This uses the already retained trusted bindings and performs no store I/O.
func (r *ContractRoutes) CheckMethodExecutionSupport(method uint32, services []ServiceBinding) error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	for _, entry := range r.entries {
		p := entry.policy
		if !entry.registered || entry.method != method || p.Semantics != 1 {
			continue
		}
		found := false
		for _, service := range services {
			if service.Authority.Namespace != p.Namespace {
				continue
			}
			if p.ExecutionMode == 0 && service.History == nil || p.ExecutionMode == 1 && service.DurableHistory == nil || p.Checkpoint && (service.DurableHistory == nil || service.Recovery == nil) || p.RetainedContent && !(service.DurableHistory != nil && service.DurableHistory.config.Store.SupportsContent(p) || service.History != nil && service.History.supportsContent(p)) {
				return ErrExecutionUnsupported
			}
			found = true
		}
		if !found {
			return ErrExecutionUnsupported
		}
	}
	return nil
}
