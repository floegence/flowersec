package protocolv4

import (
	"bytes"
	"context"
	"crypto/sha256"
)

// ReplaceFailed reserves the same namespace slot for an independently configured
// fresh bootstrap. The failed incarnation and all of its real tails remain
// pinned; copying its complete signed trust history does not release them. The
// replacement cannot authorize until its new complete pair covers that history.
// This bounded recovery path does not evict a namespace or change continuity.
func (r *NamespaceRegistry) ReplaceFailed(previous, next *NamespaceTrustStore) error {
	if r == nil || previous == nil || next == nil || previous == next {
		return CBORFailure("revocation_namespace_owner")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return CBORFailure("revocation_namespace_owner")
	}
	var entry *namespaceRegistryEntry
	for i := range r.entries[:r.used] {
		if r.entries[i].trust == previous {
			entry = &r.entries[i]
			break
		}
	}
	if entry == nil || entry.historyCount == len(entry.history) {
		return CBORFailure("configuration_capacity")
	}
	previous.mu.Lock()
	oldNamespace := previous.namespace
	previous.mu.Unlock()
	if oldNamespace != nil {
		oldNamespace.mu.Lock()
		defer oldNamespace.mu.Unlock()
	}
	previous.mu.Lock()
	defer previous.mu.Unlock()
	if previous.namespace != oldNamespace || previous.busy || previous.closing || previous.bootstrap || previous.retired || previous.restoring {
		return CBORFailure("revocation_namespace_owner")
	}
	if oldNamespace == nil {
		if !previous.closed {
			return CBORFailure("revocation_namespace_owner")
		}
	} else if oldNamespace.terminal == nil || oldNamespace.destroyed || oldNamespace.durable != nil && oldNamespace.durable.busy {
		return CBORFailure("revocation_namespace_owner")
	}
	next.mu.Lock()
	if next.closed || next.retired || next.busy || next.restoring || next.registry != nil || next.bootstrapStarted || next.namespace != nil || next.count != 0 || next.root != previous.root || next.clock != previous.clock {
		next.mu.Unlock()
		return CBORFailure("revocation_namespace_binding")
	}
	if err := r.reservation.CheckSameEnvironment(next.reservation); err != nil {
		next.mu.Unlock()
		return err
	}
	if next.limits.Configurations < uint32(previous.count) || next.limits.ConfigBytes < previous.limits.ConfigBytes || next.limits.MapNodes < previous.limits.MapNodes {
		next.mu.Unlock()
		return CBORFailure("configuration_capacity")
	}
	pin, err := next.reservation.Borrow()
	if err != nil {
		next.mu.Unlock()
		return err
	}
	next.restoring = true
	next.mu.Unlock()
	// No provider or storage call runs under the registry gate. These bounded
	// checks retain the original signed bytes and revalidate every configuration.
	for i := 0; i < previous.count; i++ {
		wire, copyErr := previous.configurations[i].signed.Bytes()
		if copyErr == nil {
			copyErr = next.update(wire, true)
		}
		if copyErr != nil {
			next.mu.Lock()
			next.restoring = false
			next.closed = true
			next.mu.Unlock()
			pin.Release()
			return copyErr
		}
	}
	next.mu.Lock()
	next.restoring = false
	next.registry, next.continuity, next.replacementOf = r, r.continuity, previous
	next.mu.Unlock()
	previous.closed = true
	entry.history[entry.historyCount] = namespaceRegistryHistory{trust: previous, pin: entry.pin}
	entry.historyCount++
	entry.trust, entry.pin = next, pin
	return nil
}

// checkReplacementCoverage runs before publishing or durably committing the
// independently authenticated bootstrap pair. The old owner remains closed;
// its observed frontier cannot be replaced merely by a newer nonce or signature.
func (t *NamespaceTrustStore) checkReplacementCoverage(next *LiveNamespace) error {
	t.mu.Lock()
	previous := t.replacementOf
	t.mu.Unlock()
	for previous != nil {
		if err := t.checkPreviousCoverage(previous, next); err != nil {
			return err
		}
		previous = previous.replacementOf
	}
	return nil
}

func (t *NamespaceTrustStore) checkPreviousCoverage(previous *NamespaceTrustStore, next *LiveNamespace) error {
	sample, err := t.sampleCurrent()
	if err != nil {
		return err
	}
	previous.mu.Lock()
	old := previous.namespace
	previous.mu.Unlock()
	if old == nil {
		return nil
	}
	old.mu.Lock()
	defer old.mu.Unlock()
	next.mu.Lock()
	defer next.mu.Unlock()
	previous.mu.Lock()
	defer previous.mu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	if previous.namespace != old || !previous.closed || previous.retired || old.terminal == nil || old.destroyed || old.active == nil || old.observed == nil || t.namespace != next || t.count == 0 {
		return CBORFailure("revocation_namespace_owner")
	}
	if !t.rules.Matches(previous.rules.capacity, previous.rules.publication) {
		return CBORFailure("revocation_namespace_binding")
	}
	if err := t.checkCurrentLockedAt(sample); err != nil {
		return err
	}
	current := &t.configurations[t.count-1]
	if err := previous.checkHistory(current); err != nil {
		return err
	}
	if next.observed.generation == old.observed.generation {
		if err := replacementHeadFollows(next.observed, old.observed); err != nil {
			return err
		}
		if err := old.active.checkReplacementSuccessor(next.active, current.retired); err != nil {
			return err
		}
	} else {
		if next.observed.generation <= old.observed.generation || current.generation != next.observed.generation {
			return CBORFailure("revocation_trust_rollback")
		}
		// A generation jump must independently and permanently retire every
		// previously permitted signer; a Head cannot assert this on its own.
		for _, config := range previous.configurations[:previous.count] {
			for _, issuer := range config.issuers {
				if !includesTrustID(current.retired, issuer.permission.Issuer) {
					return CBORFailure("revocation_issuer_not_retired")
				}
			}
			for _, activation := range config.activations {
				if !includesTrustID(current.retired, activation.binding.Issuer) {
					return CBORFailure("revocation_issuer_not_retired")
				}
			}
			for _, head := range config.heads {
				if !includesTrustID(current.rejectedHeads, head.signer) {
					return CBORFailure("revocation_trust_rollback")
				}
			}
		}
	}
	return t.stateHistoryLocked(next.active)
}

func replacementHeadFollows(next, previous *NamespaceHead) error {
	if next == nil || previous == nil || !next.rules.Matches(previous.rules.capacity, previous.rules.publication) || next.schema != previous.schema || next.generation != previous.generation || next.sequence < previous.sequence {
		return CBORFailure("revocation_head_rollback")
	}
	if next.sequence == previous.sequence && !bytes.Equal(next.bytes, previous.bytes) {
		return CBORFailure("revocation_head_equivocation")
	}
	for class, floor := range next.floors {
		if floor < previous.floors[class] {
			return CBORFailure("revocation_floor_rollback")
		}
	}
	return nil
}

// prepareReplacementCommit reads only the current complete storage fact. Its
// version must name an exact previously acknowledged or uncertain original
// write retained by the failed owner. It never guesses a new CAS predecessor.
func (t *NamespaceTrustStore) prepareReplacementCommit(ctx context.Context, next *LiveNamespace) error {
	if next.durable == nil || t.replacementOf == nil {
		return nil
	}
	d := next.durable
	version, size, err := d.store.LoadNamespace(ctx, d.buffer)
	defer clear(d.buffer)
	if err != nil {
		return err
	}
	if size == 0 && version == (NamespaceContinuityVersion{}) {
		for previous := t.replacementOf; previous != nil; previous = previous.replacementOf {
			previous.mu.Lock()
			old := previous.namespace
			previous.mu.Unlock()
			if old != nil {
				old.mu.Lock()
				known := old.durable != nil && old.durable.version.Revision != 0
				old.mu.Unlock()
				if known {
					return CBORFailure("revocation_continuity_receipt")
				}
			}
		}
		return ctx.Err()
	}
	if size < 1 || size > len(d.buffer) || version.Revision == 0 || sha256.Sum256(d.buffer[:size]) != version.Digest {
		return CBORFailure("revocation_continuity_receipt")
	}
	if anchor, ok := d.store.(NamespaceContinuityRecoveryAnchor); ok {
		if err := anchor.CheckNamespaceContinuity(ctx, d.scope, version); err != nil {
			return err
		}
	}
	known := false
	for previous := t.replacementOf; previous != nil; previous = previous.replacementOf {
		previous.mu.Lock()
		old := previous.namespace
		previous.mu.Unlock()
		if old == nil {
			continue
		}
		old.mu.Lock()
		if old.durable != nil && old.durable.scope == d.scope && !old.durable.busy {
			known = known || old.durable.version == version || old.durable.attempted == version
		}
		old.mu.Unlock()
	}
	if !known {
		return CBORFailure("revocation_continuity_receipt")
	}
	if err := d.dependencies.Check(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.version = version
	return nil
}
