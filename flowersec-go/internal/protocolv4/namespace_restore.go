package protocolv4

import (
	"context"
	"crypto/sha256"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// RestoreNamespace reconstructs verification facts into a new Environment.
// The independently configured store must prove the latest complete history;
// this function then revalidates all original signatures and common namespace
// rules. It never restores Session/crypto/execution owners. Failed restoration
// consumes the anchor's startup position; a cache cannot retry as a new owner.
func RestoreNamespace(ctx, environment context.Context, trust *NamespaceTrustStore, config NamespaceDurabilityConfig, subscribers uint32, allocation NamespaceAllocation) (result *LiveNamespace, err error) {
	if ctx == nil || environment == nil || trust == nil || allocation.Root == nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = environment.Err(); err != nil {
		return nil, err
	}
	if err = trust.checkContinuityProfile(DurableRestore); err != nil {
		return nil, err
	}
	d, err := newNamespaceDurability(config, trust)
	if err != nil {
		return nil, err
	}
	trust.mu.Lock()
	if trust.checkContinuityProfileLocked(DurableRestore) != nil || trust.closed || trust.bootstrapStarted || trust.busy || trust.namespace != nil || trust.count != 0 {
		trust.mu.Unlock()
		d.destroy()
		return nil, CBORFailure("revocation_trust_owner")
	}
	trust.bootstrap, trust.bootstrapStarted, trust.restoring = true, true, true
	trust.mu.Unlock()
	var candidate *LiveNamespace
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = CBORFailure("revocation_continuity_provider")
			result = nil
		}
		trust.mu.Lock()
		if candidate == nil {
			candidate = trust.namespace
		}
		trust.bootstrap, trust.restoring = false, false
		trust.mu.Unlock()
		if candidate != nil && result == nil {
			candidate.Close(err)
			_ = candidate.WaitCleanup(context.Background())
		}
		if candidate == nil {
			d.destroy()
		}
	}()
	result, candidate, err = restoreNamespace(ctx, environment, trust, d, subscribers, allocation)
	returned = true
	return
}

func restoreNamespace(ctx, environment context.Context, t *NamespaceTrustStore, d *namespaceDurability, subscribers uint32, allocation NamespaceAllocation) (result, candidate *LiveNamespace, err error) {
	v, size, err := d.store.LoadNamespace(ctx, d.buffer)
	if err != nil {
		return nil, nil, err
	}
	if anchor, ok := d.store.(NamespaceContinuityRecoveryAnchor); ok {
		if err = anchor.CheckNamespaceContinuity(ctx, d.scope, v); err != nil {
			return nil, nil, err
		}
	}
	if size < 1 || size > len(d.buffer) || v.Revision == 0 || sha256.Sum256(d.buffer[:size]) != v.Digest {
		return nil, nil, CBORFailure("revocation_continuity_receipt")
	}
	if err = d.dependencies.Check(); err != nil {
		return nil, nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, nil, err
	}
	r, err := DecodeNamespaceContinuityRecord(d.buffer[:size], d.scope.Limits)
	if err != nil {
		return nil, nil, err
	}
	// The record header is part of the authenticated storage projection. A
	// backend manifest check alone cannot prevent a complete blob copied from a
	// different tenant, authority, capacity mapping or wire/profile group from
	// being presented through an otherwise correctly scoped store adapter.
	if r.StorageSchemaRevision != namespaceContinuityStorageSchemaRevision || r.Tenant != d.scope.Tenant || r.Authority != d.scope.Authority || r.CapacityDigest != d.scope.Capacity || r.WireProfile != namespaceContinuityWireProfile {
		return nil, nil, CBORFailure("revocation_continuity_binding")
	}
	for _, wire := range r.Trust[:r.TrustCount] {
		if err = t.update(wire, true); err != nil {
			return nil, nil, err
		}
	}
	sample, err := t.sampleCurrent()
	if err != nil {
		return nil, nil, err
	}
	t.mu.Lock()
	err = t.checkCurrentLockedAt(sample)
	if t.count != int(r.TrustCount) {
		err = CBORFailure("revocation_continuity_record")
	}
	rules := t.rules
	t.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	if rules == nil || rules.capacityDigest != d.scope.Capacity || rules.stateBytes > d.scope.Limits.StateBytes {
		return nil, nil, CBORFailure("revocation_continuity_binding")
	}
	refs, err := reserveNamespace(rules, subscribers, allocation)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	for _, ref := range refs {
		if err = d.reservation.CheckSameEnvironment(ref); err != nil {
			return nil, nil, err
		}
	}
	headLimit, _ := SchemaByteLimit("FreshnessHead")
	decoder, err := newSchemaDecoder("FreshnessHead", headLimit, headLimit)
	if err != nil {
		return nil, nil, err
	}
	codec, err := NewSignedMapCodec("FreshnessHead", headLimit, headLimit)
	if err != nil {
		return nil, nil, err
	}
	active, err := t.bindHeadRevision(decoder, codec, nil, r.Active.Head, r.Active.TrustRevision)
	if err != nil {
		return nil, nil, err
	}
	observed, err := t.bindHeadRevision(decoder, codec, nil, r.Observed.Head, r.Observed.TrustRevision)
	if err != nil {
		return nil, nil, err
	}
	if err = observed.follows(active); err != nil {
		return nil, nil, err
	}
	var pinned *NamespaceHead
	if len(r.Pinned.Head) > 0 {
		pinned, err = t.bindHeadRevision(decoder, codec, nil, r.Pinned.Head, r.Pinned.TrustRevision)
		if err != nil {
			return nil, nil, err
		}
		if pinned.sequence <= max(active.sequence, r.SettledSequence) || r.PinnedDeadlineMS > min(pinned.next, pinned.signerEnd, pinned.trustEnd) {
			return nil, nil, CBORFailure("revocation_continuity_record")
		}
		if pinned.sequence > observed.sequence {
			err = pinned.follows(observed)
		} else {
			err = observed.follows(pinned)
		}
		if err != nil {
			return nil, nil, err
		}
	}
	w, err := NewRevocationWorkspace(rules, refs[0])
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if candidate == nil {
			_ = w.Close()
		}
	}()
	spare, err := NewRevocationWorkspace(rules, refs[1])
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if candidate == nil {
			_ = spare.Close()
		}
	}()
	pair, err := w.Bind(active, r.State)
	if err != nil {
		return nil, nil, err
	}
	// The common State binder verifies contents and evidence against this exact
	// historical Head. Expired active Heads may retain denial history, but the
	// ordinary live gate still refuses them for authorization.
	candidate, err = newLiveNamespace(environment, t.clock, t, pair, spare, r.FetchDurationMS, r.FetchAttempts, subscribers, refs[2], true, false)
	if err != nil {
		return nil, nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, candidate, err
	}
	restoredSample, err := candidate.sampleCurrent()
	if err != nil {
		return nil, candidate, err
	}
	candidate.mu.Lock()
	defer candidate.mu.Unlock()
	if err = candidate.checkAvailable(); err != nil {
		return nil, candidate, err
	}
	candidate.observed, candidate.settledSequence = observed, r.SettledSequence
	candidate.durable = d
	d.version = v
	d.dirty = false
	t.mu.Lock()
	t.namespace = candidate
	t.mu.Unlock()
	// The unpublished owner remains fenced while its original watchdog is
	// already responsible for cleanup, including an abnormal recovery tail.
	go candidate.watch()
	if pinned != nil {
		err = candidate.restorePin(pinned, r, restoredSample)
	}
	// All borrowed record views are finished before the reusable commit buffer
	// is cleared. Restored expired/exhausted work remains settled, never reset.
	clear(d.buffer)
	if err == nil {
		err = candidate.checkAvailable()
	}
	if err == nil {
		restoredSample, err = candidate.clock.RefreshSample(restoredSample)
	}
	if err == nil {
		err = candidate.persistContinuity()
	}
	if err != nil {
		return nil, candidate, err
	}
	candidate.initializing = false
	candidate.notifySubscribers()
	t.mu.Lock()
	t.continuityReady = true
	t.mu.Unlock()
	return candidate, candidate, nil
}

func (n *LiveNamespace) restorePin(head *NamespaceHead, r NamespaceContinuityRecord, now timev4.Sample) error {
	if current, err := n.clock.RefreshSample(now); err != nil {
		return err
	} else {
		now = current
	}
	if r.PinnedAttempts == n.attemptLimit || !now.Interval.ValidBefore(r.PinnedDeadlineMS) {
		n.settledSequence = max(n.settledSequence, head.sequence)
		n.continuityChanged()
		return nil
	}
	deadline, err := timev4.NewDeadlineAt(n.clock, now, r.PinnedDeadlineMS)
	if err != nil {
		return err
	}
	// This new local projection is capped by the original absolute deadline,
	// including uncertainty. It never receives a fresh full download interval.
	window, err := timev4.NewWindowAt(n.clock, now.Mark, min(n.fetchDuration, r.PinnedDeadlineMS-now.UpperMS))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancelCause(n.ctx)
	n.pin = &NamespacePin{owner: n, head: head, deadline: deadline, window: window, ctx: ctx, cancel: cancel, attempts: r.PinnedAttempts}
	return nil
}
