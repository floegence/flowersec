package protocolv4

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NamespaceDurabilityConfig fixes the continuity profile before construction.
// Dependencies retains the real store/recovery authority through actual work
// and history destruction. The store has its own separately admitted backing.
type NamespaceDurabilityConfig struct {
	Scope                     NamespaceContinuityScope
	Store                     NamespaceContinuityStore
	Reservation, Dependencies resourcev4.Reference
}

type namespaceDurability struct {
	scope                     NamespaceContinuityScope
	store                     NamespaceContinuityStore
	reservation, dependencies resourcev4.Reference
	version                   NamespaceContinuityVersion
	attempted                 NamespaceContinuityVersion
	buffer                    []byte
	busy, dirty               bool
	done                      chan struct{}
}

func NamespaceDurabilityCharge(l NamespaceContinuityLimits) (resourcev4.Vector, error) {
	n, err := NamespaceContinuityRecordBytes(l)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	h, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	c, err := SignedMapBackingBytes("FreshnessHead", h, h)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	d, err := DecoderBackingBytes(h, h)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: n + c + d + uint64(unsafe.Sizeof(namespaceDurability{})) + uint64(unsafe.Sizeof(NamespaceContinuityRecord{})) + 512, resourcev4.Items: 1, resourcev4.WorkSlots: 1}, nil
}

func newNamespaceDurability(c NamespaceDurabilityConfig, t *NamespaceTrustStore) (out *namespaceDurability, err error) {
	if t == nil || c.Store == nil || c.Scope.Tenant != t.root.Tenant || c.Scope.Authority != t.root.Authority || c.Scope.Capacity == ([32]byte{}) || c.Scope.Limits.TrustConfigurations != t.limits.Configurations || int(c.Scope.Limits.TrustConfigBytes) != t.limits.ConfigBytes {
		return nil, CBORFailure("revocation_continuity_binding")
	}
	charge, err := NamespaceDurabilityCharge(c.Scope.Limits)
	if err != nil {
		return nil, err
	}
	if err = c.Reservation.CheckSameEnvironment(t.reservation); err != nil {
		return nil, err
	}
	if err = c.Reservation.CheckSameEnvironment(c.Dependencies); err != nil {
		return nil, err
	}
	if err = c.Store.CheckNamespaceScope(c.Scope); err != nil {
		return nil, err
	}
	dep, err := c.Dependencies.TakeBorrow()
	if err != nil {
		return nil, err
	}
	owned, err := c.Reservation.Take(charge)
	if err != nil {
		dep.Release()
		return nil, err
	}
	size, _ := NamespaceContinuityRecordBytes(c.Scope.Limits)
	c.Scope.Tenant, c.Scope.Authority = strings.Clone(c.Scope.Tenant), strings.Clone(c.Scope.Authority)
	return &namespaceDurability{scope: c.Scope, store: c.Store, reservation: owned, dependencies: dep, buffer: make([]byte, int(size)), dirty: true}, nil
}

func (d *namespaceDurability) destroy() {
	clear(d.buffer)
	d.buffer = nil
	d.store = nil
	d.scope = NamespaceContinuityScope{}
	d.reservation.Release()
	d.dependencies.Release()
	d.reservation, d.dependencies = resourcev4.Reference{}, resourcev4.Reference{}
}

func (n *LiveNamespace) continuityAvailable() error {
	if n.terminal != nil {
		return n.terminal
	}
	if n.initializing {
		return timev4.ErrUnavailable
	}
	if d := n.durable; d != nil && d.busy {
		return timev4.ErrUnavailable
	}
	return nil
}

func (n *LiveNamespace) continuityChanged() {
	if n.durable != nil {
		n.durable.dirty = true
	}
}

// lockAfterContinuity is restricted to an already admitted fetch invocation. New
// calls refuse busy instead of allocating an unbounded queue of waiting work.
func (n *LiveNamespace) lockAfterContinuity() {
	for {
		n.mu.Lock()
		if n.durable == nil || !n.durable.busy {
			return
		}
		done := n.durable.done
		n.mu.Unlock()
		<-done
	}
}

// sampleAfterContinuityLocked keeps the original fetch gate on entry and
// return, including abnormal exit. A sample preceding a durable commit wait
// cannot authorize the later publication: sample again after that real wait.
func (n *LiveNamespace) sampleAfterContinuityLocked() (sample timev4.Sample, err error) {
	for {
		if n.terminal != nil {
			return sample, n.terminal
		}
		if n.durable != nil && n.durable.busy {
			done := n.durable.done
			func() { n.mu.Unlock(); defer n.mu.Lock(); <-done }()
			continue
		}
		func() { n.mu.Unlock(); defer n.mu.Lock(); sample, err = n.sampleCurrent() }()
		if err != nil {
			return sample, err
		}
		if n.durable != nil && n.durable.busy {
			continue
		}
		return sample, n.checkAvailable()
	}
}

// continuityRecord captures immutable borrows while namespace and trust are
// pinned. Encoding/copying and provider calls happen after both short gates
// are released. The busy bit excludes all other history publishers.
func (n *LiveNamespace) continuityRecord() (r NamespaceContinuityRecord, err error) {
	d := n.durable
	if d == nil {
		return r, CBORFailure("revocation_continuity_binding")
	}
	t, ok := n.trust.(*NamespaceTrustStore)
	if !ok {
		return r, CBORFailure("revocation_continuity_binding")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.namespace != n || t.closed || t.rules != n.rules || t.count < 1 || n.rules.capacityDigest != n.durable.scope.Capacity || n.rules.stateBytes > n.durable.scope.Limits.StateBytes {
		return r, CBORFailure("revocation_continuity_binding")
	}
	if err = t.reservation.Check(); err != nil {
		return r, err
	}
	if err = t.dependencies.Check(); err != nil {
		return r, err
	}
	r.TrustCount = uint32(t.count)
	r.StorageSchemaRevision = namespaceContinuityStorageSchemaRevision
	r.Tenant, r.Authority = d.scope.Tenant, d.scope.Authority
	r.CapacityDigest = d.scope.Capacity
	r.WireProfile = namespaceContinuityWireProfile
	for i := 0; i < t.count; i++ {
		r.Trust[i], err = t.configurations[i].signed.Bytes()
		if err != nil {
			return r, err
		}
	}
	head := func(h *NamespaceHead) NamespaceHeadHistory {
		return NamespaceHeadHistory{TrustRevision: h.trustRevision, Head: h.bytes}
	}
	r.Active, r.Observed = head(n.active.head), head(n.observed)
	r.State = n.active.document.Bytes()
	r.FetchDurationMS, r.FetchAttempts = n.fetchDuration, n.attemptLimit
	r.SettledSequence = n.settledSequence
	if p := n.pin; p != nil && p.terminal == nil {
		r.Pinned = head(p.head)
		r.PinnedDeadlineMS = p.deadline.Cap()
		r.PinnedAttempts = p.attempts
	}
	return r, nil
}

// persistContinuity is entered and returns with the namespace gate held. No
// caller may hold trust, State workspace, Session or resource gates across it.
// An ambiguous commit never publishes authority or retries against an assumed
// version. The original owner is fenced while its complete history stays held.
func (n *LiveNamespace) persistContinuity() (err error) {
	d := n.durable
	if d == nil || !d.dirty {
		return nil
	}
	if d.busy {
		return timev4.ErrUnavailable
	}
	if n.terminal != nil {
		return n.terminal
	}
	d.busy = true
	d.done = make(chan struct{})
	defer func() {
		d.busy = false
		close(d.done)
		d.done = nil
		n.notifySubscribers()
		if err != nil {
			n.failContinuity(err)
		}
		n.cleanup()
		n.signal()
	}()
	for d.dirty && n.terminal == nil {
		r, e := n.continuityRecord()
		if e != nil {
			return e
		}
		d.dirty = false
		var version NamespaceContinuityVersion
		err = CBORFailure("revocation_continuity_provider")
		func() {
			n.mu.Unlock()
			defer n.mu.Lock()
			version, e = d.commit(n.ctx, r)
		}()
		err = e
		if e != nil {
			return e
		}
		d.version = version
		if e = n.checkAvailable(); e != nil {
			return n.terminal
		}
	}
	return n.terminal
}

func (d *namespaceDurability) commit(ctx context.Context, r NamespaceContinuityRecord) (out NamespaceContinuityVersion, err error) {
	returned := false
	defer func() {
		clear(d.buffer)
		if recover() != nil || !returned {
			err = CBORFailure("revocation_continuity_provider")
		}
	}()
	if err = d.reservation.Check(); err == nil {
		err = d.dependencies.Check()
	}
	var size int
	if err == nil {
		size, err = EncodeNamespaceContinuityRecord(d.buffer, d.scope.Limits, r)
	}
	if err == nil {
		digest := sha256.Sum256(d.buffer[:size])
		if digest == d.version.Digest {
			out = d.version
		} else {
			if d.version.Revision == ^uint64(0) {
				return out, CBORFailure("revocation_continuity_receipt")
			}
			d.attempted = NamespaceContinuityVersion{Revision: d.version.Revision + 1, Digest: digest}
			out, err = d.store.CommitNamespace(ctx, d.version, d.buffer[:size:size])
			if err == nil && (out.Revision <= d.version.Revision || out.Revision-d.version.Revision != 1 || out.Digest != digest) {
				err = CBORFailure("revocation_continuity_receipt")
			}
		}
	}
	if err == nil {
		err = d.dependencies.Check()
	}
	if err == nil {
		err = d.reservation.Check()
	}
	if err == nil {
		err = ctx.Err()
	}
	returned = true
	return
}

func (n *LiveNamespace) failContinuity(err error) {
	if n.terminal == nil {
		n.terminal = err
		n.reservation.Seal()
		n.cancel(err)
		n.notifySubscribers()
	}
	if n.pin != nil {
		n.finishPin(n.pin, err)
	}
}

func (n *LiveNamespace) unlockContinuity(err *error) {
	defer n.mu.Unlock()
	if e := n.persistContinuity(); e != nil {
		*err = errors.Join(*err, e)
	}
}
