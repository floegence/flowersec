package protocolv4

import (
	"bytes"
	"context"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NamespacePublicationScope fixes one authority generation and its immutable
// capacity. A new generation requires independently authorized provisioning.
type NamespacePublicationScope struct {
	Tenant, Authority string
	Capacity          [32]byte
	Generation        uint64
}

// NamespacePublicationVersion is the durable publication high-water mark.
// Snapshot is an internal authority transaction version, never a wire field.
type NamespacePublicationVersion struct {
	Snapshot, Sequence         uint64
	StateDigest, HeadDigest    [32]byte
	ThisUpdateMS, NextUpdateMS uint64
}

// NamespacePublicationSnapshot is the original store claim. Closing a job
// releases its actual work, not the committed version or read obligations.
type NamespacePublicationSnapshot struct {
	Fence, Owner, Version uint64
	Previous              NamespacePublicationVersion
	StateBytes            uint64
}

// NamespacePublicationStore is an independently installed authority, not a
// consumer cache. ReadSnapshot copies the complete linearizable current State
// into dst and reserves a publication/history position before returning.
// Ordinary state updates must not invalidate an acquired snapshot. Commit checks
// its original claim, fencing epoch, previous sequence and guard in its final
// transaction, retaining the exact State/Head pair and snapshot version.
// Failed/unknown commits must be resolved from durable bytes before another
// sequence is chosen; signed private candidates must never be distributed.
type NamespacePublicationStore interface {
	ReferencePublicationStore(NamespacePublicationScope, resourcev4.Reference) (resourcev4.Reference, error)
	ReadPublicationSnapshot(context.Context, []byte) (NamespacePublicationSnapshot, error)
	CommitNamespacePublication(context.Context, NamespacePublicationSnapshot, NamespacePublicationVersion, []byte, []byte, func() error, func(func() error) error) error
	ReleasePublicationSnapshot(NamespacePublicationSnapshot)
}

type NamespacePublisherConfig struct {
	Clock                                   *timev4.Clock
	Trust                                   *NamespaceTrustStore
	Store                                   NamespacePublicationStore
	Signer                                  MapSigner
	SignerID                                [16]byte
	Generation                              uint64
	WorkMS, MinimumValidityMS, RuntimeBytes uint64
}

// NamespacePublisher owns one synchronous signing job and no pending queue.
// A stalled signer retains the slot, buffers and original dependency references
// until it actually returns. Close cancels the job without freeing its backing.
type NamespacePublisher struct {
	mu                                      sync.Mutex
	c                                       NamespacePublisherConfig
	rules                                   *NamespaceRules
	scope                                   NamespacePublicationScope
	codec                                   *SignedMapCodec
	decoder                                 *Decoder
	workspace                               *RevocationWorkspace
	input                                   []byte
	reservation, dependencies, trust, store resourcev4.Reference
	busy, closed, cleaned                   bool
	cancel                                  context.CancelFunc
	done                                    chan struct{}
}

func NamespacePublisherCharges(c NamespacePublisherConfig) (owner, state resourcev4.Vector, err error) {
	if c.Clock == nil || c.Trust == nil || c.Store == nil || c.Signer == nil || c.SignerID == ([16]byte{}) || c.Generation == 0 || c.WorkMS == 0 || c.WorkMS > 120000 || c.MinimumValidityMS == 0 || c.RuntimeBytes == 0 {
		return owner, state, resourcev4.ErrConfiguration
	}
	r, err := c.Trust.Rules()
	if err != nil {
		return owner, state, err
	}
	h, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return owner, state, err
	}
	codec, err := SignedMapBackingBytes("FreshnessHead", h, h)
	if err != nil {
		return owner, state, err
	}
	decoder, err := DecoderBackingBytes(int(r.stateBytes), int(r.stateBytes))
	if err != nil {
		return owner, state, err
	}
	head, err := NamespaceHeadBackingBytes()
	if err != nil {
		return owner, state, err
	}
	state, err = r.StateCharge()
	if err != nil {
		return owner, state, err
	}
	owner, err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespacePublisher{})) + r.stateBytes + codec + decoder + head + 4096, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	return
}

func NewNamespacePublisher(c NamespacePublisherConfig, owner, state, dependencies resourcev4.Reference) (_ *NamespacePublisher, err error) {
	cost, _, err := NamespacePublisherCharges(c)
	if err != nil {
		return nil, err
	}
	if err = owner.CheckSameEnvironment(state); err != nil {
		return nil, err
	}
	if err = owner.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	p := &NamespacePublisher{c: c, done: make(chan struct{})}
	defer func() {
		if err != nil {
			p.release()
		}
	}()
	p.reservation, err = owner.Take(cost)
	if err != nil {
		return nil, err
	}
	p.dependencies, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	p.trust, err = c.Trust.ReferenceFor(c.Clock, p.reservation)
	if err != nil {
		return nil, err
	}
	p.rules, err = c.Trust.Rules()
	if err != nil {
		return nil, err
	}
	p.scope = NamespacePublicationScope{p.rules.tenant, p.rules.authority, p.rules.capacityDigest, c.Generation}
	p.store, err = c.Store.ReferencePublicationStore(p.scope, p.reservation)
	if err != nil {
		return nil, err
	}
	h, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return nil, err
	}
	p.codec, err = NewSignedMapCodec("FreshnessHead", h, h)
	if err != nil {
		return nil, err
	}
	p.decoder, err = NewDecoder(int(p.rules.stateBytes), int(p.rules.stateBytes))
	if err != nil {
		return nil, err
	}
	p.workspace, err = NewRevocationWorkspace(p.rules, state)
	if err != nil {
		return nil, err
	}
	p.input = make([]byte, int(p.rules.stateBytes))
	return p, nil
}

// Publish samples trusted time before the actual authority read. The signed
// timestamp never moves to the end of encoding/signing, including when ordinary
// revocations commit during that work. Only committed metadata escapes.
func (p *NamespacePublisher) Publish(ctx context.Context) (out NamespacePublicationVersion, err error) {
	if p == nil || ctx == nil {
		return out, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed || p.busy {
		p.mu.Unlock()
		return out, CBORFailure("revocation_publication_owner")
	}
	if err = p.reservation.Check(); err != nil {
		p.mu.Unlock()
		return out, err
	}
	work, cancel := context.WithTimeout(ctx, time.Duration(p.c.WorkMS)*time.Millisecond)
	p.busy, p.cancel = true, cancel
	p.mu.Unlock()
	defer func() {
		cancel()
		clear(p.input)
		p.mu.Lock()
		p.busy, p.cancel = false, nil
		if p.closed {
			p.release()
		}
		p.mu.Unlock()
	}()
	window, err := timev4.NewWindow(p.c.Clock, p.c.WorkMS)
	if err != nil {
		return out, err
	}
	defer window.Cancel()
	guard := func() error {
		if err := work.Err(); err != nil {
			return err
		}
		if err := p.reservation.Check(); err != nil {
			return err
		}
		if err := p.dependencies.Check(); err != nil {
			return err
		}
		if err := p.store.Check(); err != nil {
			return err
		}
		return window.Check()
	}
	if err = guard(); err != nil {
		return out, err
	}
	delegation, key, trustIssued, trustEnd, err := p.delegation()
	if err != nil {
		return out, err
	}
	defer clear(delegation)
	before, err := p.c.Clock.Sample()
	if err != nil {
		return out, err
	}
	snapshot, err := p.c.Store.ReadPublicationSnapshot(work, p.input)
	if snapshot.Owner != 0 {
		defer p.c.Store.ReleasePublicationSnapshot(snapshot)
	}
	if err != nil {
		return out, err
	}
	if snapshot.Owner == 0 || snapshot.Version == 0 || snapshot.Previous.Sequence == math.MaxUint64 || snapshot.Version < snapshot.Previous.Snapshot || snapshot.StateBytes == 0 || snapshot.StateBytes > uint64(len(p.input)) {
		return out, CBORFailure("revocation_publication_snapshot")
	}
	wire := p.input[:int(snapshot.StateBytes)]
	doc, err := p.decoder.DecodeMap(wire, "RevocationState", DecodeContext{Limits: p.rules.limits})
	if err != nil {
		return out, err
	}
	defer doc.Release()
	root := doc.Root()
	if !p.rules.matchesNamespace(root, "RevocationState") || !p.rules.matchesPublication(root, "RevocationState") || valueUint(root, "RevocationState", "authority_generation") != p.scope.Generation {
		return out, CBORFailure("revocation_namespace_binding")
	}
	digest, err := fullMapDigest("revocation_state_digest", "RevocationState", doc.Bytes())
	if err != nil {
		return out, err
	}
	if snapshot.Version == snapshot.Previous.Snapshot && digest != snapshot.Previous.StateDigest || before.Interval.LowerMS < snapshot.Previous.ThisUpdateMS {
		return out, CBORFailure("revocation_publication_rollback")
	}
	next, err := namespaceAdd(before.Interval.LowerMS, p.rules.headValidity)
	if err != nil {
		return out, err
	}
	delegationDoc, err := boundedMap(delegation, "HeadSignerDelegation")
	if err != nil {
		return out, err
	}
	entry := delegationDoc.Root()
	issued := valueUint(entry, "HeadSignerDelegation", "issued_at_ms")
	notBefore := valueUint(entry, "HeadSignerDelegation", "not_before_ms")
	notAfter := valueUint(entry, "HeadSignerDelegation", "not_after_ms")
	lifetimeEnd, lifetimeErr := namespaceAdd(issued, p.rules.signerLife)
	next = min(next, trustEnd, notAfter)
	delegationDoc.Release()
	if lifetimeErr != nil || notBefore > issued || issued >= notAfter || notAfter > lifetimeEnd || before.Interval.LowerMS < max(issued, trustIssued) {
		return out, CBORFailure("revocation_delegation_lifetime")
	}
	delegationDigest, err := fullMapDigest("head_signer_delegation_digest", "HeadSignerDelegation", delegation)
	if err != nil {
		return out, err
	}
	binding := NamespaceHeadTrust{Tenant: p.scope.Tenant, Authority: p.scope.Authority, Capacity: p.scope.Capacity, Generation: p.scope.Generation, Signer: p.c.SignerID, Delegation: delegationDigest, TrustIssuedMS: trustIssued, TrustNotAfterMS: trustEnd}
	publicationGuard := func() error {
		if err := guard(); err != nil {
			return err
		}
		if err := p.c.Trust.Head(binding); err != nil {
			return err
		}
		now, err := p.c.Clock.Sample()
		if err != nil {
			return err
		}
		if !now.Interval.ValidBefore(next) || p.c.MinimumValidityMS > next-now.Interval.UpperMS {
			return timev4.ErrExpired
		}
		return now.Interval.LowerBound(before.Interval.LowerMS, true)
	}
	fields := publicationHeadFields(root, snapshot.Previous.Sequence+1, before.Interval.LowerMS, next, digest, uint64(len(wire)), p.c.SignerID, delegationDigest)
	signed, err := p.codec.SignWith(fields[:], key, p.c.Signer, DecodeContext{}, publicationGuard)
	if err != nil {
		return out, err
	}
	defer signed.Release()
	head, err := p.rules.BindHead(signed, delegation, p.scope.Generation, trustIssued, trustEnd)
	if err != nil {
		return out, err
	}
	now, err := p.c.Clock.Sample()
	if err != nil {
		return out, err
	}
	if err = head.CheckTime(now.Interval); err != nil {
		return out, err
	}
	state, err := p.workspace.Bind(head, wire)
	if err != nil {
		return out, err
	}
	defer state.Release()
	if err = p.c.Trust.StateHistory(state); err != nil {
		return out, err
	}
	version := NamespacePublicationVersion{snapshot.Version, head.sequence, digest, head.digest, head.issued, head.next}
	commitGate := func(commit func() error) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.closed {
			return CBORFailure("revocation_publication_owner")
		}
		if err := work.Err(); err != nil {
			return err
		}
		return commit()
	}
	if err = p.c.Store.CommitNamespacePublication(work, snapshot, version, wire, head.bytes, publicationGuard, commitGate); err != nil {
		return out, err
	}
	return version, nil
}

func publicationHeadFields(state Value, sequence, issued, next uint64, digest [32]byte, size uint64, signer [16]byte, delegation [32]byte) [15]Field {
	var fields [15]Field
	for i, name := range []string{"schema_revision", "tenant_id", "revocation_authority_id", "namespace_capacity_digest", "authority_generation", "credential_revocation_floors", "publication_policy_id", "publication_policy_revision"} {
		value := state.Named("RevocationState", name)
		fields[i].Name = name
		switch i {
		case 0, 1, 2, 6:
			fields[i].Kind = TextString
			fields[i].Text, _ = value.Text()
		case 3:
			fields[i].Kind = ByteString
			fields[i].Bytes, _ = value.ByteString()
		case 5:
			fields[i].Kind = EncodedArray
			fields[i].Bytes = value.Encoded()
		default:
			fields[i].Number, _ = value.Uint()
		}
	}
	fields[8] = Field{Name: "head_sequence", Number: sequence}
	fields[9] = Field{Name: "this_update_ms", Number: issued}
	fields[10] = Field{Name: "next_update_ms", Number: next}
	fields[11] = Field{Name: "state_digest", Kind: ByteString, Bytes: digest[:]}
	fields[12] = Field{Name: "state_encoded_bytes", Number: size}
	fields[13] = Field{Name: "signing_key_id", Kind: ByteString, Bytes: signer[:]}
	fields[14] = Field{Name: "signer_delegation_digest", Kind: ByteString, Bytes: delegation[:]}
	return fields
}

func (p *NamespacePublisher) delegation() ([]byte, [32]byte, uint64, uint64, error) {
	t := p.c.Trust
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return nil, [32]byte{}, 0, 0, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLockedAt(sample); err != nil {
		return nil, [32]byte{}, 0, 0, err
	}
	c := &t.configurations[t.count-1]
	if c.generation != p.scope.Generation || includesTrustID(c.rejectedHeads, p.c.SignerID) {
		return nil, [32]byte{}, 0, 0, CBORFailure("revocation_trust_binding")
	}
	for i, h := range c.heads {
		if h.signer == p.c.SignerID {
			v := c.signed.Field("head_delegations").Index(i)
			if trust32(v, "HeadSignerDelegation", "signer_public_key") == t.root.PublicKey {
				return nil, [32]byte{}, 0, 0, CBORFailure("revocation_signer_key")
			}
			return bytes.Clone(v.Encoded()), trust32(v, "HeadSignerDelegation", "signer_public_key"), c.issued, c.end, nil
		}
	}
	return nil, [32]byte{}, 0, 0, CBORFailure("revocation_trust_binding")
}

func (p *NamespacePublisher) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	if !p.busy {
		p.release()
	}
}

func (p *NamespacePublisher) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *NamespacePublisher) release() {
	if p.cleaned {
		return
	}
	clear(p.input)
	p.input = nil
	if p.workspace != nil {
		_ = p.workspace.Close()
		p.workspace = nil
	}
	p.codec, p.decoder = nil, nil
	p.store.Release()
	p.trust.Release()
	p.dependencies.Release()
	p.reservation.Release()
	p.c = NamespacePublisherConfig{}
	p.rules = nil
	p.scope = NamespacePublicationScope{}
	p.cleaned = true
	close(p.done)
}
