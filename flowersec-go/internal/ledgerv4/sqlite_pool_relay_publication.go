package ledgerv4

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// SQLitePoolRelayParent identifies one candidate in an original complete pool
// issuance. Both public leg Grants must occur in that artifact's material set.
// Separately issued endpoint outboxes use CaptureRelayLeg and Install instead.
type SQLitePoolRelayParent struct {
	ArtifactSequence uint64
	Projection       *protocolv4.RelayParentProjection
	Mapping          protocolv4.RelayIssuerMapping
	Parent           protocolv4.CredentialValidation
}

type SQLitePoolRelayPublicationConfig struct {
	Table          *SQLiteRelayAuthorityTable
	SourceIdentity SQLiteIdentity
	Parents        []SQLitePoolRelayParent
}

type sqlitePoolRelayEntry struct {
	sequence     uint64
	key          protocolv4.RelayParentKey
	projection   *protocolv4.RelayParentProjection
	registration SQLiteRelayParentRegistration
	receipts     [2]SQLiteCommittedRelayLeg
	reserved     bool
}

// SQLitePoolRelayPublication retains bounded public registration work before
// the pool outbox commit. It has no signing, server-allow or activation right.
// A replay may register the same retained original outbox, but cannot recreate
// any endpoint publication owner or material that has already been retired.
type SQLitePoolRelayPublication struct {
	mu                            sync.Mutex
	table                         *SQLiteRelayAuthorityTable
	source                        *SQLiteTopUpServer
	identity                      SQLiteIdentity
	request                       protocolv4.TopUpRequestFacts
	facts                         protocolv4.TopUpResponseFacts
	wireDigest                    [32]byte
	invocation                    [16]byte
	entries                       []sqlitePoolRelayEntry
	reservation, shared, storeRef resourcev4.Reference
	ctx                           context.Context
	access                        TopUpAccess
	started, active, closed       bool
	cleaning, cleaned, held       bool
	cleanupErr                    error
}

func SQLitePoolRelayPublicationCharge(c SQLitePoolRelayPublicationConfig) (resourcev4.Vector, error) {
	if c.Table == nil || !validSQLiteIdentity(c.SourceIdentity) || len(c.Parents) < 1 || len(c.Parents) > 64 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	projection, err := protocolv4.RelayParentProjectionBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	decoder, err := protocolv4.DecoderBackingBytes(65536, 166)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	count := uint64(len(c.Parents))
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLitePoolRelayPublication{})) + count*(projection+uint64(unsafe.Sizeof(sqlitePoolRelayEntry{}))+8192) + codec + decoder + 8192,
		resourcev4.Items: 1 + 3*count, resourcev4.WorkSlots: 1, resourcev4.Timers: 1}, nil
}

func NewSQLitePoolRelayPublication(ctx context.Context, source *SQLiteTopUpServer, original TopUpServerSnapshot, response []byte, c SQLitePoolRelayPublicationConfig, reservation, dependencies resourcev4.Reference) (_ *SQLitePoolRelayPublication, err error) {
	charge, err := SQLitePoolRelayPublicationCharge(c)
	if err != nil {
		return nil, err
	}
	if ctx == nil || source == nil || source.store == nil || original.State != TopUpServerPending && original.State != TopUpServerCommitted {
		return nil, ErrConfiguration
	}
	if err = source.CheckSourceBinding(original.Request.Tenant, original.Request.Source); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	storeRef, identity, _, _, err := source.store.admissionReference(dependencies)
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			storeRef.Release()
		}
	}()
	if identity != c.SourceIdentity {
		return nil, ErrOwner
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &SQLitePoolRelayPublication{table: c.Table, source: source, identity: identity, request: original.Request,
		wireDigest: sha256.Sum256(response), entries: make([]sqlitePoolRelayEntry, len(c.Parents)), reservation: owned, storeRef: storeRef}
	defer func() {
		if !adopted {
			_ = p.Close()
		}
	}()
	p.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	p.identity.Authority, p.request.Tenant = strings.Clone(identity.Authority), strings.Clone(p.request.Tenant)
	codec, err := protocolv4.NewTopUpCodec()
	if err != nil {
		return nil, err
	}
	batch, err := codec.ParseResponse(response, original.Request)
	if err != nil {
		return nil, err
	}
	defer batch.Release()
	p.facts, err = batch.Facts()
	if err != nil {
		return nil, err
	}
	p.facts.Tenant = strings.Clone(p.facts.Tenant)
	if original.State == TopUpServerCommitted && original.Response != p.facts {
		return nil, ErrConflict
	}
	decoder, err := protocolv4.NewDecoder(65536, 166)
	if err != nil {
		return nil, err
	}
	matched := 0
	for i, entry := range p.facts.Entries[:p.facts.Count] {
		wire, err := batch.Material(uint32(i))
		if err != nil {
			return nil, err
		}
		doc, err := decoder.DecodeShape(wire, "", protocolv4.DecodeContext{})
		if err != nil {
			return nil, err
		}
		count, err := protocolv4.CompletePoolRelayParentCount(doc)
		if err == nil {
			found := 0
			for index, input := range c.Parents {
				if input.ArtifactSequence != entry.Sequence {
					continue
				}
				found++
				err = p.prepareEntry(index, input, doc, dependencies)
				if err != nil {
					break
				}
			}
			if err == nil && found != count {
				err = ErrConfiguration
			}
			matched += found
		}
		doc.Release()
		if err != nil {
			return nil, err
		}
	}
	if matched != len(c.Parents) {
		return nil, ErrConfiguration
	}
	if _, err = rand.Read(p.invocation[:]); err != nil {
		return nil, err
	}
	if p.invocation == ([16]byte{}) {
		return nil, ErrConfiguration
	}
	if err = p.table.reservePoolPublication(p); err != nil {
		return nil, err
	}
	p.held = true
	for i := range p.entries {
		entry := &p.entries[i]
		n, err := entry.projection.CopyPublicRecord(p.table.wire)
		if err != nil {
			return nil, err
		}
		// Mark before I/O: an uncertain reservation may still need cleanup.
		entry.reserved = true
		entry.reserved, err = p.table.store.reservePoolRelayRegistration(ctx, entry.key, entry.registration.IssuanceIdentity, p.invocation, p.table.wire[:n], p.table.original, p.Check)
		clear(p.table.wire)
		clear(p.table.original)
		if err != nil {
			entry.reserved = true
			return nil, err
		}
	}
	if err = p.Check(); err != nil {
		return nil, err
	}
	adopted = true
	return p, nil
}

func (p *SQLitePoolRelayPublication) prepareEntry(index int, input SQLitePoolRelayParent, doc *protocolv4.Document, dependencies resourcev4.Reference) error {
	if input.Projection == nil || input.ArtifactSequence == 0 {
		return ErrConfiguration
	}
	if err := input.Projection.MatchMapping(input.Mapping); err != nil {
		return err
	}
	if err := input.Projection.CheckCurrent(input.Parent, p.reservation); err != nil {
		return err
	}
	if err := input.Projection.MatchIssuedPoolMaterial(doc, protocolv4.ServerToClient); err != nil {
		return err
	}
	projection, err := input.Projection.CloneIssuedPoolMaterial(doc, protocolv4.ClientToServer)
	if err != nil {
		return err
	}
	key, err := projection.Key()
	if err != nil {
		return err
	}
	for i := range p.entries {
		if p.entries[i].projection != nil && p.entries[i].key == key {
			return ErrConflict
		}
	}
	e := &p.entries[index]
	e.sequence, e.key, e.projection = input.ArtifactSequence, key, projection
	e.registration = SQLiteRelayParentRegistration{IssuanceIdentity: [2]SQLiteIdentity{p.identity, p.identity}, Mapping: cloneRelayIssuerMapping(input.Mapping), Parent: input.Parent}
	e.registration.Parent.Issuer.Schema = strings.Clone(e.registration.Parent.Issuer.Schema)
	for side := range e.receipts {
		r := &e.receipts[side]
		r.identity, r.role = p.identity, protocolv4.Direction(side)
		r.reservation, err = p.reservation.Borrow()
		if err != nil {
			return err
		}
		r.shared, err = dependencies.Borrow()
		if err != nil {
			return err
		}
		e.registration.Committed[side] = r
	}
	return nil
}

func (p *SQLitePoolRelayPublication) Check() error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrOwner
	}
	for _, ref := range []resourcev4.Reference{p.reservation, p.shared, p.storeRef} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	p.table.mu.Lock()
	defer p.table.mu.Unlock()
	if p.table.closed || p.table.publication != p || !p.table.installing {
		return ErrOwner
	}
	for _, ref := range []resourcev4.Reference{p.table.reservation, p.table.shared, p.table.storeRef} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (p *SQLitePoolRelayPublication) begin(ctx context.Context, source *SQLiteTopUpServer, access TopUpAccess, response []byte) error {
	if p == nil || ctx == nil {
		return ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.started || source != nil && p.source != source || p.wireDigest != sha256.Sum256(response) {
		return ErrOwner
	}
	p.started, p.active, p.ctx, p.access = true, true, ctx, access
	return nil
}

func (p *SQLitePoolRelayPublication) finish() {
	p.mu.Lock()
	p.active, p.ctx, p.access = false, nil, nil
	p.mu.Unlock()
}

// PublishCommitted registers only an exact complete durable outbox. This may
// repair public distribution of an original pool batch, never endpoint once
// rights. The admitted owner is single-use even when publication fails.
func (p *SQLitePoolRelayPublication) PublishCommitted(ctx context.Context, access TopUpAccess, response []byte) error {
	if p == nil {
		return ErrConfiguration
	}
	if err := p.begin(ctx, nil, access, response); err != nil {
		return err
	}
	defer p.finish()
	return p.publish()
}

func (p *SQLitePoolRelayPublication) publish() error {
	if err := p.checkCommit(); err != nil {
		return err
	}
	j := p.source
	// The source method position pins its actual outbox through complete
	// comparison. Source and relay are separate fenced transaction domains.
	if err := j.store.begin(p.ctx); err != nil {
		return err
	}
	err := func() error {
		defer j.store.end()
		defer clear(j.wire)
		if err := j.store.checkFence(); err != nil {
			return err
		}
		s, err := j.readState()
		if err != nil {
			return err
		}
		if s.State != TopUpServerCommitted || s.Permanent || s.Request != p.request || s.Response != p.facts {
			return ErrRelayHistoryUnknown
		}
		fence, err := j.fence()
		if err != nil {
			return err
		}
		if fence.Permanent {
			return ErrFenced
		}
		n, err := j.readWire()
		if err != nil {
			return err
		}
		if sha256.Sum256(j.wire[:n]) != p.wireDigest {
			return ErrConflict
		}
		return p.checkCommit()
	}()
	if err != nil {
		return err
	}
	for i := range p.entries {
		e := &p.entries[i]
		for side := range e.receipts {
			e.receipts[side].mu.Lock()
			e.receipts[side].projection = e.projection
			e.receipts[side].mu.Unlock()
		}
		if err := p.table.install(p.ctx, e.registration, p); err != nil {
			return err
		}
		// Ready registrations remain independently retained after Close.
		e.reserved = false
	}
	return p.checkCommit()
}

func (p *SQLitePoolRelayPublication) checkCommit() error {
	if err := p.Check(); err != nil {
		return err
	}
	p.mu.Lock()
	ctx, access, active := p.ctx, p.access, p.active
	p.mu.Unlock()
	if !active || ctx == nil {
		return ErrOwner
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.source.authorize(access); err != nil {
		return err
	}
	now, err := p.source.config.Clock.Sample()
	if err != nil {
		return err
	}
	for _, entry := range p.facts.Entries[:p.facts.Count] {
		if !now.ValidBefore(entry.ExpiryMS) {
			return ErrOwner
		}
	}
	return nil
}

func (p *SQLitePoolRelayPublication) invocationID() [16]byte { return p.invocation }
func (p *SQLitePoolRelayPublication) hasReservation(key protocolv4.RelayParentKey) bool {
	for i := range p.entries {
		if p.entries[i].key == key {
			return p.entries[i].reserved
		}
	}
	return false
}

func (p *SQLitePoolRelayPublication) Close() error {
	if p == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return p.CloseContext(ctx)
}

func (p *SQLitePoolRelayPublication) CloseContext(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		return ErrConfiguration
	}
	p.mu.Lock()
	p.closed = true
	if p.active || p.cleaning {
		p.mu.Unlock()
		return ErrCapacity
	}
	if p.cleaned {
		err := p.cleanupErr
		p.mu.Unlock()
		return err
	}
	p.cleaning = true
	p.mu.Unlock()
	var cleanupErr error
	for i := range p.entries {
		e := &p.entries[i]
		if e.reserved {
			if err := p.table.store.releaseRelayReservation(ctx, e.key, e.registration.IssuanceIdentity, p.invocation); err != nil && cleanupErr == nil {
				cleanupErr = err
			}
		}
		for side := range e.receipts {
			e.receipts[side].Close()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held {
		p.table.releasePublication(p)
	}
	clear(p.entries)
	p.entries, p.source, p.table = nil, nil, nil
	p.shared.Release()
	p.storeRef.Release()
	p.reservation.Release()
	p.shared, p.storeRef, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaning, p.cleaned, p.cleanupErr = false, true, cleanupErr
	return cleanupErr
}

func (a *SQLiteRelayAuthorityTable) reservePoolPublication(p *SQLitePoolRelayPublication) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrOwner
	}
	if a.installing || a.publication != nil {
		return ErrCapacity
	}
	missing := 0
	for i := range p.entries {
		entry := &p.entries[i]
		if entry.registration.Mapping.Activation.WinnerAuthority != a.identity.Authority {
			return ErrOwner
		}
		if _, exists := a.index[entry.key]; !exists {
			missing++
		}
	}
	if missing > cap(a.entries)-len(a.entries) || a.maxRecordBytes < protocolv4.RelayParentRecordMaxBytes {
		return ErrCapacity
	}
	for _, ref := range []resourcev4.Reference{a.reservation, a.shared, a.storeRef} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	if err := a.reservation.CheckSameEnvironment(p.reservation); err != nil {
		return err
	}
	a.publication, a.installing = p, true
	return nil
}

func cloneRelayIssuerMapping(m protocolv4.RelayIssuerMapping) protocolv4.RelayIssuerMapping {
	for _, s := range []*string{&m.Parent.Tenant, &m.Parent.Authority, &m.Activation.Tenant, &m.Activation.AuthorityNamespace,
		&m.Activation.SigningKeyID, &m.Activation.SpendAuthority, &m.Activation.WinnerAuthority, &m.Service, &m.RelayAudience,
		&m.EndpointAudience, &m.Profile, &m.Grants[0].Namespace.Tenant, &m.Grants[0].Namespace.Authority,
		&m.Grants[1].Namespace.Tenant, &m.Grants[1].Namespace.Authority} {
		*s = strings.Clone(*s)
	}
	return m
}

func (*SQLitePoolRelayPublication) String() string               { return "Flowersec.PoolRelayPublication" }
func (*SQLitePoolRelayPublication) GoString() string             { return "Flowersec.PoolRelayPublication" }
func (*SQLitePoolRelayPublication) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
