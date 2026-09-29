package ledgerv4

import (
	"context"
	"crypto/rand"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// SQLiteLiveRelayPublicationConfig is trusted in-process distribution. Table
// belongs to the independently configured winner authority; SourceIdentity is
// the original live TxA/TxB store, never an identity reported by a peer.
type SQLiteLiveRelayPublicationConfig struct {
	Table                     *SQLiteRelayAuthorityTable
	SourceIdentity            SQLiteIdentity
	Mapping                   protocolv4.RelayIssuerMapping
	Parent                    protocolv4.CredentialValidation
	Reservation, Dependencies resourcev4.Reference
}

// SQLiteLiveRelayPublication owns one pre-TxA table position and durable row
// reservation. Only the original confirmed TxB may fill it. Reads, restarts and
// public receipts cannot reconstruct this owner or trigger endpoint publication.
type SQLiteLiveRelayPublication struct {
	mu                      sync.Mutex
	table                   *SQLiteRelayAuthorityTable
	plan                    *protocolv4.LiveActivationPlan
	source                  *sqliteStore
	original                *sqliteLiveSpend
	identity                SQLiteIdentity
	registration            SQLiteRelayParentRegistration
	key                     protocolv4.RelayParentKey
	invocation              [16]byte
	receipts                [2]SQLiteCommittedRelayLeg
	reservation, shared     resourcev4.Reference
	started, active, closed bool
	reserved, published     bool
	cleaning, cleaned       bool
	cleanupErr              error
}

func SQLiteLiveRelayPublicationCharge() (resourcev4.Vector, error) {
	evidence, err := protocolv4.LiveRelayProjectionBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteLiveRelayPublication{})) + evidence + 8192,
		resourcev4.Items: 3, resourcev4.WorkSlots: 1, resourcev4.Timers: 1}, nil
}

func NewSQLiteLiveRelayPublication(ctx context.Context, source *SQLiteStore, plan *protocolv4.LiveActivationPlan, c SQLiteLiveRelayPublicationConfig) (_ *SQLiteLiveRelayPublication, err error) {
	if ctx == nil || c.Table == nil || plan == nil || !validSQLiteIdentity(c.SourceIdentity) {
		return nil, ErrConfiguration
	}
	if err = c.Reservation.CheckSameEnvironment(c.Dependencies); err != nil {
		return nil, err
	}
	if err = plan.CheckEnvironment(c.Reservation); err != nil {
		return nil, err
	}
	ref, identity, _, _, err := source.admissionReference(c.Dependencies)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	if identity != c.SourceIdentity {
		return nil, ErrOwner
	}
	key, err := plan.RelayRegistrationBinding(c.Mapping, c.Parent)
	if err != nil {
		return nil, err
	}
	if c.Mapping.Activation.SpendAuthority != identity.Authority {
		return nil, ErrOwner
	}
	charge, err := SQLiteLiveRelayPublicationCharge()
	if err != nil {
		return nil, err
	}
	owned, err := c.Reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &SQLiteLiveRelayPublication{table: c.Table, plan: plan, source: source.sqliteStore, identity: identity, key: key, reservation: owned}
	adopted := false
	defer func() {
		if !adopted {
			_ = p.Close()
		}
	}()
	p.shared, err = c.Dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	p.identity.Authority, p.key.Tenant = strings.Clone(identity.Authority), strings.Clone(key.Tenant)
	p.registration = SQLiteRelayParentRegistration{IssuanceIdentity: [2]SQLiteIdentity{p.identity, p.identity}, Mapping: cloneRelayIssuerMapping(c.Mapping), Parent: c.Parent}
	p.registration.Parent.Issuer.Schema = strings.Clone(p.registration.Parent.Issuer.Schema)
	for side := range p.receipts {
		r := &p.receipts[side]
		r.identity, r.role = p.identity, protocolv4.Direction(side)
		r.reservation, err = owned.Borrow()
		if err != nil {
			return nil, err
		}
		r.shared, err = c.Dependencies.Borrow()
		if err != nil {
			return nil, err
		}
		p.registration.Committed[side] = r
	}
	if _, err = rand.Read(p.invocation[:]); err != nil {
		return nil, err
	}
	if p.invocation == ([16]byte{}) {
		return nil, ErrConfiguration
	}
	if err = p.table.reservePublication(p); err != nil {
		return nil, err
	}
	p.reserved = true
	if err = p.table.store.reserveRelayRegistration(ctx, p.key, p.registration.IssuanceIdentity, p.invocation, p.Check); err != nil {
		return nil, err
	}
	if err = p.Check(); err != nil {
		return nil, err
	}
	adopted = true
	return p, nil
}

func (p *SQLiteLiveRelayPublication) Check() error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrOwner
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
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

// publish is called by SQLiteLiveSpend inside its sole original TxB dispatch.
// Neither arbitrary caller bytes nor readback may supply committed provenance.
func (p *SQLiteLiveRelayPublication) publish(ctx context.Context, original *sqliteLiveSpend) (err error) {
	if p == nil || ctx == nil || original == nil {
		return ErrConfiguration
	}
	p.mu.Lock()
	if p.closed || p.started || original.plan != p.plan || original.store != p.source || p.original != original || !original.tunnel {
		p.mu.Unlock()
		return ErrOwner
	}
	p.started, p.active = true, true
	p.original = original
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active = false
		p.mu.Unlock()
	}()
	if err = p.Check(); err != nil {
		return err
	}
	if err = original.check(); err != nil {
		return err
	}
	material := [3][]byte{original.proof[:original.proofSize], original.grants[0][:original.grantSizes[0]], original.grants[1][:original.grantSizes[1]]}
	projection, err := p.plan.DetachRelayMaterial(material)
	if err != nil {
		return err
	}
	key, err := projection.Key()
	if err != nil || key != p.key {
		return ErrConflict
	}
	for side := range p.receipts {
		p.receipts[side].mu.Lock()
		p.receipts[side].projection = projection
		p.receipts[side].mu.Unlock()
	}
	if err = p.table.install(ctx, p.registration, p); err != nil {
		return err
	}
	p.mu.Lock()
	p.published = true
	p.mu.Unlock()
	if err = original.check(); err != nil {
		return err
	}
	return p.Check()
}

func (p *SQLiteLiveRelayPublication) checkCommit() error {
	if err := p.Check(); err != nil {
		return err
	}
	p.mu.Lock()
	original, active := p.original, p.active
	p.mu.Unlock()
	if original == nil || !active {
		return ErrOwner
	}
	return original.check()
}

func (p *SQLiteLiveRelayPublication) invocationID() [16]byte { return p.invocation }
func (p *SQLiteLiveRelayPublication) hasReservation(key protocolv4.RelayParentKey) bool {
	return p.key == key
}

func (p *SQLiteLiveRelayPublication) Close() error {
	if p == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return p.CloseContext(ctx)
}

// CloseContext first revokes publication, then attempts bounded reclamation of
// its exact unused row. Cancellation cannot erase complete original issuance.
// The table position and references stay held until actual cleanup returns.
func (p *SQLiteLiveRelayPublication) CloseContext(ctx context.Context) error {
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
	table, reserved := p.table, p.reserved && !p.published
	p.mu.Unlock()
	var err error
	if reserved {
		err = table.store.releaseRelayReservation(ctx, p.key, p.registration.IssuanceIdentity, p.invocation)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for side := range p.receipts {
		p.receipts[side].Close()
	}
	if p.table != nil {
		p.table.releasePublication(p)
	}
	p.registration = SQLiteRelayParentRegistration{}
	p.plan, p.source, p.original, p.table = nil, nil, nil, nil
	p.shared.Release()
	p.reservation.Release()
	p.shared, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaning, p.cleaned, p.cleanupErr = false, true, err
	return err
}

func (a *SQLiteRelayAuthorityTable) reservePublication(p *SQLiteLiveRelayPublication) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrOwner
	}
	if a.installing || a.publication != nil || len(a.entries) == cap(a.entries) {
		return ErrCapacity
	}
	if _, exists := a.index[p.key]; exists {
		return ErrConflict
	}
	if p.registration.Mapping.Activation.WinnerAuthority != a.identity.Authority || a.store == nil || a.maxRecordBytes < protocolv4.RelayParentRecordMaxBytes {
		return ErrConfiguration
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

func (a *SQLiteRelayAuthorityTable) releasePublication(p sqliteRelayPublication) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.publication == p {
		a.publication, a.installing = nil, false
		a.cleanupLocked()
	}
}

func (*SQLiteLiveRelayPublication) String() string               { return "Flowersec.LiveRelayPublication" }
func (*SQLiteLiveRelayPublication) GoString() string             { return "Flowersec.LiveRelayPublication" }
func (*SQLiteLiveRelayPublication) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
