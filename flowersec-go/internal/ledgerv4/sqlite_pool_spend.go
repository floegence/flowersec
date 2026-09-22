package ledgerv4

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// SQLitePoolAuthority is the immutable trusted mapping from parent issuer and
// tenant to this complete local consumer history. It must not do I/O or choose
// another store from fields supplied by a peer.
type SQLitePoolAuthority interface {
	CheckPoolSpend(SQLiteIdentity, protocolv4.PoolSpendFacts) error
}

// PoolSpendOwner belongs to the original local Connect and its selected
// PreparedCarrier incarnation. It is never restored from durable history.
type PoolSpendOwner struct {
	Connect, Carrier [16]byte
	Generation       uint64
}

func (o PoolSpendOwner) valid() bool {
	return o.Connect != ([16]byte{}) && o.Carrier != ([16]byte{}) && o.Generation != 0
}

// SQLitePoolSpend owns one absent->consumed transaction and no confirmation
// reader. An uncertain commit permanently ends this object's dispatch right.
// Even a later definite row cannot restore that right or activate a carrier.
type SQLitePoolSpend struct{ *sqlitePoolSpend }
type sqlitePoolSpend struct {
	mu                                sync.Mutex
	ctx                               context.Context
	store                             *sqliteStore
	deadline                          *timev4.Deadline
	guard                             func() error
	reservation, storeReference       resourcev4.Reference
	key                               [admissionKeyBytes]byte
	keySize, projectionSize           int
	projection                        []byte
	fence                             uint64
	started, running, closed, cleaned bool
}

func SQLitePoolSpendCharge(maxRecordBytes uint32) (resourcev4.Vector, error) {
	if maxRecordBytes < 1024 || maxRecordBytes > 1<<20 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return resourcev4.Vector{
		resourcev4.SDKBytes: uint64(maxRecordBytes) + uint64(unsafe.Sizeof(SQLitePoolSpend{})) + uint64(unsafe.Sizeof(sqlitePoolSpend{})) + uint64(unsafe.Sizeof(timev4.Deadline{})),
		resourcev4.Items:    1, resourcev4.WorkSlots: 1,
	}, nil
}

func NewSQLitePoolSpend(ctx context.Context, store *SQLiteStore, authority SQLitePoolAuthority, facts protocolv4.PoolSpendFacts, proof []byte, owner PoolSpendOwner, clock *timev4.Clock, deadline *timev4.Deadline, guard func() error, reservation, environment resourcev4.Reference) (_ *SQLitePoolSpend, err error) {
	if ctx == nil || authority == nil || !owner.valid() || guard == nil || !deadline.BelongsTo(clock) {
		return nil, ErrConfiguration
	}
	f, err := facts.Fields()
	if err != nil {
		return nil, err
	}
	if err = facts.MatchProofBytes(proof); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	ref, identity, epoch, limit, err := store.admissionReference(environment)
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			ref.Release()
		}
	}()
	charge, err := SQLitePoolSpendCharge(limit)
	if err != nil {
		return nil, err
	}
	held, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			held.Release()
		}
	}()
	if err = authority.CheckPoolSpend(identity, facts); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = guard(); err != nil {
		return nil, err
	}
	deadline, err = deadline.Fork(min(deadline.Cap(), f.ActivationEnd))
	if err != nil {
		return nil, err
	}
	now, err := deadline.Sample()
	if err != nil {
		return nil, err
	}
	if err = now.LowerBound(f.IssuedAt, true); err != nil {
		return nil, err
	}
	p := &sqlitePoolSpend{ctx: ctx, store: store.sqliteStore, deadline: deadline, guard: guard,
		reservation: held, storeReference: ref, projection: make([]byte, limit), fence: epoch}
	// The unique key is exactly tenant + parent Artifact issuer + lease. It
	// excludes attempt, candidate, source, consumer and PreparedCarrier IDs.
	key := admissionRecord{fields: protocolv4.AdmissionFields{Tenant: f.Tenant, Issuer: f.Issuer, Lease: f.Lease}}
	p.keySize, err = key.key(p.key[:])
	if err != nil {
		return nil, err
	}
	w := admissionWriter{dst: p.projection}
	w.text("flowersec/pool-consume/1")
	for _, n := range []uint64{1, epoch, identity.Generation, owner.Generation, deadline.Cap(), now.UpperMS, f.IssuedAt, f.ActivationEnd, f.SessionEnd, f.Winner.Index,
		f.Budget.CandidateAddressAttempts, f.Budget.CandidatePreauthBytes, f.Budget.CandidateWorkUnits, f.Budget.TotalAddressAttempts, f.Budget.TotalPreauthBytes, f.Budget.TotalWorkUnits, f.Budget.ParallelCandidates} {
		w.uint(n)
	}
	for _, s := range []string{identity.Authority, f.Tenant, f.Audience, f.Profile, f.SpendAuthority, f.WinnerAuthority, f.SigningKey} {
		w.text(s)
	}
	for _, b := range [][]byte{identity.StoreID[:], owner.Connect[:], owner.Carrier[:], f.Issuer[:], f.Lease[:], f.Attempt[:], f.Winner.CandidateID[:], f.Winner.RouteDigest[:], f.Artifact[:], f.Proof[:], f.SessionNonce[:], f.ClientIdentity[:], f.ServerIdentity[:], f.CandidateSet[:], f.RouteSet[:]} {
		w.bytes(b)
	}
	// The full original proof includes the real PoolSelectionRef and issuance
	// signature. No raw Artifact/PSK, fake callback intent or TxB is persisted.
	w.uint(uint64(len(proof)))
	w.bytes(proof)
	if w.err != nil {
		clear(p.projection)
		return nil, w.err
	}
	p.projectionSize = w.n
	adopted = true
	return &SQLitePoolSpend{p}, nil
}

func (p *sqlitePoolSpend) check() error {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return ErrOwner
	}
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if err := p.deadline.Check(); err != nil {
		return err
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.storeReference.Check(); err != nil {
		return err
	}
	return p.guard()
}

// Consume dispatches the original local continuation only on a definite
// durable COMMIT and a still-live original owner. There is one write attempt,
// no callback authorization, TxB, confirmation read or source fallback.
func (p *SQLitePoolSpend) Consume(action func() error) (err error) {
	if p == nil || p.sqlitePoolSpend == nil || action == nil {
		return ErrConfiguration
	}
	p.mu.Lock()
	if p.closed || p.started {
		p.mu.Unlock()
		return ErrOwner
	}
	p.started, p.running = true, true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
		if err != nil {
			p.Close(err)
		}
	}()
	if err = p.check(); err != nil {
		return err
	}
	s := p.store
	if err = s.begin(p.ctx); err != nil {
		return err
	}
	defer s.end()
	if s.epoch != p.fence {
		return ErrFenced
	}
	err = s.writeTransaction(p.ctx, p.check, func() error {
		present, err := s.scalar("SELECT count(*) FROM spend WHERE lease=?1", named(1, p.key[:p.keySize]))
		if err != nil {
			return err
		}
		if present != int64(0) {
			return ErrConflict
		}
		value, err := s.scalar("SELECT admission_rows+spend_rows FROM manifest WHERE id=1")
		if err != nil {
			return err
		}
		count, ok := value.(int64)
		if !ok || count < 0 {
			return ErrStorageFormat
		}
		if count >= int64(s.backing.limits.MaxRecords) {
			return ErrCapacity
		}
		if err = s.exec("INSERT INTO spend VALUES (?1,1,1,?2,?3,?4)", named(1, p.key[:p.keySize]), named(2, sqliteUint(1)), named(3, sqliteUint(p.fence)), named(4, p.projection[:p.projectionSize])); err != nil {
			return err
		}
		return s.exec("UPDATE manifest SET spend_rows=spend_rows+1 WHERE id=1")
	})
	if err != nil {
		return err
	}
	if err = p.check(); err != nil {
		return err
	}
	return action()
}

func (p *SQLitePoolSpend) Close(_ error) {
	if p == nil || p.sqlitePoolSpend == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	p.reservation.Seal()
	p.mu.Unlock()
}

// Cleanup retains the actual synchronous provider call and original action
// through their return. Cancellation alone never refunds either owner.
func (p *SQLitePoolSpend) Cleanup() error {
	if p == nil || p.sqlitePoolSpend == nil {
		return ErrConfiguration
	}
	p.Close(ErrOwner)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cleaned {
		return nil
	}
	if p.running {
		return ErrCapacity
	}
	clear(p.projection)
	clear(p.key[:])
	p.projection, p.guard, p.ctx, p.deadline, p.store = nil, nil, nil, nil, nil
	p.storeReference.Release()
	p.reservation.Release()
	p.cleaned = true
	return nil
}
