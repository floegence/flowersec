package ledgerv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrDenied = errors.New("ledgerv4: authorization denied")

// SQLiteLiveAuthority is the independently configured parent issuer->SpendLedger
// mapping. The service must retain the exact plan, trust and policy dependencies
// behind guard throughout this original authority invocation.
type SQLiteLiveAuthority interface {
	CheckLiveSpend(SQLiteIdentity, protocolv4.LiveActivationFields) error
}

type LiveSpendOwner struct {
	Invocation             [16]byte
	Generation             uint64
	RequestDigest          [32]byte
	ClientMaterialNotAfter uint64
}

// SQLiteLiveSpend owns the authority's original TxA/callback/TxB chain. It
// deliberately provides no constructor from an existing row and no resumed
// callback API. Read-only client material service is a separate operation.
type SQLiteLiveSpend struct{ *sqliteLiveSpend }
type sqliteLiveSpend struct {
	mu                                           sync.Mutex
	store                                        *sqliteStore
	invocation                                   *Invocation
	plan                                         *protocolv4.LiveActivationPlan
	guard                                        func() error
	reservation, storeReference                  resourcev4.Reference
	key                                          [admissionKeyBytes]byte
	keySize, spendingSize, targetSize, proofSize int
	spending, target, scratch, proof             []byte
	authority                                    string
	fence                                        uint64
	started, running, closed, cleaned            bool
}

func SQLiteLiveSpendCharges(maxRecordBytes uint32) (owner, invocation resourcev4.Vector, err error) {
	proof, err := protocolv4.SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		return owner, invocation, err
	}
	// Both the complete TxA projection and complete proof must fit together
	// in the TxB record before policy is allowed to run.
	if maxRecordBytes < uint32(2*proof+2048) || maxRecordBytes > 1<<20 {
		return owner, invocation, ErrConfiguration
	}
	owner = resourcev4.Vector{resourcev4.SDKBytes: 3*uint64(maxRecordBytes) + uint64(proof) + uint64(unsafe.Sizeof(SQLiteLiveSpend{})) + uint64(unsafe.Sizeof(sqliteLiveSpend{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + 128, resourcev4.Items: 1, resourcev4.WorkSlots: 1}
	invocation, err = InvocationCharge(admissionKeyBytes, int(maxRecordBytes))
	return
}

func NewSQLiteLiveSpend(ctx context.Context, store *SQLiteStore, authority SQLiteLiveAuthority, plan *protocolv4.LiveActivationPlan, owner LiveSpendOwner, clock *timev4.Clock, deadline *timev4.Deadline, guard func() error, buffers, invocation, environment resourcev4.Reference) (_ *SQLiteLiveSpend, err error) {
	if ctx == nil || authority == nil || plan == nil || owner.Invocation == ([16]byte{}) || owner.Generation == 0 || owner.RequestDigest == ([32]byte{}) || owner.ClientMaterialNotAfter == 0 || guard == nil || !deadline.BelongsTo(clock) {
		return nil, ErrConfiguration
	}
	if err = buffers.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if err = invocation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if err = plan.CheckEnvironment(environment); err != nil {
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
	charge, _, err := SQLiteLiveSpendCharges(limit)
	if err != nil {
		return nil, err
	}
	held, err := buffers.Take(charge)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			held.Release()
		}
	}()
	proofCap, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	a := &sqliteLiveSpend{store: store.sqliteStore, plan: plan, guard: guard, reservation: held, storeReference: ref, spending: make([]byte, limit), target: make([]byte, limit), scratch: make([]byte, limit), proof: make([]byte, proofCap), authority: identity.Authority, fence: epoch}
	fields, unsignedSize, err := plan.CopyProjection(a.scratch)
	if err != nil {
		return nil, err
	}
	if identity.Authority != fields.Authority || owner.ClientMaterialNotAfter > fields.ActivationEnd {
		return nil, ErrConfiguration
	}
	if err = authority.CheckLiveSpend(identity, fields); err != nil {
		return nil, err
	}
	if err = guard(); err != nil {
		return nil, err
	}
	deadline, err = deadline.Fork(min(deadline.Cap(), fields.ActivationEnd, owner.ClientMaterialNotAfter))
	if err != nil {
		return nil, err
	}
	now, err := deadline.Sample()
	if err != nil {
		return nil, err
	}
	if err = now.LowerBound(fields.IssuedAt, true); err != nil {
		return nil, err
	}
	a.invocation, err = NewInvocation(ctx, clock, deadline, epoch, admissionKeyBytes, int(limit), invocation)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			_ = a.invocation.Cleanup()
		}
	}()
	key := admissionRecord{fields: protocolv4.AdmissionFields{Tenant: fields.Tenant, Issuer: fields.Issuer, Lease: fields.Lease}}
	a.keySize, err = key.key(a.key[:])
	if err != nil {
		return nil, err
	}
	var intent [32]byte
	if _, err = rand.Read(intent[:]); err != nil {
		return nil, err
	}
	if intent == ([32]byte{}) {
		return nil, ErrStorageUnavailable
	}
	w := admissionWriter{dst: a.spending}
	w.text("flowersec/live-spending/1")
	for _, n := range []uint64{1, epoch, identity.Generation, owner.Generation, deadline.Cap(), owner.ClientMaterialNotAfter, now.UpperMS, fields.Winner.Index} {
		w.uint(n)
	}
	w.text(identity.Authority)
	for _, b := range [][]byte{identity.StoreID[:], owner.Invocation[:], owner.RequestDigest[:], intent[:], fields.Winner.CandidateID[:], fields.Winner.RouteDigest[:], fields.Artifact[:], fields.Signer[:]} {
		w.bytes(b)
	}
	w.uint(uint64(unsignedSize))
	w.bytes(a.scratch[:unsignedSize])
	if w.err != nil {
		return nil, w.err
	}
	a.spendingSize = w.n
	clear(a.scratch)
	adopted = true
	return &SQLiteLiveSpend{a}, nil
}

func (a *sqliteLiveSpend) check() error {
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		return ErrOwner
	}
	if err := a.invocation.ctx.Err(); err != nil {
		return err
	}
	if err := a.invocation.deadline.Check(); err != nil {
		return err
	}
	if err := a.reservation.Check(); err != nil {
		return err
	}
	if err := a.storeReference.Check(); err != nil {
		return err
	}
	return a.guard()
}

// Authorize starts policy once only after original TxA confirmation. Positive
// policy signs just the frozen projection and atomically commits the complete
// consumed/proof record before exposing bytes to the original publisher.
// Callback errors become a consumed unknown outcome; neither queries nor a
// second object may dispatch the old intent again.
func (a *SQLiteLiveSpend) Authorize(policy func(context.Context) (bool, error), publish func(context.Context, []byte) error) (err error) {
	if a == nil || a.sqliteLiveSpend == nil || policy == nil || publish == nil {
		return ErrConfiguration
	}
	a.mu.Lock()
	if a.closed || a.started {
		a.mu.Unlock()
		return ErrOwner
	}
	a.started, a.running = true, true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		if err != nil {
			a.Close(err)
		}
	}()
	if err = a.check(); err != nil {
		return err
	}
	tx := Transaction{Kind: SpendTxA, Authority: a.authority, Key: a.key[:a.keySize], BeforeVersion: 0, CommitVersion: 1, FencingEpoch: a.fence, Projection: a.spending[:a.spendingSize]}
	first, err := a.invocation.Begin(tx)
	if err != nil {
		return err
	}
	backend := liveCommitStore{a.sqliteLiveSpend, false}
	if err = first.Run(backend); err != nil {
		return err
	}
	allowed := false
	var policyErr error
	if err = first.Dispatch(func(ctx context.Context) error {
		if err := a.check(); err != nil {
			return err
		}
		allowed, policyErr = policy(ctx)
		return nil
	}); err != nil {
		return err
	}
	if err = a.check(); err != nil {
		return err
	}
	outcome := uint64(1) // denied
	if policyErr != nil {
		outcome = 0
	} else if allowed {
		outcome = 2
	}
	if outcome == 2 {
		a.proofSize, err = a.plan.Issue(a.proof, a.check)
		if err != nil {
			return err
		}
	}
	w := admissionWriter{dst: a.target}
	w.text("flowersec/live-consumed/1")
	w.uint(2)
	w.uint(a.fence)
	w.uint(outcome)
	w.uint(uint64(a.spendingSize))
	w.bytes(a.spending[:a.spendingSize])
	w.uint(uint64(a.proofSize))
	w.bytes(a.proof[:a.proofSize])
	if w.err != nil {
		return w.err
	}
	a.targetSize = w.n
	if outcome != 2 {
		// No next irreversible action follows denied/unknown consumption, so
		// no confirmation continuation is created for this terminal write.
		s := a.store
		if err = s.begin(a.invocation.ctx); err != nil {
			return err
		}
		err = s.writeTransaction(a.invocation.ctx, a.check, func() error { return a.consume() })
		s.end()
		if err != nil {
			return err
		}
		if outcome == 0 {
			return ErrUnknown
		}
		return ErrDenied
	}
	tx.Kind, tx.BeforeVersion, tx.CommitVersion, tx.Projection = AuthorizedTxB, 1, 2, a.target[:a.targetSize]
	second, err := a.invocation.Begin(tx)
	if err != nil {
		return err
	}
	if err = second.Run(liveCommitStore{a.sqliteLiveSpend, true}); err != nil {
		return err
	}
	return second.Dispatch(func(ctx context.Context) error {
		if err := a.check(); err != nil {
			return err
		}
		return publish(ctx, a.proof[:a.proofSize:a.proofSize])
	})
}

func (a *sqliteLiveSpend) consume() error {
	s := a.store
	if err := s.exec("UPDATE spend SET state=1,version=?1,projection=?2 WHERE lease=?3 AND source=0 AND state=0 AND version=?4 AND fence=?5 AND projection=?6", named(1, sqliteUint(2)), named(2, a.target[:a.targetSize]), named(3, a.key[:a.keySize]), named(4, sqliteUint(1)), named(5, sqliteUint(a.fence)), named(6, a.spending[:a.spendingSize])); err != nil {
		return err
	}
	return s.changedOne()
}

type liveCommitStore struct {
	original *sqliteLiveSpend
	consumed bool
}

func (b liveCommitStore) valid(tx Transaction, dst []byte) bool {
	a := b.original
	if a == nil || tx.Authority != a.authority || tx.FencingEpoch != a.fence || !bytes.Equal(tx.Key, a.key[:a.keySize]) {
		return false
	}
	if b.consumed {
		return tx.Kind == AuthorizedTxB && tx.BeforeVersion == 1 && tx.CommitVersion == 2 && bytes.Equal(tx.Projection, a.target[:a.targetSize]) && len(dst) >= a.targetSize
	}
	return tx.Kind == SpendTxA && tx.BeforeVersion == 0 && tx.CommitVersion == 1 && bytes.Equal(tx.Projection, a.spending[:a.spendingSize]) && len(dst) >= a.spendingSize
}
func (b liveCommitStore) Commit(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
	if !b.valid(tx, dst) {
		return Observation{}, ErrConfiguration
	}
	a, s := b.original, b.original.store
	if err := s.begin(ctx); err != nil {
		return Observation{}, err
	}
	defer s.end()
	if s.epoch != tx.FencingEpoch {
		return Observation{}, ErrFenced
	}
	err := s.writeTransaction(ctx, a.check, func() error {
		if b.consumed {
			return a.consume()
		}
		present, err := s.scalar("SELECT count(*) FROM spend WHERE lease=?1", named(1, tx.Key))
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
		if err = s.exec("INSERT INTO spend VALUES (?1,0,0,?2,?3,?4)", named(1, tx.Key), named(2, sqliteUint(1)), named(3, sqliteUint(tx.FencingEpoch)), named(4, tx.Projection)); err != nil {
			return err
		}
		return s.exec("UPDATE manifest SET spend_rows=spend_rows+1 WHERE id=1")
	})
	if err != nil {
		return Observation{}, err
	}
	copy(dst, tx.Projection)
	return Observation{State: DurablyCommitted, CommitVersion: tx.CommitVersion, AggregateVersion: tx.CommitVersion, CommitFence: s.epoch, CurrentFence: s.epoch, ProjectionBytes: len(tx.Projection)}, nil
}
func (b liveCommitStore) Confirm(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
	if !b.valid(tx, dst) {
		return Observation{}, ErrConfiguration
	}
	s := b.original.store
	if err := s.begin(ctx); err != nil {
		return Observation{}, err
	}
	defer s.end()
	if err := s.checkFence(); err != nil {
		return Observation{}, err
	}
	rows, err := s.querier.QueryContext(context.Background(), "SELECT source,state,version,fence,length(projection),CASE WHEN length(projection)<=?2 THEN projection ELSE NULL END FROM spend WHERE lease=?1", []driver.NamedValue{named(1, tx.Key), named(2, int64(len(dst)))})
	if err != nil {
		return Observation{}, err
	}
	var result Observation
	read := func() error {
		var values [6]driver.Value
		if err := rows.Next(values[:]); err == io.EOF {
			result.State = NotObserved
			return nil
		} else if err != nil {
			return err
		}
		version, ve := readSQLiteUint(values[2])
		fence, fe := readSQLiteUint(values[3])
		projection, ok := values[5].([]byte)
		if ve != nil || fe != nil || !ok || len(projection) == 0 || len(projection) > len(dst) || values[4] != int64(len(projection)) {
			return ErrStorageFormat
		}
		state := int64(0)
		if b.consumed {
			state = 1
		}
		result = Observation{State: DurablyCommitted, CommitVersion: version, AggregateVersion: version, CommitFence: fence, CurrentFence: s.epoch, ProjectionBytes: copy(dst, projection)}
		if values[0] != int64(0) || values[1] != state {
			result.State = Conflicting
		}
		if err := rows.Next(values[:]); err != io.EOF {
			return ErrStorageFormat
		}
		return nil
	}
	err = errors.Join(read(), rows.Close(), ctx.Err())
	return result, err
}

func (a *SQLiteLiveSpend) Close(cause error) {
	if a == nil || a.sqliteLiveSpend == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	a.reservation.Seal()
	i := a.invocation
	a.mu.Unlock()
	i.Cancel(cause)
}
func (a *SQLiteLiveSpend) Cleanup() error {
	if a == nil || a.sqliteLiveSpend == nil {
		return ErrConfiguration
	}
	a.Close(ErrOwner)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cleaned {
		return nil
	}
	if a.running {
		return ErrCapacity
	}
	if err := a.invocation.Cleanup(); err != nil {
		return err
	}
	clear(a.spending)
	clear(a.target)
	clear(a.scratch)
	clear(a.proof)
	clear(a.key[:])
	a.spending, a.target, a.scratch, a.proof, a.guard, a.plan, a.store = nil, nil, nil, nil, nil, nil, nil
	a.storeReference.Release()
	a.reservation.Release()
	a.cleaned = true
	return nil
}
