package ledgerv4

import (
	"context"
	"crypto/rand"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// SQLiteAdmissionAuthority is the trusted host's stable service mapping. It
// must verify that this signed tenant/issuer/server/audience resolves to this
// one complete AdmissionLedger authority across all accepting instances. It is
// bounded, immutable local configuration; peer input cannot choose a store.
type SQLiteAdmissionAuthority interface {
	CheckAdmission(SQLiteIdentity, protocolv4.AdmissionFacts) error
}

// SQLiteAdmission owns the single original reserve/admit path. Its original
// Invocation is never returned. Only a successful original CAS and Dispatch
// may call the supplied trusted Acceptor continuation; queries cannot do so.
type SQLiteAdmission struct{ *sqliteAdmission }
type sqliteAdmission struct {
	mu                                sync.Mutex
	store                             *sqliteStore
	invocation                        *Invocation
	guard                             func() error
	record                            admissionRecord
	key                               [admissionKeyBytes]byte
	keySize, reservedSize, targetSize int
	reserved, target, scratch         []byte
	targetState                       byte
	reservation, storeReference       resourcev4.Reference
	started, running, closed, cleaned bool
}

func (a *sqliteAdmission) check() error {
	if err := a.storeReference.Check(); err != nil {
		return err
	}
	return a.guard()
}

func SQLiteAdmissionCharges(maxRecordBytes uint32) (owner, invocation resourcev4.Vector, err error) {
	if maxRecordBytes < 1024 || maxRecordBytes > 1<<20 {
		return owner, invocation, ErrConfiguration
	}
	owner = resourcev4.Vector{resourcev4.SDKBytes: 4*uint64(maxRecordBytes) + uint64(unsafe.Sizeof(SQLiteAdmission{})) + uint64(unsafe.Sizeof(sqliteAdmission{})) + uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 1, resourcev4.WorkSlots: 1}
	invocation, err = InvocationCharge(admissionKeyBytes, int(maxRecordBytes))
	return
}

func (s *SQLiteStore) admissionReference(environment resourcev4.Reference) (resourcev4.Reference, SQLiteIdentity, uint64, uint32, error) {
	if s == nil || s.sqliteStore == nil {
		return resourcev4.Reference{}, SQLiteIdentity{}, 0, 0, ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired {
		return resourcev4.Reference{}, SQLiteIdentity{}, 0, 0, ErrOwner
	}
	if err := s.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, SQLiteIdentity{}, 0, 0, err
	}
	ref, err := s.reservation.Borrow()
	return ref, s.identity, s.epoch, s.backing.limits.MaxRecordBytes, err
}

func NewSQLiteAdmission(ctx context.Context, store *SQLiteStore, authority SQLiteAdmissionAuthority, facts protocolv4.AdmissionFacts, owner AdmissionOwner, clock *timev4.Clock, deadline *timev4.Deadline, guard func() error, buffers, invocation, environment resourcev4.Reference) (*SQLiteAdmission, error) {
	if ctx == nil || authority == nil || !owner.valid() || guard == nil || !deadline.BelongsTo(clock) {
		return nil, ErrConfiguration
	}
	fields, err := facts.Fields()
	if err != nil {
		return nil, err
	}
	if err = buffers.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if err = invocation.CheckSameEnvironment(environment); err != nil {
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
	charge, _, err := SQLiteAdmissionCharges(limit)
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
	if err = authority.CheckAdmission(identity, facts); err != nil {
		return nil, err
	}
	if err = guard(); err != nil {
		return nil, err
	}
	// Admission has an earlier absolute authorization boundary than an
	// already-admitted Session. Keep the original stage's monotonic projection
	// while tightening this separately charged invocation to activation end.
	deadline, err = deadline.Fork(min(deadline.Cap(), fields.ActivationEnd))
	if err != nil {
		return nil, err
	}
	sample, err := deadline.Sample()
	if err != nil {
		return nil, err
	}
	if err = sample.LowerBound(fields.IssuedAt, true); err != nil {
		return nil, err
	}
	i, err := NewInvocation(ctx, clock, deadline, epoch, admissionKeyBytes, int(limit), invocation)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			_ = i.Cleanup()
		}
	}()
	// Clone every retained textual fact into this precharged owner. Binary
	// facts are values; codec reuse cannot change the original CAS projection.
	for _, p := range []*string{&fields.Tenant, &fields.Audience, &fields.Profile, &fields.Source, &fields.SpendAuthority, &fields.WinnerAuthority, &fields.SigningKey} {
		*p = strings.Clone(*p)
	}
	a := &sqliteAdmission{store: store.sqliteStore, invocation: i, guard: guard, reservation: held, storeReference: ref, reserved: make([]byte, limit), target: make([]byte, limit), scratch: make([]byte, limit), record: admissionRecord{fields: fields, owner: owner, authority: strings.Clone(identity.Authority), storeID: identity.StoreID, storeGeneration: identity.Generation, fence: epoch, deadline: deadline.Cap(), reservedAt: sample.UpperMS}}
	a.keySize, err = a.record.key(a.key[:])
	if err != nil {
		return nil, err
	}
	a.reservedSize, err = a.record.encode(a.reserved, admissionReserved, 0, [32]byte{})
	if err != nil {
		return nil, err
	}
	adopted = true
	return &SQLiteAdmission{a}, nil
}

// Admit performs one reserve and one reserved->admitted CAS. Reserve
// uncertainty terminates the path. Only the admitted CAS may use the original
// invocation's bounded confirmation reads. No network response is sent here.
func (a *SQLiteAdmission) Admit(action func(context.Context, protocolv4.AdmissionResponse) error) (err error) {
	if a == nil || a.sqliteAdmission == nil || action == nil {
		return ErrConfiguration
	}
	a.mu.Lock()
	if a.closed || a.started {
		a.mu.Unlock()
		return ErrOwner
	}
	a.started, a.running = true, true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.running = false; a.mu.Unlock() }()
	defer func() {
		if err != nil {
			a.Close(err)
		}
	}()
	if err = a.reserve(a.invocation.ctx); err != nil {
		return err
	}
	if err = a.check(); err != nil {
		return err
	}
	sample, err := a.invocation.deadline.Sample()
	if err != nil {
		return err
	}
	var key [32]byte
	// Generate once for this CAS. It is absent in reserved history and becomes
	// an observable FSA value only in the confirmed original continuation.
	if _, err = rand.Read(key[:]); err != nil {
		return err
	}
	if key == ([32]byte{}) {
		return ErrStorageUnavailable
	}
	a.targetState = admissionAdmitted
	a.targetSize, err = a.record.encode(a.target, a.targetState, sample.UpperMS, key)
	if err != nil {
		return err
	}
	tx := Transaction{Kind: AdmissionCommit, Authority: a.record.authority, Key: a.key[:a.keySize], BeforeVersion: 1, CommitVersion: 2, FencingEpoch: a.record.fence, Projection: a.target[:a.targetSize]}
	original, err := a.invocation.Begin(tx)
	if err != nil {
		return err
	}
	if err = original.Run(admissionCommitStore{a.sqliteAdmission}); err != nil {
		return err
	}
	return original.Dispatch(func(ctx context.Context) error {
		if err := a.check(); err != nil {
			return err
		}
		return action(ctx, protocolv4.AdmissionResponse{Admitted: true, ServerEpoch: a.record.fence, ReservationKey: key, AdmissionBinding: a.record.fields.AdmissionBinding, ServerIdentityDigest: a.record.fields.ServerIdentity})
	})
}

func (a *SQLiteAdmission) Close(cause error) {
	if a == nil || a.sqliteAdmission == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	a.reservation.Seal()
	i := a.invocation
	a.mu.Unlock()
	i.Cancel(cause)
}

// Cleanup never detaches an active SQLite call or Acceptor continuation. The
// store borrow and all original bytes remain charged until their real return.
func (a *SQLiteAdmission) Cleanup() error {
	if a == nil || a.sqliteAdmission == nil {
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
	clear(a.reserved)
	clear(a.target)
	clear(a.scratch)
	clear(a.key[:])
	a.reserved, a.target, a.scratch = nil, nil, nil
	a.guard = nil
	a.record = admissionRecord{}
	a.store = nil
	a.storeReference.Release()
	a.reservation.Release()
	a.cleaned = true
	return nil
}
