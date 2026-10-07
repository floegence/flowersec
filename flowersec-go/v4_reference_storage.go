package flowersec

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type SQLiteReferenceConfig = ledgerv4.SQLiteReferenceConfig

var ErrOperationReferenceExpired = ledgerv4.ErrReferenceExpired

// SQLiteReferences persists bounded query locators in its own local file.
// Create and Open preserve distinct continuity requirements. Closing this
// owner never deletes references or changes remote execution history.
type SQLiteReferences struct {
	mu    sync.Mutex
	inner *ledgerv4.SQLiteReferences
	page  [16]protocolv4.OperationReference
}

func SQLiteReferencesCharge(limits SQLiteLimits, config SQLiteReferenceConfig) (ResourceVector, error) {
	charge, err := ledgerv4.SQLiteReferencesCharge(limits, config)
	if err != nil {
		return ResourceVector{}, err
	}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteReferences{}))})
}

func CreateSQLiteReferences(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, config SQLiteReferenceConfig, reservation, environment ResourceReference) (*SQLiteReferences, error) {
	return openSQLiteReferences(ctx, backing, identity, continuity, config, reservation, environment, true)
}

func OpenSQLiteReferences(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, config SQLiteReferenceConfig, reservation, environment ResourceReference) (*SQLiteReferences, error) {
	return openSQLiteReferences(ctx, backing, identity, continuity, config, reservation, environment, false)
}

func openSQLiteReferences(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, config SQLiteReferenceConfig, reservation, environment ResourceReference, create bool) (*SQLiteReferences, error) {
	if backing == nil {
		return nil, ledgerv4.ErrConfiguration
	}
	// The inner store takes this entire charge, including the public view and
	// its one bounded enumeration workspace, through actual provider cleanup.
	charge, err := SQLiteReferencesCharge(backing.Limits(), config)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	var inner *ledgerv4.SQLiteReferences
	if create {
		inner, err = ledgerv4.CreateSQLiteReferences(ctx, backing, identity, continuity, config, owned, environment)
	} else {
		inner, err = ledgerv4.OpenSQLiteReferences(ctx, backing, identity, continuity, config, owned, environment)
	}
	if inner == nil {
		owned.Release()
		return nil, err
	}
	return &SQLiteReferences{inner: inner}, err
}

func (s *SQLiteReferences) Save(ctx context.Context, reference OperationReference) error {
	if s == nil || s.inner == nil {
		return ledgerv4.ErrOwner
	}
	return s.inner.Save(ctx, reference.inner)
}

func (s *SQLiteReferences) Load(ctx context.Context, selector OperationReference) (OperationReference, bool, error) {
	if s == nil || s.inner == nil {
		return OperationReference{}, false, ledgerv4.ErrOwner
	}
	reference, found, err := s.inner.Load(ctx, selector.inner)
	return OperationReference{inner: reference}, found, err
}

// List scans at most len(output) rows, with at most sixteen per call. An
// advanced cursor with zero returned references can represent expired rows.
func (s *SQLiteReferences) List(ctx context.Context, after [32]byte, output []OperationReference) (int, [32]byte, error) {
	if s == nil || s.inner == nil {
		return 0, after, ledgerv4.ErrOwner
	}
	if len(output) == 0 || len(output) > len(s.page) {
		return 0, after, ledgerv4.ErrConfiguration
	}
	if !s.mu.TryLock() {
		return 0, after, ledgerv4.ErrCapacity
	}
	defer s.mu.Unlock()
	defer clear(s.page[:])
	n, next, err := s.inner.List(ctx, after, s.page[:len(output)])
	if err != nil {
		return 0, after, err
	}
	for index := range n {
		output[index] = OperationReference{inner: s.page[index]}
	}
	return n, next, nil
}

func (s *SQLiteReferences) Collect(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return ledgerv4.ErrOwner
	}
	return s.inner.Collect(ctx)
}
func (s *SQLiteReferences) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
func (s *SQLiteReferences) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return ledgerv4.ErrOwner
	}
	return s.inner.WaitCleanup(ctx)
}
func (s *SQLiteReferences) Retire() error {
	if s == nil || s.inner == nil {
		return ledgerv4.ErrOwner
	}
	if !s.mu.TryLock() {
		return ledgerv4.ErrCapacity
	}
	defer s.mu.Unlock()
	return s.inner.Retire()
}
func (*SQLiteReferences) String() string               { return "Flowersec.SQLiteReferences" }
func (*SQLiteReferences) GoString() string             { return "Flowersec.SQLiteReferences" }
func (*SQLiteReferences) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// SQLiteReferenceStore is an explicitly charged provider adapter. It borrows
// the caller's original store, runs on the existing ordinary executor and
// creates no background dispatch, retry queue or additional file owner.
type SQLiteReferenceStore struct {
	inner *sessionv4.SQLiteReferenceStore
}

func SQLiteReferenceStoreCharge() ResourceVector {
	charge := sessionv4.SQLiteReferenceStoreCharge()
	charge[resourcev4.SDKBytes] += uint64(unsafe.Sizeof(SQLiteReferenceStore{}))
	return charge
}
func NewSQLiteReferenceStore(store *SQLiteReferences, domain string, reservation ResourceReference) (*SQLiteReferenceStore, error) {
	if store == nil || store.inner == nil {
		return nil, ledgerv4.ErrOwner
	}
	owned, err := reservation.Take(SQLiteReferenceStoreCharge())
	if err != nil {
		return nil, err
	}
	inner, err := sessionv4.NewSQLiteReferenceStore(store.inner, domain, owned)
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &SQLiteReferenceStore{inner: inner}, nil
}
func (s *SQLiteReferenceStore) Binding() (ReferenceStoreBinding, error) {
	if s == nil || s.inner == nil {
		return ReferenceStoreBinding{}, ledgerv4.ErrOwner
	}
	binding, err := s.inner.Binding()
	if err != nil {
		return ReferenceStoreBinding{}, err
	}
	return ReferenceStoreBinding{Domain: binding.Domain, Store: s, Backing: binding.Backing}, nil
}
func (s *SQLiteReferenceStore) SaveOperationReference(ctx context.Context, reference OperationReference) (ReferenceSaveOutcome, error) {
	if s == nil || s.inner == nil {
		return ReferenceSaveUnknown, ledgerv4.ErrOwner
	}
	return s.inner.SaveOperationReference(ctx, reference.inner)
}
func (s *SQLiteReferenceStore) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
