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

type V4SQLiteReferenceConfig = ledgerv4.SQLiteReferenceConfig

var ErrOperationReferenceExpired = ledgerv4.ErrReferenceExpired

// V4SQLiteReferences persists bounded query locators in its own local file.
// Create and Open preserve distinct continuity requirements. Closing this
// owner never deletes references or changes remote execution history.
type V4SQLiteReferences struct {
	mu    sync.Mutex
	inner *ledgerv4.SQLiteReferences
	page  [16]protocolv4.OperationReference
}

func V4SQLiteReferencesCharge(limits V4SQLiteLimits, config V4SQLiteReferenceConfig) (V4ResourceVector, error) {
	charge, err := ledgerv4.SQLiteReferencesCharge(limits, config)
	if err != nil {
		return V4ResourceVector{}, err
	}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(V4SQLiteReferences{}))})
}

func CreateV4SQLiteReferences(ctx context.Context, backing *V4SQLiteBacking, identity V4SQLiteIdentity, continuity V4SQLiteContinuity, config V4SQLiteReferenceConfig, reservation, environment V4ResourceReference) (*V4SQLiteReferences, error) {
	return openV4SQLiteReferences(ctx, backing, identity, continuity, config, reservation, environment, true)
}

func OpenV4SQLiteReferences(ctx context.Context, backing *V4SQLiteBacking, identity V4SQLiteIdentity, continuity V4SQLiteContinuity, config V4SQLiteReferenceConfig, reservation, environment V4ResourceReference) (*V4SQLiteReferences, error) {
	return openV4SQLiteReferences(ctx, backing, identity, continuity, config, reservation, environment, false)
}

func openV4SQLiteReferences(ctx context.Context, backing *V4SQLiteBacking, identity V4SQLiteIdentity, continuity V4SQLiteContinuity, config V4SQLiteReferenceConfig, reservation, environment V4ResourceReference, create bool) (*V4SQLiteReferences, error) {
	if backing == nil {
		return nil, ledgerv4.ErrConfiguration
	}
	// The inner store takes this entire charge, including the public view and
	// its one bounded enumeration workspace, through actual provider cleanup.
	charge, err := V4SQLiteReferencesCharge(backing.Limits(), config)
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
	return &V4SQLiteReferences{inner: inner}, err
}

func (s *V4SQLiteReferences) Save(ctx context.Context, reference OperationReference) error {
	if s == nil || s.inner == nil {
		return ledgerv4.ErrOwner
	}
	return s.inner.Save(ctx, reference.inner)
}

func (s *V4SQLiteReferences) Load(ctx context.Context, selector OperationReference) (OperationReference, bool, error) {
	if s == nil || s.inner == nil {
		return OperationReference{}, false, ledgerv4.ErrOwner
	}
	reference, found, err := s.inner.Load(ctx, selector.inner)
	return OperationReference{inner: reference}, found, err
}

// List scans at most len(output) rows, with at most sixteen per call. An
// advanced cursor with zero returned references can represent expired rows.
func (s *V4SQLiteReferences) List(ctx context.Context, after [32]byte, output []OperationReference) (int, [32]byte, error) {
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

func (s *V4SQLiteReferences) Collect(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return ledgerv4.ErrOwner
	}
	return s.inner.Collect(ctx)
}
func (s *V4SQLiteReferences) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
func (s *V4SQLiteReferences) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return ledgerv4.ErrOwner
	}
	return s.inner.WaitCleanup(ctx)
}
func (s *V4SQLiteReferences) Retire() error {
	if s == nil || s.inner == nil {
		return ledgerv4.ErrOwner
	}
	if !s.mu.TryLock() {
		return ledgerv4.ErrCapacity
	}
	defer s.mu.Unlock()
	return s.inner.Retire()
}
func (*V4SQLiteReferences) String() string               { return "Flowersec.SQLiteReferences" }
func (*V4SQLiteReferences) GoString() string             { return "Flowersec.SQLiteReferences" }
func (*V4SQLiteReferences) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// V4SQLiteReferenceStore is an explicitly charged provider adapter. It borrows
// the caller's original store, runs on the existing ordinary executor and
// creates no background dispatch, retry queue or additional file owner.
type V4SQLiteReferenceStore struct {
	inner *sessionv4.SQLiteReferenceStore
}

func V4SQLiteReferenceStoreCharge() V4ResourceVector {
	charge := sessionv4.SQLiteReferenceStoreCharge()
	charge[resourcev4.SDKBytes] += uint64(unsafe.Sizeof(V4SQLiteReferenceStore{}))
	return charge
}
func NewV4SQLiteReferenceStore(store *V4SQLiteReferences, domain string, reservation V4ResourceReference) (*V4SQLiteReferenceStore, error) {
	if store == nil || store.inner == nil {
		return nil, ledgerv4.ErrOwner
	}
	owned, err := reservation.Take(V4SQLiteReferenceStoreCharge())
	if err != nil {
		return nil, err
	}
	inner, err := sessionv4.NewSQLiteReferenceStore(store.inner, domain, owned)
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &V4SQLiteReferenceStore{inner: inner}, nil
}
func (s *V4SQLiteReferenceStore) Binding() (V4ReferenceStoreBinding, error) {
	if s == nil || s.inner == nil {
		return V4ReferenceStoreBinding{}, ledgerv4.ErrOwner
	}
	binding, err := s.inner.Binding()
	if err != nil {
		return V4ReferenceStoreBinding{}, err
	}
	return V4ReferenceStoreBinding{Domain: binding.Domain, Store: s, Backing: binding.Backing}, nil
}
func (s *V4SQLiteReferenceStore) SaveOperationReference(ctx context.Context, reference OperationReference) (V4ReferenceSaveOutcome, error) {
	if s == nil || s.inner == nil {
		return V4ReferenceSaveUnknown, ledgerv4.ErrOwner
	}
	return s.inner.SaveOperationReference(ctx, reference.inner)
}
func (s *V4SQLiteReferenceStore) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
