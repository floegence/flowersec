package sessionv4

import (
	"context"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// SQLiteReferenceStore adapts only query-reference persistence. Its provider
// has explicit record/byte/retention limits and one actual synchronous call.
// It adds no worker, outbox or dispatch capability; PrepareAndSave supplies the
// original ordinary task and retains it through actual commit/cleanup return.
type SQLiteReferenceStore struct {
	mu               sync.Mutex
	store            *ledgerv4.SQLiteReferences
	domain           string
	reservation, pin resourcev4.Reference
	active           uint32
	closed           bool
}

func SQLiteReferenceStoreCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteReferenceStore{})) + 128, resourcev4.Items: 1}
}

func NewSQLiteReferenceStore(store *ledgerv4.SQLiteReferences, domain string, reservation resourcev4.Reference) (*SQLiteReferenceStore, error) {
	if store == nil || !executionIdentityText(domain) {
		return nil, rpcv4.ErrConfiguration
	}
	owned, err := reservation.Take(SQLiteReferenceStoreCharge())
	if err != nil {
		return nil, err
	}
	pin, err := store.Borrow(domain, owned)
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &SQLiteReferenceStore{store: store, domain: strings.Clone(domain), reservation: owned, pin: pin}, nil
}

func (s *SQLiteReferenceStore) Binding() (ReferenceStoreBinding, error) {
	if s == nil {
		return ReferenceStoreBinding{}, rpcv4.ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ReferenceStoreBinding{}, rpcv4.ErrClosed
	}
	if err := s.reservation.Check(); err != nil {
		return ReferenceStoreBinding{}, err
	}
	return ReferenceStoreBinding{Domain: s.domain, Store: s, Backing: s.reservation}, nil
}

func (s *SQLiteReferenceStore) SaveOperationReference(ctx context.Context, ref protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
	if s == nil || ctx == nil {
		return ReferenceSaveUnknown, rpcv4.ErrConfiguration
	}
	s.mu.Lock()
	if s.closed || s.active != 0 {
		s.mu.Unlock()
		return ReferenceSaveUnknown, rpcv4.ErrCapacity
	}
	if err := s.reservation.Check(); err != nil {
		s.mu.Unlock()
		return ReferenceSaveUnknown, err
	}
	if err := s.pin.Check(); err != nil {
		s.mu.Unlock()
		return ReferenceSaveUnknown, err
	}
	s.active = 1
	store := s.store
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active = 0; s.cleanupLocked(); s.mu.Unlock() }()
	if err := store.Save(ctx, ref); err != nil {
		return ReferenceSaveUnknown, err
	}
	if err := ctx.Err(); err != nil {
		return ReferenceSaveUnknown, err
	}
	return ReferenceSaveConfirmed, nil
}

func (s *SQLiteReferenceStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.reservation.Seal()
	s.cleanupLocked()
}
func (s *SQLiteReferenceStore) cleanupLocked() {
	if !s.closed || s.active != 0 {
		return
	}
	s.store = nil
	s.pin.Release()
	s.pin = resourcev4.Reference{}
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
}
