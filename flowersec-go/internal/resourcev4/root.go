package resourcev4

import (
	"math"
	"sync"
	"unsafe"
)

const MaxAccountsPerCharge = 8

type AccountKind uint8

const (
	TenantAccount AccountKind = iota + 1
	EnvironmentAccount
	SessionAccount
	DirectionAccount
	PoolAccount
)

// AccountKey is created only by trusted local composition. Unauthenticated
// peer names must never create tenant accounts. Equal keys in one root always
// resolve to the same bounded account, even across different Environments.
type AccountKey struct {
	Kind AccountKind
	ID   [16]byte
}

type Config struct {
	ProfileRevision                                [32]byte
	Limit                                          Vector
	AccountSlots, ReservationSlots, ReferenceSlots uint32
	// Covers the selected allocator's charge above the actual root/slab sizes.
	// Runtime/OS memory outside SDK control is measured separately.
	AllocationOverheadBytes uint64
}

// Root is one actual budget authority. Equal configurations in two roots do
// not give a shared process bound. All slabs are allocated before admission;
// reserve/borrow/transfer/release perform no allocation, I/O or callbacks.
type Root struct {
	waitFirst, waitLast        *ReservationWaiter
	drainingWaiters            bool
	mu                         sync.Mutex
	profile                    [32]byte
	limit, used                Vector
	accounts                   []accountSlot
	charges                    []chargeSlot
	refs                       []referenceSlot
	chargeCount                uint32
	referenceCount             uint32
	resultCount                uint32
	closed                     bool
	applicationExecutorClaimed bool
}

type accountSlot struct {
	generation     uint64
	key            AccountKey
	limit, used    Vector
	charges        uint32
	active, closed bool
}

type chargeSlot struct {
	resultOwner     bool
	protected       *ProtectedReservation
	protectedClosed bool
	generation      uint64
	value           Vector
	accounts        [MaxAccountsPerCharge]Account
	accountRefs     [MaxAccountsPerCharge]uint32
	count           int
	refs            uint32
	active, sealed  bool
}

// Handles may be copied, but copying does not acquire another reference.
// Generations prevent a stale Release from returning a reused slab slot.
type Account struct {
	root       *Root
	index      uint32
	generation uint64
}

func BackingBytes(config Config) (uint64, error) {
	if config.ProfileRevision == [32]byte{} || config.AccountSlots == 0 || config.ReservationSlots == 0 || config.ReferenceSlots < config.ReservationSlots {
		return 0, ErrConfiguration
	}
	total := uint64(unsafe.Sizeof(Root{}))
	for _, part := range [...]struct {
		count uint32
		size  uintptr
	}{
		{config.AccountSlots, unsafe.Sizeof(accountSlot{})},
		{config.ReservationSlots, unsafe.Sizeof(chargeSlot{})},
		{config.ReferenceSlots, unsafe.Sizeof(referenceSlot{})},
	} {
		if uint64(part.count) > uint64(math.MaxInt)/uint64(part.size) {
			return 0, ErrConfiguration
		}
		bytes := uint64(part.count) * uint64(part.size)
		if bytes > math.MaxUint64-total {
			return 0, ErrConfiguration
		}
		total += bytes
	}
	if config.AllocationOverheadBytes > math.MaxUint64-total {
		return 0, ErrConfiguration
	}
	return total + config.AllocationOverheadBytes, nil
}

func NewRoot(config Config) (*Root, error) {
	backing, err := BackingBytes(config)
	if err != nil || backing > config.Limit[SDKBytes] {
		return nil, ErrConfiguration
	}
	return &Root{profile: config.ProfileRevision, limit: config.Limit, used: Vector{SDKBytes: backing},
		accounts: make([]accountSlot, int(config.AccountSlots)), charges: make([]chargeSlot, int(config.ReservationSlots)), refs: make([]referenceSlot, int(config.ReferenceSlots))}, nil
}

func (r *Root) Account(key AccountKey, limit Vector) (Account, error) {
	if r == nil || key.Kind < TenantAccount || key.Kind > PoolAccount || key.ID == [16]byte{} || limit == (Vector{}) {
		return Account{}, ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Account{}, ErrClosed
	}
	free := -1
	for i := range r.accounts {
		s := &r.accounts[i]
		if s.active && s.key == key {
			if s.limit != limit {
				return Account{}, ErrConfiguration
			}
			if s.closed {
				return Account{}, ErrClosed
			}
			return Account{r, uint32(i), s.generation}, nil
		}
		if !s.active && s.generation < math.MaxUint64 && free < 0 {
			free = i
		}
	}
	if free < 0 {
		return Account{}, ErrCapacity
	}
	s := &r.accounts[free]
	*s = accountSlot{generation: s.generation + 1, key: key, limit: limit, active: true}
	return Account{r, uint32(free), s.generation}, nil
}

func (a Account) slotLocked(r *Root) *accountSlot {
	if a.root != r || a.generation == 0 || uint64(a.index) >= uint64(len(r.accounts)) {
		return nil
	}
	s := &r.accounts[a.index]
	if !s.active || s.generation != a.generation {
		return nil
	}
	return s
}

// Close seals this scope, including existing submission gates, without
// releasing its outstanding backing or another Environment's reservations.
func (a Account) Close() {
	if a.root == nil {
		return
	}
	r := a.root
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := a.slotLocked(r); s != nil {
		s.closed = true
		if s.charges == 0 {
			s.active = false
		}
	}
	r.drainWaitersLocked()
}

func (a Account) Usage() (Vector, error) {
	if a.root == nil {
		return Vector{}, ErrOwner
	}
	r := a.root
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := a.slotLocked(r); s != nil {
		return s.used, nil
	}
	return Vector{}, ErrOwner
}

type Snapshot struct {
	Limit, Charged           Vector
	Reservations, References uint32
	ResultOwners             uint32
	Closed, CleanupComplete  bool
}

func (r *Root) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Snapshot{Limit: r.limit, Charged: r.used, Reservations: r.chargeCount, References: r.referenceCount, ResultOwners: r.resultCount, Closed: r.closed, CleanupComplete: r.closed && r.chargeCount == 0}
}

func (r *Root) Close() { r.mu.Lock(); r.closed = true; r.drainWaitersLocked(); r.mu.Unlock() }
