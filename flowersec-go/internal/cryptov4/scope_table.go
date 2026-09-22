package cryptov4

import (
	"iter"
	"math"
	"unsafe"
)

type scopeBucket struct {
	scope uint64
	owner *scopeKeys
}

// scopeTable owns one fixed index. Its slots may move or be reused; the unique
// scopeKeys objects never do. Jobs and packets retain their original key owners,
// not table positions. An empty owner marks a hole because scope zero is valid.
type scopeTable struct {
	slots        []scopeBucket
	limit, count int
}

// scopeTableCapacity includes pending authenticated OPENs retained by rejection
// publication after their decoder workspace has returned. Bootstrap occupies a
// positive slot already; maintenance and optional datagram scopes do not.
func scopeTableCapacity(config Config) (int, error) {
	count := uint64(1) + uint64(config.MaxScopes)
	if config.Datagrams {
		count++
	}
	if config.PendingScopes != 0 {
		count += uint64(config.PendingScopes) + uint64(config.WorkSlots)
	}
	if count > uint64(math.MaxInt) {
		return 0, ErrConfiguration
	}
	return int(count), nil
}

// scopeTableSlots is also the exact array shape for preadmission accounting.
// This is index storage only; key objects, crypto and job tails are separate.
func scopeTableSlots(limit int) (int, error) {
	if limit < 1 || limit > math.MaxInt/2 {
		return 0, ErrConfiguration
	}
	n := 1
	for n < 2*limit {
		if n > math.MaxInt/2 {
			return 0, ErrConfiguration
		}
		n *= 2
	}
	if uint64(n) > uint64(math.MaxInt)/uint64(unsafe.Sizeof(scopeBucket{})) {
		return 0, ErrConfiguration
	}
	return n, nil
}

func newScopeTable(limit int) (scopeTable, error) {
	n, err := scopeTableSlots(limit)
	if err != nil {
		return scopeTable{}, err
	}
	return scopeTable{slots: make([]scopeBucket, n), limit: limit}, nil
}

func (s *scopeTable) bucket(scope uint64) int {
	// Mix all scope bits before selecting a power-of-two bucket. Sequential
	// ordinals and peer-chosen strides must not share only their low bits.
	scope ^= scope >> 30
	scope *= 0xbf58476d1ce4e5b9
	scope ^= scope >> 27
	scope *= 0x94d049bb133111eb
	scope ^= scope >> 31
	return int(scope & uint64(len(s.slots)-1))
}

func (s *scopeTable) get(scope uint64) *scopeKeys {
	if len(s.slots) == 0 {
		return nil
	}
	mask := len(s.slots) - 1
	for at, probes := s.bucket(scope), 0; probes < len(s.slots); at, probes = (at+1)&mask, probes+1 {
		entry := &s.slots[at]
		if entry.owner == nil || entry.scope == scope {
			return entry.owner
		}
	}
	return nil
}

func (s *scopeTable) insert(scope uint64, owner *scopeKeys) error {
	if owner == nil || len(s.slots) == 0 {
		return ErrConfiguration
	}
	mask := len(s.slots) - 1
	for at, probes := s.bucket(scope), 0; probes < len(s.slots); at, probes = (at+1)&mask, probes+1 {
		entry := &s.slots[at]
		if entry.owner == nil {
			if s.count == s.limit {
				return ErrCapacity
			}
			*entry = scopeBucket{scope, owner}
			s.count++
			return nil
		}
		if entry.scope == scope {
			return ErrScope
		}
	}
	return ErrCapacity
}

func (s *scopeTable) remove(scope uint64) {
	if len(s.slots) == 0 {
		return
	}
	mask := len(s.slots) - 1
	for at, probes := s.bucket(scope), 0; probes < len(s.slots); at, probes = (at+1)&mask, probes+1 {
		if s.slots[at].owner == nil {
			return
		}
		if s.slots[at].scope != scope {
			continue
		}
		s.slots[at] = scopeBucket{}
		s.count--
		// Move only entries whose search path crosses the hole. No tombstones
		// accumulate, even after every lifetime scope has been used and retired.
		hole := at
		for next, shifts := (at+1)&mask, 0; shifts < len(s.slots); next, shifts = (next+1)&mask, shifts+1 {
			entry := s.slots[next]
			if entry.owner == nil {
				return
			}
			start := s.bucket(entry.scope)
			if (hole-start)&mask < (next-start)&mask {
				s.slots[hole] = entry
				s.slots[next] = scopeBucket{}
				hole = next
			}
		}
		return
	}
}

// all runs only under Engine.mu; callers may not mutate the table during it.
func (s *scopeTable) all() iter.Seq2[uint64, *scopeKeys] {
	return func(yield func(uint64, *scopeKeys) bool) {
		for _, entry := range s.slots {
			if entry.owner != nil && !yield(entry.scope, entry.owner) {
				return
			}
		}
	}
}

func (s *scopeTable) clear() {
	clear(s.slots)
	s.slots = nil
	s.count = 0
}

// Recycle only the index. Its previous epoch loses the slice before that array
// can name another owner, while packet/KDF references keep their unique keys.
func (e *Engine) recycleScopeTable(table *scopeTable) {
	clear(table.slots)
	if !e.closed {
		e.spareScopes = *table
		e.spareScopes.count = 0
	}
	*table = scopeTable{}
}
