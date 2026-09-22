package ledgerv4

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var (
	ErrStorageFormat      = errors.New("ledgerv4: storage format incompatible")
	ErrStorageUnavailable = errors.New("ledgerv4: storage unavailable")
)

const sqlitePageBytes = 4096

// SQLiteLimits fixes one local transaction group's admitted bounds. Full page
// cache/transaction backing is accounted separately from the supplied driver
// runtime allowance. Filesystem metadata and allocation granularity belong in
// DiskOverheadBytes. These are host limits, not a wire profile or an RSS claim.
type SQLiteLimits struct {
	MaxPages, MaxRecords, MaxRecordBytes                  uint32
	RuntimeBytes, ProviderRuntimeBytes, DiskOverheadBytes uint64
}

func (l SQLiteLimits) valid() bool {
	return l.MaxPages >= 16 && l.MaxPages <= 1<<20 && l.MaxRecords > 0 && l.MaxRecords <= 1<<20 && l.MaxRecordBytes >= 1024 && l.MaxRecordBytes <= 1<<20 && l.RuntimeBytes > 0 && l.ProviderRuntimeBytes > 0 && l.DiskOverheadBytes > 0
}

// SQLiteBackingCharge covers files across connection shutdown and restart.
// Checkpointing before every subsequent write bounds WAL to one full database
// transaction, including its frame headers and shared-memory index segments.
func SQLiteBackingCharge(l SQLiteLimits) (resourcev4.Vector, error) {
	if !l.valid() {
		return resourcev4.Vector{}, ErrConfiguration
	}
	pages := uint64(l.MaxPages)
	disk := pages*sqlitePageBytes + 32 + pages*(sqlitePageBytes+24) + (1+pages/4096)*32768
	if l.DiskOverheadBytes > math.MaxUint64-disk {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteBacking{})) + uint64(unsafe.Sizeof(sqliteBacking{})) + 4096, resourcev4.DiskBytes: disk + l.DiskOverheadBytes, resourcev4.Items: 1}, nil
}

// SQLiteBacking owns the persistent namespace allocation independently of a
// live database connection. Closing a store cannot refund files that still
// contain once history. The host retains this owner across store reopen.
// ReleaseRemoved never deletes data; the trusted host must first discharge all
// history obligations and remove the complete database through its own policy.
type SQLiteBacking struct{ *sqliteBacking }

type sqliteBacking struct {
	mu                       sync.Mutex
	path                     string
	limits                   SQLiteLimits
	reservation, environment resourcev4.Reference
	active, closed, released bool
}

func NewSQLiteBacking(path string, limits SQLiteLimits, reservation, environment resourcev4.Reference) (*SQLiteBacking, error) {
	charge, err := SQLiteBackingCharge(limits)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrConfiguration
	}
	if err := reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	shared, err := environment.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	return &SQLiteBacking{&sqliteBacking{path: strings.Clone(path), limits: limits, reservation: owned, environment: shared}}, nil
}

func (b *SQLiteBacking) acquire(environment resourcev4.Reference) (resourcev4.Reference, error) {
	if b == nil || b.sqliteBacking == nil {
		return resourcev4.Reference{}, ErrConfiguration
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.released {
		return resourcev4.Reference{}, ErrOwner
	}
	if b.active {
		return resourcev4.Reference{}, ErrCapacity
	}
	if err := b.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	ref, err := b.reservation.Borrow()
	if err != nil {
		return resourcev4.Reference{}, err
	}
	b.active = true
	return ref, nil
}

func (b *SQLiteBacking) releaseConnection(ref resourcev4.Reference) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ref.Release()
	b.active = false
}

func (b *SQLiteBacking) checkFiles() error {
	pages := uint64(b.limits.MaxPages)
	for _, file := range []struct {
		suffix string
		limit  uint64
	}{{"", pages * sqlitePageBytes}, {"-wal", 32 + pages*(sqlitePageBytes+24)}, {"-shm", (1 + pages/4096) * 32768}, {"-journal", 0}} {
		info, err := os.Lstat(b.path + file.suffix)
		if os.IsNotExist(err) && file.suffix != "" {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() < 0 {
			return ErrStorageUnavailable
		}
		if uint64(info.Size()) > file.limit || file.suffix == "-journal" {
			return ErrCapacity
		}
	}
	return nil
}

// Close seals this backing against another Open while retaining all live
// references and durable file charges. It performs no database or filesystem I/O.
func (b *SQLiteBacking) Close() {
	if b == nil || b.sqliteBacking == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.reservation.Seal()
}

func (b *SQLiteBacking) ReleaseRemoved() error {
	if b == nil || b.sqliteBacking == nil {
		return ErrConfiguration
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.released {
		return nil
	}
	if !b.closed || b.active {
		return ErrOwner
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(b.path + suffix); !os.IsNotExist(err) {
			return ErrOwner
		}
	}
	b.released = true
	b.path = ""
	b.reservation.Release()
	b.environment.Release()
	return nil
}
