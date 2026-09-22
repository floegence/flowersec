package ledgerv4

import (
	"context"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"modernc.org/sqlite"
)

const sqliteStorageRevision = 2

// SQLiteIdentity is independently configured stable authority identity. It is
// not learned from the database or a peer. Generation changes require the
// trusted restoration procedure; ordinary Open never rewrites this binding.
type SQLiteIdentity struct {
	Authority  string
	StoreID    [32]byte
	Generation uint64
}

// SQLiteContinuity is the trusted host's independent history/provisioning gate.
// Check must be bounded local work, without I/O or application callbacks. For
// create it must authorize a truly new empty namespace. For open it must prove
// the current deployment may use this complete history, including any required
// external recovery anchor. A SQLite file cannot attest against its own rollback.
// Its immutable storage is preadmitted in the same Environment and retained
// through actual store cleanup. There is deliberately no default implementation.
type SQLiteContinuity interface {
	Check(identity SQLiteIdentity, epoch uint64, create bool) error
}

type SQLiteStore struct{ *sqliteStore }
type sqliteStore struct {
	mu                                sync.Mutex
	backing                           *SQLiteBacking
	identity                          SQLiteIdentity
	continuity                        SQLiteContinuity
	epoch                             uint64
	conn                              driver.Conn
	business                          *SQLiteExecutions
	references                        *SQLiteReferences
	workPins                          uint32
	execer                            driver.ExecerContext
	querier                           driver.QueryerContext
	reservation, environment, disk    resourcev4.Reference
	active, closed, complete, retired bool
	closeErr                          error
	wake, done                        chan struct{}
}

// SQLiteStoreCharge includes one synchronous driver connection, a full pager
// and transaction cache bound plus explicit qualified driver/runtime overhead.
// The original persistent disk allocation is charged by SQLiteBacking.
func SQLiteStoreCharge(l SQLiteLimits) (resourcev4.Vector, error) {
	if !l.valid() {
		return resourcev4.Vector{}, ErrConfiguration
	}
	sdk := uint64(unsafe.Sizeof(SQLiteStore{})) + uint64(unsafe.Sizeof(sqliteStore{})) + 128
	provider := uint64(l.MaxPages)*sqlitePageBytes*2 + uint64(l.MaxRecordBytes)*2
	if l.RuntimeBytes > math.MaxUint64-sdk || l.ProviderRuntimeBytes > math.MaxUint64-provider {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: sdk + l.RuntimeBytes, resourcev4.ProviderBytes: provider + l.ProviderRuntimeBytes, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.NativeHandles: 4}, nil
}

func validSQLiteIdentity(identity SQLiteIdentity) bool {
	if identity.StoreID == ([32]byte{}) || identity.Generation == 0 || len(identity.Authority) == 0 || len(identity.Authority) > 128 {
		return false
	}
	for _, b := range []byte(identity.Authority) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == ':') {
			return false
		}
	}
	return true
}

// CreateSQLite explicitly provisions one new file. Failure never deletes or
// reinitializes it, because a commit may already have become durable. The
// backing owner continues charging any files left by that failed attempt.
func CreateSQLite(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, reservation, environment resourcev4.Reference) (*SQLiteStore, error) {
	return openSQLite(ctx, backing, identity, continuity, reservation, environment, true)
}

// OpenSQLite accepts only the exact current manifest and schema. It never
// creates an absent database or treats incompatible/unknown state as empty.
func OpenSQLite(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, reservation, environment resourcev4.Reference) (*SQLiteStore, error) {
	return openSQLite(ctx, backing, identity, continuity, reservation, environment, false)
}

func openSQLite(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, reservation, environment resourcev4.Reference, create bool) (result *SQLiteStore, err error) {
	return openSQLitePurpose(ctx, backing, identity, continuity, reservation, environment, create, nil, nil)
}

func openSQLitePurpose(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, reservation, environment resourcev4.Reference, create bool, business *SQLiteExecutionConfig, references *SQLiteReferenceConfig) (result *SQLiteStore, err error) {
	if business != nil && references != nil {
		return nil, ErrConfiguration
	}
	if ctx == nil || backing == nil || backing.sqliteBacking == nil || continuity == nil || !validSQLiteIdentity(identity) {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	charge, err := SQLiteStoreCharge(backing.limits)
	if business != nil {
		charge, err = SQLiteExecutionsCharge(backing.limits, *business)
	}
	if references != nil {
		charge, err = SQLiteReferencesCharge(backing.limits, *references)
	}
	if err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	disk, err := backing.acquire(environment)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && result == nil {
			backing.releaseConnection(disk)
		}
	}()
	shared, err := environment.Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && result == nil {
			shared.Release()
		}
	}()
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && result == nil {
			owned.Release()
		}
	}()
	if create {
		if err = continuity.Check(identity, 0, true); err != nil {
			return nil, err
		}
		// Refuse a leftover journal as well as an existing database. An
		// interrupted older initialization is never an empty-namespace proof.
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			if _, statErr := os.Lstat(backing.path + suffix); !os.IsNotExist(statErr) {
				return nil, ErrStorageUnavailable
			}
		}
		var f *os.File
		f, err = os.OpenFile(backing.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		err = f.Close()
		if err != nil {
			return nil, err
		}
	} else {
		var info os.FileInfo
		info, err = os.Lstat(backing.path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, ErrStorageUnavailable
		}
	}
	if err = backing.checkFiles(); err != nil {
		return nil, err
	}
	d := &sqlite.Driver{}
	u := url.URL{Scheme: "file", Path: backing.path, RawQuery: "mode=rw"}
	connection, err := d.Open(u.String())
	if err != nil {
		return nil, err
	}
	execer, execOK := connection.(driver.ExecerContext)
	querier, queryOK := connection.(driver.QueryerContext)
	s := &sqliteStore{backing: backing, identity: identity, continuity: continuity, conn: connection, execer: execer, querier: querier, reservation: owned, environment: shared, disk: disk, wake: make(chan struct{}, 1), done: make(chan struct{})}
	defer func() {
		if err != nil {
			if closeErr := connection.Close(); closeErr != nil {
				// A provider that cannot prove cleanup remains charged. Return
				// its incomplete owner even though construction failed.
				s.closed = true
				s.closeErr = closeErr
				close(s.done)
				result = &SQLiteStore{s}
				err = errors.Join(err, closeErr)
			}
		}
	}()
	if !execOK || !queryOK {
		return nil, ErrConfiguration
	}
	s.identity.Authority = strings.Clone(identity.Authority)
	if business != nil {
		s.business, err = newSQLiteExecutions(s, *business)
		if err != nil {
			return nil, err
		}
	}
	if references != nil {
		s.references, err = newSQLiteReferences(s, *references)
		if err != nil {
			return nil, err
		}
	}
	if err = s.configure(create); err != nil {
		return nil, err
	}
	if create {
		err = s.createSchema()
	} else {
		err = s.openSchema()
	}
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = s.reservation.Check(); err != nil {
		return nil, err
	}
	if err = s.disk.Check(); err != nil {
		return nil, err
	}
	if err = continuity.Check(s.identity, s.epoch, false); err != nil {
		return nil, err
	}
	if create {
		if err = syncSQLiteDirectory(backing.path); err != nil {
			return nil, err
		}
	}
	if s.business != nil {
		s.business.refreshCapacity()
	}
	go s.cleanupWorker()
	return &SQLiteStore{s}, nil
}

func syncSQLiteDirectory(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	return errors.Join(err, dir.Close())
}

// Driver calls intentionally have no cancellable context: this pinned driver
// otherwise creates unjoined per-statement interrupt tasks. The original
// invocation remains synchronous and charged through its actual return. Busy
// waiting is disabled; bounded fixed statements do not retry on contention.
func (s *sqliteStore) exec(query string, args ...driver.NamedValue) error {
	_, err := s.execer.ExecContext(context.Background(), query, args)
	return err
}

// readOne lends the sole driver's row to a finite SDK decoder before either
// stepping or finalizing. consume must copy/decode blobs synchronously and may
// not retain them or start another database statement on this connection.
func (s *sqliteStore) readOne(query string, columns int, consume func([]driver.Value) error, args ...driver.NamedValue) (err error) {
	if columns < 1 || columns > 16 || consume == nil {
		return ErrConfiguration
	}
	rows, err := s.querier.QueryContext(context.Background(), query, args)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	if len(rows.Columns()) != columns {
		return ErrStorageFormat
	}
	var row [16]driver.Value
	if err = rows.Next(row[:columns]); err != nil {
		return err
	}
	if err = consume(row[:columns]); err != nil {
		return err
	}
	if err = rows.Next(row[:columns]); err != io.EOF {
		return ErrStorageFormat
	}
	return nil
}

func (s *sqliteStore) one(query string, output []driver.Value, args ...driver.NamedValue) error {
	return s.readOne(query, len(output), func(row []driver.Value) error {
		// Copy driver-owned blobs before the cursor advances or is finalized.
		for i, value := range row {
			if blob, ok := value.([]byte); ok {
				output[i] = append([]byte(nil), blob...)
			} else {
				output[i] = value
			}
		}
		return nil
	}, args...)
}

func (s *sqliteStore) scalar(query string, args ...driver.NamedValue) (driver.Value, error) {
	var out [1]driver.Value
	err := s.one(query, out[:], args...)
	return out[0], err
}

func sqliteUint(value uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	return out[:]
}
func readSQLiteUint(value driver.Value) (uint64, error) {
	b, ok := value.([]byte)
	if !ok || len(b) != 8 {
		return 0, ErrStorageFormat
	}
	return binary.BigEndian.Uint64(b), nil
}

func (s *sqliteStore) begin(ctx context.Context) error {
	if ctx == nil {
		return ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.complete {
		return ErrOwner
	}
	if s.active {
		return ErrCapacity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, ref := range []resourcev4.Reference{s.reservation, s.environment, s.disk} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	s.active = true
	return nil
}

func (s *sqliteStore) end() {
	if s.business != nil {
		s.business.refreshCapacity()
	}
	s.mu.Lock()
	s.active = false
	s.signalLocked()
	s.mu.Unlock()
}
func (s *sqliteStore) signalLocked() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *SQLiteStore) Close() {
	if s == nil || s.sqliteStore == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.reservation.Seal()
		s.signalLocked()
	}
}

func (s *sqliteStore) cleanupWorker() {
	for {
		s.mu.Lock()
		if s.closed && !s.active && s.workPins == 0 {
			conn := s.conn
			s.mu.Unlock()
			err := conn.Close()
			s.mu.Lock()
			s.closeErr = err
			if err == nil {
				s.conn = nil
				s.execer = nil
				s.querier = nil
				s.continuity = nil
				s.complete = true
			}
			close(s.done)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		<-s.wake
	}
}

func (s *SQLiteStore) WaitCleanup(ctx context.Context) error {
	if s == nil || s.sqliteStore == nil || ctx == nil {
		return ErrConfiguration
	}
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SQLiteStore) Retire() error {
	if s == nil || s.sqliteStore == nil {
		return ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.complete {
		return ErrOwner
	}
	if !s.retired {
		s.retired = true
		s.backing.releaseConnection(s.disk)
		s.disk = resourcev4.Reference{}
		s.backing = nil
		s.environment.Release()
		s.reservation.Release()
	}
	return nil
}
