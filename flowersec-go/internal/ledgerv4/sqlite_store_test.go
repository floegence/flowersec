package ledgerv4

import (
	"context"
	"database/sql/driver"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type sqliteContinuityFunc func(SQLiteIdentity, uint64, bool) error

func (f sqliteContinuityFunc) Check(i SQLiteIdentity, e uint64, create bool) error {
	return f(i, e, create)
}

type sqliteFixture struct {
	t           *testing.T
	root        *resourcev4.Root
	environment resourcev4.Reference
	backing     *SQLiteBacking
	identity    SQLiteIdentity
	continuity  SQLiteContinuity
	stores      []*SQLiteStore
	next        byte
}

func newSQLiteFixture(t *testing.T, path string) *sqliteFixture {
	return newSQLiteFixtureWithLimits(t, path, SQLiteLimits{MaxPages: 64, MaxRecords: 16, MaxRecordBytes: 4096, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})
}

func newSQLiteFixtureWithLimits(t *testing.T, path string, l SQLiteLimits) *sqliteFixture {
	t.Helper()
	if path == "" {
		path = filepath.Join(t.TempDir(), "ledger.db")
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 2, ReservationSlots: 16, ReferenceSlots: 64}
	for i := range config.Limit {
		config.Limit[i] = 1 << 32
	}
	r, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	f := &sqliteFixture{t: t, root: r, identity: SQLiteIdentity{Authority: "admission.test", StoreID: [32]byte{3}, Generation: 1}}
	f.environment = f.reserve(resourcev4.Vector{resourcev4.Items: 1}, 1)
	charge, err := SQLiteBackingCharge(l)
	if err != nil {
		t.Fatal(err)
	}
	f.backing, err = NewSQLiteBacking(path, l, f.reserve(charge, 1), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	f.continuity = sqliteContinuityFunc(func(i SQLiteIdentity, _ uint64, _ bool) error {
		if i != f.identity {
			return ErrFenced
		}
		return nil
	})
	t.Cleanup(func() {
		for _, s := range f.stores {
			s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			if err := s.WaitCleanup(ctx); err != nil {
				t.Error(err)
			}
			cancel()
			if err := s.Retire(); err != nil {
				t.Error(err)
			}
		}
		f.backing.Close()
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		if err := f.backing.ReleaseRemoved(); err != nil {
			t.Error(err)
		}
		f.environment.Release()
		r.Close()
		if !r.Snapshot().CleanupComplete {
			t.Error("actual storage cleanup retained a charge", r.Snapshot())
		}
	})
	return f
}

func (f *sqliteFixture) reserve(charge resourcev4.Vector, environment byte) resourcev4.Reference {
	f.t.Helper()
	f.next++
	r, err := f.root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{environment}, Instance: [16]byte{f.next}, Backing: [16]byte{f.next}, Kind: 1}, charge)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(r.Release)
	return r
}

func (f *sqliteFixture) open(create bool) (*SQLiteStore, error) {
	f.t.Helper()
	charge, err := SQLiteStoreCharge(f.backing.limits)
	if err != nil {
		f.t.Fatal(err)
	}
	r := f.reserve(charge, 1)
	var s *SQLiteStore
	if create {
		s, err = CreateSQLite(context.Background(), f.backing, f.identity, f.continuity, r, f.environment)
	} else {
		s, err = OpenSQLite(context.Background(), f.backing, f.identity, f.continuity, r, f.environment)
	}
	if s != nil {
		f.stores = append(f.stores, s)
	}
	r.Release() // Stale after Take; also releases any refusal before Take.
	return s, err
}

func (f *sqliteFixture) create() *SQLiteStore {
	f.t.Helper()
	s, err := f.open(true)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func closeSQLite(t *testing.T, s *SQLiteStore) {
	t.Helper()
	s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := s.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteCreateReopenAndPersistentBacking(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	if s.epoch != 1 {
		t.Fatal(s.epoch)
	}
	disk := f.root.Snapshot().Charged[resourcev4.DiskBytes]
	copyOwner := *s
	closeSQLite(t, &copyOwner)
	if err := s.Retire(); err != nil {
		t.Fatal(err)
	}
	if disk == 0 || f.root.Snapshot().Charged[resourcev4.DiskBytes] != disk {
		t.Fatal("connection close refunded once history")
	}
	reopened, err := f.open(false)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.epoch != 2 {
		t.Fatal("reopen did not advance original fence", reopened.epoch)
	}
	if _, err = f.open(false); !errors.Is(err, ErrCapacity) {
		t.Fatal("parallel connection admitted", err)
	}
	closeSQLite(t, reopened)
	f.backing.Close()
	if err := f.backing.ReleaseRemoved(); !errors.Is(err, ErrOwner) {
		t.Fatal("durable bytes refunded", err)
	}
}

func TestSQLiteOpenNeverCreatesOrRepairs(t *testing.T) {
	f := newSQLiteFixture(t, "")
	if _, err := f.open(false); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.backing.path); !os.IsNotExist(err) {
		t.Fatal("missing Open created database", err)
	}
	if err := os.WriteFile(f.backing.path, []byte("incompatible"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.open(false); err == nil {
		t.Fatal("invalid file opened")
	}
	if _, err := f.open(true); !os.IsExist(err) {
		t.Fatal("Create replaced existing file", err)
	}
	b, err := os.ReadFile(f.backing.path)
	if err != nil || string(b) != "incompatible" {
		t.Fatal("failure repaired history", err)
	}
}

func TestSQLiteRequiresIndependentContinuityAndEnvironment(t *testing.T) {
	f := newSQLiteFixture(t, "")
	charge, _ := SQLiteStoreCharge(f.backing.limits)
	foreign := f.reserve(charge, 2)
	if _, err := CreateSQLite(context.Background(), f.backing, f.identity, f.continuity, foreign, f.environment); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal(err)
	}
	foreign.Release()
	f.continuity = nil
	if _, err := f.open(true); !errors.Is(err, ErrConfiguration) {
		t.Fatal(err)
	}
	f.continuity = sqliteContinuityFunc(func(SQLiteIdentity, uint64, bool) error { return ErrFenced })
	if _, err := f.open(true); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.backing.path); !os.IsNotExist(err) {
		t.Fatal("denied provisioning wrote file", err)
	}
}

func TestSQLiteRejectsManifestAndSchemaChanges(t *testing.T) {
	for _, change := range []string{
		"PRAGMA user_version=3",
		"UPDATE manifest SET spend_rows=1",
		"UPDATE manifest SET authority='replacement'",
		"UPDATE manifest SET max_records=17",
		"UPDATE manifest SET admission_rows=1",
		"CREATE TABLE unrelated (value TEXT)",
		"CREATE TRIGGER shadow AFTER INSERT ON admission BEGIN SELECT 1; END",
		"CREATE TRIGGER sqliteXerase AFTER UPDATE OF epoch ON manifest BEGIN DELETE FROM admission; END",
	} {
		t.Run(change, func(t *testing.T) {
			f := newSQLiteFixture(t, "")
			s := f.create()
			if err := s.exec(change); err != nil {
				t.Fatal(err)
			}
			closeSQLite(t, s)
			if _, err := f.open(false); !errors.Is(err, ErrStorageFormat) {
				t.Fatal("incompatible store accepted", err)
			}
		})
	}
}

func TestSQLiteExactUnsignedEpochAndOverflow(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	if err := s.exec("UPDATE manifest SET epoch=?1", named(1, sqliteUint(math.MaxUint64-1))); err != nil {
		t.Fatal(err)
	}
	closeSQLite(t, s)
	s, err := f.open(false)
	if err != nil || s.epoch != math.MaxUint64 {
		t.Fatal("epoch narrowed to signed integer", err)
	}
	closeSQLite(t, s)
	if _, err = f.open(false); !errors.Is(err, ErrStorageFormat) {
		t.Fatal("epoch wrapped", err)
	}
}

func TestSQLiteFailedContinuityDoesNotAdvanceEpoch(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	closeSQLite(t, s)
	good := f.continuity
	f.continuity = sqliteContinuityFunc(func(SQLiteIdentity, uint64, bool) error { return ErrFenced })
	if _, err := f.open(false); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	f.continuity = good
	s, err := f.open(false)
	if err != nil || s.epoch != 2 {
		t.Fatal("denied history changed epoch", err)
	}
}

func TestSQLiteBoundsExistingFilesBeforeProviderOpen(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		t.Run(suffix, func(t *testing.T) {
			f := newSQLiteFixture(t, "")
			s := f.create()
			closeSQLite(t, s)
			file, err := os.OpenFile(f.backing.path+suffix, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(1 << 30); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := f.open(false); !errors.Is(err, ErrCapacity) {
				t.Fatal("oversized provider file accepted", err)
			}
		})
	}
}

type blockingSQLiteClose struct {
	driver.Conn
	once             sync.Once
	entered, release chan struct{}
}

func (c *blockingSQLiteClose) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Close()
}

func TestSQLiteCloseRetainsActualCallAndProviderTail(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	c := &blockingSQLiteClose{Conn: s.conn, entered: make(chan struct{}), release: make(chan struct{})}
	s.mu.Lock()
	s.conn = c
	s.mu.Unlock()
	if err := s.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.begin(context.Background()); !errors.Is(err, ErrCapacity) {
		t.Fatal("unbounded waiter admitted", err)
	}
	before := f.root.Snapshot().Charged
	s.Close()
	if err := s.Retire(); !errors.Is(err, ErrOwner) {
		t.Fatal(err)
	}
	select {
	case <-c.entered:
		t.Fatal("provider closed during active call")
	default:
	}
	s.end()
	<-c.entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.root.Snapshot().Charged != before {
		t.Fatal("logical close refunded actual provider tail")
	}
	close(c.release)
	closeSQLite(t, s)
}

// The subprocess exits without closing SQLite. The parent must recover the
// committed WAL before changing the durable authority incarnation.
func TestSQLiteCrashCommittedWAL(t *testing.T) {
	const variable = "FLOWERSEC_SQLITE_CRASH_PATH"
	if path := os.Getenv(variable); path != "" {
		f := newSQLiteFixture(t, path)
		s := f.create()
		if err := s.exec("BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		key := make([]byte, 34)
		key[0] = 1
		if err := s.exec("INSERT INTO admission VALUES (?1,?2,?3,1,1,?4)", named(1, key), named(2, sqliteUint(math.MaxUint64)), named(3, sqliteUint(1)), named(4, []byte("original committed projection"))); err != nil {
			t.Fatal(err)
		}
		if err := s.exec("UPDATE manifest SET admission_rows=1"); err != nil {
			t.Fatal(err)
		}
		if err := s.exec("COMMIT"); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	f := newSQLiteFixture(t, "")
	cmd := exec.Command(os.Args[0], "-test.run=^TestSQLiteCrashCommittedWAL$")
	cmd.Env = append(os.Environ(), variable+"="+f.backing.path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crash helper: %v\n%s", err, output)
	}
	info, err := os.Stat(f.backing.path + "-wal")
	if err != nil || info.Size() <= 32 {
		t.Fatal("helper did not leave committed WAL", err)
	}
	s, err := f.open(false)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.querier.QueryContext(context.Background(), "SELECT version,projection FROM admission", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var values [2]driver.Value
	if err := rows.Next(values[:]); err != nil {
		t.Fatal(err)
	}
	version, err := readSQLiteUint(values[0])
	if err != nil || version != math.MaxUint64 || string(values[1].([]byte)) != "original committed projection" || s.epoch != 2 {
		t.Fatal("lost committed crash history", values, err)
	}
}
