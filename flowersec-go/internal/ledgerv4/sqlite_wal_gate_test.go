package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"modernc.org/sqlite"
)

// immutable intentionally excludes WAL here to prove a fixture's committed
// fact is absent from main. Production admission must include the real WAL.
func sqliteMainOnlyScalar(t *testing.T, path, query string) driver.Value {
	t.Helper()
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}
	connection, err := (&sqlite.Driver{}).Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	rows, err := connection.(driver.QueryerContext).QueryContext(context.Background(), query, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result [1]driver.Value
	if err := rows.Next(result[:]); err != nil {
		t.Fatal(err)
	}
	return result[0]
}

func sqliteFileSet(t *testing.T, path string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = body
	}
	return files
}

func assertSQLiteFileSet(t *testing.T, before, after map[string][]byte) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("storage refusal changed the file set: before=%d after=%d", len(before), len(after))
	}
	for name, original := range before {
		body, exists := after[name]
		if !exists || !bytes.Equal(body, original) {
			t.Fatalf("storage refusal changed %s after provider cleanup", name)
		}
	}
}

func TestSQLiteStorageRefusalPreservesActiveReaderWALFileSet(t *testing.T) {
	const variable = "FLOWERSEC_SQLITE_REFUSAL_WAL_PATH"
	if path := os.Getenv(variable); path != "" {
		f := newSQLiteFixture(t, path)
		s := f.create()
		formatMutation("PRAGMA wal_checkpoint(TRUNCATE)", "PRAGMA journal_mode=DELETE", "PRAGMA locking_mode=NORMAL", "PRAGMA journal_mode=WAL")(t, s)
		switch os.Getenv(variable + "_CASE") {
		case "older":
			replaceStorageHeaderRevision(t, s, 2)
		case "current_state":
			formatMutation("UPDATE manifest SET admission_rows=1")(t, s)
		default:
			t.Fatal("unknown WAL fixture")
		}
		// A real process exit preserves committed frames and the original SHM.
		// Closing the last connection here would checkpoint the fixture away.
		os.Exit(0)
	}
	for _, name := range []string{"older", "current_state"} {
		t.Run(name, func(t *testing.T) {
			f := newSQLiteFixture(t, "")
			command := exec.Command(os.Args[0], "-test.run=^TestSQLiteStorageRefusalPreservesActiveReaderWALFileSet$")
			command.Env = append(os.Environ(), variable+"="+f.backing.path, variable+"_CASE="+name)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("WAL fixture: %v\n%s", err, output)
			}
			// Establish a real reader snapshot of the committed WAL before
			// refusal. This covers shared-reader admission; a crash image with
			// no reader has different SQLite SHM initialization semantics.
			u := url.URL{Scheme: "file", Path: f.backing.path, RawQuery: "mode=ro"}
			reader, err := (&sqlite.Driver{}).Open(u.String())
			if err != nil {
				t.Fatal(err)
			}
			readerOpen := true
			closeReader := func() {
				if readerOpen {
					readerOpen = false
					if _, err := reader.(driver.ExecerContext).ExecContext(context.Background(), "ROLLBACK", nil); err != nil {
						t.Error(err)
					}
					if err := reader.Close(); err != nil {
						t.Error(err)
					}
				}
			}
			defer closeReader()
			if _, err := reader.(driver.ExecerContext).ExecContext(context.Background(), "BEGIN", nil); err != nil {
				t.Fatal(err)
			}
			rows, err := reader.(driver.QueryerContext).QueryContext(context.Background(), "SELECT revision FROM manifest", nil)
			if err != nil {
				t.Fatal(err)
			}
			var revision [1]driver.Value
			readErr := rows.Next(revision[:])
			if closeErr := rows.Close(); readErr != nil || closeErr != nil {
				t.Fatal("reader did not establish the committed snapshot", readErr, closeErr)
			}
			before := sqliteFileSet(t, f.backing.path)
			if len(before["ledger.db-wal"]) <= 32 || len(before["ledger.db-shm"]) == 0 {
				t.Fatalf("fixture lacks committed WAL and its original SHM: wal=%d shm=%d", len(before["ledger.db-wal"]), len(before["ledger.db-shm"]))
			}
			opened, err := f.open(false)
			if opened != nil || !errors.Is(err, ErrStorageUnavailable) {
				t.Fatal("exclusive inspection must refuse while an external reader holds the WAL", err)
			}
			assertSQLiteFileSet(t, before, sqliteFileSet(t, f.backing.path))
			closeReader()
			before = sqliteFileSet(t, f.backing.path)
			// Once the unrelated reader releases its lock, the same original
			// store must classify the committed WAL without modifying its files.
			opened, err = f.open(false)
			if opened != nil {
				t.Fatal("incompatible WAL returned a usable store")
			}
			projection := storageFormatProjection(t, err)
			wantRevision, wantReason := uint32(2), StorageFormatOlder
			if name == "current_state" {
				wantRevision, wantReason = sqliteStorageRevision, StorageFormatState
			}
			if projection.ObservedRevision != (StorageRevision{true, wantRevision}) || projection.Reason != wantReason {
				t.Fatal("refusal ignored committed WAL", projection)
			}
			f.backing.mu.Lock()
			active := f.backing.active
			f.backing.mu.Unlock()
			if active {
				t.Fatal("refused open retained its provider or backing lock")
			}
			assertSQLiteFileSet(t, before, sqliteFileSet(t, f.backing.path))
		})
	}
}
