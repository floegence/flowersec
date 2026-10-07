package ledgerv4

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func storageFormatProjection(t *testing.T, err error) StorageFormatProjection {
	t.Helper()
	var refusal *StorageFormatError
	if !errors.Is(err, ErrStorageFormat) || !errors.As(err, &refusal) {
		t.Fatal("missing typed format refusal", err)
	}
	p := refusal.Projection()
	if p.Code != "storage_format_incompatible" || p.WireProfile != "flowersec-v4-transport-security" || p.ExactConversionAvailable {
		t.Fatal("untrusted format or converter projection", p)
	}
	copy := refusal.Projection()
	copy.RequiredRevision = 99
	if refusal.Projection() != p {
		t.Fatal("caller changed original refusal")
	}
	return p
}

// These are synthetic fixed-header fixtures, not supported historical record
// formats or claims that a converter exists for either revision pair.
func replaceStorageHeaderRevision(t *testing.T, s *SQLiteStore, revision uint32) {
	t.Helper()
	number := strconv.FormatUint(uint64(revision), 10)
	for _, statement := range []string{
		"ALTER TABLE manifest RENAME TO prior_manifest",
		strings.Replace(sqliteManifestSQL, "CHECK(revision="+strconv.FormatUint(sqliteStorageRevision, 10)+")", "CHECK(revision="+number+")", 1),
		"INSERT INTO manifest SELECT id,format," + number + ",authority,instance,generation,epoch,max_pages,max_records,max_record_bytes,admission_rows,spend_rows,winner_rows,issuance_rows,relay_rows FROM prior_manifest",
		"DROP TABLE prior_manifest",
		"PRAGMA user_version=" + number,
	} {
		if err := s.exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLiteStorageFormatRefusalFactsAndRedaction(t *testing.T) {
	for _, test := range []struct {
		name     string
		mutate   func(*testing.T, *SQLiteStore)
		observed StorageRevision
		reason   StorageFormatReason
	}{
		{"older_header", func(t *testing.T, s *SQLiteStore) { replaceStorageHeaderRevision(t, s, 2) }, StorageRevision{true, 2}, StorageFormatOlder},
		{"newer_header", func(t *testing.T, s *SQLiteStore) { replaceStorageHeaderRevision(t, s, sqliteStorageRevision+1) }, StorageRevision{true, sqliteStorageRevision + 1}, StorageFormatNewer},
		{"newer_before_current_tables", func(t *testing.T, s *SQLiteStore) {
			replaceStorageHeaderRevision(t, s, sqliteStorageRevision+1)
			formatMutation("DROP TABLE admission", "CREATE TABLE future_admission(private_value TEXT)")(t, s)
		}, StorageRevision{true, sqliteStorageRevision + 1}, StorageFormatNewer},
		{"newer_before_backend_configuration", func(t *testing.T, s *SQLiteStore) {
			replaceStorageHeaderRevision(t, s, sqliteStorageRevision+1)
			formatMutation("PRAGMA journal_mode=DELETE")(t, s)
		}, StorageRevision{true, sqliteStorageRevision + 1}, StorageFormatNewer},
		{"hint_only", formatMutation("PRAGMA user_version=2"), StorageRevision{}, StorageFormatRevisionConflict},
		{"row_only", formatMutation("PRAGMA ignore_check_constraints=ON", "UPDATE manifest SET revision=2", "PRAGMA user_version=2"), StorageRevision{}, StorageFormatRevisionConflict},
		{"identity", formatMutation("UPDATE manifest SET authority='private.authority.marker'"), StorageRevision{}, StorageFormatIdentity},
		{"foreign_format", formatMutation("PRAGMA ignore_check_constraints=ON", "UPDATE manifest SET format='private.format.marker'"), StorageRevision{}, StorageFormatManifest},
		{"invalid_epoch", formatMutation("PRAGMA ignore_check_constraints=ON", "UPDATE manifest SET epoch=x'00'"), StorageRevision{}, StorageFormatManifest},
		{"extra_manifest_row", formatMutation("PRAGMA ignore_check_constraints=ON", "INSERT INTO manifest SELECT 2,format,revision,authority,instance,generation,epoch,max_pages,max_records,max_record_bytes,admission_rows,spend_rows,winner_rows,issuance_rows,relay_rows FROM manifest"), StorageRevision{}, StorageFormatManifest},
		{"missing_manifest", formatMutation("DROP TABLE manifest"), StorageRevision{}, StorageFormatManifest},
		{"count_mismatch", formatMutation("UPDATE manifest SET admission_rows=1"), StorageRevision{true, sqliteStorageRevision}, StorageFormatState},
		{"unexpected_table", formatMutation("CREATE TABLE private_schema_marker (secret TEXT)"), StorageRevision{true, sqliteStorageRevision}, StorageFormatState},
		{"view_header", formatMutation("ALTER TABLE manifest RENAME TO private_manifest_marker", "CREATE VIEW manifest AS SELECT * FROM private_manifest_marker"), StorageRevision{}, StorageFormatManifest},
		{"oversized_header_value", formatMutation("PRAGMA ignore_check_constraints=ON", "UPDATE manifest SET authority=CAST(zeroblob(1048576) AS TEXT)"), StorageRevision{}, StorageFormatIdentity},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSQLiteFixture(t, "")
			// Give the oversized-value fixture sufficient admitted physical space.
			if test.name == "oversized_header_value" {
				f = newSQLiteFixtureWithLimits(t, "", SQLiteLimits{MaxPages: 512, MaxRecords: 16, MaxRecordBytes: 4096, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})
			}
			s := f.create()
			test.mutate(t, s)
			closeSQLite(t, s)
			before, err := os.ReadFile(f.backing.path)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := f.open(false)
			if opened != nil {
				t.Fatal("incompatible store returned a usable owner")
			}
			p := storageFormatProjection(t, err)
			if p.TransactionGroup != "flowersec-v4-sqlite" || p.RequiredRevision != sqliteStorageRevision || p.ObservedRevision != test.observed || p.Reason != test.reason {
				t.Fatal("incorrect bounded refusal", p)
			}
			wire, encodeErr := json.Marshal(p)
			if encodeErr != nil || len(wire) > 512 || strings.Contains(string(wire), "private") || strings.Contains(string(wire), f.backing.path) || err.Error() != "ledgerv4: storage_format_incompatible" {
				t.Fatal("format refusal leaked store/provider data", string(wire), err, encodeErr)
			}
			after, readErr := os.ReadFile(f.backing.path)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal repaired or rewrote history", readErr)
			}
		})
	}
}

func formatMutation(statements ...string) func(*testing.T, *SQLiteStore) {
	return func(t *testing.T, s *SQLiteStore) {
		t.Helper()
		for _, statement := range statements {
			if err := s.exec(statement); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSQLiteStorageFormatCorruptFileReportsUnknown(t *testing.T) {
	f := newSQLiteFixture(t, "")
	if err := os.WriteFile(f.backing.path, []byte("private.corrupt.database.marker"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := f.open(false)
	p := storageFormatProjection(t, err)
	if p.Reason != StorageFormatManifest || p.ObservedRevision.Known || p.ObservedRevision.Value != 0 {
		t.Fatal("corrupt file guessed a source revision", p)
	}
	if _, err := f.open(true); !os.IsExist(err) {
		t.Fatal("format refusal enabled destructive create", err)
	}
}

func TestSQLiteStorageFormatUsesRequestedTransactionGroup(t *testing.T) {
	t.Run("executions", func(t *testing.T) {
		f := newBusinessFixture(t, "")
		s, err := f.openBusiness(true)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.store.exec("PRAGMA user_version=5"); err != nil {
			t.Fatal(err)
		}
		closeSQLite(t, s.store)
		_, err = f.openBusiness(false)
		p := storageFormatProjection(t, err)
		if p.TransactionGroup != "flowersec-v4-executions" || p.RequiredRevision != 4 || p.ObservedRevision.Known {
			t.Fatal("execution group used another group's revision", p)
		}
	})
	t.Run("verification", func(t *testing.T) {
		f := newSQLiteNamespaceFixture(t)
		h, err := f.openHistory(true)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.store.exec("PRAGMA user_version=2"); err != nil {
			t.Fatal(err)
		}
		closeSQLite(t, h.store)
		_, err = f.openHistory(false)
		p := storageFormatProjection(t, err)
		if p.TransactionGroup != "flowersec-v4-verification" || p.RequiredRevision != 1 || p.ObservedRevision.Known {
			t.Fatal("verification group used another group's revision", p)
		}
	})
}
