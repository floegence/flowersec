package ledgerv4

import (
	"database/sql/driver"
	"errors"
	"math"
	"strconv"
	"strings"

	sqlite3 "modernc.org/sqlite/lib"
)

// StorageFormatReason is a finite refusal classification, never provider text.
type StorageFormatReason string

const (
	StorageFormatBackend          StorageFormatReason = "backend_configuration"
	StorageFormatManifest         StorageFormatReason = "manifest_unknown_or_invalid"
	StorageFormatIdentity         StorageFormatReason = "identity_mismatch"
	StorageFormatRevisionConflict StorageFormatReason = "revision_conflict"
	StorageFormatOlder            StorageFormatReason = "older_revision"
	StorageFormatNewer            StorageFormatReason = "newer_revision"
	StorageFormatState            StorageFormatReason = "schema_or_state_invalid"
)

// StorageRevision reports unknown explicitly. Value is zero when Known is false.
type StorageRevision struct {
	Known bool   `json:"known"`
	Value uint32 `json:"value"`
}

// StorageFormatProjection contains only fixed runtime identifiers, validated
// revision numbers and finite classifications. It contains no stored identity,
// database contents, provider error, path, command or executable URL.
type StorageFormatProjection struct {
	Code                     string              `json:"code"`
	TransactionGroup         string              `json:"transaction_group"`
	WireProfile              string              `json:"wire_profile"`
	ObservedRevision         StorageRevision     `json:"observed_revision"`
	RequiredRevision         uint32              `json:"required_revision"`
	Reason                   StorageFormatReason `json:"reason"`
	ExactConversionAvailable bool                `json:"exact_conversion_available"`
}

// StorageFormatError preserves errors.Is(err, ErrStorageFormat). Projection
// returns a value copy; callers cannot mutate the original refusal facts.
type StorageFormatError struct{ projection StorageFormatProjection }

func (e *StorageFormatError) Error() string { return "ledgerv4: storage_format_incompatible" }
func (e *StorageFormatError) Unwrap() error { return ErrStorageFormat }
func (e *StorageFormatError) Projection() StorageFormatProjection {
	return e.projection
}

type sqliteStorageFormat struct {
	group    string
	revision uint32
}

// The group identifier also binds the backend and unique wire in the manifest.
// Tables that commit together, including the top-up server's audit rows, share
// one identifier and revision. These values never come from a refused store.
func (s *sqliteStore) storageFormat() sqliteStorageFormat {
	switch {
	case s.publication != nil:
		return sqliteStorageFormat{"flowersec-v4-publication", 1}
	case s.archive != nil:
		return sqliteStorageFormat{"flowersec-v4-audit-archive", 1}
	case s.namespace != nil:
		return sqliteStorageFormat{"flowersec-v4-verification", 1}
	case s.topUpServer != nil:
		return sqliteStorageFormat{"flowersec-v4-topup-server", 2}
	case s.topUps != nil:
		return sqliteStorageFormat{"flowersec-v4-topup-client", 3}
	case s.business != nil:
		return sqliteStorageFormat{"flowersec-v4-executions", 4}
	case s.references != nil:
		return sqliteStorageFormat{"flowersec-v4-references", 1}
	default:
		return sqliteStorageFormat{"flowersec-v4-sqlite", sqliteStorageRevision}
	}
}

func (f sqliteStorageFormat) refusal(observed StorageRevision, reason StorageFormatReason) error {
	return &StorageFormatError{StorageFormatProjection{
		Code: "storage_format_incompatible", TransactionGroup: f.group,
		WireProfile: "flowersec-v4-transport-security", ObservedRevision: observed,
		RequiredRevision: f.revision, Reason: reason,
		// No trusted exact revision-pair converter is shipped by this runtime.
		ExactConversionAvailable: false,
	}}
}

func (s *sqliteStore) projectStorageFormat(err error, observed StorageRevision, reason StorageFormatReason) error {
	var refusal *StorageFormatError
	if errors.As(err, &refusal) {
		return err
	}
	if errors.Is(err, ErrStorageFormat) {
		return s.storageFormat().refusal(observed, reason)
	}
	var provider interface{ Code() int }
	if errors.As(err, &provider) {
		switch provider.Code() & 0xff {
		case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
			return ErrStorageUnavailable
		case sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB:
			return s.storageFormat().refusal(StorageRevision{}, StorageFormatManifest)
		}
	}
	return err
}

const sqliteManifestPrefixBytes = 512

// inspectStorageHeader reads only the fixed manifest envelope. It never decodes
// old records or accepts an old schema. A known revision requires a matching
// format, fixed physical header columns, configured identity, valid epoch and
// agreement between the manifest's declaration, row and user_version hint.
func (s *sqliteStore) inspectStorageHeader() (StorageRevision, error) {
	f := s.storageFormat()
	unknown := StorageRevision{}
	refuse := func(reason StorageFormatReason) (StorageRevision, error) {
		return unknown, f.refusal(unknown, reason)
	}
	// Bound the returned schema bytes before materializing them. A view, virtual
	// table or altered header cannot supply trusted revision observations.
	value, err := s.scalar("SELECT substr(CAST(sql AS BLOB),1,512) FROM sqlite_schema WHERE type='table' AND name='manifest'")
	if err != nil {
		return refuse(StorageFormatManifest)
	}
	prefix, ok := value.([]byte)
	if !ok || len(prefix) > sqliteManifestPrefixBytes {
		return refuse(StorageFormatManifest)
	}
	start := "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='" + f.group + "'), revision INTEGER NOT NULL CHECK(revision="
	declaration, ok := strings.CutPrefix(string(prefix), start)
	if !ok {
		return refuse(StorageFormatManifest)
	}
	digits, rest, ok := strings.Cut(declaration, ")")
	revision, parseErr := strconv.ParseUint(digits, 10, 32)
	const headerTail = "), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8),"
	if !ok || parseErr != nil || revision == 0 || digits != strconv.FormatUint(revision, 10) || !strings.HasPrefix(")"+rest, headerTail) {
		return refuse(StorageFormatManifest)
	}
	var identityMatches, revisionMatches bool
	// Predicates return bounded booleans instead of copying stored text/blob
	// values. LIMIT 2 and readOne also reject absent or multiple manifest rows.
	err = s.readOne("SELECT id=1,typeof(format)='text' AND format=?1,CASE WHEN typeof(revision)='integer' AND revision BETWEEN 1 AND 4294967295 THEN revision ELSE NULL END,typeof(authority)='text' AND authority=?2,typeof(instance)='blob' AND instance=?3,typeof(generation)='blob' AND generation=?4,CASE WHEN typeof(epoch)='blob' AND length(epoch)=8 THEN epoch ELSE NULL END FROM manifest LIMIT 2", 7, func(v []driver.Value) error {
		epoch, epochErr := readSQLiteUint(v[6])
		if v[0] != int64(1) || v[1] != int64(1) || epochErr != nil || epoch == 0 || epoch == math.MaxUint64 {
			return ErrStorageFormat
		}
		identityMatches = v[3] == int64(1) && v[4] == int64(1) && v[5] == int64(1)
		revisionMatches = v[2] == int64(revision)
		return nil
	}, named(1, f.group), named(2, s.identity.Authority), named(3, s.identity.StoreID[:]), named(4, sqliteUint(s.identity.Generation)))
	if err != nil {
		return refuse(StorageFormatManifest)
	}
	if !identityMatches {
		return refuse(StorageFormatIdentity)
	}
	hint, err := s.scalar("PRAGMA user_version")
	if err != nil || !revisionMatches || hint != int64(revision) {
		return refuse(StorageFormatRevisionConflict)
	}
	observed := StorageRevision{Known: true, Value: uint32(revision)}
	if revision < uint64(f.revision) {
		return observed, f.refusal(observed, StorageFormatOlder)
	}
	if revision > uint64(f.revision) {
		return observed, f.refusal(observed, StorageFormatNewer)
	}
	return observed, nil
}

// inspectCurrentStorage never configures durable storage, advances an epoch,
// invokes a recovery writer or selects another revision's decoder.
func (s *sqliteStore) inspectCurrentStorage() (err error) {
	if err = s.exec("PRAGMA trusted_schema=OFF"); err != nil {
		return s.projectStorageFormat(err, StorageRevision{}, StorageFormatBackend)
	}
	if err = s.exec("BEGIN"); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, s.exec("ROLLBACK")) }()
	observed, err := s.inspectStorageHeader()
	if err != nil {
		return err
	}
	if err = s.openSchema(true); err != nil {
		return s.projectStorageFormat(err, observed, StorageFormatState)
	}
	integrity, integrityErr := s.scalar("PRAGMA quick_check")
	if integrityErr != nil || integrity != "ok" {
		return s.storageFormat().refusal(observed, StorageFormatState)
	}
	mode, modeErr := s.scalar("PRAGMA journal_mode")
	page, pageErr := s.scalar("PRAGMA page_size")
	if modeErr != nil || pageErr != nil || mode != "wal" || page != int64(sqlitePageBytes) {
		return s.storageFormat().refusal(observed, StorageFormatBackend)
	}
	return s.backing.checkFiles()
}
