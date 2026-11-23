package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"fmt"
	"io"
	"math"
)

const sqliteManifestSQL = `CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-sqlite'), revision INTEGER NOT NULL CHECK(revision=2), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, admission_rows INTEGER NOT NULL CHECK(admission_rows>=0), spend_rows INTEGER NOT NULL CHECK(spend_rows>=0)) STRICT, WITHOUT ROWID`
const sqliteAdmissionSQL = `CREATE TABLE admission (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3), admission_count INTEGER NOT NULL CHECK(admission_count IN (0,1)), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576), CHECK((state=1 AND admission_count=1) OR (state<>1 AND admission_count=0))) STRICT, WITHOUT ROWID`

// Purpose tables have independent lease keys; one admission does not stand in
// for a spend, even when both share this local transaction domain.
const sqliteSpendSQL = `CREATE TABLE spend (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), source INTEGER NOT NULL CHECK(source IN (0,1)), state INTEGER NOT NULL CHECK(state IN (0,1)), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576), CHECK(source=0 OR state=1)) STRICT, WITHOUT ROWID`

func (s *sqliteStore) configure(create bool) error {
	if create {
		if err := s.exec("PRAGMA page_size=4096"); err != nil {
			return err
		}
	}
	modeQuery := "PRAGMA journal_mode"
	if create {
		modeQuery = "PRAGMA journal_mode=WAL"
	}
	mode, err := s.scalar(modeQuery)
	if err != nil {
		return err
	}
	if mode != "wal" {
		return ErrStorageFormat
	}
	page, err := s.scalar("PRAGMA page_size")
	if err != nil {
		return err
	}
	if page != int64(sqlitePageBytes) {
		return ErrStorageFormat
	}
	for _, setting := range []struct {
		name, value string
		expected    driver.Value
	}{
		{"synchronous", "FULL", int64(2)},
		{"fullfsync", "ON", int64(1)},
		{"checkpoint_fullfsync", "ON", int64(1)},
		{"foreign_keys", "ON", int64(1)},
		{"trusted_schema", "OFF", int64(0)},
		{"busy_timeout", "0", int64(0)},
		{"temp_store", "MEMORY", int64(2)},
		{"cache_spill", "OFF", int64(0)},
		{"wal_autocheckpoint", "0", int64(0)},
		{"locking_mode", "EXCLUSIVE", "exclusive"},
		{"cache_size", fmt.Sprint(s.backing.limits.MaxPages), int64(s.backing.limits.MaxPages)},
	} {
		if err := s.exec("PRAGMA " + setting.name + "=" + setting.value); err != nil {
			return err
		}
		actual, err := s.scalar("PRAGMA " + setting.name)
		if err != nil {
			return err
		}
		if actual != setting.expected {
			return ErrConfiguration
		}
	}
	return nil
}

func (s *sqliteStore) boundPages() error {
	pages, err := s.scalar("PRAGMA max_page_count=" + fmt.Sprint(s.backing.limits.MaxPages))
	if err != nil {
		return err
	}
	if pages != int64(s.backing.limits.MaxPages) {
		return ErrCapacity
	}
	wal := uint64(32) + uint64(s.backing.limits.MaxPages)*(sqlitePageBytes+24)
	actual, err := s.scalar("PRAGMA journal_size_limit=" + fmt.Sprint(wal))
	if err != nil {
		return err
	}
	if actual != int64(wal) {
		return ErrConfiguration
	}
	return nil
}

func named(ordinal int, value driver.Value) driver.NamedValue {
	return driver.NamedValue{Ordinal: ordinal, Value: value}
}

func (s *sqliteStore) createSchema() (err error) {
	if s.business != nil {
		return s.business.createSchema()
	}
	if s.references != nil {
		return s.references.createSchema()
	}
	if err = s.boundPages(); err != nil {
		return err
	}
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = s.exec("ROLLBACK")
		}
	}()
	for _, sql := range []string{sqliteManifestSQL, sqliteAdmissionSQL, sqliteSpendSQL} {
		if err = s.exec(sql); err != nil {
			return err
		}
	}
	l := s.backing.limits
	err = s.exec("INSERT INTO manifest VALUES (1,'flowersec-v4-sqlite',2,?1,?2,?3,?4,?5,?6,?7,0,0)", named(1, s.identity.Authority), named(2, s.identity.StoreID[:]), named(3, sqliteUint(s.identity.Generation)), named(4, sqliteUint(1)), named(5, int64(l.MaxPages)), named(6, int64(l.MaxRecords)), named(7, int64(l.MaxRecordBytes)))
	if err != nil {
		return err
	}
	if err = s.exec("PRAGMA user_version=2"); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	s.epoch = 1
	return s.checkpoint()
}

// A full checkpoint must complete before the next write, so no prior live
// reader or failed truncation can cause unbounded WAL accumulation. A failure
// never undoes or disproves the previous transaction's committed fact.
func (s *sqliteStore) checkpoint() error {
	var output [3]driver.Value
	if err := s.one("PRAGMA wal_checkpoint(TRUNCATE)", output[:]); err != nil {
		return err
	}
	if output[0] != int64(0) || output[1] != int64(0) || output[2] != int64(0) {
		return ErrStorageUnavailable
	}
	return nil
}

func (s *sqliteStore) verifySchema() error {
	version, err := s.scalar("PRAGMA user_version")
	if err != nil {
		return err
	}
	if version != int64(sqliteStorageRevision) {
		return ErrStorageFormat
	}
	count, err := s.scalar("SELECT count(*) FROM sqlite_schema")
	if err != nil {
		return err
	}
	if count != int64(3) {
		return ErrStorageFormat
	}
	for _, table := range []struct{ name, sql string }{{"manifest", sqliteManifestSQL}, {"admission", sqliteAdmissionSQL}, {"spend", sqliteSpendSQL}} {
		// Table names are compile-time constants, never caller input. Check the
		// length first to avoid loading an oversized incompatible definition.
		n, err := s.scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil {
			return ErrStorageFormat
		}
		if n != int64(len(table.sql)) {
			return ErrStorageFormat
		}
		actual, err := s.scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil {
			return ErrStorageFormat
		}
		if actual != table.sql {
			return ErrStorageFormat
		}
	}
	return nil
}

func (s *sqliteStore) openSchema() (err error) {
	if s.business != nil {
		return s.business.openSchema()
	}
	if s.references != nil {
		return s.references.openSchema()
	}
	if err = s.verifySchema(); err != nil {
		return err
	}
	rows, err := s.querier.QueryContext(context.Background(), "SELECT format,revision,authority,instance,generation,epoch,max_pages,max_records,max_record_bytes,admission_rows,spend_rows FROM manifest WHERE id=1", nil)
	if err != nil {
		return ErrStorageFormat
	}
	var values [11]driver.Value
	readErr := rows.Next(values[:])
	if readErr != nil {
		_ = rows.Close()
		return ErrStorageFormat
	}
	generation, genErr := readSQLiteUint(values[4])
	epoch, epochErr := readSQLiteUint(values[5])
	id, idOK := values[3].([]byte)
	l := s.backing.limits
	count, countOK := values[9].(int64)
	spendCount, spendCountOK := values[10].(int64)
	valid := values[0] == "flowersec-v4-sqlite" && values[1] == int64(sqliteStorageRevision) && values[2] == s.identity.Authority && idOK && bytes.Equal(id, s.identity.StoreID[:]) && genErr == nil && generation == s.identity.Generation && epochErr == nil && epoch > 0 && epoch < math.MaxUint64 && values[6] == int64(l.MaxPages) && values[7] == int64(l.MaxRecords) && values[8] == int64(l.MaxRecordBytes) && countOK && count >= 0 && count <= int64(l.MaxRecords) && spendCountOK && spendCount >= 0 && spendCount <= int64(l.MaxRecords)-count
	if !valid {
		_ = rows.Close()
		return ErrStorageFormat
	}
	if err = rows.Next(values[:]); err != io.EOF {
		_ = rows.Close()
		return ErrStorageFormat
	}
	if err = rows.Close(); err != nil {
		return err
	}
	actual, err := s.scalar("SELECT count(*) FROM admission")
	if err != nil {
		return err
	}
	if actual != count {
		return ErrStorageFormat
	}
	actualSpend, err := s.scalar("SELECT count(*) FROM spend")
	if err != nil {
		return err
	}
	if actualSpend != spendCount {
		return ErrStorageFormat
	}
	if err = s.continuity.Check(s.identity, epoch, false); err != nil {
		return err
	}
	if err = s.boundPages(); err != nil {
		return err
	}
	// The exclusive connection keeps the validated manifest stable. A crash
	// may have left a complete transaction in WAL; checkpoint it before the
	// new incarnation's write so both transactions cannot accumulate there.
	if err = s.checkpoint(); err != nil {
		return err
	}
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = s.exec("ROLLBACK")
		}
	}()
	// Each newly owned connection is a new fenced authority incarnation.
	// Restored rows retain their old commit fence and never recover guards.
	s.epoch = epoch + 1
	if err = s.exec("UPDATE manifest SET epoch=?1 WHERE id=1", named(1, sqliteUint(s.epoch))); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	return s.checkpoint()
}
