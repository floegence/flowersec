package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"math"
)

const referenceManifestSQL = `CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-references'), revision INTEGER NOT NULL CHECK(revision=1), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, domain TEXT NOT NULL CHECK(length(CAST(domain AS BLOB)) BETWEEN 1 AND 128), retention BLOB NOT NULL CHECK(length(retention)=8), max_bytes BLOB NOT NULL CHECK(length(max_bytes)=8), records INTEGER NOT NULL CHECK(records>=0), bytes INTEGER NOT NULL CHECK(bytes>=0)) STRICT, WITHOUT ROWID`
const referenceRowsSQL = `CREATE TABLE refs (key BLOB PRIMARY KEY CHECK(length(key)=32), saved BLOB NOT NULL CHECK(length(saved)=8), expires BLOB NOT NULL CHECK(length(expires)=8), reference BLOB NOT NULL CHECK(length(reference) BETWEEN 1 AND 2048)) STRICT, WITHOUT ROWID`

func (r *SQLiteReferences) createSchema() (err error) {
	s := r.store.sqliteStore
	if err = s.boundPages(); err != nil {
		return err
	}
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.exec("ROLLBACK"))
		}
	}()
	for _, query := range []string{referenceManifestSQL, referenceRowsSQL} {
		if err = s.exec(query); err != nil {
			return err
		}
	}
	l := s.backing.limits
	if err = s.exec("INSERT INTO manifest VALUES (1,'flowersec-v4-references',1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,0)", named(1, s.identity.Authority), named(2, s.identity.StoreID[:]), named(3, sqliteUint(s.identity.Generation)), named(4, sqliteUint(1)), named(5, int64(l.MaxPages)), named(6, int64(l.MaxRecords)), named(7, int64(l.MaxRecordBytes)), named(8, r.config.Domain), named(9, sqliteUint(r.config.RetentionMS)), named(10, sqliteUint(r.config.MaxBytes))); err != nil {
		return err
	}
	if err = s.exec("PRAGMA user_version=1"); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	s.epoch = 1
	return s.checkpoint()
}

func (r *SQLiteReferences) verifySchema() error {
	s := r.store.sqliteStore
	version, err := s.scalar("PRAGMA user_version")
	if err != nil {
		return err
	}
	if version != int64(1) {
		return ErrStorageFormat
	}
	count, err := s.scalar("SELECT count(*) FROM sqlite_schema")
	if err != nil {
		return err
	}
	if count != int64(2) {
		return ErrStorageFormat
	}
	for _, table := range []struct{ name, sql string }{{"manifest", referenceManifestSQL}, {"refs", referenceRowsSQL}} {
		length, err := s.scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || length != int64(len(table.sql)) {
			return ErrStorageFormat
		}
		actual, err := s.scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || actual != table.sql {
			return ErrStorageFormat
		}
	}
	return nil
}

func (r *SQLiteReferences) readManifest() (epoch, records, total uint64, err error) {
	s := r.store.sqliteStore
	rows, err := s.querier.QueryContext(context.Background(), "SELECT format,revision,CASE WHEN length(CAST(authority AS BLOB))<=128 THEN authority ELSE NULL END,CASE WHEN length(instance)=32 THEN instance ELSE NULL END,CASE WHEN length(generation)=8 THEN generation ELSE NULL END,CASE WHEN length(epoch)=8 THEN epoch ELSE NULL END,max_pages,max_records,max_record_bytes,CASE WHEN length(CAST(domain AS BLOB))<=128 THEN domain ELSE NULL END,CASE WHEN length(retention)=8 THEN retention ELSE NULL END,CASE WHEN length(max_bytes)=8 THEN max_bytes ELSE NULL END,records,bytes FROM manifest WHERE id=1", nil)
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var v [14]driver.Value
	if err = rows.Next(v[:]); err != nil {
		return 0, 0, 0, ErrStorageFormat
	}
	id, iok := v[3].([]byte)
	generation, ge := readSQLiteUint(v[4])
	epoch, err = readSQLiteUint(v[5])
	retention, re := readSQLiteUint(v[10])
	maxBytes, be := readSQLiteUint(v[11])
	count, cok := v[12].(int64)
	size, sok := v[13].(int64)
	l := s.backing.limits
	if v[0] != "flowersec-v4-references" || v[1] != int64(1) || v[2] != s.identity.Authority || !iok || !bytes.Equal(id, s.identity.StoreID[:]) || ge != nil || generation != s.identity.Generation || err != nil || epoch == 0 || epoch == math.MaxUint64 || v[6] != int64(l.MaxPages) || v[7] != int64(l.MaxRecords) || v[8] != int64(l.MaxRecordBytes) || v[9] != r.config.Domain || re != nil || retention != r.config.RetentionMS || be != nil || maxBytes != r.config.MaxBytes || !cok || count < 0 || count > int64(l.MaxRecords) || !sok || size < 0 || uint64(size) > maxBytes {
		return 0, 0, 0, ErrStorageFormat
	}
	if err = rows.Next(v[:]); err != io.EOF {
		return 0, 0, 0, ErrStorageFormat
	}
	return epoch, uint64(count), uint64(size), nil
}

func (r *SQLiteReferences) nextKey(after [32]byte) (key [32]byte, found bool, err error) {
	rows, err := r.store.querier.QueryContext(context.Background(), "SELECT CASE WHEN length(key)=32 THEN key ELSE NULL END FROM refs WHERE key>?1 ORDER BY key LIMIT 1", []driver.NamedValue{named(1, after[:])})
	if err != nil {
		return key, false, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var v [1]driver.Value
	if err = rows.Next(v[:]); err == io.EOF {
		return key, false, nil
	} else if err != nil {
		return key, false, err
	}
	b, ok := v[0].([]byte)
	if !ok || len(b) != 32 {
		return key, false, ErrStorageFormat
	}
	copy(key[:], b)
	if err = rows.Next(v[:]); err != io.EOF {
		return key, false, ErrStorageFormat
	}
	return key, true, nil
}

func (r *SQLiteReferences) openSchema() (err error) {
	s := r.store.sqliteStore
	if err = r.verifySchema(); err != nil {
		return err
	}
	epoch, records, total, err := r.readManifest()
	if err != nil {
		return err
	}
	count, err := s.scalar("SELECT count(*) FROM manifest")
	if err != nil || count != int64(1) {
		return ErrStorageFormat
	}
	actualCount, err := s.scalar("SELECT count(*) FROM refs")
	if err != nil || actualCount != int64(records) {
		return ErrStorageFormat
	}
	var actual, bytes uint64
	var cursor [32]byte
	defer clear(r.existing[:])
	for {
		key, found, err := r.nextKey(cursor)
		if err != nil {
			return err
		}
		if !found {
			break
		}
		if actual >= records {
			return ErrStorageFormat
		}
		n, _, present, err := r.readRow(key)
		if err != nil {
			return err
		}
		if !present || uint64(n) > total-bytes {
			return ErrStorageFormat
		}
		actual++
		bytes += uint64(n)
		cursor = key
	}
	if actual != records || bytes != total {
		return ErrStorageFormat
	}
	// This is local namespace/owner continuity only; the resulting objects are
	// query locators, never evidence that an execution was absent or completed.
	if err = s.continuity.Check(s.identity, epoch, false); err != nil {
		return err
	}
	if err = s.boundPages(); err != nil {
		return err
	}
	if err = s.checkpoint(); err != nil {
		return err
	}
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.exec("ROLLBACK"))
		}
	}()
	s.epoch = epoch + 1
	if err = s.exec("UPDATE manifest SET epoch=?1 WHERE id=1 AND epoch=?2", named(1, sqliteUint(s.epoch)), named(2, sqliteUint(epoch))); err != nil {
		return err
	}
	if err = s.changedOne(); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	return s.checkpoint()
}
