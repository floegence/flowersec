package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"math"
)

const auditArchiveManifestSQL = `CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-audit-archive'), revision INTEGER NOT NULL CHECK(revision=1), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 512), records_count INTEGER NOT NULL CHECK(records_count>=0)) STRICT, WITHOUT ROWID`
const auditArchiveEventsSQL = `CREATE TABLE archived_events (event_id BLOB PRIMARY KEY CHECK(length(event_id)=16), sequence INTEGER NOT NULL CHECK(sequence>0), recorded BLOB NOT NULL CHECK(length(recorded)=8), expires BLOB NOT NULL CHECK(length(expires)=8), record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 512)) STRICT, WITHOUT ROWID`

func (a *SQLiteAuditArchive) secureDelete() error {
	if err := a.store.exec("PRAGMA secure_delete=ON"); err != nil {
		return err
	}
	value, err := a.store.scalar("PRAGMA secure_delete")
	if err != nil || value != int64(1) {
		return ErrStorageUnavailable
	}
	return nil
}
func (a *SQLiteAuditArchive) createSchema() (err error) {
	s := a.store.sqliteStore
	if err = a.secureDelete(); err != nil {
		return err
	}
	if err = s.boundPages(); err != nil {
		return err
	}
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer namespaceRollback(s, &err)
	for _, statement := range []string{auditArchiveManifestSQL, auditArchiveEventsSQL} {
		if err = s.exec(statement); err != nil {
			return err
		}
	}
	l := s.backing.limits
	if err = s.exec("INSERT INTO manifest VALUES(1,'flowersec-v4-audit-archive',1,?1,?2,?3,?4,?5,?6,?7,?8,0)", named(1, s.identity.Authority), named(2, s.identity.StoreID[:]), named(3, sqliteUint(s.identity.Generation)), named(4, sqliteUint(1)), named(5, int64(l.MaxPages)), named(6, int64(l.MaxRecords)), named(7, int64(l.MaxRecordBytes)), named(8, a.configuration[:a.configurationBytes])); err != nil {
		return err
	}
	if err = s.exec("PRAGMA user_version=1"); err != nil {
		return err
	}
	if err = s.continuity.Check(s.identity, 0, true); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	s.epoch = 1
	return s.checkpoint()
}
func (a *SQLiteAuditArchive) openSchema(readOnly bool) (err error) {
	s := a.store.sqliteStore
	if !readOnly {
		if err = a.secureDelete(); err != nil {
			return err
		}
	}
	version, err := s.scalar("PRAGMA user_version")
	if err != nil || version != int64(1) {
		return ErrStorageFormat
	}
	count, err := s.scalar("SELECT count(*) FROM sqlite_schema")
	if err != nil || count != int64(2) {
		return ErrStorageFormat
	}
	for _, table := range []struct{ name, sql string }{{"manifest", auditArchiveManifestSQL}, {"archived_events", auditArchiveEventsSQL}} {
		size, err := s.scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || size != int64(len(table.sql)) {
			return ErrStorageFormat
		}
		ddl, err := s.scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || ddl != table.sql {
			return ErrStorageFormat
		}
	}
	if !readOnly {
		if err = s.boundPages(); err != nil {
			return err
		}
		if err = s.checkpoint(); err != nil {
			return err
		}
		if err = s.exec("BEGIN IMMEDIATE"); err != nil {
			return err
		}
		defer namespaceRollback(s, &err)
	}
	var epoch uint64
	err = s.readOne("SELECT format,revision,CASE WHEN length(CAST(authority AS BLOB))<=128 THEN authority ELSE NULL END,CASE WHEN length(instance)=32 THEN instance ELSE NULL END,CASE WHEN length(generation)=8 THEN generation ELSE NULL END,CASE WHEN length(epoch)=8 THEN epoch ELSE NULL END,max_pages,max_records,max_record_bytes,CASE WHEN length(configuration)<=512 THEN configuration ELSE NULL END FROM manifest WHERE id=1", 10, func(v []driver.Value) error {
		id, ok := v[3].([]byte)
		config, cok := v[9].([]byte)
		generation, ge := readSQLiteUint(v[4])
		var ee error
		epoch, ee = readSQLiteUint(v[5])
		l := s.backing.limits
		if v[0] != "flowersec-v4-audit-archive" || v[1] != int64(1) || v[2] != s.identity.Authority || !ok || !bytes.Equal(id, s.identity.StoreID[:]) || ge != nil || generation != s.identity.Generation || ee != nil || epoch == 0 || epoch == math.MaxUint64 || v[6] != int64(l.MaxPages) || v[7] != int64(l.MaxRecords) || v[8] != int64(l.MaxRecordBytes) || !cok || !bytes.Equal(config, a.configuration[:a.configurationBytes]) {
			return ErrStorageFormat
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err = a.verifyRecords(); err != nil {
		return err
	}
	if readOnly {
		return nil
	}
	if err = s.continuity.Check(s.identity, epoch, false); err != nil {
		return err
	}
	s.epoch = epoch + 1
	if err = s.exec("UPDATE manifest SET epoch=?1 WHERE id=1", named(1, sqliteUint(s.epoch))); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	return s.checkpoint()
}
func (a *SQLiteAuditArchive) count() (uint32, error) {
	value, err := a.store.scalar("SELECT records_count FROM manifest WHERE id=1")
	if err != nil {
		return 0, err
	}
	n, ok := value.(int64)
	if !ok || n < 0 || uint64(n) > uint64(a.config.Records) {
		return 0, ErrStorageFormat
	}
	return uint32(n), nil
}

const auditArchiveColumns = "sequence,CASE WHEN length(event_id)=16 THEN event_id ELSE NULL END,CASE WHEN length(recorded)=8 THEN recorded ELSE NULL END,CASE WHEN length(expires)=8 THEN expires ELSE NULL END,CASE WHEN length(record)<=512 THEN record ELSE NULL END"

func (a *SQLiteAuditArchive) recordRow(row []driver.Value) (AuditRecord, error) {
	if len(row) != 5 {
		return AuditRecord{}, ErrStorageFormat
	}
	sequence, sok := row[0].(int64)
	id, iok := row[1].([]byte)
	stamp, se := readSQLiteUint(row[2])
	expiry, ee := readSQLiteUint(row[3])
	wire, wok := row[4].([]byte)
	if !sok || sequence < 1 || !iok || len(id) != 16 || se != nil || ee != nil || !wok || len(wire) > auditRecordBytes {
		return AuditRecord{}, ErrStorageFormat
	}
	record, err := DecodeAuditRecord(wire)
	if err != nil || !bytes.Equal(record.EventID[:], id) || record.UTCMS != stamp || stamp > math.MaxUint64-a.config.RetentionMS || expiry != stamp+a.config.RetentionMS || record.Tenant != a.config.Tenant || record.Object != a.config.Object {
		return AuditRecord{}, ErrStorageFormat
	}
	return record, nil
}
func (a *SQLiteAuditArchive) verifyRecords() (err error) {
	n, err := a.count()
	if err != nil {
		return err
	}
	count, err := a.store.scalar("SELECT count(*) FROM archived_events")
	if err != nil || count != int64(n) {
		return ErrStorageFormat
	}
	duplicates, err := a.store.scalar("SELECT count(*) FROM (SELECT sequence FROM archived_events GROUP BY sequence HAVING count(*)<>1)")
	if err != nil || duplicates != int64(0) {
		return ErrStorageFormat
	}
	rows, err := a.store.querier.QueryContext(context.Background(), "SELECT "+auditArchiveColumns+" FROM archived_events ORDER BY sequence", nil)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	if len(rows.Columns()) != 5 {
		return ErrStorageFormat
	}
	var row [5]driver.Value
	for i := uint32(0); ; i++ {
		if err = rows.Next(row[:]); err == io.EOF {
			if i != n {
				return ErrStorageFormat
			}
			return nil
		}
		if err != nil {
			return err
		}
		if i >= n {
			return ErrStorageFormat
		}
		if _, err = a.recordRow(row[:]); err != nil {
			return err
		}
		clear(row[:])
	}
}
