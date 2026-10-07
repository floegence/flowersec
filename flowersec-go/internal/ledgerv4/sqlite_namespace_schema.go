package ledgerv4

import (
	"bytes"
	"database/sql/driver"
	"math"
)

const namespaceManifestSQL = `CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-verification'), revision INTEGER NOT NULL CHECK(revision=1), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 512), snapshot_revision BLOB NOT NULL CHECK(length(snapshot_revision)=8), snapshot_digest BLOB NOT NULL CHECK(length(snapshot_digest)=32), snapshot_bytes INTEGER NOT NULL CHECK(snapshot_bytes>=0)) STRICT, WITHOUT ROWID`
const namespaceChunksSQL = `CREATE TABLE chunks (ordinal INTEGER PRIMARY KEY CHECK(ordinal BETWEEN 0 AND 16799), data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 65536)) STRICT, WITHOUT ROWID`

func (h *SQLiteNamespaceHistory) createSchema() (err error) {
	s := h.store.sqliteStore
	if err = s.boundPages(); err != nil {
		return err
	}
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer namespaceRollback(s, &err)
	for _, query := range []string{namespaceManifestSQL, namespaceChunksSQL} {
		if err = s.exec(query); err != nil {
			return err
		}
	}
	l := s.backing.limits
	var empty [32]byte
	if err = s.exec("INSERT INTO manifest VALUES (1,'flowersec-v4-verification',1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0)", named(1, s.identity.Authority), named(2, s.identity.StoreID[:]), named(3, sqliteUint(s.identity.Generation)), named(4, sqliteUint(1)), named(5, int64(l.MaxPages)), named(6, int64(l.MaxRecords)), named(7, int64(l.MaxRecordBytes)), named(8, h.configuration[:h.configurationBytes]), named(9, sqliteUint(0)), named(10, empty[:])); err != nil {
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

func (h *SQLiteNamespaceHistory) openSchema(readOnly bool) (err error) {
	s := h.store.sqliteStore
	version, err := s.scalar("PRAGMA user_version")
	if err != nil || version != int64(1) {
		return ErrStorageFormat
	}
	count, err := s.scalar("SELECT count(*) FROM sqlite_schema")
	if err != nil || count != int64(2) {
		return ErrStorageFormat
	}
	for _, table := range []struct{ name, sql string }{{"manifest", namespaceManifestSQL}, {"chunks", namespaceChunksSQL}} {
		n, e := s.scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if e != nil || n != int64(len(table.sql)) {
			return ErrStorageFormat
		}
		actual, e := s.scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if e != nil || actual != table.sql {
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
		// Authenticate and fence the exact same transaction snapshot. A concurrent
		// opener cannot pass the old epoch check and later overwrite a newer fence.
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
		if v[0] != "flowersec-v4-verification" || v[1] != int64(1) || v[2] != s.identity.Authority || !ok || !bytes.Equal(id, s.identity.StoreID[:]) || ge != nil || generation != s.identity.Generation || ee != nil || epoch == 0 || epoch == math.MaxUint64 || v[6] != int64(l.MaxPages) || v[7] != int64(l.MaxRecords) || v[8] != int64(l.MaxRecordBytes) || !cok || !bytes.Equal(config, h.configuration[:h.configurationBytes]) {
			return ErrStorageFormat
		}
		return nil
	})
	if err != nil {
		return err
	}
	v, size, err := h.readVersion()
	if err != nil {
		return err
	}
	if size == 0 {
		return ErrStorageUnavailable
	}
	if err = h.checkChunkShape(size); err != nil {
		return err
	}
	if err = h.inspectChunks(size, v.Digest); err != nil {
		return err
	}
	if readOnly {
		return nil
	}
	if err = s.continuity.Check(s.identity, epoch, false); err != nil {
		return err
	}
	if err = h.config.Restore.CheckNamespaceRestore(s.identity, h.config.Scope, v); err != nil {
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

func (h *SQLiteNamespaceHistory) checkChunkShape(size uint64) error {
	count := (size + namespaceChunkBytes - 1) / namespaceChunkBytes
	return h.store.readOne("SELECT count(*),coalesce(sum(length(data)),0),coalesce(min(ordinal),0),coalesce(max(ordinal),-1) FROM chunks", 4, func(v []driver.Value) error {
		if v[0] != int64(count) || v[1] != int64(size) || v[2] != int64(0) || v[3] != int64(count)-1 {
			return ErrStorageFormat
		}
		return nil
	})
}
