package ledgerv4

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"math"
	"strconv"
)

const topUpManifestSQL = `CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-topup-client'), revision INTEGER NOT NULL CHECK(revision=3), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 512), binding BLOB NOT NULL CHECK(length(binding)=8), next_sequence BLOB NOT NULL CHECK(length(next_sequence)=8), retired_sequence BLOB NOT NULL CHECK(length(retired_sequence)=8), frontier BLOB NOT NULL CHECK(length(frontier)=8), state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 4), pending BLOB NOT NULL CHECK(length(pending)<=1024), applied BLOB NOT NULL CHECK(length(applied)<=1024), identity BLOB NOT NULL CHECK(length(identity)<=65536), key_reference BLOB NOT NULL CHECK(length(key_reference)<=512), pool_count INTEGER NOT NULL CHECK(pool_count>=0), pool_bytes INTEGER NOT NULL CHECK(pool_bytes>=0), terminal BLOB NOT NULL CHECK(length(terminal)<=2048), permanent_fence BLOB NOT NULL CHECK(length(permanent_fence)=8)) STRICT, WITHOUT ROWID`
const topUpPoolSQL = `CREATE TABLE pool (sequence BLOB PRIMARY KEY CHECK(length(sequence)=8), generation BLOB NOT NULL CHECK(length(generation)=8), expiry BLOB NOT NULL CHECK(length(expiry)=8), material_digest BLOB NOT NULL CHECK(length(material_digest)=32), identity_digest BLOB NOT NULL CHECK(length(identity_digest)=32), record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID`

func (j *SQLiteTopUpJournal) createSchema() (err error) {
	s := j.store.sqliteStore
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
	for _, query := range []string{topUpManifestSQL, topUpPoolSQL} {
		if err = s.exec(query); err != nil {
			return err
		}
	}
	l := s.backing.limits
	if err = s.exec("INSERT INTO manifest VALUES (1,'flowersec-v4-topup-client',3,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?11,0,x'',x'',x'',x'',0,0,x'',?11)", named(1, s.identity.Authority), named(2, s.identity.StoreID[:]), named(3, sqliteUint(s.identity.Generation)), named(4, sqliteUint(1)), named(5, int64(l.MaxPages)), named(6, int64(l.MaxRecords)), named(7, int64(l.MaxRecordBytes)), named(8, j.configuration[:j.configurationBytes]), named(9, sqliteUint(j.config.BindingGeneration)), named(10, sqliteUint(1)), named(11, sqliteUint(0))); err != nil {
		return err
	}
	if err = s.exec("PRAGMA user_version=3"); err != nil {
		return err
	}
	if err = j.check(); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	s.epoch = 1
	return s.checkpoint()
}
func (j *SQLiteTopUpJournal) openSchema() (err error) {
	s := j.store.sqliteStore
	version, err := s.scalar("PRAGMA user_version")
	if err != nil || version != int64(3) {
		return ErrStorageFormat
	}
	count, err := s.scalar("SELECT count(*) FROM sqlite_schema")
	if err != nil || count != int64(2) {
		return ErrStorageFormat
	}
	for _, table := range []struct{ name, sql string }{{"manifest", topUpManifestSQL}, {"pool", topUpPoolSQL}} {
		n, err := s.scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || n != int64(len(table.sql)) {
			return ErrStorageFormat
		}
		actual, err := s.scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || actual != table.sql {
			return ErrStorageFormat
		}
	}
	var epoch uint64
	err = s.readOne("SELECT format,revision,CASE WHEN length(CAST(authority AS BLOB))<=128 THEN authority ELSE NULL END,CASE WHEN length(instance)=32 THEN instance ELSE NULL END,CASE WHEN length(generation)=8 THEN generation ELSE NULL END,CASE WHEN length(epoch)=8 THEN epoch ELSE NULL END,max_pages,max_records,max_record_bytes,CASE WHEN length(configuration)<=512 THEN configuration ELSE NULL END,pool_count,pool_bytes FROM manifest WHERE id=1", 12, func(v []driver.Value) error {
		id, ok := v[3].([]byte)
		config, cok := v[9].([]byte)
		generation, ge := readSQLiteUint(v[4])
		var ee error
		epoch, ee = readSQLiteUint(v[5])
		l := s.backing.limits
		rows, rok := v[10].(int64)
		size, sok := v[11].(int64)
		if v[0] != "flowersec-v4-topup-client" || v[1] != int64(3) || v[2] != s.identity.Authority || !ok || !bytes.Equal(id, s.identity.StoreID[:]) || ge != nil || generation != s.identity.Generation || ee != nil || epoch == 0 || epoch == math.MaxUint64 || v[6] != int64(l.MaxPages) || v[7] != int64(l.MaxRecords) || v[8] != int64(l.MaxRecordBytes) || !cok || !bytes.Equal(config, j.configuration[:j.configurationBytes]) || !rok || !sok || rows < 0 || rows > int64(l.MaxRecords-1) || size < 0 || uint64(size) > j.config.PoolBytes {
			return ErrStorageFormat
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Validate aggregate storage bounds before exposing any recovered frontier.
	var actual [2]driver.Value
	if err = s.one("SELECT count(*),coalesce(sum(length(record)),0) FROM pool", actual[:]); err != nil {
		return err
	}
	var expected [2]driver.Value
	if err = s.one("SELECT pool_count,pool_bytes FROM manifest WHERE id=1", expected[:]); err != nil {
		return err
	}
	if actual != expected {
		return ErrStorageFormat
	}
	invalid, err := s.scalar("SELECT count(*) FROM pool WHERE length(record)>" + strconv.FormatUint(uint64(s.backing.limits.MaxRecordBytes), 10))
	if err != nil || invalid != int64(0) {
		return ErrStorageFormat
	}
	state, err := j.readRecovery()
	if err != nil {
		return err
	}
	if j.config.BindingGeneration < state.BindingGeneration {
		return ErrFenced
	}
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
	if err = j.check(); err != nil {
		return err
	}
	s.epoch = epoch + 1
	// Only independently authorized new-owner construction advances this fence.
	// Original pending generation and all Applied entry generations stay intact.
	if err = s.exec("UPDATE manifest SET epoch=?1,binding=?2 WHERE id=1", named(1, sqliteUint(s.epoch)), named(2, sqliteUint(j.config.BindingGeneration))); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	return s.checkpoint()
}
