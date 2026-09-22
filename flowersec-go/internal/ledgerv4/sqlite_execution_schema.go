package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"math"
)

const executionManifestSQL = `CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-executions'), revision INTEGER NOT NULL CHECK(revision=4), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 24576), registry_revision BLOB NOT NULL CHECK(length(registry_revision)=8), record_count INTEGER NOT NULL CHECK(record_count>=0), active_count INTEGER NOT NULL CHECK(active_count>=0 AND active_count<=record_count)) STRICT, WITHOUT ROWID`
const executionContractsSQL = `CREATE TABLE contracts (digest BLOB PRIMARY KEY CHECK(length(digest)=32), revision BLOB NOT NULL CHECK(length(revision)=8), type INTEGER NOT NULL CHECK(type BETWEEN 1 AND 4294967295), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), terms BLOB NOT NULL CHECK(length(terms) BETWEEN 1 AND 8192), offers BLOB NOT NULL CHECK(length(offers)<=128 AND length(offers)%16=0)) STRICT, WITHOUT ROWID`
const executionDomainsSQL = `CREATE TABLE domains (authority BLOB PRIMARY KEY CHECK(length(authority)=32), floor BLOB NOT NULL CHECK(length(floor)=8)) STRICT, WITHOUT ROWID`
const executionRecordsSQL = `CREATE TABLE executions (key BLOB PRIMARY KEY CHECK(length(key)=193), request BLOB NOT NULL CHECK(length(request)=32), contract BLOB NOT NULL CHECK(length(contract)=32), invocation BLOB NOT NULL CHECK(length(invocation)=32), terms BLOB NOT NULL CHECK(length(terms) BETWEEN 1 AND 8192), facts BLOB NOT NULL CHECK(length(facts)=104), active INTEGER NOT NULL CHECK(active IN (0,1)), payload BLOB NOT NULL CHECK(length(payload)<=1048576)) STRICT, WITHOUT ROWID`

func (e *SQLiteExecutions) createSchema() (err error) {
	s := e.store.sqliteStore
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
	for _, sql := range [...]string{executionManifestSQL, executionContractsSQL, executionDomainsSQL, executionRecordsSQL, executionRecoveryHeadsSQL, executionRecoveryTokensSQL, executionContentHeadsSQL, executionContentItemsSQL} {
		if err = s.exec(sql); err != nil {
			return err
		}
	}
	l := s.backing.limits
	if err = s.exec("INSERT INTO manifest VALUES (1,'flowersec-v4-executions',4,?1,?2,?3,?4,?5,?6,?7,?8,?9,0,0)", named(1, s.identity.Authority), named(2, s.identity.StoreID[:]), named(3, sqliteUint(s.identity.Generation)), named(4, sqliteUint(1)), named(5, int64(l.MaxPages)), named(6, int64(l.MaxRecords)), named(7, int64(l.MaxRecordBytes)), named(8, e.configuration[:e.configurationBytes]), named(9, sqliteUint(0))); err != nil {
		return err
	}
	for _, a := range e.config.CallerAuthorities {
		if err = s.exec("INSERT INTO domains VALUES (?1,?2)", named(1, a[:]), named(2, sqliteUint(0))); err != nil {
			return err
		}
	}
	if err = s.exec("PRAGMA user_version=4"); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	s.epoch = 1
	return s.checkpoint()
}

func (e *SQLiteExecutions) verifySchema() error {
	s := e.store.sqliteStore
	version, err := s.scalar("PRAGMA user_version")
	if err != nil {
		return err
	}
	if version != int64(4) {
		return ErrStorageFormat
	}
	count, err := s.scalar("SELECT count(*) FROM sqlite_schema")
	if err != nil {
		return err
	}
	if count != int64(8) {
		return ErrStorageFormat
	}
	for _, table := range [...]struct{ name, sql string }{{"manifest", executionManifestSQL}, {"contracts", executionContractsSQL}, {"domains", executionDomainsSQL}, {"executions", executionRecordsSQL}, {"recovery_heads", executionRecoveryHeadsSQL}, {"recovery_tokens", executionRecoveryTokensSQL}, {"content_heads", executionContentHeadsSQL}, {"content_items", executionContentItemsSQL}} {
		n, err := s.scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || n != int64(len(table.sql)) {
			return ErrStorageFormat
		}
		actual, err := s.scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || actual != table.sql {
			return ErrStorageFormat
		}
	}
	return nil
}

func (e *SQLiteExecutions) openSchema() (err error) {
	s := e.store.sqliteStore
	if err = e.verifySchema(); err != nil {
		return err
	}
	manifestCount, err := s.scalar("SELECT count(*) FROM manifest WHERE id=1 AND format='flowersec-v4-executions' AND revision=4")
	if err != nil || manifestCount != int64(1) {
		return ErrStorageFormat
	}
	var epoch uint64
	if epoch, err = e.readManifest(); err != nil {
		return err
	}
	if err = e.verifyRecoveryCounts(); err != nil {
		return err
	}
	if err = e.verifyContentCounts(); err != nil {
		return err
	}
	if err = e.verifyContracts(); err != nil {
		return err
	}
	for _, a := range e.config.CallerAuthorities {
		if _, err = e.floor(a); err != nil {
			return err
		}
	}
	count, err := s.scalar("SELECT count(*) FROM domains")
	if err != nil || count != int64(len(e.config.CallerAuthorities)) {
		return ErrStorageFormat
	}
	// A valid local file is not evidence that no newer business history exists.
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
	// Recovery does not reconstruct any execution work capability. Independent
	// continuity attests that the old actual work was settled or fenced first.
	if err = e.recoverRows(); err != nil {
		return err
	}
	s.epoch = epoch + 1
	if err = s.exec("UPDATE manifest SET epoch=?1,active_count=0 WHERE id=1", named(1, sqliteUint(s.epoch))); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	return s.checkpoint()
}

func (e *SQLiteExecutions) readManifest() (epoch uint64, err error) {
	s := e.store.sqliteStore
	rows, err := s.querier.QueryContext(context.Background(), "SELECT CASE WHEN length(CAST(authority AS BLOB))<=128 THEN authority ELSE NULL END,CASE WHEN length(instance)=32 THEN instance ELSE NULL END,CASE WHEN length(generation)=8 THEN generation ELSE NULL END,CASE WHEN length(epoch)=8 THEN epoch ELSE NULL END,max_pages,max_records,max_record_bytes,CASE WHEN length(configuration)<=24576 THEN configuration ELSE NULL END,CASE WHEN length(registry_revision)=8 THEN registry_revision ELSE NULL END,record_count,active_count FROM manifest WHERE id=1", nil)
	if err != nil {
		return 0, err
	}
	var values [11]driver.Value
	if err = rows.Next(values[:]); err != nil {
		_ = rows.Close()
		return 0, ErrStorageFormat
	}
	id, iok := values[1].([]byte)
	configuration, cok := values[7].([]byte)
	gen, ge := readSQLiteUint(values[2])
	epoch, err = readSQLiteUint(values[3])
	_, re := readSQLiteUint(values[8])
	records, rok := values[9].(int64)
	active, aok := values[10].(int64)
	l := s.backing.limits
	valid := values[0] == s.identity.Authority && iok && bytes.Equal(id, s.identity.StoreID[:]) && ge == nil && gen == s.identity.Generation && err == nil && epoch > 0 && epoch < math.MaxUint64 && values[4] == int64(l.MaxPages) && values[5] == int64(l.MaxRecords) && values[6] == int64(l.MaxRecordBytes) && cok && bytes.Equal(configuration, e.configuration[:e.configurationBytes]) && re == nil && rok && aok && records >= 0 && records <= int64(l.MaxRecords) && active >= 0 && active <= records && active <= int64(e.config.Active)
	if !valid {
		_ = rows.Close()
		return 0, ErrStorageFormat
	}
	if err = rows.Next(values[:]); err != io.EOF {
		_ = rows.Close()
		return 0, ErrStorageFormat
	}
	if err = rows.Close(); err != nil {
		return 0, err
	}
	for _, v := range [...]struct {
		sql  string
		want int64
	}{{"SELECT count(*) FROM executions", records}, {"SELECT coalesce(sum(active),0) FROM executions", active}} {
		n, err := s.scalar(v.sql)
		if err != nil || n != v.want {
			return 0, ErrStorageFormat
		}
	}
	n, err := s.scalar("SELECT count(*) FROM contracts")
	if err != nil {
		return 0, err
	}
	contracts, ok := n.(int64)
	if !ok || contracts < 0 || contracts > int64(len(e.config.Methods)*8) {
		return 0, ErrStorageFormat
	}
	return epoch, nil
}

func (e *SQLiteExecutions) recoverRows() error {
	var cursor [executionStorageKeyBytes]byte
	for {
		n, err := e.readGCPage(cursor[:])
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		for i := 0; i < n; i++ {
			row := &e.gc[i]
			// Validate the bounded row and original full-result backing before
			// changing its old work fact. No recovered row authorizes dispatch.
			r, err := e.readExecution(row.key[:])
			if err != nil {
				return err
			}
			n, err := e.readTerms(row.key[:])
			if err != nil {
				return err
			}
			c, err := e.codec.Decode(e.contract[:n])
			if err != nil {
				return err
			}
			p, policyErr := e.checkContract(c)
			c.Release()
			if policyErr != nil || p.Digest != r.contract || r.StreamMetadataOnly != (p.Shape == 1) || r.ResponseLimitBytes < p.MinResponseBytes || r.ResponseLimitBytes > p.MaxResponseBytes || p.HistoryRetentionMS > math.MaxUint64-r.DeadlineAtMS || r.HistoryNotBeforeGCMS != r.DeadlineAtMS+p.HistoryRetentionMS {
				return ErrStorageFormat
			}
			if err := e.verifyContentRow(row.key[:], p); err != nil {
				return err
			}
			if err := e.verifyRecoveryRow(row.key[:]); err != nil {
				return err
			}
			if r.WorkActive {
				r.WorkActive = false
				if r.State == SQLiteExecutionAccepted {
					r.State, r.Reason = SQLiteExecutionFailed, SQLiteExecutionReasonNotDispatched
				} else if r.State == SQLiteExecutionExecuting {
					r.State, r.Reason = SQLiteExecutionUnknown, SQLiteExecutionReasonOutcomeUnknown
				}
				if err = e.updateFacts(row.key[:], r.SQLiteExecutionObservation); err != nil {
					return err
				}
			}
			cursor = row.key
		}
	}
}

func (e *SQLiteExecutions) verifyContracts() error {
	var cursor [32]byte
	revision, err := e.registryRevision()
	if err != nil {
		return err
	}
	for {
		var key [32]byte
		n, err := e.readBoundedBlob("SELECT length(digest),CASE WHEN length(digest)=32 THEN digest ELSE NULL END FROM contracts WHERE digest>?1 ORDER BY digest LIMIT 1", key[:], named(1, cursor[:]))
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n != 32 {
			return ErrStorageFormat
		}
		r, err := e.readContract(key)
		if err != nil {
			return err
		}
		if r.revision > revision {
			return ErrStorageFormat
		}
		c, err := e.codec.Decode(e.contract[:r.bytes])
		if err != nil {
			return err
		}
		p, policyErr := e.checkContract(c)
		c.Release()
		if policyErr != nil || p.Digest != key {
			return ErrStorageFormat
		}
		typeID, err := e.store.scalar("SELECT type FROM contracts WHERE digest=?1", named(1, key[:]))
		if err != nil || typeID != int64(p.Type) {
			return ErrStorageFormat
		}
		cursor = key
	}
}
