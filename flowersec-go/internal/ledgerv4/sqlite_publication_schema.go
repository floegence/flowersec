package ledgerv4

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"io"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

const publicationManifestSQL = `CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-publication'), revision INTEGER NOT NULL CHECK(revision=1), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 512)) STRICT, WITHOUT ROWID`
const publicationCurrentSQL = `CREATE TABLE current_state (id INTEGER PRIMARY KEY CHECK(id=1), version BLOB NOT NULL CHECK(length(version)=8), digest BLOB NOT NULL CHECK(length(digest)=32), encoded_bytes INTEGER NOT NULL CHECK(encoded_bytes>=0)) STRICT, WITHOUT ROWID`
const publicationPairsSQL = `CREATE TABLE publications (slot INTEGER PRIMARY KEY CHECK(slot BETWEEN 1 AND 64), snapshot BLOB NOT NULL CHECK(length(snapshot)=8), sequence BLOB NOT NULL CHECK(length(sequence)=8), state_digest BLOB NOT NULL CHECK(length(state_digest)=32), head_digest BLOB NOT NULL CHECK(length(head_digest)=32), this_update BLOB NOT NULL CHECK(length(this_update)=8), next_update BLOB NOT NULL CHECK(length(next_update)=8), encoded_bytes INTEGER NOT NULL CHECK(encoded_bytes>0), head BLOB NOT NULL CHECK(length(head) BETWEEN 1 AND 8192)) STRICT, WITHOUT ROWID`
const publicationChunksSQL = `CREATE TABLE chunks (slot INTEGER NOT NULL CHECK(slot BETWEEN 0 AND 64), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 16799), data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 65536), PRIMARY KEY(slot,ordinal)) STRICT, WITHOUT ROWID`

var publicationTables = [...]struct{ name, sql string }{{"manifest", publicationManifestSQL}, {"current_state", publicationCurrentSQL}, {"publications", publicationPairsSQL}, {"chunks", publicationChunksSQL}}

var errNoPublicationRow = io.EOF

func isNoPublicationRow(err error) bool { return errors.Is(err, io.EOF) }

func (p *SQLitePublicationStore) createSchema() (err error) {
	s := p.store.sqliteStore
	if err = s.boundPages(); err != nil {
		return
	}
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return
	}
	defer namespaceRollback(s, &err)
	for _, table := range publicationTables {
		if err = s.exec(table.sql); err != nil {
			return
		}
	}
	l := s.backing.limits
	if err = s.exec("INSERT INTO manifest VALUES (1,'flowersec-v4-publication',1,?1,?2,?3,?4,?5,?6,?7,?8)", named(1, s.identity.Authority), named(2, s.identity.StoreID[:]), named(3, sqliteUint(s.identity.Generation)), named(4, sqliteUint(1)), named(5, int64(l.MaxPages)), named(6, int64(l.MaxRecords)), named(7, int64(l.MaxRecordBytes)), named(8, p.configuration[:p.configurationBytes])); err != nil {
		return
	}
	var empty [32]byte
	if err = s.exec("INSERT INTO current_state VALUES (1,?1,?2,0)", named(1, sqliteUint(0)), named(2, empty[:])); err != nil {
		return
	}
	if err = s.exec("PRAGMA user_version=1"); err != nil {
		return
	}
	if err = p.config.Access.CheckPublicationMutation(p.config.Scope); err != nil {
		return
	}
	if err = s.continuity.Check(s.identity, 0, true); err != nil {
		return
	}
	if err = s.exec("COMMIT"); err != nil {
		return
	}
	s.epoch = 1
	return s.checkpoint()
}

func (p *SQLitePublicationStore) openSchema(readOnly bool) (err error) {
	s := p.store.sqliteStore
	defer clear(p.head)
	n, err := s.scalar("SELECT count(*) FROM sqlite_schema")
	if err != nil || n != int64(len(publicationTables)) {
		return ErrStorageFormat
	}
	for _, table := range publicationTables {
		n, e := s.scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name=?1", named(1, table.name))
		if e != nil || n != int64(len(table.sql)) {
			return ErrStorageFormat
		}
		sql, e := s.scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1", named(1, table.name))
		if e != nil || sql != table.sql {
			return ErrStorageFormat
		}
	}
	if !readOnly {
		if err = s.boundPages(); err != nil {
			return
		}
		if err = s.checkpoint(); err != nil {
			return
		}
		if err = s.exec("BEGIN IMMEDIATE"); err != nil {
			return
		}
		defer namespaceRollback(s, &err)
	}
	var epoch uint64
	err = s.readOne("SELECT CASE WHEN length(epoch)=8 THEN epoch ELSE NULL END,max_pages,max_records,max_record_bytes,CASE WHEN length(configuration)<=512 THEN configuration ELSE NULL END FROM manifest WHERE id=1", 5, func(v []driver.Value) error {
		var e error
		epoch, e = readSQLiteUint(v[0])
		config, ok := v[4].([]byte)
		l := s.backing.limits
		if e != nil || epoch == 0 || epoch == math.MaxUint64 || v[1] != int64(l.MaxPages) || v[2] != int64(l.MaxRecords) || v[3] != int64(l.MaxRecordBytes) || !ok || !bytes.Equal(config, p.configuration[:p.configurationBytes]) {
			return ErrStorageFormat
		}
		return nil
	})
	if err != nil {
		return
	}
	count, err := s.scalar("SELECT count(*) FROM current_state")
	if err != nil || count != int64(1) {
		return ErrStorageFormat
	}
	version, currentDigest, size, err := p.readCurrent()
	if err != nil {
		return err
	}
	if err = p.inspectStoredPublication(0, size, nil, protocolv4.NamespacePublicationVersion{Snapshot: version, StateDigest: currentDigest}); err != nil {
		return err
	}
	var maxSequence uint64
	for slot := uint32(1); slot <= p.config.HistorySlots; slot++ {
		var pair protocolv4.NamespacePublicationVersion
		var stateBytes uint64
		var headBytes int
		err = s.readOne("SELECT slot,snapshot,sequence,state_digest,head_digest,this_update,next_update,encoded_bytes,CASE WHEN length(head) BETWEEN 1 AND ?2 THEN head ELSE NULL END FROM publications WHERE slot=?1", 9, func(v []driver.Value) error {
			var e error
			_, pair, e = publicationRow(v[:7])
			if e != nil {
				return e
			}
			n, ok := v[7].(int64)
			h, hok := v[8].([]byte)
			if !ok || n <= 0 || uint64(n) > p.maximum || !hok || len(h) == 0 || uint64(len(h)) > p.headMaximum || pair.Snapshot > version || pair.Snapshot == version && pair.StateDigest != currentDigest {
				return ErrStorageFormat
			}
			stateBytes = uint64(n)
			headBytes = copy(p.head, h)
			return nil
		}, named(1, int64(slot)), named(2, int64(p.headMaximum)))
		if isNoPublicationRow(err) {
			err = nil
		} else if err != nil {
			return err
		}
		if pair.Sequence > maxSequence {
			maxSequence = pair.Sequence
		}
		if err = p.inspectStoredPublication(slot, stateBytes, p.head[:headBytes], pair); err != nil {
			return err
		}
		clear(p.head[:headBytes])
	}
	count, err = s.scalar("SELECT count(*) FROM publications WHERE slot>?1", named(1, int64(p.config.HistorySlots)))
	if err != nil || count != int64(0) {
		return ErrStorageFormat
	}
	count, err = s.scalar("SELECT count(*) FROM chunks WHERE slot>?1", named(1, int64(p.config.HistorySlots)))
	if err != nil || count != int64(0) {
		return ErrStorageFormat
	}
	count, err = s.scalar("SELECT count(*)-count(DISTINCT sequence) FROM publications")
	if err != nil || count != int64(0) {
		return ErrStorageFormat
	}
	if maxSequence > 0 && version == 0 {
		return ErrStorageFormat
	}
	count, err = s.scalar("SELECT count(*) FROM publications a JOIN publications b ON a.sequence<b.sequence WHERE a.snapshot>b.snapshot OR a.this_update>b.this_update OR (a.snapshot=b.snapshot AND a.state_digest<>b.state_digest) OR (a.state_digest=b.state_digest AND a.next_update>b.next_update)")
	if err != nil || count != int64(0) {
		return ErrStorageFormat
	}
	if readOnly {
		return nil
	}
	if err = s.continuity.Check(s.identity, epoch, false); err != nil {
		return err
	}
	if err = p.config.Access.CheckPublicationMutation(p.config.Scope); err != nil {
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

func (p *SQLitePublicationStore) inspectStoredPublication(slot uint32, size uint64, head []byte, version protocolv4.NamespacePublicationVersion) error {
	if size == 0 {
		return p.checkChunks(slot, 0)
	}
	if size > uint64(len(p.current)) {
		return ErrStorageFormat
	}
	wire := p.current[:size]
	defer clear(wire)
	if err := p.readChunks(slot, wire); err != nil {
		return err
	}
	return storageFactsError(p.workspaces[0].InspectStoredPublication(wire, head, p.decoder, p.config.Scope, version))
}

func (p *SQLitePublicationStore) readCurrent() (version uint64, digest [32]byte, size uint64, err error) {
	err = p.store.readOne("SELECT CASE WHEN length(version)=8 THEN version ELSE NULL END,CASE WHEN length(digest)=32 THEN digest ELSE NULL END,encoded_bytes FROM current_state WHERE id=1", 3, func(v []driver.Value) error {
		var e error
		version, e = readSQLiteUint(v[0])
		b, ok := v[1].([]byte)
		n, nok := v[2].(int64)
		if e != nil || !ok || len(b) != 32 || !nok || n < 0 || uint64(n) > p.maximum {
			return ErrStorageFormat
		}
		copy(digest[:], b)
		size = uint64(n)
		if (version == 0) != (size == 0) || (version == 0) != (digest == ([32]byte{})) {
			return ErrStorageFormat
		}
		return nil
	})
	return
}

func publicationRow(v []driver.Value) (slot uint32, out protocolv4.NamespacePublicationVersion, err error) {
	n, ok := v[0].(int64)
	if !ok || n < 1 || n > 64 {
		return 0, out, ErrStorageFormat
	}
	slot = uint32(n)
	for _, field := range []struct {
		i int
		p *uint64
	}{{1, &out.Snapshot}, {2, &out.Sequence}, {5, &out.ThisUpdateMS}, {6, &out.NextUpdateMS}} {
		*field.p, err = readSQLiteUint(v[field.i])
		if err != nil {
			return 0, out, err
		}
	}
	for _, field := range []struct {
		i int
		p *[32]byte
	}{{3, &out.StateDigest}, {4, &out.HeadDigest}} {
		b, ok := v[field.i].([]byte)
		if !ok || len(b) != 32 {
			return 0, out, ErrStorageFormat
		}
		copy(field.p[:], b)
	}
	if out.Snapshot == 0 || out.Sequence == 0 || out.NextUpdateMS <= out.ThisUpdateMS || out.StateDigest == ([32]byte{}) || out.HeadDigest == ([32]byte{}) {
		return 0, out, ErrStorageFormat
	}
	return
}

func (p *SQLitePublicationStore) readPublicationVersion() (out protocolv4.NamespacePublicationVersion, err error) {
	err = p.store.readOne("SELECT slot,snapshot,sequence,state_digest,head_digest,this_update,next_update FROM publications ORDER BY sequence DESC LIMIT 1", 7, func(v []driver.Value) error {
		var e error
		_, out, e = publicationRow(v)
		return e
	})
	if isNoPublicationRow(err) {
		return protocolv4.NamespacePublicationVersion{}, nil
	}
	return
}

func (p *SQLitePublicationStore) checkChunks(slot uint32, size uint64) error {
	count := (size + namespaceChunkBytes - 1) / namespaceChunkBytes
	return p.store.readOne("SELECT count(*),coalesce(sum(length(data)),0),coalesce(min(ordinal),0),coalesce(max(ordinal),-1) FROM chunks WHERE slot=?1", 4, func(v []driver.Value) error {
		if v[0] != int64(count) || v[1] != int64(size) || v[2] != int64(0) || v[3] != int64(count)-1 {
			return ErrStorageFormat
		}
		return nil
	}, named(1, int64(slot)))
}

func (p *SQLitePublicationStore) writeChunks(slot uint32, wire []byte) error {
	if err := p.store.exec("DELETE FROM chunks WHERE slot=?1", named(1, int64(slot))); err != nil {
		return err
	}
	for i := 0; i*namespaceChunkBytes < len(wire); i++ {
		end := min((i+1)*namespaceChunkBytes, len(wire))
		if err := p.store.exec("INSERT INTO chunks VALUES (?1,?2,?3)", named(1, int64(slot)), named(2, int64(i)), named(3, wire[i*namespaceChunkBytes:end])); err != nil {
			return err
		}
	}
	return nil
}

func (p *SQLitePublicationStore) readChunks(slot uint32, dst []byte) error {
	if err := p.checkChunks(slot, uint64(len(dst))); err != nil {
		return err
	}
	for i := 0; i*namespaceChunkBytes < len(dst); i++ {
		end := min((i+1)*namespaceChunkBytes, len(dst))
		err := p.store.readOne("SELECT CASE WHEN length(data)<=65536 THEN data ELSE NULL END FROM chunks WHERE slot=?1 AND ordinal=?2", 1, func(v []driver.Value) error {
			b, ok := v[0].([]byte)
			if !ok || len(b) != end-i*namespaceChunkBytes {
				return ErrStorageFormat
			}
			copy(dst[i*namespaceChunkBytes:end], b)
			return nil
		}, named(1, int64(slot)), named(2, int64(i)))
		if err != nil {
			return err
		}
	}
	return nil
}
