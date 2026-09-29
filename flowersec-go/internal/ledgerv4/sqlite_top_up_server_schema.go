package ledgerv4

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

const topUpServerManifestSQL = `CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-topup-server'), revision INTEGER NOT NULL CHECK(revision=2), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 512), binding BLOB NOT NULL CHECK(length(binding)=8), next_sequence BLOB NOT NULL CHECK(length(next_sequence)=8), retired_sequence BLOB NOT NULL CHECK(length(retired_sequence)=8), highest BLOB NOT NULL CHECK(length(highest)=8), retired_artifact BLOB NOT NULL CHECK(length(retired_artifact)=8), permanent INTEGER NOT NULL CHECK(permanent IN (0,1)), state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 4), pending BLOB NOT NULL CHECK(length(pending)<=1024), facts BLOB NOT NULL CHECK(length(facts)<=1024), terminal TEXT NOT NULL CHECK(length(CAST(terminal AS BLOB))<=32), response BLOB NOT NULL CHECK(length(response)<=524288), state_revision BLOB NOT NULL CHECK(length(state_revision)=8)) STRICT, WITHOUT ROWID`

func (j *SQLiteTopUpServer) createSchema() (err error) {
	s := j.store.sqliteStore
	if err = j.audit.configure(); err != nil {
		return err
	}
	permit, err := j.config.Authority.AcquireTopUpCommit(s.identity, j.config.Tenant, j.config.Source)
	if err != nil {
		return err
	}
	if permit == nil {
		return ErrConfiguration
	}
	defer permit.Release()
	if err = permit.Check(); err != nil {
		return err
	}
	f, err := j.fence()
	if err != nil {
		return err
	}
	if f.Permanent {
		return topUpFailure(protocolv4.V4TopUpErrorCodeSourceResetRequired)
	}
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
	if err = s.exec(topUpServerManifestSQL); err != nil {
		return err
	}
	if err = j.audit.createSchema(); err != nil {
		return err
	}
	l := s.backing.limits
	if err = s.exec("INSERT INTO manifest VALUES (1,'flowersec-v4-topup-server',2,?1,?2,?3,?4,?5,?6,?7,?8,?9,?4,?10,?10,?10,0,0,x'',x'','',x'',?10)", named(1, s.identity.Authority), named(2, s.identity.StoreID[:]), named(3, sqliteUint(s.identity.Generation)), named(4, sqliteUint(1)), named(5, int64(l.MaxPages)), named(6, int64(l.MaxRecords)), named(7, int64(l.MaxRecordBytes)), named(8, j.configuration[:j.configurationBytes]), named(9, sqliteUint(f.Generation)), named(10, sqliteUint(0))); err != nil {
		return err
	}
	if err = s.exec("PRAGMA user_version=2"); err != nil {
		return err
	}
	if err = j.current(f.Generation); err != nil {
		return err
	}
	if err = permit.Check(); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	s.epoch = 1
	return s.checkpoint()
}
func (j *SQLiteTopUpServer) openSchema() (err error) {
	s := j.store.sqliteStore
	if err = j.audit.configure(); err != nil {
		return err
	}
	permit, err := j.config.Authority.AcquireTopUpCommit(s.identity, j.config.Tenant, j.config.Source)
	if err != nil {
		return err
	}
	if permit == nil {
		return ErrConfiguration
	}
	defer permit.Release()
	if err = permit.Check(); err != nil {
		return err
	}
	version, err := s.scalar("PRAGMA user_version")
	if err != nil || version != int64(2) {
		return ErrStorageFormat
	}
	count, err := s.scalar("SELECT count(*) FROM sqlite_schema")
	if err != nil || count != int64(3) {
		return ErrStorageFormat
	}
	length, err := s.scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name='manifest'")
	if err != nil || length != int64(len(topUpServerManifestSQL)) {
		return ErrStorageFormat
	}
	schema, err := s.scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name='manifest'")
	if err != nil || schema != topUpServerManifestSQL {
		return ErrStorageFormat
	}
	var epoch uint64
	err = s.readOne("SELECT format,revision,CASE WHEN length(CAST(authority AS BLOB))<=128 THEN authority ELSE NULL END,CASE WHEN length(instance)=32 THEN instance ELSE NULL END,CASE WHEN length(generation)=8 THEN generation ELSE NULL END,CASE WHEN length(epoch)=8 THEN epoch ELSE NULL END,max_pages,max_records,max_record_bytes,CASE WHEN length(configuration)<=512 THEN configuration ELSE NULL END FROM manifest WHERE id=1", 10, func(v []driver.Value) error {
		id, ok := v[3].([]byte)
		config, cok := v[9].([]byte)
		generation, ge := readSQLiteUint(v[4])
		var ee error
		epoch, ee = readSQLiteUint(v[5])
		l := s.backing.limits
		if v[0] != "flowersec-v4-topup-server" || v[1] != int64(2) || v[2] != s.identity.Authority || !ok || !bytes.Equal(id, s.identity.StoreID[:]) || ge != nil || generation != s.identity.Generation || ee != nil || epoch == 0 || epoch == math.MaxUint64 || v[6] != int64(l.MaxPages) || v[7] != int64(l.MaxRecords) || v[8] != int64(l.MaxRecordBytes) || !cok || !bytes.Equal(config, j.configuration[:j.configurationBytes]) {
			return ErrStorageFormat
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err = j.audit.verifySchema(); err != nil {
		return err
	}
	state, err := j.readState()
	if err != nil {
		return err
	}
	n, err := j.readWire()
	if err != nil {
		return err
	}
	defer clear(j.wire)
	if state.State == TopUpServerCommitted || state.State == TopUpServerTerminal && state.Response.Count > 0 {
		batch, err := j.codec.ParseResponse(j.wire[:n], state.Request)
		if err != nil {
			return ErrStorageFormat
		}
		facts, err := batch.Facts()
		batch.Release()
		if err != nil || facts != state.Response {
			return ErrStorageFormat
		}
	} else if n != 0 {
		return ErrStorageFormat
	}
	fence, err := j.fence()
	if err != nil {
		return err
	}
	// Authority rollback or resurrection of a retired incarnation is never
	// repaired by trusting the local file or replacing its source identifier.
	if fence.Generation < state.BindingGeneration || state.Permanent && !fence.Permanent {
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
	current, err := j.fence()
	if err != nil {
		return err
	}
	if current != fence {
		return ErrFenced
	}
	s.epoch = epoch + 1
	if err = s.exec("UPDATE manifest SET epoch=?1 WHERE id=1", named(1, sqliteUint(s.epoch))); err != nil {
		return err
	}
	if err = permit.Check(); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	return s.checkpoint()
}

func (j *SQLiteTopUpServer) readState() (out TopUpServerSnapshot, err error) {
	err = j.store.readOne("SELECT state,CASE WHEN length(binding)=8 THEN binding ELSE NULL END,CASE WHEN length(next_sequence)=8 THEN next_sequence ELSE NULL END,CASE WHEN length(retired_sequence)=8 THEN retired_sequence ELSE NULL END,CASE WHEN length(highest)=8 THEN highest ELSE NULL END,CASE WHEN length(retired_artifact)=8 THEN retired_artifact ELSE NULL END,permanent,CASE WHEN length(pending)<=1024 THEN pending ELSE NULL END,CASE WHEN length(facts)<=1024 THEN facts ELSE NULL END,CASE WHEN length(CAST(terminal AS BLOB))<=32 THEN terminal ELSE NULL END,CASE WHEN length(state_revision)=8 THEN state_revision ELSE NULL END FROM manifest WHERE id=1", 11, func(v []driver.Value) error {
		state, ok := v[0].(int64)
		permanent, pok := v[6].(int64)
		if !ok || state < 0 || state > 4 || !pok || permanent < 0 || permanent > 1 {
			return ErrStorageFormat
		}
		out.State = TopUpServerState(state)
		revision, revisionErr := readSQLiteUint(v[10])
		if revisionErr != nil || revision == 0 && (state != int64(TopUpServerEmpty) || permanent != 0) {
			return ErrStorageFormat
		}
		out.Permanent = permanent == 1
		for i, dst := range []*uint64{&out.BindingGeneration, &out.NextSequence, &out.RetiredSequence, &out.HighestArtifact, &out.RetiredArtifact} {
			*dst, err = readSQLiteUint(v[i+1])
			if err != nil {
				return err
			}
		}
		pending, pok := v[7].([]byte)
		facts, fok := v[8].([]byte)
		terminal, tok := v[9].(string)
		if !pok || !fok || !tok || out.BindingGeneration == 0 || out.NextSequence == 0 || out.RetiredSequence == math.MaxUint64 || out.RetiredArtifact > out.HighestArtifact {
			return ErrStorageFormat
		}
		out.Terminal = protocolv4.V4TopUpErrorCode(terminal)
		if terminal != "" {
			if _, ok := protocolv4.TopUpErrorProjection(out.Terminal, protocolv4.V4TopUpWriteActionTerminal); !ok {
				return ErrStorageFormat
			}
		}
		if out.State == TopUpServerEmpty {
			if len(pending) != 0 || len(facts) != 0 || terminal != "" || out.NextSequence != 1 || out.RetiredSequence != 0 || out.HighestArtifact != 0 || out.RetiredArtifact != 0 {
				return ErrStorageFormat
			}
			return nil
		}
		out.Request, err = decodeTopUpRequest(pending)
		if err != nil {
			return err
		}
		r := out.Request
		if !j.boundRequest(r) || r.Generation > out.BindingGeneration || r.Sequence() == math.MaxUint64 || out.NextSequence != r.Sequence()+1 {
			return ErrStorageFormat
		}
		if out.State == TopUpServerRetired {
			if out.RetiredSequence != r.Sequence() {
				return ErrStorageFormat
			}
		} else if out.RetiredSequence+1 != r.Sequence() {
			return ErrStorageFormat
		}
		if out.Permanent && out.State != TopUpServerRetired {
			return ErrStorageFormat
		}
		if len(facts) > 0 {
			out.Response, err = decodeTopUpResponse(facts)
			if err != nil {
				return err
			}
			f := out.Response
			if f.Tenant != r.Tenant || f.Source != r.Source || f.Operation != r.Operation || f.Generation != r.Generation || f.Count != r.DesiredCount || f.Highest != out.HighestArtifact || f.Entries[f.Count-1].Sequence != f.Highest {
				return ErrStorageFormat
			}
			for _, e := range f.Entries[:f.Count] {
				if e.Identity != r.Identity {
					return ErrStorageFormat
				}
			}
		}
		switch out.State {
		case TopUpServerPending:
			if len(facts) != 0 || terminal != "" {
				return ErrStorageFormat
			}
		case TopUpServerCommitted:
			if len(facts) == 0 || terminal != "" {
				return ErrStorageFormat
			}
		case TopUpServerTerminal:
			if terminal == "" || len(facts) > 0 && out.Terminal != protocolv4.V4TopUpErrorCodeSourceResetRequired {
				return ErrStorageFormat
			}
		case TopUpServerRetired:
			if len(facts) == 0 && terminal == "" {
				return ErrStorageFormat
			}
		}
		return nil
	})
	return out, err
}
func (j *SQLiteTopUpServer) writeState(s TopUpServerSnapshot, wire []byte) error {
	current, err := j.readState()
	if err != nil {
		return err
	}
	if current == s {
		return nil
	}
	previous, err := j.stateRevision()
	if err != nil {
		return err
	}
	if previous == math.MaxUint64 {
		return ErrCapacity
	}
	defer clear(j.request[:])
	defer clear(j.response[:])
	rn, fn := 0, 0
	if s.State != TopUpServerEmpty {
		rn, err = encodeTopUpRequest(j.request[:], s.Request)
		if err != nil {
			return err
		}
	}
	if s.Response.Count != 0 {
		fn, err = encodeTopUpResponse(j.response[:], s.Response)
		if err != nil {
			return err
		}
	}
	permanent := int64(0)
	if s.Permanent {
		permanent = 1
	}
	if err = j.store.exec("UPDATE manifest SET binding=?1,next_sequence=?2,retired_sequence=?3,highest=?4,retired_artifact=?5,permanent=?6,state=?7,pending=?8,facts=?9,terminal=?10,response=?11,state_revision=?12 WHERE id=1 AND state_revision=?13", named(1, sqliteUint(s.BindingGeneration)), named(2, sqliteUint(s.NextSequence)), named(3, sqliteUint(s.RetiredSequence)), named(4, sqliteUint(s.HighestArtifact)), named(5, sqliteUint(s.RetiredArtifact)), named(6, permanent), named(7, int64(s.State)), named(8, j.request[:rn]), named(9, j.response[:fn]), named(10, string(s.Terminal)), named(11, wire), named(12, sqliteUint(previous+1)), named(13, sqliteUint(previous))); err != nil {
		return err
	}
	return j.store.changedOne()
}
func (j *SQLiteTopUpServer) readWire() (n int, err error) {
	err = j.store.readOne("SELECT CASE WHEN length(response)<=524288 THEN response ELSE NULL END FROM manifest WHERE id=1", 1, func(v []driver.Value) error {
		b, ok := v[0].([]byte)
		if !ok || len(b) > len(j.wire) {
			return ErrStorageFormat
		}
		n = copy(j.wire, b)
		return nil
	})
	return n, err
}

// stateRevision versions only this local authority record. It is not a TopUp
// wire field, client terminal receipt, ownership generation or admission fact.
func (j *SQLiteTopUpServer) stateRevision() (uint64, error) {
	value, err := j.store.scalar("SELECT CASE WHEN length(state_revision)=8 THEN state_revision ELSE NULL END FROM manifest WHERE id=1")
	if err != nil {
		return 0, err
	}
	return readSQLiteUint(value)
}
