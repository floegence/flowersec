package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"
)

const sqliteRelayParentSQL = `CREATE TABLE relay_parent (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), version BLOB NOT NULL CHECK(length(version)=8), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID`
const sqliteRelayLegSQL = `CREATE TABLE relay_leg (lease BLOB NOT NULL REFERENCES relay_parent(lease), side INTEGER NOT NULL CHECK(side IN (0,1)), claimed INTEGER NOT NULL CHECK(claimed IN (0,1)), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576), PRIMARY KEY(lease,side), CHECK((claimed=0 AND version=x'0000000000000000' AND fence=x'0000000000000000') OR (claimed=1 AND version=x'0000000000000001' AND fence<>x'0000000000000000'))) STRICT, WITHOUT ROWID`
const sqliteRelayCapacitySQL = `CREATE TRIGGER relay_parent_aggregate_capacity BEFORE INSERT ON relay_parent WHEN (SELECT admission_rows+spend_rows+winner_rows+issuance_rows+relay_rows+3>max_records FROM manifest WHERE id=1) BEGIN SELECT RAISE(ABORT,'aggregate capacity'); END`

// Each parent reserves durable room for its root and both fixed slots on the
// first claim. There is no deletion or reopening API. Expiry of a short Grant
// does not establish permanent rejection of its parent, so it cannot free this
// history. SQLiteBacking's disk/page reservation remains a separate hard cap.
func (s *sqliteStore) verifyRelayRows(reserved int64) error {
	parents, err := s.scalar("SELECT count(*) FROM relay_parent")
	if err != nil {
		return err
	}
	registrations, err := s.scalar("SELECT count(*) FROM relay_issuance")
	if err != nil {
		return err
	}
	issuance, valid := registrations.(int64)
	n, ok := parents.(int64)
	if !ok || !valid || issuance < 0 || issuance > int64(s.backing.limits.MaxRecords) || n < 0 || n > (int64(s.backing.limits.MaxRecords)-issuance)/3 || reserved != n*3+issuance {
		return ErrStorageFormat
	}
	bad, err := s.scalar("SELECT count(*) FROM relay_parent p WHERE (SELECT count(*) FROM relay_leg l WHERE l.lease=p.lease)<>2 OR version NOT IN (x'0000000000000001',x'0000000000000002') OR (version=x'0000000000000001' AND (SELECT count(*) FROM relay_leg l WHERE l.lease=p.lease AND l.claimed=1)<>1) OR (version=x'0000000000000002' AND (SELECT count(*) FROM relay_leg l WHERE l.lease=p.lease AND l.claimed=1)<>2)")
	if err != nil {
		return err
	}
	if bad != int64(0) {
		return ErrStorageFormat
	}
	bad, err = s.scalar("SELECT count(*) FROM relay_leg l WHERE (claimed=0 AND (version<>x'0000000000000000' OR fence<>x'0000000000000000' OR length(projection)<>(SELECT max_record_bytes FROM manifest WHERE id=1))) OR (claimed=1 AND (version<>x'0000000000000001' OR fence=x'0000000000000000')) OR NOT EXISTS (SELECT 1 FROM relay_parent p WHERE p.lease=l.lease)")
	if err != nil {
		return err
	}
	if bad != int64(0) {
		return ErrStorageFormat
	}
	return nil
}

func (s *sqliteStore) readRelayParent(ctx context.Context, key, dst []byte) (version uint64, n int, found bool, err error) {
	rows, err := s.querier.QueryContext(ctx, "SELECT version,length(projection),CASE WHEN length(projection)<=?2 THEN projection ELSE NULL END FROM relay_parent WHERE lease=?1", []driver.NamedValue{named(1, key), named(2, int64(len(dst)))})
	if err != nil {
		return 0, 0, false, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [3]driver.Value
	if err = rows.Next(values[:]); err == io.EOF {
		return 0, 0, false, nil
	} else if err != nil {
		return 0, 0, false, err
	}
	version, err = readSQLiteUint(values[0])
	length, lok := values[1].(int64)
	projection, pok := values[2].([]byte)
	if err != nil || version < 1 || version > 2 || !lok || !pok || length < 1 || length != int64(len(projection)) || length > int64(len(dst)) || length > int64(s.backing.limits.MaxRecordBytes) {
		return 0, 0, false, ErrStorageFormat
	}
	n = copy(dst, projection)
	if err = rows.Next(values[:]); err != io.EOF {
		return 0, 0, false, ErrStorageFormat
	}
	return version, n, true, nil
}

func (s *sqliteStore) readRelayLeg(ctx context.Context, parent []byte, side byte, dst []byte) (result Observation, found bool, err error) {
	rows, err := s.querier.QueryContext(ctx, "SELECT l.version,l.fence,p.version,length(l.projection),CASE WHEN length(l.projection)<=?3 THEN l.projection ELSE NULL END FROM relay_leg l JOIN relay_parent p ON p.lease=l.lease WHERE l.lease=?1 AND l.side=?2 AND l.claimed=1", []driver.NamedValue{named(1, parent), named(2, int64(side)), named(3, int64(len(dst)))})
	if err != nil {
		return result, false, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var v [5]driver.Value
	if err = rows.Next(v[:]); err == io.EOF {
		return result, false, nil
	} else if err != nil {
		return result, false, err
	}
	version, ve := readSQLiteUint(v[0])
	fence, fe := readSQLiteUint(v[1])
	aggregate, ae := readSQLiteUint(v[2])
	length, lok := v[3].(int64)
	projection, pok := v[4].([]byte)
	if ve != nil || fe != nil || ae != nil || version != 1 || fence == 0 || aggregate < 1 || aggregate > 2 || !lok || !pok || length < 1 || length != int64(len(projection)) || length > int64(len(dst)) || length > int64(s.backing.limits.MaxRecordBytes) {
		return result, false, ErrStorageFormat
	}
	n := copy(dst, projection)
	if err = rows.Next(v[:]); err != io.EOF {
		return result, false, ErrStorageFormat
	}
	return Observation{State: DurablyCommitted, CommitVersion: version, AggregateVersion: aggregate, CommitFence: fence, CurrentFence: s.epoch, ProjectionBytes: n}, true, nil
}

type relayCommitStore struct{ original *sqliteRelayActivation }

func (b relayCommitStore) valid(tx Transaction, dst []byte) bool {
	a := b.original
	return a != nil && tx.Kind == RelayClaim && tx.Authority == a.identity.Authority && tx.BeforeVersion == 0 && tx.CommitVersion == 1 && tx.FencingEpoch == a.fence && bytes.Equal(tx.Key, a.key[:a.keySize]) && bytes.Equal(tx.Projection, a.target[:a.targetSize]) && len(dst) >= a.targetSize
}

func (b relayCommitStore) Commit(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
	if !b.valid(tx, dst) {
		return Observation{}, ErrConfiguration
	}
	a, s := b.original, b.original.store
	if err := s.begin(ctx); err != nil {
		return Observation{}, err
	}
	defer s.end()
	if s.epoch != a.fence {
		return Observation{}, ErrFenced
	}
	parent, side := a.key[:a.keySize-1], a.key[a.keySize-1]
	var aggregate uint64
	err := s.writeTransaction(ctx, a.check, func() error {
		// Winner and relay root/slot consumption share this real transaction.
		if a.selection.Source == "preauthorized_pool" {
			if err := s.matchParentWinnerInTransaction(ctx, parent, a.winner[:a.winnerSize], a.scratch); err != nil {
				return err
			}
		}
		version, n, found, err := s.readRelayParent(ctx, parent, a.scratch)
		if err != nil {
			return err
		}
		if found {
			if !bytes.Equal(a.scratch[:n], a.root[:a.rootSize]) {
				return ErrConflict
			}
			_, occupied, err := s.readRelayLeg(ctx, parent, side, a.scratch)
			if err != nil {
				return err
			}
			if occupied || version >= 2 {
				return ErrConflict
			}
			if err = s.exec("UPDATE relay_parent SET version=?1 WHERE lease=?2 AND version=?3 AND projection=?4", named(1, sqliteUint(version+1)), named(2, parent), named(3, sqliteUint(version)), named(4, a.root[:a.rootSize])); err != nil {
				return err
			}
			if err = s.changedOne(); err != nil {
				return err
			}
			aggregate = version + 1
		} else {
			total, err := s.scalar("SELECT admission_rows+spend_rows+winner_rows+issuance_rows+relay_rows FROM manifest WHERE id=1")
			if err != nil {
				return err
			}
			count, ok := total.(int64)
			if !ok || count < 0 {
				return ErrStorageFormat
			}
			if count+3 > int64(s.backing.limits.MaxRecords) {
				return ErrCapacity
			}
			if err = s.exec("INSERT INTO relay_parent VALUES (?1,?2,?3)", named(1, parent), named(2, sqliteUint(1)), named(3, a.root[:a.rootSize])); err != nil {
				return err
			}
			if err = s.exec("UPDATE manifest SET relay_rows=relay_rows+3 WHERE id=1"); err != nil {
				return err
			}
			// Materialize the claimed leg and the full unused slot in the same
			// transaction. Only the unused leg needs a zero projection to reserve
			// storage; the original leg already has its complete claimed record.
			// Later claims replace only their original fixed unused slot.
			for slot := int64(0); slot < 2; slot++ {
				if byte(slot) == side {
					err = s.exec("INSERT INTO relay_leg VALUES (?1,?2,1,?3,?4,?5)", named(1, parent), named(2, slot), named(3, sqliteUint(1)), named(4, sqliteUint(a.fence)), named(5, tx.Projection))
				} else {
					err = s.exec("INSERT INTO relay_leg VALUES (?1,?2,0,?3,?3,zeroblob(?4))", named(1, parent), named(2, slot), named(3, sqliteUint(0)), named(4, int64(s.backing.limits.MaxRecordBytes)))
				}
				if err != nil {
					return err
				}
			}
			aggregate = 1
			return nil
		}
		if err := s.exec("UPDATE relay_leg SET claimed=1,version=?1,fence=?2,projection=?3 WHERE lease=?4 AND side=?5 AND claimed=0", named(1, sqliteUint(1)), named(2, sqliteUint(a.fence)), named(3, tx.Projection), named(4, parent), named(5, int64(side))); err != nil {
			return err
		}
		return s.changedOne()
	})
	if err != nil {
		return Observation{}, err
	}
	copy(dst, tx.Projection)
	return Observation{State: DurablyCommitted, CommitVersion: 1, AggregateVersion: aggregate, CommitFence: a.fence, CurrentFence: s.epoch, ProjectionBytes: len(tx.Projection)}, nil
}

func (b relayCommitStore) Confirm(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
	if !b.valid(tx, dst) {
		return Observation{}, ErrConfiguration
	}
	a, s := b.original, b.original.store
	if err := s.begin(ctx); err != nil {
		return Observation{}, err
	}
	defer s.end()
	if err := s.checkFence(); err != nil {
		return Observation{}, err
	}
	parent, side := a.key[:a.keySize-1], a.key[a.keySize-1]
	_, n, found, err := s.readRelayParent(ctx, parent, a.scratch)
	if err != nil {
		return Observation{}, err
	}
	if !found {
		return Observation{State: NotObserved}, nil
	}
	if !bytes.Equal(a.scratch[:n], a.root[:a.rootSize]) {
		return Observation{State: Conflicting}, nil
	}
	observation, found, err := s.readRelayLeg(ctx, parent, side, dst)
	if err != nil {
		return Observation{}, err
	}
	if err = ctx.Err(); err != nil {
		return Observation{}, err
	}
	if !found {
		return Observation{State: NotObserved}, nil
	}
	return observation, nil
}
