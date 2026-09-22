package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type storedAdmission struct {
	Observation
	state int64
	found bool
}

func (s *sqliteStore) readAdmission(key, dst []byte) (result storedAdmission, err error) {
	// Evaluate the byte bound inside SQLite before asking the driver to copy
	// the projection. Malformed storage cannot allocate an unbounded Go row.
	rows, err := s.querier.QueryContext(context.Background(), "SELECT version,fence,state,admission_count,length(projection),CASE WHEN length(projection)<=?2 THEN projection ELSE NULL END FROM admission WHERE lease=?1", []driver.NamedValue{named(1, key), named(2, int64(len(dst)))})
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [6]driver.Value
	if err = rows.Next(values[:]); err == io.EOF {
		return result, nil
	} else if err != nil {
		return result, err
	}
	version, ve := readSQLiteUint(values[0])
	fence, fe := readSQLiteUint(values[1])
	state, ok := values[2].(int64)
	count, cok := values[3].(int64)
	n, nok := values[4].(int64)
	projection, pok := values[5].([]byte)
	if ve != nil || fe != nil || !ok || state < 0 || state > 3 || !cok || count < 0 || count > 1 || (state == admissionAdmitted) != (count == 1) || !nok || !pok || n < 1 || n != int64(len(projection)) || n > int64(len(dst)) || n > int64(s.backing.limits.MaxRecordBytes) {
		return result, ErrStorageFormat
	}
	copy(dst, projection)
	result = storedAdmission{found: true, state: state, Observation: Observation{State: DurablyCommitted, CommitVersion: version, AggregateVersion: version, CommitFence: fence, CurrentFence: s.epoch, ProjectionBytes: int(n)}}
	if err = rows.Next(values[:]); err != io.EOF {
		return storedAdmission{}, ErrStorageFormat
	}
	return result, nil
}

func (s *sqliteStore) checkFence() error {
	rows, err := s.querier.QueryContext(context.Background(), "SELECT epoch FROM manifest WHERE id=1", nil)
	if err != nil {
		return err
	}
	var v [1]driver.Value
	err = rows.Next(v[:])
	epoch, decodeErr := readSQLiteUint(v[0])
	closeErr := rows.Close()
	if err != nil || decodeErr != nil || closeErr != nil {
		return errors.Join(err, decodeErr, closeErr)
	}
	if epoch != s.epoch {
		return ErrFenced
	}
	return nil
}

func (s *sqliteStore) poison() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.reservation.Seal()
	s.signalLocked()
}

// writeTransaction owns one complete fixed transaction. A failed COMMIT remains
// unknown. Failure to roll back poisons the connection; no later operation can
// mistake an unfinished transaction for a new durable fact.
func (s *sqliteStore) writeTransaction(ctx context.Context, guard func() error, write func() error) (err error) {
	return s.writeTransactionMode(ctx, guard, write, false)
}

// Retained mode is restricted to ending an already owned business work tail.
// It cannot register, dispatch, publish a result or create a new obligation.
func (s *sqliteStore) writeTransactionMode(ctx context.Context, guard func() error, write func() error, retained bool) (err error) {
	if err = s.checkpoint(); err != nil {
		return err
	}
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if rollback := s.exec("ROLLBACK"); rollback != nil {
				// COMMIT may have succeeded before its result was lost. A
				// fresh read transaction proves the connection has no pending
				// write without interpreting driver error strings as rollback.
				probe := s.exec("BEGIN DEFERRED")
				if probe == nil {
					probe = s.exec("ROLLBACK")
				}
				if probe != nil {
					s.poison()
					err = errors.Join(err, rollback, probe)
				}
			}
		}
	}()
	if err = s.checkFence(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = guard(); err != nil {
		return err
	}
	if err = write(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	for _, ref := range []resourcev4.Reference{s.reservation, s.environment, s.disk} {
		if retained {
			err = ref.CheckRetained()
		} else {
			err = ref.Check()
		}
		if err != nil {
			return err
		}
	}
	if err = guard(); err != nil {
		return err
	}
	if err = s.exec("COMMIT"); err != nil {
		return errors.Join(ErrUnknown, err)
	}
	committed = true
	return ctx.Err()
}

func (s *sqliteStore) changedOne() error {
	n, err := s.scalar("SELECT changes()")
	if err != nil {
		return err
	}
	if n != int64(1) {
		return ErrConflict
	}
	return nil
}

func (a *sqliteAdmission) reserve(ctx context.Context) error {
	s := a.store
	if err := s.begin(ctx); err != nil {
		return err
	}
	defer s.end()
	if s.epoch != a.record.fence {
		return ErrFenced
	}
	return s.writeTransaction(ctx, a.check, func() error {
		// All competitors share exactly tenant + Artifact issuer + lease. A
		// duplicate can report a fact but cannot manufacture this invocation.
		existing, err := s.readAdmission(a.key[:a.keySize], a.scratch)
		if err != nil {
			return err
		}
		if existing.found {
			return ErrConflict
		}
		count, err := s.scalar("SELECT admission_rows+spend_rows FROM manifest WHERE id=1")
		if err != nil {
			return err
		}
		n, ok := count.(int64)
		if !ok || n < 0 {
			return ErrStorageFormat
		}
		if n >= int64(s.backing.limits.MaxRecords) {
			return ErrCapacity
		}
		if err = s.exec("INSERT INTO admission VALUES (?1,?2,?3,0,0,?4)", named(1, a.key[:a.keySize]), named(2, sqliteUint(1)), named(3, sqliteUint(s.epoch)), named(4, a.reserved[:a.reservedSize])); err != nil {
			return err
		}
		return s.exec("UPDATE manifest SET admission_rows=admission_rows+1 WHERE id=1")
	})
}

type admissionCommitStore struct{ original *sqliteAdmission }

func (b admissionCommitStore) valid(tx Transaction, dst []byte) bool {
	a := b.original
	return a != nil && tx.Kind == AdmissionCommit && tx.Authority == a.record.authority && tx.BeforeVersion == 1 && tx.CommitVersion == 2 && tx.FencingEpoch == a.record.fence && bytes.Equal(tx.Key, a.key[:a.keySize]) && bytes.Equal(tx.Projection, a.target[:a.targetSize]) && len(dst) >= a.targetSize
}

func (b admissionCommitStore) Commit(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
	if !b.valid(tx, dst) {
		return Observation{}, ErrConfiguration
	}
	a, s := b.original, b.original.store
	if err := s.begin(ctx); err != nil {
		return Observation{}, err
	}
	defer s.end()
	if s.epoch != tx.FencingEpoch {
		return Observation{}, ErrFenced
	}
	err := s.writeTransaction(ctx, a.check, func() error {
		state, count := int64(a.targetState), int64(0)
		if state == admissionAdmitted {
			count = 1
		}
		if err := s.exec("UPDATE admission SET version=?1,state=?2,admission_count=?3,projection=?4 WHERE lease=?5 AND version=?6 AND fence=?7 AND state=0 AND projection=?8", named(1, sqliteUint(2)), named(2, state), named(3, count), named(4, tx.Projection), named(5, tx.Key), named(6, sqliteUint(1)), named(7, sqliteUint(tx.FencingEpoch)), named(8, a.reserved[:a.reservedSize])); err != nil {
			return err
		}
		return s.changedOne()
	})
	if err != nil {
		return Observation{}, err
	}
	copy(dst, tx.Projection)
	return Observation{State: DurablyCommitted, CommitVersion: 2, AggregateVersion: 2, CommitFence: s.epoch, CurrentFence: s.epoch, ProjectionBytes: len(tx.Projection)}, nil
}

func (b admissionCommitStore) Confirm(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
	if !b.valid(tx, dst) {
		return Observation{}, ErrConfiguration
	}
	s := b.original.store
	if err := s.begin(ctx); err != nil {
		return Observation{}, err
	}
	defer s.end()
	if err := s.checkFence(); err != nil {
		return Observation{}, err
	}
	r, err := s.readAdmission(tx.Key, dst)
	if err != nil {
		return Observation{}, err
	}
	if err = ctx.Err(); err != nil {
		return Observation{}, err
	}
	if !r.found {
		return Observation{State: NotObserved}, nil
	}
	if r.state != int64(b.original.targetState) {
		r.State = Conflicting
	}
	return r.Observation, nil
}
