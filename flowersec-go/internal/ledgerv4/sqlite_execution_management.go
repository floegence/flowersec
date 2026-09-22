package ledgerv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"io"
)

var ErrExecutionCancelUnsupported = errors.New("ledgerv4: original contract does not support cancellation")

// RequestCancel records an authorized request against the original contract.
// It never refunds the actual task or asserts that external effects stopped.
func (e *SQLiteExecutions) RequestCancel(ctx context.Context, q SQLiteExecutionRequest, guard func() error) (observation SQLiteExecutionObservation, err error) {
	key, err := e.encodeKey(q.Key)
	if err != nil {
		return observation, err
	}
	if guard == nil || q.RequestDigest == ([32]byte{}) || q.ContractDigest == ([32]byte{}) {
		return observation, ErrConfiguration
	}
	if err = e.store.begin(ctx); err != nil {
		return observation, err
	}
	defer e.store.end()
	err = e.store.writeTransaction(ctx, func() error { return e.check(guard) }, func() error {
		r, err := e.readExecution(key[:])
		if err != nil {
			return err
		}
		if err = executionMatches(r, q); err != nil {
			return err
		}
		if !r.Found {
			floor, err := e.floor(q.Key.CallerAuthority)
			if err != nil {
				return err
			}
			if storageOperationCutoff(key[:]) <= floor {
				return ErrExecutionHistoryUnknown
			}
			return nil
		}
		n, err := e.readTerms(key[:])
		if err != nil {
			return err
		}
		c, err := e.codec.Decode(e.contract[:n])
		if err != nil {
			return err
		}
		defer c.Release()
		p, err := c.Policy()
		if err != nil {
			return err
		}
		if p.Digest != r.contract {
			return ErrStorageFormat
		}
		if p.CancelMode != 1 {
			return ErrExecutionCancelUnsupported
		}
		if !r.CancelRequested && r.WorkActive && (r.State == SQLiteExecutionAccepted || r.State == SQLiteExecutionExecuting || r.State == SQLiteExecutionUnknown) {
			r.CancelRequested = true
			if err = e.updateFacts(key[:], r.SQLiteExecutionObservation); err != nil {
				return err
			}
			r.Version++
		}
		observation = e.observation(r)
		return nil
	})
	if err != nil {
		return SQLiteExecutionObservation{}, err
	}
	return observation, nil
}

// ReadResult copies into the adapter's already admitted output. No live reader
// or provider cursor escapes this call and no query resets result retention.
func (e *SQLiteExecutions) ReadResult(ctx context.Context, q SQLiteExecutionRequest, dst []byte, guard func() error) (observation SQLiteExecutionObservation, n int, err error) {
	key, err := e.encodeKey(q.Key)
	if err != nil {
		return observation, 0, err
	}
	if guard == nil || q.RequestDigest == ([32]byte{}) || q.ContractDigest == ([32]byte{}) {
		return observation, 0, ErrConfiguration
	}
	if err = e.store.begin(ctx); err != nil {
		return observation, 0, err
	}
	defer e.store.end()
	if err = e.check(guard); err != nil {
		return observation, 0, err
	}
	if err = e.store.checkFence(); err != nil {
		return observation, 0, err
	}
	r, err := e.readExecution(key[:])
	if err != nil {
		return observation, 0, err
	}
	if err = executionMatches(r, q); err != nil {
		return observation, 0, err
	}
	observation = e.observation(r)
	if !r.Found {
		floor, err := e.floor(q.Key.CallerAuthority)
		if err != nil {
			return observation, 0, err
		}
		if storageOperationCutoff(key[:]) <= floor {
			return observation, 0, ErrExecutionHistoryUnknown
		}
		return observation, 0, ErrOwner
	}
	if !r.ResultFormed {
		return observation, 0, ErrExecutionResultUnavailable
	}
	if r.ResultDeleted || r.ResultNotAfterMS == 0 && !r.WorkActive {
		return observation, 0, ErrExecutionResultExpired
	}
	now, sampleErr := e.config.Clock.Sample()
	if sampleErr != nil {
		return observation, 0, sampleErr
	}
	if r.ResultNotAfterMS != 0 && !now.ValidBefore(r.ResultNotAfterMS) {
		return observation, 0, ErrExecutionResultExpired
	}
	if uint64(len(dst)) < uint64(r.ResultBytes) {
		return observation, 0, ErrCapacity
	}
	n, err = e.readBoundedBlob("SELECT ?2,substr(payload,1,?2) FROM executions WHERE key=?1", dst, named(1, key[:]), named(2, int64(r.ResultBytes)))
	if err == nil && sha256.Sum256(dst[:n]) != r.ResultDigest {
		err = ErrStorageFormat
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = e.check(guard)
	}
	if err == nil {
		now, sampleErr := e.config.Clock.Sample()
		err = sampleErr
		if err == nil && r.ResultNotAfterMS != 0 && !now.ValidBefore(r.ResultNotAfterMS) {
			err = ErrExecutionResultExpired
		}
	}
	if err != nil {
		clear(dst[:n])
		return observation, 0, err
	}
	return observation, n, nil
}

func (e *SQLiteExecutions) validStoredKey(key []byte) bool {
	if len(key) != executionStorageKeyBytes {
		return false
	}
	n := int(key[32])
	if n < 1 || n > 128 {
		return false
	}
	var q SQLiteExecutionKey
	copy(q.CallerAuthority[:], key[:32])
	copy(q.OperationID[:], key[161:])
	q.CallerSubject = string(key[33 : 33+n])
	encoded, err := e.encodeKey(q)
	return err == nil && bytes.Equal(encoded[:], key)
}

func (e *SQLiteExecutions) readGCPage(after []byte) (n int, err error) {
	rows, err := e.store.querier.QueryContext(context.Background(), "SELECT CASE WHEN length(key)=193 THEN key ELSE NULL END,CASE WHEN length(facts)=104 THEN facts ELSE NULL END FROM executions WHERE key>?1 ORDER BY key LIMIT 16", []driver.NamedValue{named(1, after)})
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [2]driver.Value
	for n < len(e.gc) {
		if err = rows.Next(values[:]); err == io.EOF {
			return n, nil
		} else if err != nil {
			return 0, err
		}
		key, ok := values[0].([]byte)
		if !ok || !e.validStoredKey(key) {
			return 0, ErrStorageFormat
		}
		v, err := decodeExecutionFacts(values[1])
		if err != nil {
			return 0, err
		}
		copy(e.gc[n].key[:], key)
		e.gc[n].facts = v
		n++
	}
	return n, nil
}

// Collect performs one bounded page of reclamation. The monotonic domain floors
// are installed durably in the SAME transaction before any detail is removed.
// Active original work, promised result lifetime, and history lifetime remain
// independent reasons to retain a row. Unknown outcome alone is not eternal.
func (e *SQLiteExecutions) Collect(ctx context.Context) error {
	if e == nil || e.store == nil {
		return ErrOwner
	}
	if err := e.store.begin(ctx); err != nil {
		return err
	}
	defer e.store.end()
	now, err := e.config.Clock.Sample()
	if err != nil {
		return err
	}
	var next [executionStorageKeyBytes]byte
	err = e.store.writeTransaction(ctx, func() error { return nil }, func() error {
		for _, authority := range e.config.CallerAuthorities {
			if err := e.store.exec("UPDATE domains SET floor=?1 WHERE authority=?2 AND floor<?1", named(1, sqliteUint(now.LowerMS)), named(2, authority[:])); err != nil {
				return err
			}
		}
		n, err := e.readGCPage(e.gcCursor[:])
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			row := &e.gc[i]
			r, err := e.readExecution(row.key[:])
			if err != nil {
				return err
			}
			next = row.key
			changed := false
			if r.WorkActive && (r.State == SQLiteExecutionAccepted || r.State == SQLiteExecutionExecuting) && (!now.ValidBefore(r.DeadlineAtMS) || r.RunDeadlineAtMS != 0 && !now.ValidBefore(r.RunDeadlineAtMS)) {
				// Still retain the actual work owner, regardless of this fact.
				r.State, r.Reason = SQLiteExecutionUnknown, SQLiteExecutionReasonDeadline
				changed = true
			}
			if r.ResultFormed && !r.ResultDeleted && (r.ResultNotAfterMS != 0 && now.RetainedThrough(r.ResultNotAfterMS) || r.ResultNotAfterMS == 0 && !r.WorkActive) {
				if err = e.store.exec("UPDATE executions SET payload=x'' WHERE key=?1", named(1, row.key[:])); err != nil {
					return err
				}
				r.ResultDeleted = true
				changed = true
			}
			recoveryHeld, err := e.collectRecovery(row.key[:], now.LowerMS)
			if err != nil {
				return err
			}
			contentHeld, err := e.collectContent(row.key[:], now.LowerMS)
			if err != nil {
				return err
			}
			if !contentHeld && !recoveryHeld && !r.WorkActive && (!r.ResultFormed || r.ResultDeleted) && now.RetainedThrough(r.HistoryNotBeforeGCMS) && storageOperationCutoff(row.key[:]) <= now.LowerMS {
				if err = e.store.exec("DELETE FROM recovery_heads WHERE key=?1", named(1, row.key[:])); err != nil {
					return err
				}
				if err = e.store.exec("DELETE FROM content_items WHERE key=?1", named(1, row.key[:])); err != nil {
					return err
				}
				if err = e.store.exec("DELETE FROM content_heads WHERE key=?1", named(1, row.key[:])); err != nil {
					return err
				}
				if err = e.store.exec("DELETE FROM executions WHERE key=?1", named(1, row.key[:])); err != nil {
					return err
				}
				if err = e.store.exec("UPDATE manifest SET record_count=record_count-1 WHERE id=1"); err != nil {
					return err
				}
			} else if changed {
				if err = e.updateFacts(row.key[:], r.SQLiteExecutionObservation); err != nil {
					return err
				}
			}
		}
		if n < len(e.gc) {
			next = [executionStorageKeyBytes]byte{}
		}
		return nil
	})
	if err == nil {
		e.gcCursor = next
	}
	return err
}
