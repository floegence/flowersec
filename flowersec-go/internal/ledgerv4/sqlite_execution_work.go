package ledgerv4

import (
	"context"
	"crypto/sha256"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func (w *SQLiteExecutionWork) acquire(ctx context.Context, retained bool) error {
	if w == nil || w.sqliteExecutionWork == nil || w.store == nil || ctx == nil {
		return ErrOwner
	}
	if !w.busy.CompareAndSwap(false, true) {
		return ErrCapacity
	}
	if w.closed {
		w.busy.Store(false)
		return ErrOwner
	}
	s := w.store.store.sqliteStore
	var err error
	if retained {
		s.mu.Lock()
		if s.complete || s.conn == nil || s.active {
			err = ErrCapacity
		} else {
			err = ctx.Err()
			for _, r := range [...]resourcev4.Reference{w.reservation, w.backing, s.reservation, s.environment, s.disk} {
				if err == nil {
					err = r.CheckRetained()
				}
			}
			if err == nil {
				s.active = true
			}
		}
		s.mu.Unlock()
	} else {
		err = s.begin(ctx)
	}
	if err != nil {
		w.busy.Store(false)
		return err
	}
	if w.epoch != s.epoch {
		s.end()
		w.busy.Store(false)
		return ErrFenced
	}
	return nil
}

func (w *SQLiteExecutionWork) end() { w.store.store.end(); w.busy.Store(false) }

func (w *SQLiteExecutionWork) CleanupComplete() bool {
	if w == nil || w.sqliteExecutionWork == nil {
		return true
	}
	if !w.busy.CompareAndSwap(false, true) {
		return false
	}
	done := w.closed
	w.busy.Store(false)
	return done
}

func (w *SQLiteExecutionWork) record() (storedExecution, error) {
	r, err := w.store.readExecution(w.key[:])
	if err != nil {
		return r, err
	}
	if r.Found && r.invocation != w.invocation {
		// An uncertain attempt may have rolled back before a different
		// original invocation registered this same key. It has no dispatch
		// rights and must release only its own cleanup pin, not that row.
		if !w.registered {
			return storedExecution{}, nil
		}
		return storedExecution{}, ErrFenced
	}
	if err = executionMatches(r, w.request); err != nil {
		return r, err
	}
	if r.Found && (r.Epoch != w.epoch || r.RegistrationRevision != w.request.RegistrationRevision) {
		return storedExecution{}, ErrFenced
	}
	return r, nil
}

// Enter persists the one original handoff before the adapter lends input or
// invokes application code. A failed or ambiguous handoff is never retried as
// permission to dispatch; Exit can still settle that original work tail.
func (w *SQLiteExecutionWork) Enter(ctx context.Context, guard func() error) error {
	if err := w.acquire(ctx, false); err != nil {
		return err
	}
	defer w.end()
	if !w.committed || w.entered || guard == nil {
		return ErrOwner
	}
	e := w.store
	check := func() error {
		if err := e.check(guard); err != nil {
			return err
		}
		if err := w.reservation.Check(); err != nil {
			return err
		}
		if err := w.deadline.Check(); err != nil {
			return err
		}
		if w.run != nil {
			return w.run.Check()
		}
		return nil
	}
	attempted := false
	err := e.store.writeTransaction(ctx, check, func() error {
		r, err := w.record()
		if err != nil {
			return err
		}
		if !r.Found || !r.WorkActive || r.Dispatched || r.State != SQLiteExecutionAccepted {
			return ErrOwner
		}
		if r.CancelRequested {
			return timev4.ErrCancelled
		}
		registration, err := e.readContract(r.contract)
		if err != nil {
			return err
		}
		if !registration.enabled {
			return ErrExecutionContract
		}
		n, err := e.readTerms(w.key[:])
		if err != nil {
			return err
		}
		c, err := e.codec.Decode(e.contract[:n])
		if err != nil {
			return err
		}
		defer c.Release()
		p, err := e.checkContract(c)
		if err != nil {
			return err
		}
		if p.Digest != r.contract {
			return ErrStorageFormat
		}
		now, err := w.deadline.Sample()
		if err != nil {
			return err
		}
		runMS := p.ExecutionRunMS
		if p.Shape == 1 {
			runMS = min(runMS, p.StreamDurationMS)
		}
		w.run, err = w.deadline.ForkAgeAt(now, runMS)
		if err != nil {
			return err
		}
		r.State, r.Dispatched, r.RunDeadlineAtMS = SQLiteExecutionExecuting, true, w.run.Cap()
		attempted = true
		return e.updateFacts(w.key[:], r.SQLiteExecutionObservation)
	})
	// No second attempt can turn an uncertain original handoff into another
	// handoff. The adapter receives permission only from this definite success.
	if attempted {
		w.committed = false
	}
	if err == nil {
		w.entered = true
	}
	return err
}

// CheckRunning supplies the original dispatcher with the stored cancellation
// fact and its unchanged deadline owners. It does not terminate actual work.
func (w *SQLiteExecutionWork) CheckRunning(ctx context.Context, guard func() error) error {
	if err := w.acquire(ctx, false); err != nil {
		return err
	}
	defer w.end()
	if !w.entered || guard == nil {
		return ErrOwner
	}
	if err := w.store.check(guard); err != nil {
		return err
	}
	r, err := w.record()
	if err != nil {
		return err
	}
	if !r.Found || !r.WorkActive {
		return ErrOwner
	}
	if r.CancelRequested {
		return timev4.ErrCancelled
	}
	if err = w.deadline.Check(); err != nil {
		return err
	}
	return w.run.Check()
}

// Finish records a real original handler result, including a late result from
// work whose dispatch/run deadline already ended. It creates no new execution.
// Retention begins at this formation, never at a later query or Session join.
// Once the write is attempted, another Finish cannot replace that result,
// including when its original commit response was lost.
func (w *SQLiteExecutionWork) Finish(ctx context.Context, errorCode uint32, payload []byte, guard func() error) error {
	if err := w.acquire(ctx, false); err != nil {
		return err
	}
	defer w.end()
	if !w.entered || w.finished || guard == nil {
		return ErrOwner
	}
	e := w.store
	check := func() error {
		if err := w.reservation.Check(); err != nil {
			return err
		}
		return e.check(guard)
	}
	attempted := false
	var result SQLiteExecutionObservation
	err := e.store.writeTransaction(ctx, check, func() error {
		r, err := w.record()
		if err != nil {
			return err
		}
		return w.finishRecord(r, errorCode, payload, &attempted, &result)
	})
	if attempted {
		w.finished = true
	}
	if err == nil {
		w.result = result
	}
	return err
}

// finishRecord runs only inside this original work's admitted store transaction.
// Recovery can atomically bind its checkpoint generation and form this same
// original unary result without creating another execution or commit owner.
func (w *SQLiteExecutionWork) finishRecord(r storedExecution, errorCode uint32, payload []byte, attempted *bool, result *SQLiteExecutionObservation) error {
	e := w.store
	if !r.Found || !r.WorkActive || !r.Dispatched || r.ResultFormed || r.State != SQLiteExecutionExecuting && r.State != SQLiteExecutionUnknown {
		return ErrOwner
	}
	if uint64(len(payload)) > uint64(r.ResponseLimitBytes) {
		return ErrCapacity
	}
	n, err := e.readTerms(w.key[:])
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
	if p.Shape == 2 {
		if len(payload) != 0 || errorCode != 0 {
			return ErrExecutionContract
		}
	} else if p.Shape == 1 && len(payload) != 0 {
		return ErrExecutionContract
	} else if err = c.CheckResponsePayload(errorCode, uint32(len(payload))); err != nil {
		return err
	}
	now, err := e.config.Clock.Sample()
	if err != nil {
		return err
	}
	if p.ResultRetentionMS > math.MaxUint64-now.UpperMS {
		return ErrConfiguration
	}
	r.State, r.Reason = SQLiteExecutionCompleted, SQLiteExecutionReasonNone
	if errorCode != 0 {
		r.State = SQLiteExecutionFailed
	}
	*attempted = true
	if p.Shape == 1 {
		r.ApplicationErrorCode = errorCode
	}
	if p.Shape == 0 {
		r.ResultFormed, r.ResultBytes, r.ApplicationErrorCode, r.ResultDigest = true, uint32(len(payload)), errorCode, sha256.Sum256(payload)
		if p.ResultRetentionMS != 0 {
			r.ResultNotAfterMS = now.UpperMS + p.ResultRetentionMS
		}
		// Keep the original full reservation until result GC. SQLite's
		// fixed bounded expression needs no uncharged SDK result buffer.
		if err = e.store.exec("UPDATE executions SET payload=CAST(coalesce(?1,x'') || zeroblob(?2) AS BLOB) WHERE key=?3", named(1, payload), named(2, int64(r.ResponseLimitBytes)-int64(len(payload))), named(3, w.key[:])); err != nil {
			return err
		}
	}
	*result = r.SQLiteExecutionObservation
	result.Version++
	return e.updateFacts(w.key[:], r.SQLiteExecutionObservation)
}

// FinishedResult returns only facts from this handle's definitely committed
// result. It neither reads the provider nor grants another result write.
func (w *SQLiteExecutionWork) FinishedResult() (SQLiteExecutionObservation, error) {
	if w == nil || w.sqliteExecutionWork == nil {
		return SQLiteExecutionObservation{}, ErrOwner
	}
	if !w.busy.CompareAndSwap(false, true) {
		return SQLiteExecutionObservation{}, ErrCapacity
	}
	defer w.busy.Store(false)
	if !w.result.Found {
		return SQLiteExecutionObservation{}, ErrOwner
	}
	return w.result, nil
}

// Exit is called only after the original task and its external work have
// actually ended. It remains available after Close or root revocation, and
// retains its pin if durable settlement cannot be confirmed. Retrying Exit is
// cleanup of this same original owner, never permission to execute again.
func (w *SQLiteExecutionWork) Exit(ctx context.Context) error {
	if err := w.acquire(ctx, true); err != nil {
		return err
	}
	defer w.end()
	e := w.store
	err := e.store.writeTransactionMode(ctx, func() error { return w.reservation.CheckRetained() }, func() error {
		r, err := w.record()
		if err != nil {
			return err
		}
		if !r.Found || !r.WorkActive {
			return nil
		}
		r.WorkActive = false
		if r.State == SQLiteExecutionAccepted {
			r.State, r.Reason = SQLiteExecutionFailed, SQLiteExecutionReasonNotDispatched
			if r.CancelRequested {
				r.Reason = SQLiteExecutionReasonCancelled
			}
		} else if r.State == SQLiteExecutionExecuting {
			r.State, r.Reason = SQLiteExecutionUnknown, SQLiteExecutionReasonOutcomeUnknown
		}
		if err = e.updateFacts(w.key[:], r.SQLiteExecutionObservation); err != nil {
			return err
		}
		return e.store.exec("UPDATE manifest SET active_count=active_count-1 WHERE id=1")
	}, true)
	if err == nil {
		w.release()
	}
	return err
}

func (w *SQLiteExecutionWork) release() {
	w.closed = true
	w.deadline, w.run = nil, nil
	if w.capacity == nil {
		w.backing.Release()
	} else {
		w.capacity.releaseWork()
	}
	w.reservation.Release()
	s := w.store.store.sqliteStore
	s.mu.Lock()
	s.workPins--
	s.signalLocked()
	s.mu.Unlock()
}

// ConstrainRunDeadline copies only the original local run cap/projection. It
// performs no storage I/O and cannot change a committed dispatch or restart its
// duration. The same busy gate excludes cleanup of this actual work owner.
func (w *SQLiteExecutionWork) ConstrainRunDeadline(deadline *timev4.Deadline) error {
	if w == nil || w.sqliteExecutionWork == nil || deadline == nil {
		return ErrOwner
	}
	if !w.busy.CompareAndSwap(false, true) {
		return ErrCapacity
	}
	defer w.busy.Store(false)
	if w.closed || !w.entered || w.run == nil {
		return ErrOwner
	}
	return deadline.TightenFrom(w.run)
}
