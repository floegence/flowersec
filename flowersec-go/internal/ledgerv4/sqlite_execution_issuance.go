package ledgerv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// RecoveryGeneration is an authorized, read-only snapshot for an explicit
// issuance invocation. The eventual transaction rechecks this generation;
// this read neither renews a token nor grants dispatch rights.
func (e *SQLiteExecutions) RecoveryGeneration(ctx context.Context, original SQLiteExecutionRequest, guard func() error) (generation uint64, err error) {
	if e == nil || e.recovery == nil || guard == nil {
		return 0, ErrConfiguration
	}
	key, err := e.encodeKey(original.Key)
	if err != nil {
		return 0, err
	}
	if err = e.store.begin(ctx); err != nil {
		return 0, err
	}
	defer e.store.end()
	if err = e.check(guard); err != nil {
		return 0, err
	}
	if err = e.store.checkFence(); err != nil {
		return 0, err
	}
	err = func() error {
		r, err := e.readExecution(key[:])
		if err != nil {
			return err
		}
		if err = executionMatches(r, original); err != nil {
			return err
		}
		if !r.Found {
			return ErrExecutionHistoryUnknown
		}
		generation, _, err = e.recoveryGeneration(key[:])
		return err
	}()
	if err == nil {
		err = e.check(guard)
	}
	if err != nil {
		return 0, err
	}
	return generation, nil
}

// FinishRecoveryToken atomically stores the one newly issued token and this
// original unary issuance execution's result. Duplicate issuance requests use
// that execution's ordinary result join, including after restart; they never
// regenerate a nonce, sign again, or change the original expiry.
func (w *SQLiteExecutionWork) FinishRecoveryToken(ctx context.Context, original SQLiteExecutionRequest, proof protocolv4.VerifiedResumeToken, maxIssuedDurationMS, historyNotAfterMS uint64, guard func() error) error {
	if err := w.acquire(ctx, false); err != nil {
		return err
	}
	defer w.end()
	e := w.store
	if e.recovery == nil || !w.entered || w.finished || guard == nil || !proof.Valid() || maxIssuedDurationMS == 0 {
		return ErrOwner
	}
	key, err := e.encodeKey(original.Key)
	if err != nil {
		return err
	}
	claims := proof.Claims()
	if key == w.key || !e.recoveryMatches(original, claims) {
		return ErrRecoveryConflict
	}
	defer clear(e.recovery.token[:])
	n, err := proof.Token().CopyEncoded(e.recovery.token[:])
	if err != nil {
		return err
	}
	check := func() error {
		if err := e.check(guard); err != nil {
			return err
		}
		if err := w.reservation.Check(); err != nil {
			return err
		}
		now, err := w.deadline.Sample()
		if err != nil {
			return err
		}
		if err := now.LowerBound(claims.IssuedAtMS, true); err != nil {
			return err
		}
		duration := min(maxIssuedDurationMS, e.config.RecoveryMaxIssuedDurationMS)
		if claims.ExpiresAtMS <= now.UpperMS || claims.ExpiresAtMS <= claims.IssuedAtMS || claims.ExpiresAtMS-claims.IssuedAtMS > duration || claims.ExpiresAtMS > historyNotAfterMS {
			return timev4.ErrExpired
		}
		return w.run.Check()
	}
	attempted := false
	var result SQLiteExecutionObservation
	err = e.store.writeTransaction(ctx, check, func() error {
		r, err := w.record()
		if err != nil {
			return err
		}
		// All quota/history checks and writes share this transaction. Failure
		// rolls back both rows; a lost commit response remains unknown.
		if err := e.recordRecoveryToken(key[:], original, proof.Token(), e.recovery.token[:n]); err != nil {
			return err
		}
		return w.finishRecord(r, 0, e.recovery.token[:n], &attempted, &result)
	})
	if attempted {
		w.finished = true
	}
	if err == nil {
		w.result = result
	}
	return err
}
