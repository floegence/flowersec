package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

const executionRecoveryHeadsSQL = `CREATE TABLE recovery_heads (key BLOB PRIMARY KEY CHECK(length(key)=193), generation BLOB NOT NULL CHECK(length(generation)=8), target BLOB NOT NULL CHECK(length(target)=32), stream BLOB NOT NULL CHECK(length(stream)=8)) STRICT, WITHOUT ROWID`
const executionRecoveryTokensSQL = `CREATE TABLE recovery_tokens (key BLOB NOT NULL CHECK(length(key)=193), nonce BLOB NOT NULL CHECK(length(nonce)=32), generation BLOB NOT NULL CHECK(length(generation)=8), expires BLOB NOT NULL CHECK(length(expires)=8), protection INTEGER NOT NULL CHECK(protection IN (0,1)), token BLOB NOT NULL CHECK(length(token) BETWEEN 1 AND 4980), PRIMARY KEY(key,nonce)) STRICT, WITHOUT ROWID`

var ErrRecoveryConflict = errors.New("ledgerv4: checkpoint generation or token conflict")

// Recovery uses the original store transaction/workspace and bounded pages.
// It adds no driver, task, pending manager, key cache or independent history.
type sqliteExecutionRecovery struct {
	codec  *protocolv4.ResumeCodec
	token  [4980]byte
	result [4248]byte
}

func (e *SQLiteExecutions) SupportsCheckpoints() bool { return e != nil && e.recovery != nil }

func (e *SQLiteExecutions) recoveryGeneration(key []byte) (generation uint64, found bool, err error) {
	err = e.store.readOne("SELECT CASE WHEN length(generation)=8 THEN generation ELSE NULL END FROM recovery_heads WHERE key=?1", 1, func(values []driver.Value) error {
		var readErr error
		generation, readErr = readSQLiteUint(values[0])
		return readErr
	}, named(1, key))
	if errors.Is(err, io.EOF) {
		return 0, false, nil
	}
	return generation, err == nil, err
}

func (e *SQLiteExecutions) recoveryToken(key []byte, nonce [32]byte) (token protocolv4.ResumeToken, found bool, err error) {
	if e.recovery == nil {
		return token, false, ErrExecutionContract
	}
	err = e.store.readOne("SELECT CASE WHEN length(generation)=8 THEN generation ELSE NULL END,CASE WHEN length(expires)=8 THEN expires ELSE NULL END,protection,CASE WHEN length(token) BETWEEN 1 AND 4980 THEN token ELSE NULL END FROM recovery_tokens WHERE key=?1 AND nonce=?2", 4, func(values []driver.Value) error {
		generation, ge := readSQLiteUint(values[0])
		expires, ee := readSQLiteUint(values[1])
		protection, pe := values[2].(int64)
		wire, we := values[3].([]byte)
		if ge != nil || ee != nil || !pe || protection < 0 || protection > 1 || !we {
			return ErrStorageFormat
		}
		var decodeErr error
		token, decodeErr = e.recovery.codec.DecodeToken(wire, uint8(protection))
		if decodeErr != nil {
			return ErrStorageFormat
		}
		c := token.Claims()
		if !e.validStoredKey(key) || c.Nonce != nonce || c.Generation != generation || c.ExpiresAtMS != expires || c.Tenant != e.config.Service.Tenant || c.Audience != e.config.Service.Audience || c.Namespace != e.config.Service.Namespace || c.Caller != string(key[33:33+int(key[32])]) || !bytes.Equal(c.Operation[:], key[161:]) {
			return ErrStorageFormat
		}
		return nil
	}, named(1, key), named(2, nonce[:]))
	if errors.Is(err, io.EOF) {
		return protocolv4.ResumeToken{}, false, nil
	}
	if err != nil {
		return protocolv4.ResumeToken{}, false, err
	}
	return token, true, nil
}

// RecordRecoveryToken is an explicit authorized issuance commit. The caller
// creates and verifies the token with independent recovery keys before this
// call and may disclose it only after definite commit. Unknown commit is not
// permission to issue another token or to recover an execution capability.
func (e *SQLiteExecutions) RecordRecoveryToken(ctx context.Context, original SQLiteExecutionRequest, proof protocolv4.VerifiedResumeToken, maxIssuedDurationMS uint64, guard func() error) error {
	if e == nil || e.recovery == nil || guard == nil || !proof.Valid() || maxIssuedDurationMS == 0 {
		return ErrConfiguration
	}
	key, err := e.encodeKey(original.Key)
	if err != nil {
		return err
	}
	token := proof.Token()
	claims := proof.Claims()
	if !e.recoveryMatches(original, claims) {
		return ErrRecoveryConflict
	}
	if err = e.store.begin(ctx); err != nil {
		return err
	}
	defer e.store.end()
	defer clear(e.recovery.token[:])
	n, err := token.CopyEncoded(e.recovery.token[:])
	if err != nil {
		return err
	}
	check := func() error {
		if err := e.check(guard); err != nil {
			return err
		}
		now, err := e.config.Clock.Sample()
		if err != nil {
			return err
		}
		cap := min(maxIssuedDurationMS, e.config.RecoveryMaxIssuedDurationMS)
		if err := now.LowerBound(claims.IssuedAtMS, true); err != nil {
			return err
		}
		if claims.ExpiresAtMS <= now.UpperMS || claims.ExpiresAtMS <= claims.IssuedAtMS || claims.ExpiresAtMS-claims.IssuedAtMS > cap {
			return timev4.ErrExpired
		}
		return nil
	}
	return e.store.writeTransaction(ctx, check, func() error {
		return e.recordRecoveryToken(key[:], original, token, e.recovery.token[:n])
	})
}

// recordRecoveryToken runs inside the original execution-store transaction.
// An explicit issuance operation uses it together with its own result commit.
func (e *SQLiteExecutions) recordRecoveryToken(key []byte, original SQLiteExecutionRequest, token protocolv4.ResumeToken, wire []byte) error {
	claims := token.Claims()
	r, err := e.readExecution(key)
	if err != nil {
		return err
	}
	if err = executionMatches(r, original); err != nil {
		return err
	}
	if !r.Found {
		return ErrExecutionHistoryUnknown
	}
	size, err := e.readTerms(key)
	if err != nil {
		return err
	}
	contract, err := e.codec.Decode(e.contract[:size])
	if err != nil {
		return err
	}
	policy, err := contract.Policy()
	contract.Release()
	if err != nil {
		return err
	}
	if policy.Digest != r.contract || !policy.Checkpoint || policy.CheckpointFormat != claims.Checkpoint.Format() {
		return ErrExecutionContract
	}
	generation, found, err := e.recoveryGeneration(key)
	if err != nil {
		return err
	}
	if claims.Generation != generation {
		return ErrRecoveryConflict
	}
	existing, present, err := e.recoveryToken(key, claims.Nonce)
	if err != nil {
		return err
	}
	if present {
		if existing != token {
			return ErrRecoveryConflict
		}
		return nil
	}
	now, err := e.config.Clock.Sample()
	if err != nil {
		return err
	}
	if _, err = e.collectRecovery(key, now.LowerMS); err != nil {
		return err
	}
	count, err := e.store.scalar("SELECT count(*) FROM recovery_tokens WHERE key=?1", named(1, key))
	if err != nil {
		return err
	}
	used, ok := count.(int64)
	if !ok || used < 0 {
		return ErrStorageFormat
	}
	if used >= int64(e.config.RecoveryTokensPerOperation) {
		return ErrCapacity
	}
	if !found {
		var target [32]byte
		if err = e.store.exec("INSERT INTO recovery_heads VALUES (?1,?2,?3,?4)", named(1, key), named(2, sqliteUint(0)), named(3, target[:]), named(4, sqliteUint(0))); err != nil {
			return err
		}
	}
	return e.store.exec("INSERT INTO recovery_tokens VALUES (?1,?2,?3,?4,?5,?6)", named(1, key), named(2, claims.Nonce[:]), named(3, sqliteUint(claims.Generation)), named(4, sqliteUint(claims.ExpiresAtMS)), named(5, int64(token.Protection())), named(6, wire))
}

func (e *SQLiteExecutions) recoveryMatches(original SQLiteExecutionRequest, c protocolv4.ResumeClaims) bool {
	return c.Tenant == e.config.Service.Tenant && c.Audience == e.config.Service.Audience && c.Namespace == e.config.Service.Namespace && c.Caller == original.Key.CallerSubject && c.Operation == original.Key.OperationID && c.RequestDigest == original.RequestDigest
}

// FinishRecovery is the new recovery execution's once-only transaction. It
// consumes the original token generation, binds the exact new transport/Stream
// and forms this execution's result in one commit. Loss of the commit response
// never grants this work object another attempt. Ordinary Query reads the same
// retained execution result and cannot consume or renew a token.
func (w *SQLiteExecutionWork) FinishRecovery(ctx context.Context, original SQLiteExecutionRequest, proof protocolv4.VerifiedResumeToken, target [32]byte, streamID uint64, output []byte, guard func() error) (protocolv4.ResumeResult, error) {
	if err := w.acquire(ctx, false); err != nil {
		return protocolv4.ResumeResult{}, err
	}
	defer w.end()
	e := w.store
	if e.recovery == nil || !w.entered || w.finished || guard == nil || !proof.Valid() || streamID == 0 || streamID > math.MaxInt64 || target == ([32]byte{}) {
		return protocolv4.ResumeResult{}, ErrOwner
	}
	key, err := e.encodeKey(original.Key)
	if err != nil {
		return protocolv4.ResumeResult{}, err
	}
	claims := proof.Claims()
	if key == w.key || !e.recoveryMatches(original, claims) || w.request.Key.CallerAuthority != original.Key.CallerAuthority || w.request.Key.CallerSubject != original.Key.CallerSubject || claims.Generation == math.MaxUint64 {
		return protocolv4.ResumeResult{}, ErrRecoveryConflict
	}
	defer clear(e.recovery.result[:])
	response := protocolv4.ResumeResult{Status: 0, HasProgress: true, Checkpoint: claims.Checkpoint, Generation: claims.Generation + 1}
	n, err := e.recovery.codec.EncodeResult(e.recovery.result[:], response)
	if err != nil {
		return protocolv4.ResumeResult{}, err
	}
	if len(output) < n {
		return protocolv4.ResumeResult{}, ErrCapacity
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
		if claims.ExpiresAtMS <= now.UpperMS {
			return timev4.ErrExpired
		}
		return w.run.Check()
	}
	attempted := false
	var result SQLiteExecutionObservation
	err = e.store.writeTransaction(ctx, check, func() error {
		current, err := w.record()
		if err != nil {
			return err
		}
		finish := func(outcome protocolv4.ResumeResult) error {
			response = outcome
			n, err := e.recovery.codec.EncodeResult(e.recovery.result[:], response)
			if err != nil {
				return err
			}
			if len(output) < n {
				return ErrCapacity
			}
			copy(output, e.recovery.result[:n])
			return w.finishRecord(current, 0, e.recovery.result[:n], &attempted, &result)
		}
		old, err := e.readExecution(key[:])
		if err != nil {
			return err
		}
		// A token binds the full original request digest, which already commits
		// its original contract. The recovering caller need not manufacture an
		// extra old-contract field absent from ResumeRequest. Ordinary queries
		// continue to require their complete original reference independently.
		if old.Found && (old.request != original.RequestDigest || original.ContractDigest != ([32]byte{}) && old.contract != original.ContractDigest) {
			return finish(protocolv4.ResumeResult{Status: 1})
		}
		if !old.Found {
			return finish(protocolv4.ResumeResult{Status: 2})
		}
		generation, found, err := e.recoveryGeneration(key[:])
		if err != nil {
			return err
		}
		if !found || generation != claims.Generation {
			return finish(protocolv4.ResumeResult{Status: 1})
		}
		token, found, err := e.recoveryToken(key[:], claims.Nonce)
		if err != nil {
			return err
		}
		if !found || token != proof.Token() {
			return finish(protocolv4.ResumeResult{Status: 1})
		}
		// Result validation and formation run through the original result owner.
		// Any later error rolls back result, generation and token consumption.
		if err = finish(response); err != nil {
			return err
		}
		if err = e.store.exec("UPDATE recovery_heads SET generation=?1,target=?2,stream=?3 WHERE key=?4 AND generation=?5", named(1, sqliteUint(response.Generation)), named(2, target[:]), named(3, sqliteUint(streamID)), named(4, key[:]), named(5, sqliteUint(claims.Generation))); err != nil {
			return err
		}
		if err = e.store.changedOne(); err != nil {
			return err
		}
		// Every same-generation token has lost consumption eligibility at the
		// same transaction boundary; no per-token replay tombstones are needed.
		return e.store.exec("DELETE FROM recovery_tokens WHERE key=?1", named(1, key[:]))
	})
	if attempted {
		w.finished = true
	}
	if err != nil {
		return protocolv4.ResumeResult{}, err
	}
	w.result = result
	return response, nil
}

// collectRecovery is bounded by the configured per-operation token count and
// runs inside the existing history-GC transaction. Only a trusted lower bound
// can erase a still usable token. Live tokens pin their original execution.
func (e *SQLiteExecutions) collectRecovery(key []byte, lowerMS uint64) (bool, error) {
	if e.recovery == nil {
		return false, nil
	}
	if err := e.store.exec("DELETE FROM recovery_tokens WHERE key=?1 AND expires<=?2", named(1, key), named(2, sqliteUint(lowerMS))); err != nil {
		return false, err
	}
	value, err := e.store.scalar("SELECT count(*) FROM recovery_tokens WHERE key=?1", named(1, key))
	if err != nil {
		return false, err
	}
	n, ok := value.(int64)
	if !ok || n < 0 || n > int64(e.config.RecoveryTokensPerOperation) {
		return false, ErrStorageFormat
	}
	return n != 0, nil
}

func (e *SQLiteExecutions) verifyRecoveryCounts() error {
	for _, query := range []string{
		"SELECT count(*) FROM recovery_heads WHERE key NOT IN (SELECT key FROM executions)",
		"SELECT count(*) FROM recovery_tokens WHERE key NOT IN (SELECT key FROM recovery_heads)",
	} {
		n, err := e.store.scalar(query)
		if err != nil {
			return err
		}
		if n != int64(0) {
			return ErrStorageFormat
		}
	}
	if e.recovery == nil {
		for _, table := range []string{"recovery_heads", "recovery_tokens"} {
			n, err := e.store.scalar("SELECT count(*) FROM " + table)
			if err != nil {
				return err
			}
			if n != int64(0) {
				return ErrStorageFormat
			}
		}
	}
	return nil
}

func (e *SQLiteExecutions) verifyRecoveryRow(key []byte) error {
	if e.recovery == nil {
		return nil
	}
	generation, found, err := e.recoveryGeneration(key)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	err = e.store.readOne("SELECT CASE WHEN length(target)=32 THEN target ELSE NULL END,CASE WHEN length(stream)=8 THEN stream ELSE NULL END FROM recovery_heads WHERE key=?1", 2, func(values []driver.Value) error {
		target, ok := values[0].([]byte)
		stream, readErr := readSQLiteUint(values[1])
		var zero [32]byte
		if !ok || len(target) != 32 || readErr != nil || stream > math.MaxInt64 || generation == 0 && (stream != 0 || !bytes.Equal(target, zero[:])) || generation != 0 && (stream == 0 || bytes.Equal(target, zero[:])) {
			return ErrStorageFormat
		}
		return nil
	}, named(1, key))
	if err != nil {
		return err
	}
	countValue, err := e.store.scalar("SELECT count(*) FROM recovery_tokens WHERE key=?1", named(1, key))
	if err != nil {
		return err
	}
	count, ok := countValue.(int64)
	if !ok || count < 0 || count > int64(e.config.RecoveryTokensPerOperation) {
		return ErrStorageFormat
	}
	var previous [32]byte
	for i := int64(0); i < count; i++ {
		query := "SELECT length(nonce),CASE WHEN length(nonce)=32 THEN nonce ELSE NULL END FROM recovery_tokens WHERE key=?1 ORDER BY nonce LIMIT 1"
		args := []driver.NamedValue{named(1, key)}
		if i != 0 {
			query = "SELECT length(nonce),CASE WHEN length(nonce)=32 THEN nonce ELSE NULL END FROM recovery_tokens WHERE key=?1 AND nonce>?2 ORDER BY nonce LIMIT 1"
			args = append(args, named(2, previous[:]))
		}
		var nonce [32]byte
		n, err := e.readBoundedBlob(query, nonce[:], args...)
		if err != nil || n != 32 {
			return ErrStorageFormat
		}
		token, found, err := e.recoveryToken(key, nonce)
		if err != nil || !found || token.Claims().Generation != generation {
			return ErrStorageFormat
		}
		r, err := e.readExecution(key)
		if err != nil || !r.Found || r.request != token.Claims().RequestDigest {
			return ErrStorageFormat
		}
		previous = nonce
	}
	return nil
}
