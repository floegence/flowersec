package rpcv4

import (
	"context"
	"crypto/rand"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// RecoveryIssuance is trusted service policy for one explicit issuance. The
// Session adapter supplies its signed caps independently. HistoryNotAfterMS is
// the application's actual checkpoint availability promise, never a refresh
// requested by a read or inferred from a new Session's expiry.
type RecoveryIssuance struct {
	DurationMS, ApplicationDurationLimitMS, HistoryNotAfterMS uint64
	SessionPolicy                                             protocolv4.ResumePolicy
}

// IssueRecoveryToken finishes this already registered unary execution with a
// canonical token. It runs only from its actual ordinary handler, and shares
// the registered recovery workspace and original durable transaction owner.
// It never returns an uncommitted token to application code. Ordinary joins
// and ReadResult return the original persisted result without entering here.
func (w *DurableExecutionWork) IssueRecoveryToken(ctx context.Context, verifier *RecoveryVerifier, keyID [16]byte, original ExecutionTarget, checkpoint protocolv4.ResumeCheckpoint, options RecoveryIssuance) error {
	if ctx == nil || verifier == nil || !options.SessionPolicy.Enabled || options.DurationMS == 0 || options.ApplicationDurationLimitMS == 0 || options.HistoryNotAfterMS == 0 {
		return ErrConfiguration
	}
	if err := w.beginIO(); err != nil {
		return err
	}
	defer w.endIO()
	if !w.entered || w.reported || w.writeFailed || w.outputBytes != 0 || w.policy.Shape != 0 || w.header.Kind() != "rpc_request" {
		return ErrOwner
	}
	if !verifier.mu.TryLock() {
		return ErrCapacity
	}
	defer verifier.mu.Unlock()
	if verifier.closed || original.Service != verifier.service || original.Service != w.target.Service || original.Operation == w.target.Operation {
		return ErrRecoveryUnauthorized
	}
	if err := verifier.reservation.CheckSameEnvironment(w.reservation); err != nil {
		return err
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.entryGuard(); err != nil {
			return err
		}
		if err := verifier.reservation.Check(); err != nil {
			return err
		}
		return w.access.WithExecutionAccess(original, func(ref resourcev4.Reference) error { return ref.CheckSameEnvironment(w.reservation) })
	}
	if err := check(); err != nil {
		return err
	}
	q, err := w.history.targetRequest(original)
	if err != nil {
		return err
	}
	generation, err := w.history.config.Store.RecoveryGeneration(ctx, q, check)
	if err != nil {
		return durableExecutionError(err)
	}
	if generation == math.MaxUint64 {
		return ErrCapacity
	}
	now, err := verifier.clock.Sample()
	if err != nil {
		return err
	}
	duration := min(options.DurationMS, options.ApplicationDurationLimitMS, options.SessionPolicy.MaxIssuedTokenDurationMS)
	if duration == 0 || duration > math.MaxUint64-now.LowerMS {
		return ErrConfiguration
	}
	expires := min(now.LowerMS+duration, options.HistoryNotAfterMS)
	if expires <= now.UpperMS {
		return timev4.ErrExpired
	}
	claims := protocolv4.ResumeClaims{Tenant: original.Service.Tenant, Audience: original.Service.Audience, Namespace: original.Service.Namespace, Caller: original.Caller.Subject, Operation: original.Operation, RequestDigest: original.RequestDigest, Checkpoint: checkpoint, Generation: generation, IssuedAtMS: now.LowerMS, ExpiresAtMS: expires}
	if _, err := rand.Read(claims.Nonce[:]); err != nil {
		return err
	}
	// Seal before signing so an ambiguous provider result cannot be retried
	// through this capability, even if an application catches the error.
	w.reported = true
	var token protocolv4.ResumeToken
	var proof protocolv4.VerifiedResumeToken
	found := false
	for index, key := range verifier.keys {
		if key.ID != keyID {
			continue
		}
		found = true
		if err := verifier.keyRefs[index].Check(); err != nil {
			return err
		}
		if key.Protection == 1 {
			token, err = verifier.codec.ProtectMACToken(claims, key.ID, key.MAC, check)
			if err == nil {
				proof, err = verifier.codec.VerifyMACToken(token, key.ID, key.MAC, check)
			}
		} else if key.Signer != nil {
			token, err = verifier.codec.SignToken(claims, key.ID, key.Public, key.Signer, check)
			if err == nil {
				proof, err = verifier.codec.VerifySignedToken(token, key.ID, key.Public)
			}
		} else {
			return ErrRecoveryUnauthorized
		}
		break
	}
	if !found {
		return ErrRecoveryUnauthorized
	}
	if err != nil {
		return err
	}
	if uint64(token.EncodedBytes()) > uint64(options.SessionPolicy.MaxTokenBytes) {
		return ErrCapacity
	}
	n, err := token.CopyEncoded(w.output)
	if err != nil {
		return ErrResponseLimit
	}
	w.outputBytes, w.outputCode = uint32(n), 0
	if err := w.database.FinishRecoveryToken(ctx, q, proof, min(options.ApplicationDurationLimitMS, options.SessionPolicy.MaxIssuedTokenDurationMS), options.HistoryNotAfterMS, check); err != nil {
		return durableExecutionError(err)
	}
	facts, err := w.database.FinishedResult()
	if err != nil {
		return err
	}
	w.final, w.resultCommitted = durableObservation(facts), true
	return nil
}

// ResultCommitted reports only this work owner's definite result commit. It
// cannot recover an execution capability from history or an imported reference.
func (w *DurableExecutionWork) ResultCommitted() bool {
	if w == nil || w.durableExecutionWork == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.io && w.resultCommitted
}
