package rpcv4

import (
	"context"
	"errors"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// RecordRecoveryToken is the explicit issuer's original history operation.
// The application's independent key service supplies the verified token;
// current execution authority is rechecked by the store's one commit owner.
func (s *DurableExecutions) RecordRecoveryToken(ctx context.Context, original ExecutionTarget, proof protocolv4.VerifiedResumeToken, maxIssuedDurationMS uint64, access ExecutionAccess) error {
	q, err := s.targetRequest(original)
	if err != nil {
		return err
	}
	if err = s.beginCall(false); err != nil {
		return err
	}
	defer s.endCall()
	return durableExecutionError(s.config.Store.RecordRecoveryToken(ctx, q, proof, maxIssuedDurationMS, func() error { return s.checkAccess(original, access) }))
}

// FinishRecovery belongs to the same dispatched durable work as its complete
// resume_request. targetGuard is the SDK's finite current target-Stream gate;
// it does no provider work or application callbacks. No ordinary Finish may
// subsequently overwrite an attempted recovery outcome, including unknown.
func (w *DurableExecutionWork) FinishRecovery(ctx context.Context, proof VerifiedRecovery, targetGuard func() error) error {
	if ctx == nil || targetGuard == nil {
		return ErrConfiguration
	}
	if err := w.beginIO(); err != nil {
		return err
	}
	defer w.endIO()
	if !w.entered || w.reported || w.writeFailed || !proof.valid || proof.verifier == nil || w.header.Kind() != "resume_request" || proof.header != w.header || proof.claims.Generation == math.MaxUint64 {
		return ErrOwner
	}
	q, err := w.history.targetRequest(proof.original)
	if err != nil {
		return err
	}
	check := func() error {
		if err := w.entryGuard(); err != nil {
			return err
		}
		if err := proof.check(ctx, w.access); err != nil {
			return err
		}
		return targetGuard()
	}
	if err := check(); err != nil {
		return err
	}
	expected := protocolv4.ResumeResult{Status: 0, HasProgress: true, Checkpoint: proof.claims.Checkpoint, Generation: proof.claims.Generation + 1}
	// The store forms the canonical response in this already admitted output
	// before its single commit. A stale token gets a durable rejected result;
	// a missing original history gets unknown. Ambiguous commits never publish.
	w.reported = true
	result, err := w.database.FinishRecovery(ctx, q, proof.token, proof.target.TransportContext, proof.target.StreamID, w.output, check)
	if err != nil {
		return durableExecutionError(err)
	}
	if result.Status == 0 && result != expected || result.Status != 0 && result.HasProgress {
		return ErrAssociation
	}
	facts, err := w.database.FinishedResult()
	if err != nil {
		return err
	}
	w.outputBytes, w.outputCode = facts.ResultBytes, 0
	w.final, w.resultCommitted = durableObservation(facts), true
	return nil
}

// ResolveRecovery makes the token decision on this execution's actual input.
// Definitive rejection is itself this recovery operation's durable result;
// uncertainty never becomes rejection and never starts another token attempt.
func (w *DurableExecutionWork) ResolveRecovery(ctx context.Context, verifier *RecoveryVerifier, target RecoveryTarget, targetGuard func() error) error {
	if ctx == nil || verifier == nil || targetGuard == nil {
		return ErrConfiguration
	}
	if err := w.beginIO(); err != nil {
		return err
	}
	if !w.entered || w.reported || w.writeFailed || w.header.Kind() != "resume_request" {
		w.endIO()
		return ErrOwner
	}
	// The real dispatched task and its verifier borrow retain all owners while
	// bounded crypto runs. Current authority/target precede token inspection.
	err := w.entryGuard()
	if err == nil {
		err = targetGuard()
	}
	var proof VerifiedRecovery
	if err == nil {
		proof, err = verifier.VerifyCallerInput(ctx, w.input, w.target.Caller, target, w.access)
	}
	if errors.Is(err, ErrRecoveryRejected) {
		// Use the verifier's original admitted codec; no per-error workspace,
		// application callback or unbounded failure payload is introduced.
		verifier.mu.Lock()
		if verifier.closed {
			err = ErrClosed
		} else {
			var n int
			n, err = verifier.codec.EncodeResult(w.output, protocolv4.ResumeResult{Status: 1})
			if err == nil {
				w.outputBytes = uint32(n)
			}
		}
		verifier.mu.Unlock()
		if err == nil {
			w.reported, w.outputCode = true, 0
			err = w.database.Finish(ctx, 0, w.output[:w.outputBytes], w.resultGuard)
			if err == nil {
				var factsErr error
				facts, factsErr := w.database.FinishedResult()
				err = factsErr
				if err == nil {
					w.final, w.resultCommitted = durableObservation(facts), true
				}
			}
		}
		w.endIO()
		return durableExecutionError(err)
	}
	w.endIO()
	if err != nil {
		return err
	}
	return w.FinishRecovery(ctx, proof, targetGuard)
}
