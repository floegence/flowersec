package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// CheckpointIssuanceOptions is the trusted method's explicit application
// promise. Signed Session duration and token-size limits are supplied by the
// SDK from the authenticated admission, never by the request payload.
type CheckpointIssuanceOptions struct {
	KeyID                                                     [16]byte
	DurationMS, ApplicationDurationLimitMS, HistoryNotAfterMS uint64
}

// IssueCheckpoint commits this unary operation's only result as a recovery
// token. The application supplies the checkpoint it actually retained and its
// availability deadline. After success, Write and another issuance are closed;
// ordinary duplicate requests read these same persisted bytes.
func (w *UnaryResponse) IssueCheckpoint(ctx context.Context, original rpcv4.ExecutionTarget, checkpoint protocolv4.ResumeCheckpoint, options CheckpointIssuanceOptions) error {
	if w == nil || w.invocation == nil || ctx == nil {
		return rpcv4.ErrOwner
	}
	i := w.invocation
	i.mu.Lock()
	x, closed := i.execution, i.closed || i.returned
	i.mu.Unlock()
	if closed || x == nil || x.durableWork == nil {
		return rpcv4.ErrExecutionUnsupported
	}
	i.plan.mu.Lock()
	policy := i.plan.resumePolicy
	i.plan.mu.Unlock()
	if !policy.Enabled {
		return rpcv4.ErrExecutionUnsupported
	}
	binding, _, err := i.dispatcher.executionBindingAuthority(i.method.Method, i.method.Namespace)
	if err != nil {
		return err
	}
	if binding.Recovery == nil || binding.DurableHistory != x.durableHistory {
		return rpcv4.ErrExecutionUnsupported
	}
	return x.durableWork.IssueRecoveryToken(ctx, binding.Recovery, options.KeyID, original, checkpoint, rpcv4.RecoveryIssuance{DurationMS: options.DurationMS, ApplicationDurationLimitMS: options.ApplicationDurationLimitMS, HistoryNotAfterMS: options.HistoryNotAfterMS, SessionPolicy: policy})
}
