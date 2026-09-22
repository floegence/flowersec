package rpcv4

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func executionRunLimit(policy protocolv4.ServiceContractPolicy) uint64 {
	if policy.Shape == 1 {
		return min(policy.ExecutionRunMS, policy.StreamDurationMS)
	}
	return policy.ExecutionRunMS
}

// Stream completion records only original execution facts. Item publication
// belongs to the dedicated Stream; duplicate/history lookup cannot acquire a
// generator or turn metadata into an archive of previously sent items.
func (w *ExecutionWork) FinishStream(applicationErrorCode uint32) error {
	if w == nil {
		return ErrOwner
	}
	w.mu.Lock()
	s := w.history
	valid := !w.exited && w.entry != nil && w.entry.policy.Shape == 1 && s != nil
	w.mu.Unlock()
	if !valid {
		return ErrExecutionUnsupported
	}
	return w.Finish(applicationErrorCode, nil)
}

// FinishStream commits only metadata on the original durable execution. A
// definite commit permits closing the live stream but never a historical replay.
func (w *DurableExecutionWork) FinishStream(ctx context.Context, applicationErrorCode uint32) error {
	if w == nil || w.durableExecutionWork == nil || w.policy.Shape != 1 {
		return ErrExecutionUnsupported
	}
	return w.Finish(ctx, applicationErrorCode, nil)
}

// ConstrainStreamDeadline lends the exact first-entry run owner; a stream item
// or a slow provider return never obtains a newly started execution duration.
func (w *ExecutionWork) ConstrainStreamDeadline(deadline *timev4.Deadline) error {
	if w == nil || deadline == nil {
		return ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || !w.entered || w.entry.policy.Shape != 1 || w.run == nil {
		return ErrExecutionUnsupported
	}
	return deadline.TightenFrom(w.run)
}

func (w *DurableExecutionWork) ConstrainStreamDeadline(deadline *timev4.Deadline) error {
	if deadline == nil {
		return ErrOwner
	}
	if err := w.beginIO(); err != nil {
		return err
	}
	defer w.endIO()
	if !w.entered || w.policy.Shape != 1 && w.header.Kind() != "resume_request" {
		return ErrExecutionUnsupported
	}
	return w.database.ConstrainRunDeadline(deadline)
}
