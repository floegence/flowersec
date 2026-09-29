package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func (r *RPCServices) bindingCore() (*SessionCore, error) {
	if r == nil {
		return nil, cryptov4.ErrNotReady
	}
	r.mu.Lock()
	plan, closed := r.plan, r.closed || r.retired
	r.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	if plan == nil {
		return nil, cryptov4.ErrNotReady
	}
	plan.mu.Lock()
	host := plan.host
	plan.mu.Unlock()
	if host == nil {
		return nil, cryptov4.ErrNotReady
	}
	return host.Core()
}

// One service call position protects preparation and its codec until the
// handoff gate. Returned handles then own their original independent lifetime.
func (c *UnaryServiceClient) PrepareStreamingMethod(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation) (*StreamOperation, error) {
	return c.streamingMethod(ctx, methodType, input, options, false)
}

// StreamMethod owns preparation and Start until the original handle is
// transferred. A failed or canceled handoff retains its physical cleanup in
// the existing service slot; a successful handoff leaves no second owner.
func (c *UnaryServiceClient) StreamMethod(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation) (*StreamOperation, error) {
	return c.streamingMethod(ctx, methodType, input, options, true)
}

func (c *UnaryServiceClient) streamingMethod(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation, start bool) (_ *StreamOperation, failure error) {
	slot, child, r, method, err := c.enter(ctx, methodType, 1, input, options)
	if err != nil {
		return nil, err
	}
	defer c.leave(slot)
	core, err := c.preparationCore(slot, r)
	if err != nil {
		return nil, err
	}
	op, err := r.prepareStreamingMethod(child, core, method.Method, method.StreamKind, method.StreamMetadata, input, options)
	if err != nil {
		return nil, err
	}
	if start {
		defer func() {
			if failure != nil {
				op.Close()
				reference, _ := op.Reference()
				failure = &StreamingStartFailure{Cause: failure, Reference: reference, CleanupComplete: op.Snapshot().CleanupComplete}
			}
		}()
	}
	if err = c.handoffPrepared(child, op.owner); err != nil {
		return nil, err
	}
	if start {
		c.mu.Lock()
		if c.closed || child.Err() != nil {
			c.mu.Unlock()
			op.Close()
			return nil, cryptov4.ErrClosed
		}
		slot.operation = op.owner
		c.mu.Unlock()
		result := op.Start(child)
		c.mu.Lock()
		err = result.Error
		if c.closed {
			err = cryptov4.ErrClosed
		} else if child.Err() != nil {
			err = child.Err()
		}
		if err == nil {
			slot.operation = nil
		}
		c.mu.Unlock()
		if err != nil {
			op.Close()
			return nil, err
		}
	}
	return op, nil
}

// StreamingStartFailure preserves the locator when a convenience scope closes
// a prepared execution before transferring its handle. It retains no owner.
type StreamingStartFailure struct {
	Cause           error
	Reference       protocolv4.OperationReference
	CleanupComplete bool
}

func (e *StreamingStartFailure) Error() string { return e.Cause.Error() }
func (e *StreamingStartFailure) Unwrap() error { return e.Cause }

func (c *UnaryServiceClient) PrepareNotifyMethod(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation) (*NotifyOperation, error) {
	op, _, _, err := c.prepareNotify(ctx, methodType, input, options, false)
	return op, err
}

func (c *UnaryServiceClient) handoffPrepared(ctx context.Context, op *UnaryOperation) error {
	c.mu.Lock()
	err := ctx.Err()
	if c.closed && err == nil {
		err = cryptov4.ErrClosed
	}
	c.mu.Unlock()
	if err != nil {
		op.Close()
	}
	return err
}

func (c *UnaryServiceClient) prepareNotify(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation, convenience bool) (*NotifyOperation, *serviceClientCall, context.Context, error) {
	slot, child, r, method, err := c.enter(ctx, methodType, 2, input, options)
	if err != nil {
		return nil, nil, nil, err
	}
	retained := false
	defer func() {
		if !retained {
			c.leave(slot)
		}
	}()
	op, err := r.prepareNotifyMethod(child, method.Method, input, options)
	if err != nil {
		return nil, nil, nil, err
	}
	c.mu.Lock()
	err = child.Err()
	if c.closed && err == nil {
		err = cryptov4.ErrClosed
	}
	if err == nil && convenience {
		slot.operation = op.owner
		retained = true
	}
	c.mu.Unlock()
	if err != nil {
		op.Close()
		if convenience {
			return op, nil, nil, err
		}
		return nil, nil, nil, err
	}
	return op, slot, child, nil
}

// NotificationResult contains only submission facts and the immutable locator
// of an execution notification. Observation leaves Reference invalid. No field
// retains the operation, Session, publication or credentials.
type NotificationResult struct {
	rpcv4.PublicationProgress
	Reference       protocolv4.OperationReference
	CleanupComplete bool
}

// NotifyMethod waits only for the original submission. It has no result,
// completion decoder, remote execution inference or implicit retry.
func (c *UnaryServiceClient) NotifyMethod(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation) (result NotificationResult, err error) {
	op, slot, child, err := c.prepareNotify(ctx, methodType, input, options, true)
	if err != nil {
		if op != nil {
			result.Reference, _ = op.Reference()
			result.PublicationProgress = op.SubmissionStatus()
			result.CleanupComplete = op.owner.Snapshot().CleanupComplete
		}
		return result, err
	}
	defer c.leave(slot)
	result.Reference, _ = op.Reference()
	defer func() {
		op.Close()
		result.CleanupComplete = op.owner.Snapshot().CleanupComplete
	}()
	if start := op.Start(child); start.Error != nil {
		result.PublicationProgress = op.SubmissionStatus()
		return result, start.Error
	}
	result.PublicationProgress, err = op.WaitSubmission(child)
	c.mu.Lock()
	if err != nil && c.closed {
		err = cryptov4.ErrClosed
	}
	c.mu.Unlock()
	return result, err
}
