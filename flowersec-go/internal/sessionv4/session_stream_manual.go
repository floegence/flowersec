package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// The manual mailbox links original admitted invocation positions. It owns no
// independent worker, stream reservation, payload copy, or application queue.
// Each entry retains its original ordinary resident permit until its actual
// Stream scope terminates and the corresponding handler callback returns.
func (d *sessionStreamDispatcher) offerManual(ctx context.Context, job *streamHandlerInvocation, metadata []byte, owner *StreamOwnership) error {
	registration, _ := job.capture.projection()
	if !registration.Manual || owner != job.owner || len(metadata) != len(job.metadata) {
		return resourcev4.ErrOwner
	}
	d.mu.Lock()
	if d.closed || job.manualQueued || job.manualTaken {
		d.mu.Unlock()
		return cryptov4.ErrClosed
	}
	job.manualKind = registration.Kind
	job.manualQueued = true
	if d.manualTail == nil {
		d.manualHead = job
	} else {
		d.manualTail.manualNext = job
	}
	d.manualTail = job
	d.signalManualLocked()
	d.mu.Unlock()
	defer d.removeManual(job)
	for {
		result, err := owner.CloseResult()
		if err == nil && result.CleanupStatus.Status == protocolv4.V4CleanupStateComplete {
			return nil
		}
		if ctx.Err() != nil {
			if result.SendDrained && result.ReadTerminal == protocolv4.V4ReadTerminalEof {
				return nil
			}
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
		case <-owner.changed:
		}
	}
}
func (d *sessionStreamDispatcher) signalManualLocked() {
	select {
	case d.manualWake <- struct{}{}:
	default:
	}
}
func (d *sessionStreamDispatcher) removeManual(job *streamHandlerInvocation) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !job.manualQueued {
		return
	}
	var previous *streamHandlerInvocation
	for position := d.manualHead; position != nil; position = position.manualNext {
		if position != job {
			previous = position
			continue
		}
		if previous == nil {
			d.manualHead = job.manualNext
		} else {
			previous.manualNext = job.manualNext
		}
		if d.manualTail == job {
			d.manualTail = previous
		}
		job.manualNext = nil
		job.manualQueued = false
		d.signalManualLocked()
		return
	}
}
func (d *sessionStreamDispatcher) acceptManual(ctx context.Context) (string, []byte, *StreamOwnership, error) {
	if ctx == nil {
		return "", nil, nil, cryptov4.ErrConfiguration
	}
	d.mu.Lock()
	if d.manualWaiting {
		d.mu.Unlock()
		return "", nil, nil, ErrOpenWaitBusy
	}
	d.manualWaiting = true
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.manualWaiting = false; d.mu.Unlock() }()
	for {
		if err := ctx.Err(); err != nil {
			return "", nil, nil, err
		}
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return "", nil, nil, cryptov4.ErrClosed
		}
		job := d.manualHead
		if job != nil {
			d.manualHead = job.manualNext
			if d.manualHead == nil {
				d.manualTail = nil
			}
			job.manualNext = nil
			job.manualQueued = false
			job.manualTaken = true
			kind, metadata, owner := job.manualKind, append([]byte(nil), job.metadata...), job.owner
			d.mu.Unlock()
			if err := job.context.Err(); err != nil {
				if errors.Is(err, context.Canceled) {
					continue
				}
				return "", nil, nil, err
			}
			return kind, metadata, owner, nil
		}
		d.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", nil, nil, ctx.Err()
		case <-d.stop:
			return "", nil, nil, cryptov4.ErrClosed
		case <-d.manualWake:
		}
	}
}
