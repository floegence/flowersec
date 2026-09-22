package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

var (
	ErrUnaryNotStarted      = errors.New("sessionv4: not_started")
	ErrUnaryResultAbandoned = errors.New("sessionv4: result_abandoned")
)

// AbandonResult preserves the immutable request and its original Start rights.
// Before irreversible publication it only reports not_started. A committed
// request loses local result interest, without requesting business cancellation
// or reopening its prepared state. No independent send or result owner exists.
func (o *UnaryOperation) AbandonResult() (UnaryResultStatus, error) {
	if o == nil {
		return UnaryResultStatus{}, cryptov4.ErrConfiguration
	}
	o.mu.Lock()
	call, header := o.call, o.header
	o.mu.Unlock()
	if call == nil {
		return UnaryResultStatus{Request: header}, ErrUnaryNotStarted
	}
	return call.AbandonResult()
}

// AbandonResult shares the original result handoff gate with both Take forms.
// The original request-publication gate orders its first accepted header with
// not_started. Network completion wins before any new ABORT/STOP is selected;
// the Network gate withdraws an unstarted marker if complete input arrives.
func (c *UnaryCall) AbandonResult() (UnaryResultStatus, error) {
	if c == nil {
		return UnaryResultStatus{}, cryptov4.ErrConfiguration
	}
	// The sole invocation can detach once. A stale snapshot therefore needs at
	// most one retry; no polling, coordinator task or new reference is created.
	for range 2 {
		c.mu.Lock()
		if err, terminal := c.abandonResultStateLocked(); terminal {
			status := c.resultStatusLocked()
			c.mu.Unlock()
			return status, err
		}
		i := c.invocation
		if i == nil {
			release := c.discardResultLocked(true)
			status := c.resultStatusLocked()
			c.mu.Unlock()
			release.finish()
			return status, nil
		}
		c.mu.Unlock()
		i.mu.Lock()
		if i.cleaned {
			i.mu.Unlock()
			continue
		}
		c.mu.Lock()
		if err, terminal := c.abandonResultStateLocked(); terminal {
			status := c.resultStatusLocked()
			c.mu.Unlock()
			i.mu.Unlock()
			return status, err
		}
		if !i.publication.Progress().HeaderAccepted {
			status := c.resultStatusLocked()
			c.mu.Unlock()
			i.mu.Unlock()
			return status, ErrUnaryNotStarted
		}
		release := c.discardResultLocked(true)
		c.mu.Unlock()
		if !i.finished {
			i.canceled = true
			if !i.completion.Progress().Complete {
				_, _ = i.publisher.CancelRequest(i.ticket)
			}
			if i.completion.Progress().Complete {
				// Preserve already authenticated response/header facts. Closed local
				// delivery prevents a waiting decoder from entering during this transfer.
				i.advanceDeferredLocked(false)
			} else {
				i.completion.Close()
				i.finishDeferredLocked(UnaryCallOutcome{Reason: "result_abandoned", Error: ErrUnaryResultAbandoned}, nil)
			}
		}
		i.mu.Unlock()
		release.finish()
		return c.ResultStatus(), nil
	}
	return c.ResultStatus(), rpcv4.ErrOwner
}

func (c *UnaryCall) abandonResultStateLocked() (error, bool) {
	d := c.deferred
	if d == nil {
		return cryptov4.ErrConfiguration, true
	}
	if d.consumed {
		return ErrUnaryResultDelivered, true
	}
	if d.abandoned {
		return nil, true
	}
	if d.closed {
		return cryptov4.ErrClosed, true
	}
	return nil, false
}

type unaryResultRelease struct {
	call                *UnaryCall
	input               *rpcv4.VerifiedInput
	authorization       *protocolv4.DeliveryAuthorization
	cancel, inputCancel context.CancelFunc
	future              *CompletionReservation
	environment         *Environment
}

// Caller holds the one result gate. Captured cleanup actions run after all
// result/publication gates are released, and pin metadata through actual exit.
func (c *UnaryCall) discardResultLocked(abandon bool) unaryResultRelease {
	d := c.deferred
	if d == nil || d.closed {
		return unaryResultRelease{}
	}
	d.closed, d.abandoned = true, abandon
	if abandon {
		d.failure = ErrUnaryResultAbandoned
	}
	d.value, d.decode = nil, nil
	close(d.closing)
	release := unaryResultRelease{call: c, input: d.input, authorization: d.authorization, cancel: d.cancel, inputCancel: d.inputCancel, future: d.future, environment: d.environment}
	d.input, d.authorization = nil, nil
	d.visits++
	return release
}

func (r unaryResultRelease) finish() {
	if r.call == nil {
		return
	}
	r.input.Close()
	if r.cancel != nil {
		r.cancel()
	}
	if r.inputCancel != nil {
		r.inputCancel()
	}
	if r.authorization != nil {
		r.authorization.Close(nil)
	}
	r.future.Close()
	r.call.mu.Lock()
	r.call.deferred.visits--
	r.call.mu.Unlock()
	if r.environment != nil {
		r.environment.signalMaterials()
	}
}

func (d *unaryResultState) closedErrorLocked() error {
	if d.abandoned {
		return ErrUnaryResultAbandoned
	}
	return cryptov4.ErrClosed
}
