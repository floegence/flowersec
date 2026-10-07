package sessionv4

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// ControllerSourceError is a trusted source's structured retry decision. Only
// preparation/acquisition may supply it; application callbacks cannot schedule
// acquisition by returning an error with the same shape or text.
type ControllerSourceError struct {
	cause       error
	notBeforeMS uint64
}

func NewControllerSourceError(cause error, notBeforeMS uint64) (*ControllerSourceError, error) {
	if cause == nil || notBeforeMS > 9_007_199_254_740_991 {
		return nil, cryptov4.ErrConfiguration
	}
	return &ControllerSourceError{cause: cause, notBeforeMS: notBeforeMS}, nil
}

func (*ControllerSourceError) Error() string { return "sessionv4: retryable source failure" }
func (e *ControllerSourceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func controllerSourceFailure(err error) *ControllerSourceError {
	failure, _ := err.(*ControllerSourceError)
	return failure
}

func controllerNetworkRetry(err error) bool {
	if err == nil || err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}
	if err == native.ErrConnectionLost || err == io.EOF || err == io.ErrUnexpectedEOF || err == io.ErrClosedPipe {
		return true
	}
	// This preserves provenance for an actual native transport operation.
	// The coordinator applies cleanup, initialization and attempt gates before
	// calling the configured Source for fresh material. Consumed material stays sealed.
	network, ok := err.(*net.OpError)
	return ok && network != nil && (network.Op == "read" || network.Op == "write") &&
		native.NetworkFailure(err) == native.ErrConnectionLost
}

func controllerBackoff(ordinal uint64) uint64 {
	delay := defaults.ConnectionControllerInitialDelay
	for ordinal > 1 && delay < defaults.ConnectionControllerMaxDelay {
		delay = min(delay*time.Duration(defaults.ConnectionControllerBackoffFactor), defaults.ConnectionControllerMaxDelay)
		ordinal--
	}
	return uint64(delay / time.Millisecond)
}

func (c *ConnectionController) retryEligibleLocked(serial uint64) bool {
	return !c.closed && !c.blocked && c.automatic && c.serial == serial && c.current == nil && c.attempt == nil &&
		c.retryContext != nil && c.retryContext.Err() == nil &&
		(c.config.MaximumAttempts == 0 || c.cycleAttempts < c.config.MaximumAttempts)
}

func (c *ConnectionController) scheduleRetry(serial, notBefore uint64) {
	c.mu.Lock()
	if !c.retryEligibleLocked(serial) {
		if c.serial == serial {
			c.retryPending = false
			c.signalLocked()
		}
		c.mu.Unlock()
		return
	}
	clock, ordinal := c.config.Clock, c.cycleAttempts
	c.mu.Unlock()
	window, err := timev4.NewWindow(clock, controllerBackoff(max(ordinal, 1)))
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.retryEligibleLocked(serial) {
		if c.serial == serial {
			c.retryPending = false
			c.signalLocked()
		}
		return
	}
	c.retryPending = false
	if err != nil {
		c.lastError = err
		c.signalLocked()
		return
	}
	c.retryWindow, c.retryNotBefore, c.retryRequested = window, notBefore, false
	c.signalLocked()
}

// The one existing coordinator owns all retry timing. A retry cannot displace
// physical cleanup or bypass the source's original absolute not-before.
func (c *ConnectionController) advanceRetry() {
	c.mu.Lock()
	w, clock, notBefore, bypass, parent := c.retryWindow, c.config.Clock, c.retryNotBefore, c.retryRequested, c.retryContext
	eligible := w != nil && c.retryEligibleLocked(c.serial)
	if w != nil && parent != nil && parent.Err() != nil {
		c.retryWindow, c.retryNotBefore = nil, 0
		c.lastError = parent.Err()
		c.signalLocked()
	}
	c.mu.Unlock()
	if !eligible {
		return
	}
	if err := w.Check(); err != nil && !errors.Is(err, timev4.ErrExpired) {
		c.mu.Lock()
		if c.retryWindow == w {
			c.retryWindow = nil
			c.retryNotBefore = 0
			c.lastError = err
			c.signalLocked()
		}
		c.mu.Unlock()
		return
	} else if err == nil && !bypass {
		return
	}
	if notBefore != 0 {
		now, err := clock.Sample()
		if err != nil || now.LowerMS < notBefore {
			return
		}
	}
	_, err := c.begin(parent, ControllerReplaceOptions{}, true, w)
	if err != nil {
		c.mu.Lock()
		if c.retryWindow == w {
			c.lastError = err
			if !errors.Is(err, ErrRetirementCapacity) && !errors.Is(err, ErrControllerBusy) {
				c.retryWindow = nil
			}
			c.changedLocked()
		}
		c.mu.Unlock()
	}
}
