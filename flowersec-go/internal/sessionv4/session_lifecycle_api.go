package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// lifecycleCall reserves the actual observer/publisher before it starts and
// pins the original core until that method's physical tail returns. It uses
// the same root and Session/tenant accounts as Stream factory invocations.
func (c *SessionCore) lifecycleCall(ctx context.Context) (*OpenAdmission, resourcev4.Reference, error) {
	if c == nil || c.plan == nil || ctx == nil {
		return nil, resourcev4.Reference{}, cryptov4.ErrConfiguration
	}
	p := c.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, resourcev4.Reference{}, err
	}
	if p.closed || p.admission == nil || p.runtime == nil || p.root == nil {
		return nil, resourcev4.Reference{}, cryptov4.ErrClosed
	}
	if p.streamMethods == math.MaxUint32 || p.streamServices == math.MaxUint32 || p.streamCalls == math.MaxUint64 {
		return nil, resourcev4.Reference{}, cryptov4.ErrCapacity
	}
	// Reserve independently of the fixed protocol waiter/sample slot. The
	// latter bounds concurrency; this charge covers this call's timer/task.
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(time.Timer{})) + 512, resourcev4.Items: 2, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Timers: 1}
	var err error
	charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: p.config.RuntimeBytes})
	if err != nil {
		return nil, resourcev4.Reference{}, err
	}
	var identity [32]byte
	copy(identity[:16], p.resourceOwner.Backing[:])
	copy(identity[16:24], "life-api")
	binary.BigEndian.PutUint64(identity[24:], p.streamCalls+1)
	digest := sha256.Sum256(identity[:])
	owner := p.resourceOwner
	copy(owner.Backing[:], digest[:16])
	ref, err := p.root.Reserve(owner, charge, p.accounts[:p.accountCount]...)
	if err != nil {
		return nil, resourcev4.Reference{}, err
	}
	p.streamCalls++
	p.streamMethods++
	// Maintenance calls hold a method pin but are excluded from the bounded
	// business OPEN invocation count, just like original service invocations.
	p.streamServices++
	return p.admission, ref, nil
}

func (c *SessionCore) finishLifecycleCall(ref resourcev4.Reference) {
	ref.Release()
	p := c.plan
	p.mu.Lock()
	p.streamMethods--
	p.streamServices--
	p.notifyLocked()
	p.mu.Unlock()
}

// Rekey joins the existing bounded manual cause. The original runtime owns
// preparation and all flights; this caller only observes that exact intent.
// Canceling the wait releases its cause and never revokes a submitted round,
// another caller, an authenticated peer cause, or a safety obligation.
func (c *SessionCore) Rekey(ctx context.Context) error {
	a, charge, err := c.lifecycleCall(ctx)
	if err != nil {
		return err
	}
	defer c.finishLifecycleCall(charge)
	a.mu.Lock()
	causes := a.rekeyCauses
	closed := a.closed
	a.mu.Unlock()
	if closed || causes == nil {
		return cryptov4.ErrClosed
	}
	ref, err := causes.JoinManual()
	if err != nil {
		return err
	}
	defer ref.Release()
	// A finite observer consumes its own reserved timer, not the service's
	// wake channel: consuming that channel could steal protocol progress.
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		causes.mu.Lock()
		i := ref.intent
		complete, canceled, closed, failure := i.completed, i.cancelled, causes.closed, i.failure
		causes.mu.Unlock()
		if complete {
			return nil
		}
		if failure != nil {
			return failure
		}
		if canceled {
			return ErrRekeyCancelled
		}
		if closed {
			return cryptov4.ErrClosed
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.engine.Done():
			// Completion and closure can become visible together. Preserve
			// the original completion fact if the round already finished.
			causes.mu.Lock()
			complete = i.completed
			causes.mu.Unlock()
			if complete {
				return nil
			}
			return cryptov4.ErrClosed
		case <-timer.C:
		}
	}
}

// ProbeLiveness observes the original authenticated PING/PONG sample. Its
// publisher retains the core and charge after caller cancellation until the
// actual provider call returns; no replacement publisher or probe is started.
func (c *SessionCore) ProbeLiveness(ctx context.Context, timeoutMS uint64) (ProbeResult, error) {
	if timeoutMS == 0 {
		return ProbeResult{}, cryptov4.ErrConfiguration
	}
	a, charge, err := c.lifecycleCall(ctx)
	if err != nil {
		return ProbeResult{}, err
	}
	a.mu.Lock()
	liveness := a.liveness
	closed := a.closed
	a.mu.Unlock()
	if closed || liveness == nil {
		c.finishLifecycleCall(charge)
		return ProbeResult{}, cryptov4.ErrClosed
	}
	probe, err := liveness.Begin(timeoutMS)
	if err != nil {
		c.finishLifecycleCall(charge)
		return ProbeResult{}, err
	}
	var exits atomic.Uint32
	finish := func() {
		if exits.Add(1) == 2 {
			c.finishLifecycleCall(charge)
		}
	}
	defer finish()
	go func() {
		returned := false
		var publishErr error
		defer finish()
		defer func() {
			if recover() != nil || !returned {
				publishErr = ErrEnvironmentTaskExit
			}
			if publishErr != nil {
				liveness.mu.Lock()
				now, _ := a.engine.Clock().Monotonic()
				probe.finish(publishErr, now)
				liveness.mu.Unlock()
			}
		}()
		publishErr = probe.publishOriginal(ctx)
		returned = true
	}()
	defer probe.Release()
	return probe.Wait(ctx)
}

func (s *EnvironmentSession) Rekey(ctx context.Context) error {
	core, err := s.Core()
	if err != nil {
		return err
	}
	return core.Rekey(ctx)
}

func (s *EnvironmentSession) ProbeLiveness(ctx context.Context, timeoutMS uint64) (ProbeResult, error) {
	core, err := s.Core()
	if err != nil {
		return ProbeResult{}, err
	}
	return core.ProbeLiveness(ctx, timeoutMS)
}
