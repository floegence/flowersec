package sessionv4

import (
	"context"
	"os"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// One original timer supervises lifetime, both native I/O deadlines, Finish
// and cleanup. No canceled method installs a replacement worker or timer.
func (c *StreamConn) supervise(sessionDone <-chan struct{}) {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	parentDone := c.parent.Done()
	sendDone := c.completion.drainDone
	workerDone := c.workerDone
	var externalDone <-chan struct{}
	if c.external != nil {
		externalDone = c.external.done
	}
	coreExited, externalExited := false, c.external == nil
	for {
		c.mu.Lock()
		// Observe actual worker exit before checking deadlines. A delayed
		// supervisor cannot turn completed cleanup into a timeout or abort.
		if !coreExited {
			select {
			case <-workerDone:
				coreExited, workerDone = true, nil
			default:
			}
		}
		if !externalExited {
			select {
			case <-externalDone:
				externalExited, externalDone = true, nil
			default:
			}
		}
		if coreExited && externalExited {
			c.complete = true
			c.result.CleanupStatus = protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStateComplete, CoreCleanup: protocolv4.V4CoreCleanupComplete}
			c.owner, c.parent, c.clock, c.deadline = nil, nil, nil, nil
			c.options.HardDeadline = nil
			if c.external != nil {
				c.external.backing.Release()
				c.external.dependencies.Release()
				c.external.backing, c.external.dependencies = resourcev4.Reference{}, resourcev4.Reference{}
			}
			c.finish, c.cleanup, c.external = nil, nil, nil
			c.reservation.Release()
			c.reservation = resourcev4.Reference{}
			c.publishLocked()
			close(c.done)
			c.mu.Unlock()
			return
		}
		wait := time.Hour
		if !c.aborted {
			remaining, err := c.deadline.RemainingMS()
			if err != nil {
				c.closeLocked(err)
			} else {
				wait = idleTimerChunk(remaining)
			}
		}
		if !c.closed && (c.owner.sealed.Load() || c.owner.revoked.Load()) {
			c.closeLocked(ErrStreamOwned)
		}
		if !c.closed {
			now := time.Now()
			for i, d := range c.ioDeadline {
				if !c.active[i] || c.ioTimedOut[i] || d.IsZero() {
					continue
				}
				if !now.Before(d) {
					c.ioTimedOut[i] = true
					c.ioCancel[i]()
					if i == 1 {
						c.closeLocked(os.ErrDeadlineExceeded)
					}
				} else {
					wait = min(wait, d.Sub(now))
				}
			}
		}
		if !c.cleaning && !c.aborted && c.finish != nil {
			remaining, err := c.finish.RemainingMS()
			settled, _ := c.completion.result(true)
			if settled {
				remaining, err = 3600000, nil
			}
			if err != nil {
				c.closeLocked(err)
			} else {
				wait = min(wait, idleTimerChunk(remaining))
			}
		}
		if c.cleaning && !c.incomplete {
			var remaining uint64
			err := ErrConnCleanupIncomplete
			if c.cleanup != nil {
				remaining, err = c.cleanup.RemainingMS()
			}
			if err != nil {
				c.incomplete = true
				c.closeLocked(ErrConnCleanupIncomplete)
				c.publishLocked()
			} else {
				wait = min(wait, idleTimerChunk(remaining))
			}
		}
		c.mu.Unlock()
		timer.Reset(wait)
		select {
		case <-sendDone:
			_, err := c.completion.result(true)
			if err != nil {
				c.mu.Lock()
				c.closeLocked(err)
				c.mu.Unlock()
			}
			sendDone = nil
		case <-c.wake:
		case <-timer.C:
		case <-parentDone:
			c.mu.Lock()
			c.closeLocked(c.parent.Err())
			c.mu.Unlock()
			parentDone = nil
		case <-sessionDone:
			c.mu.Lock()
			c.closeLocked(cryptov4.ErrClosed)
			c.mu.Unlock()
			sessionDone = nil
		case <-workerDone:
			coreExited, workerDone = true, nil
		case <-externalDone:
			externalExited, externalDone = true, nil
		}

		timer.Stop()
	}
}

func (c *StreamConn) publishLocked() {
	if !c.published {
		c.published = true
		close(c.ready)
	}
}

func (c *StreamConn) lifecycle(o *StreamOwnership) {
	defer close(c.workerDone)
	<-c.closeStart
	q, f := o.queue, o.flow.receive
	q.mu.Lock()
	err := q.finishOwnershipLocked(o)
	if err == nil {
		q.sealLocked()
	}
	q.mu.Unlock()
	if err != nil {
		c.mu.Lock()
		c.closeLocked(err)
		c.mu.Unlock()
	}
	for {
		// Consume only already authenticated bytes into this original bounded
		// close owner. Credit was sealed at Close; this never admits another
		// HTTP request or expands the peer's preexisting receive window.
		readReleased := f.drainConnBuffered()
		settled, err := c.completion.result(true)
		c.mu.Lock()
		if settled && err != nil {
			c.closeLocked(err)
		}
		stop := c.aborted || settled && readReleased
		c.mu.Unlock()
		if stop {
			if settled && err == nil {
				// Preserve the authenticated sending half. Only receive STOP is
				// needed when the peer keeps its sending half open after ours.
				f.Abandon()
			}
			break
		}
		drainDone := c.completion.drainDone
		if settled {
			drainDone = nil
		}
		select {
		case <-drainDone:
		case <-f.readWake:
		case <-c.workerWake:
		}
	}
	c.mu.Lock()
	c.cleaning = true
	c.cleanup, _ = timev4.NewWindow(c.clock, c.options.CleanupTimeoutMS)
	connNotify(c.wake)
	c.mu.Unlock()
	for {
		select {
		case <-o.changed:
		default:
		}
		if err := o.Cleanup(context.Background()); err == nil {
			break
		}
		select {
		case <-o.changed:
		case <-c.workerWake:
		}
	}
	for {
		c.mu.Lock()
		idle := !c.active[0] && !c.active[1] && !c.active[2]
		if idle {
			c.result, _ = o.CloseResult()
			c.accepted = o.AcceptedBytes()
		}
		released := idle && o.releaseConn(c) == nil
		if released {
			c.retired = true
		}
		c.mu.Unlock()
		if released {
			break
		}
		select {
		case <-o.changed:
		case <-c.workerWake:
		}
	}
}

func (f *ReceiveFlow) drainConnBuffered() bool {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	if f.readPending || f.readTails != 0 {
		return false
	}
	if f.cleaned || f.abandoned || f.size == 0 {
		f.releaseEmptyStorageLocked()
		return true
	}
	first := min(f.size, len(f.storage)-f.head)
	clear(f.storage[f.head : f.head+first])
	clear(f.storage[:f.size-first])
	f.released += uint64(f.size)
	f.pool.used -= uint64(f.size)
	f.size, f.head = 0, 0
	f.releaseEmptyStorageLocked()
	// These bytes were retired by the closing owner, never delivered to an
	// external reader. Do not increase the public delivered-byte observation.
	if f.termination.service != nil {
		f.termination.service.notify()
	}
	return true
}
