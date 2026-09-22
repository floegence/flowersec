package sessionv4

import (
	"context"
	"errors"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func (m *StreamMessages) signalLocked() {
	if m.stateChanged != nil {
		close(m.stateChanged)
		m.stateChanged = make(chan struct{})
	}
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

// observeInputEndLocked inspects only the original receive frontier. It never
// consumes a byte or advances to another item while a candidate is retained.
func (m *StreamMessages) observeInputEndLocked() error {
	if m.resumeExchange {
		return nil
	}
	if m.server || !m.requestSent || m.inputEOF || m.owner == nil || m.readBusy {
		return nil
	}
	f := m.owner.flow.receive
	f.pool.mu.Lock()
	terminal, err := f.readStatusLocked()
	queued := f.size
	f.pool.mu.Unlock()
	if err != nil {
		return err
	}
	if m.status.Terminal && queued != 0 {
		return protocolv4.CBORFailure("streaming_terminal")
	}
	if terminal == protocolv4.V4ReadTerminalEof {
		if err := m.parser.End(); err != nil {
			return err
		}
		m.inputEOF = true
		m.releasePositionLocked()
		m.signalLocked()
	} else if terminal != protocolv4.V4ReadTerminalOpen {
		return ErrScopeExchangeIncomplete
	}
	return nil
}

// A complete original terminal/candidate keeps its existing Environment and
// tenant charge after Session I/O closes. Physical aliases retain their own
// Session charges; no new result, subscription or buffer is allocated here.
func (m *StreamMessages) detachCandidateLocked() error {
	if m.server || m.detached || (!m.inputEOF && !m.status.Terminal) || !m.outputClosed || m.readBusy || m.writeBusy {
		return nil
	}
	if err := m.authorization.DetachSessionScope(); err != nil {
		return err
	}
	if err := m.reservation.DetachSessionScope(); err != nil {
		return err
	}
	m.detached = true
	return nil
}

// This is the operation's one preadmitted SDK lifetime task and timer. It does
// no application work, item prefetch or provider I/O. Only final cleanup waits
// on real transport tails, retaining the same original task and all charges.
func (m *StreamMessages) supervise() {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	defer func() {
		m.mu.Lock()
		m.workerExited = true
		close(m.done)
		m.signalLocked()
		m.cleanupLocked()
		m.mu.Unlock()
	}()
	for {
		m.mu.Lock()
		m.advanceStreamResultLocked()
		if m.transportCleaned {
			keep := m.result != nil && (m.streamResultPendingLocked() || !m.closed && m.ready)
			remaining := uint64(3600000)
			if m.result != nil && m.result.dependency != nil {
				remaining = 10
			}
			m.mu.Unlock()
			if !keep {
				return
			}
			m.waitLifecycle(timer, remaining)
			continue
		}
		if m.resumeExchange && m.inputEOF && m.outputClosed && !m.readBusy && !m.writeBusy && !m.applicationBusy && m.failure == nil {
			if err := m.releaseResumeBoundaryLocked(); err == nil {
				m.mu.Unlock()
				continue
			} else if errors.Is(err, ErrStreamOwnershipBusy) {
				m.mu.Unlock()
				m.waitLifecycle(timer, 10)
				continue
			} else {
				m.failure = err
				m.closeLocked()
			}
		}
		err := m.observeInputEndLocked()
		if err == nil {
			err = m.detachCandidateLocked()
		}
		if err == nil {
			err = m.checkAuthorization()
		}
		remaining, deadlineErr := m.deadline.RemainingMS()
		if m.result != nil && m.result.dependency != nil {
			remaining = min(remaining, 100)
		}
		if err == nil && deadlineErr != nil {
			err = deadlineErr
		}
		if cursorTimePaused(err) {
			err = nil
			remaining = 10
		}
		if err != nil && !m.ioEnded {
			m.ioEnded = true
			// Completed terminal facts survive a later transport deadline.
			if !m.detached {
				m.failure = err
				m.closed = true
			}
			m.owner.Revoke()
			_ = m.owner.Cancel()
			m.signalLocked()
		}
		if m.closed && !m.ioEnded {
			m.ioEnded = true
			m.owner.Revoke()
			if !m.inputEOF || !m.outputClosed {
				_ = m.owner.Cancel()
			}
		}
		if m.ioEnded && m.eventSource != nil {
			m.eventSource.close()
		}
		if m.ioEnded && m.invocation != nil && m.invocation.transientCancel != nil {
			m.invocation.transientCancel()
		}
		remaining = m.advanceSourceCleanupLocked(remaining)
		complete := m.ioEnded || m.inputEOF && m.outputClosed
		if complete && m.invocation != nil && m.invocation.queued.Load() != nil {
			// The stream's original factory task joins cancellation and
			// performs any provider exit; the lifetime task only seals ready.
			m.invocation.queued.Load().Cancel()
		}
		if complete && m.invocation != nil && m.invocation.releasePending() && !m.readBusy && !m.writeBusy && !m.encoding {
			i := m.invocation
			m.mu.Unlock()
			// Exit can fail transiently while the original provider/store tail
			// is still unavailable. Retry the same owner; do not clear the slot
			// or release its input and dependency charges on failure.
			retryErr := i.tryRelease()
			m.mu.Lock()
			if retryErr != nil {
				m.mu.Unlock()
				m.waitLifecycle(timer, 10)
				continue
			}
			m.mu.Unlock()
			continue
		}
		if complete && !m.readBusy && !m.writeBusy && !m.encoding && !m.applicationBusy {
			owner := m.owner
			m.mu.Unlock()
			// End the original full Stream; a blocked native/provider tail
			// keeps this precharged owner alive, never a replacement task.
			cleanupErr := owner.Cleanup(context.Background())
			m.mu.Lock()
			if errors.Is(cleanupErr, ErrTerminal) || errors.Is(cleanupErr, ErrOpenPending) || errors.Is(cleanupErr, ErrStreamOwnershipBusy) {
				m.mu.Unlock()
				m.waitLifecycle(timer, 10)
				continue
			}
			if cleanupErr != nil {
				if m.failure == nil {
					m.failure = cleanupErr
					m.signalLocked()
				}
				m.mu.Unlock()
				// An error is not proof of physical exit. Keep this exact
				// cleanup owner and all aliases until retirement is confirmed.
				m.waitLifecycle(timer, 10)
				continue
			}
			m.releasePositionLocked()
			if m.resume != nil {
				if err := m.resume.returnQualification(m); err != nil {
					m.mu.Unlock()
					m.waitLifecycle(timer, 10)
					continue
				}
				m.resume = nil
			}
			owner.mu.Lock()
			if owner.messages == m {
				owner.messages = nil
				owner.notify()
			}
			owner.mu.Unlock()
			if err := owner.Release(); err != nil {
				if m.failure == nil {
					m.failure = err
					m.signalLocked()
				}
				m.mu.Unlock()
				m.waitLifecycle(timer, 10)
				continue
			}
			m.owner = nil
			m.transportCleaned = true
			m.networkHold.Release()
			m.networkHold = resourcev4.Reference{}
			m.network = nil
			m.contract = nil
			m.route.Release()
			m.route = rpcv4.ContractRoute{}
			if d := m.result; d != nil {
				// Only actual I/O retirement sheds Session accounting. A late
				// decoder and its already disclosed input remain fully charged.
				if err := d.floor.DetachSessionScope(); err != nil && m.failure == nil {
					m.failure = err
				}
				if err := m.reservation.DetachSessionScope(); err != nil && m.failure == nil {
					m.failure = err
				}
			}
			m.signalLocked()
			m.mu.Unlock()
			continue
		}
		m.mu.Unlock()
		m.waitLifecycle(timer, remaining)
	}
}

func (m *StreamMessages) waitLifecycle(timer *time.Timer, remaining uint64) {
	if remaining == 0 {
		remaining = 10
	}
	m.mu.Lock()
	var ownerChanged, completionDone <-chan struct{}
	if m.owner != nil {
		ownerChanged = m.owner.changed
	}
	if m.result != nil && m.result.task != nil {
		completionDone = m.result.task.Done()
	}
	var authorization <-chan struct{}
	if !m.ioEnded && !m.transportCleaned {
		authorization = m.authorization.Wake()
	}
	m.mu.Unlock()
	timer.Reset(idleTimerChunk(remaining))
	select {
	case <-m.changed:
	case <-ownerChanged:
	case <-completionDone:
	case <-authorization:
	case <-timer.C:
	}
	timer.Stop()
}

// Cleanup is observation of the single original cleanup task. Wait cancellation
// does not cancel that task, refresh its deadline or manufacture another owner.
func (m *StreamMessages) Cleanup(ctx context.Context) error {
	if m == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := m.checkReadDependency(ctx); err != nil {
		return err
	}
	m.Close()
	return m.waitCleanup(ctx)
}

func (m *StreamMessages) waitCleanup(ctx context.Context) error {
	m.mu.Lock()
	if !m.workerStarted {
		m.mu.Unlock()
		return nil
	}
	count := m.cleanupWaiters + m.statusWaiters
	if m.cursorRead {
		count++
	}
	if count == 4 {
		m.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	m.cleanupWaiters++
	done := m.done
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.cleanupWaiters--; m.cleanupLocked(); m.mu.Unlock() }()
	for {
		m.mu.Lock()
		changed := m.stateChanged
		incomplete := m.sourceStatusLocked().CleanupIncomplete
		m.mu.Unlock()
		if incomplete {
			return ErrSourceCleanup
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			m.mu.Lock()
			defer m.mu.Unlock()
			if !m.transportCleaned {
				if m.failure != nil {
					return m.failure
				}
				return ErrScopeCleanupIncomplete
			}
			return nil
		case <-changed:
		}
	}
}
