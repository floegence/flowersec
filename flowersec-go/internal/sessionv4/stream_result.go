package sessionv4

import (
	"context"
	"errors"
	"io"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var ErrStreamInputDelivered = errors.New("sessionv4: stream item already entered application decoding")
var ErrStreamDecodeFailed = errors.New("sessionv4: stream item decode failed")

// StreamResultConfig binds the trusted decoder to one future Completion
// position before OPEN. The same position is reused only after actual callback
// exit. Reading status and receiving a header never invoke this callback.
type StreamResultConfig struct {
	Executor              *ApplicationExecutor
	Decode                UnaryResultDecoder
	CompletionReservation resourcev4.Reference
}

type streamResult struct {
	executor                           *ApplicationExecutor
	decode                             UnaryResultDecoder
	floor                              *CompletionFloor
	future                             *CompletionReservation
	task                               *CompletionTask
	dependencies                       applicationDependencies
	dependency                         *completionDependency
	context                            context.Context
	cancel                             context.CancelFunc
	waiting                            <-chan struct{}
	value                              any
	failure                            error
	inputDelivered, decoded            bool
	consumed, abandoned, typed, paused bool
}

func streamResultBytes() uint64 {
	return uint64(unsafe.Sizeof(streamResult{})) + uint64(unsafe.Sizeof(time.Timer{})) + applicationContextBytes() + completionDependencyBytes()
}

func (m *StreamMessages) prepareResultReader(config *StreamResultConfig) error {
	if config == nil {
		return nil
	}
	if m.server || config.Executor == nil || config.Decode == nil {
		return cryptov4.ErrConfiguration
	}
	floor, err := config.Executor.NewCompletionFloor(config.CompletionReservation, m.reservation)
	if err != nil {
		return err
	}
	future, err := floor.Checkout()
	if err == nil {
		err = future.rebindResultBacking(m.reservation)
	}
	if err != nil {
		future.Close()
		floor.Close()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.result = &streamResult{executor: config.Executor, decode: config.Decode, floor: floor, future: future, context: ctx, cancel: cancel}
	return nil
}

func (m *StreamMessages) checkReadDependency(ctx context.Context) error {
	if _, err := checkApplicationContext(ctx); err != nil {
		return err
	}
	c, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if c == nil {
		return nil
	}
	for j := 0; j <= c.count; j++ {
		s := c.state
		if j < c.count {
			s = c.ancestors[j]
		}
		s.mu.Lock()
		self := s.live && s.streamResult == m
		s.mu.Unlock()
		if self {
			return ErrCompletionDependency
		}
	}
	return nil
}

// ReadNext requests at most the current item's single decoder. All consumers
// after an interrupted wait join that same invocation; only one receives its
// value. The current cursor never advances while that item remains unconsumed.
func (m *StreamMessages) ReadNext(ctx context.Context) (any, StreamMessageStatus, error) {
	return m.readNext(ctx, false)
}

func (m *StreamMessages) readNext(ctx context.Context, iterator bool) (any, StreamMessageStatus, error) {
	if m == nil || ctx == nil {
		return nil, StreamMessageStatus{}, cryptov4.ErrConfiguration
	}
	if err := m.checkReadDependency(ctx); err != nil {
		return nil, m.Status(), err
	}
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		return nil, m.Status(), err
	}
	defer dependencies.release()
	m.mu.Lock()
	d := m.result
	if m.terminalDelivered {
		s := m.statusLocked()
		m.mu.Unlock()
		return nil, s, ErrStreamResultDelivered
	}
	if m.server || d == nil {
		m.mu.Unlock()
		return nil, StreamMessageStatus{}, cryptov4.ErrConfiguration
	}
	if m.cursorRead || m.readBusy || m.iterating != iterator {
		m.mu.Unlock()
		return nil, StreamMessageStatus{}, ErrStreamMessageBusy
	}
	if m.statusWaiters+m.cleanupWaiters == 4 {
		m.mu.Unlock()
		return nil, StreamMessageStatus{}, cryptov4.ErrCapacity
	}
	m.cursorRead, d.typed, d.waiting = true, true, ctx.Done()
	m.mu.Unlock()
	var dependencyTimer *time.Timer
	defer func() {
		if dependencyTimer != nil {
			dependencyTimer.Stop()
		}
		m.mu.Lock()
		m.cursorRead, d.typed, d.waiting = false, false, nil
		d.future.releaseDependencyClaim()
		m.signalLocked()
		m.cleanupLocked()
		m.mu.Unlock()
	}()
	for {
		m.mu.Lock()
		m.advanceStreamResultLocked()
		if err := ctx.Err(); err != nil {
			s := m.statusLocked()
			m.mu.Unlock()
			return nil, s, err
		}
		if d.abandoned {
			s := m.statusLocked()
			m.mu.Unlock()
			return nil, s, cryptov4.ErrClosed
		}
		if d.decoded && !d.consumed {
			value, failure, h := d.value, d.failure, m.candidate
			d.value, d.consumed = nil, true
			if failure == nil {
				m.consumeCandidateLocked(h, m.inputBytes)
			} else {
				clear(m.input)
				m.ready = false
				m.inputBytes = 0
				m.candidate = protocolv4.ApplicationHeader{}
				m.failure, m.closed, m.terminalDelivered = failure, true, true
				m.signalLocked()
			}
			s := m.statusLocked()
			s.Header = h
			m.mu.Unlock()
			return value, s, failure
		}
		if m.terminalDelivered {
			s := m.statusLocked()
			m.mu.Unlock()
			return nil, s, ErrStreamResultDelivered
		}
		if d.consumed && d.task == nil {
			d.inputDelivered, d.decoded, d.consumed = false, false, false
			d.failure, d.dependency = nil, nil
		}
		if !d.inputDelivered && !m.ready && !m.closed && (m.inputEOF || m.status.Terminal) {
			m.terminalDelivered = true
			s := m.statusLocked()
			m.mu.Unlock()
			return nil, s, io.EOF
		}
		if !d.inputDelivered && !m.ready {
			if err := m.ensureStreamFutureLocked(); err != nil {
				s := m.statusLocked()
				m.mu.Unlock()
				return nil, s, err
			}
			m.mu.Unlock()
			if status, err := m.captureNext(ctx, true); err != nil {
				return nil, status, err
			}
			m.mu.Lock()
			if !m.ready && (m.inputEOF || m.status.Terminal) {
				m.terminalDelivered = true
				s := m.statusLocked()
				m.mu.Unlock()
				return nil, s, io.EOF
			}
		}
		if !d.inputDelivered && m.ready && m.candidate.IsSDKError() {
			h, code := m.candidate, m.status.SDKErrorCode
			// Fixed SDK errors have no application codec. Consumption still
			// uses the original current authorization and single cursor gate.
			err := m.withCurrentAuthorization(func() error {
				if err := ctx.Err(); err != nil {
					return err
				}
				clear(m.input[:m.inputBytes])
				m.consumeCandidateLocked(h, m.inputBytes)
				return nil
			})
			s := m.statusLocked()
			s.Header = h
			m.mu.Unlock()
			if err != nil {
				return nil, s, err
			}
			return nil, s, StreamSDKError{Code: code}
		}
		if !d.inputDelivered && d.task == nil && !d.paused {
			if err := m.checkLocked(ctx); err != nil {
				s := m.statusLocked()
				m.mu.Unlock()
				return nil, s, err
			}
			if err := m.ensureStreamFutureLocked(); err != nil {
				s := m.statusLocked()
				m.mu.Unlock()
				return nil, s, err
			}
			if err = dependencies.merge(&d.dependencies); err == nil {
				var dependency *completionDependency
				dependency, err = d.future.claimDependency(&dependencies, m.inputConfig.Clock)
				if dependency != nil {
					dependency.limitDeadline(ctx)
					d.dependency = dependency
				}
			}
			if err == nil {
				d.dependencies.release()
				d.dependencies, dependencies = dependencies, applicationDependencies{}
				d.task, err = d.future.offer(m.decodeStreamResult)
			}
			if err != nil {
				s := m.statusLocked()
				m.mu.Unlock()
				return nil, s, err
			}
		}
		changed := m.stateChanged
		var taskDone, dependencyFailure <-chan struct{}
		if d.task != nil {
			taskDone = d.task.Done()
		}
		if d.dependency != nil && completionContext(ctx, d.executor) {
			dependencyFailure = d.dependency.expired
		}
		dependency := d.dependency
		m.mu.Unlock()
		var dependencyTick <-chan time.Time
		if dependencyFailure != nil {
			if dependencyTimer == nil {
				dependencyTimer = time.NewTimer(100 * time.Millisecond)
			} else {
				dependencyTimer.Reset(100 * time.Millisecond)
			}
			dependencyTick = dependencyTimer.C
		}
		select {
		case <-ctx.Done():
			return nil, m.Status(), ctx.Err()
		case <-dependencyTick:
			dependency.advance()
		case <-dependencyFailure:
			return nil, m.Status(), ErrCompletionDependency
		case <-changed:
		case <-taskDone:
		}
	}
}

// StreamSDKError reports only the fixed authenticated service error code. It
// does not infer execution state, retry safety or application delivery at peer.
type StreamSDKError struct{ Code uint64 }

func (StreamSDKError) Error() string { return "sessionv4: streaming service error" }

func (m *StreamMessages) decodeStreamResult() (err error) {
	m.mu.Lock()
	d := m.result
	if d.abandoned || !d.typed || !m.cursorRead {
		m.mu.Unlock()
		return errCompletionNotEligible
	}
	select {
	case <-d.waiting:
		m.mu.Unlock()
		return errCompletionNotEligible
	default:
	}
	if err = m.checkLocked(d.context); err != nil {
		if cursorTimePaused(err) {
			d.paused = true
			err = errCompletionNotEligible
		}
		m.mu.Unlock()
		return err
	}
	var input []byte
	var callCtx context.Context
	var exit func()
	err = m.withCurrentAuthorization(func() error {
		var err error
		callCtx, exit, err = enterApplicationContext(d.context, d.executor, completionApplicationLane, ApplicationShort, m.reservation, &d.dependencies)
		if err != nil {
			return err
		}
		callCtx.(*applicationContext).state.streamResult = m
		input = m.input[:m.inputBytes:m.inputBytes]
		m.input = nil
		d.inputDelivered = true
		return nil
	})
	m.mu.Unlock()
	if exit != nil {
		defer exit()
	}
	if err != nil {
		return err
	}
	returned := false
	defer func() {
		if recover() != nil || !returned {
			m.mu.Lock()
			d.failure, d.decoded = ErrStreamDecodeFailed, true
			m.signalLocked()
			m.mu.Unlock()
			err = ErrStreamDecodeFailed
		}
	}()
	value, failure := d.decode(callCtx, input)
	returned = true
	m.mu.Lock()
	if !d.abandoned {
		d.value = value
	}
	if failure != nil {
		d.failure = ErrStreamDecodeFailed
	}
	d.decoded = true
	m.signalLocked()
	m.mu.Unlock()
	return nil
}

// The original stream supervisor observes only finite Completion facts. It
// neither executes application code nor creates a second lifetime task.
func (m *StreamMessages) advanceStreamResultLocked() {
	d := m.result
	if d == nil {
		return
	}
	d.dependency.advance()
	if d.task != nil {
		select {
		case <-d.task.Done():
			err := d.task.Wait(context.Background())
			d.task = nil
			if !errors.Is(err, errCompletionNotEligible) {
				d.future = nil
				if err != nil && !d.decoded {
					d.decoded, d.failure = true, err
					if d.inputDelivered {
						d.failure = ErrStreamDecodeFailed
					}
				}
			}
			m.signalLocked()
		default:
		}
	}
	if d.paused {
		err := m.checkAuthorization()
		if !cursorTimePaused(err) {
			d.paused = false
			m.signalLocked()
		}
	}
	if d.task == nil {
		if d.inputDelivered || d.abandoned {
			d.dependencies.release()
		} else {
			d.dependencies.pruneExited()
		}
	}
}

func (m *StreamMessages) abandonStreamResultLocked() {
	if d := m.result; d != nil && !d.abandoned {
		d.abandoned = true
		d.cancel()
		d.value = nil
		d.future.Close()
		d.floor.Close()
	}
}

func (m *StreamMessages) streamResultPendingLocked() bool {
	d := m.result
	return d != nil && (d.task != nil || !d.abandoned && d.inputDelivered && !d.consumed)
}

func (m *StreamMessages) cleanupStreamResultLocked() {
	if d := m.result; d != nil {
		d.cancel()
		d.future.Close()
		d.floor.Close()
		d.dependencies.release()
		m.result = nil
	}
}

func (m *StreamMessages) ensureStreamFutureLocked() error {
	d := m.result
	if d == nil || d.future != nil {
		return nil
	}
	future, err := d.floor.Checkout()
	if err != nil {
		return err
	}
	if err := future.rebindResultBacking(m.reservation); err != nil {
		future.Close()
		return err
	}
	d.future = future
	return nil
}

// Encoded reads share the same candidate and wait for any consumed decoder's
// actual exit before reusing the single future Completion promise.
func (m *StreamMessages) prepareEncodedRead(ctx context.Context) error {
	for {
		m.mu.Lock()
		m.advanceStreamResultLocked()
		d := m.result
		if d == nil {
			m.mu.Unlock()
			return nil
		}
		if d.inputDelivered && !d.consumed {
			m.mu.Unlock()
			return ErrStreamInputDelivered
		}
		if d.consumed && d.task != nil {
			done := d.task.Done()
			m.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
			}
			continue
		}
		if d.consumed {
			d.inputDelivered, d.consumed, d.decoded = false, false, false
			d.failure, d.dependency = nil, nil
		}
		var err error
		if !m.inputEOF && !m.status.Terminal {
			err = m.ensureStreamFutureLocked()
		}
		m.mu.Unlock()
		return err
	}
}

// The first future decoder and every known ancestor are reserved before Start
// can take an accepted Stream. No dependency failure may be discovered only
// after the initial request has escaped into transport.
func (m *StreamMessages) prepareStartDependencies(ctx context.Context, prepared *applicationDependencies) error {
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		return err
	}
	defer dependencies.release()
	if err := dependencies.merge(prepared); err != nil {
		return err
	}
	if m.result == nil {
		if dependencies.count != 0 {
			return ErrCompletionDependency
		}
		return nil
	}
	d := m.result
	dependency, err := d.future.claimDependency(&dependencies, m.inputConfig.Clock)
	if err != nil {
		return err
	}
	if dependency != nil {
		dependency.limitDeadline(ctx)
	}
	d.dependencies, dependencies = dependencies, applicationDependencies{}
	d.dependency = dependency
	return nil
}
