package sessionv4

import (
	"context"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

var ErrStreamResultDelivered = errors.New("sessionv4: stream terminal already delivered")

// ReadNextEncoded owns the sole current-item advancement and consumption scope.
// A canceled wait leaves partial input and complete candidates untouched. The
// returned slice owns its backing; it retains no Session or stream capability.
func (m *StreamMessages) ReadNextEncoded(ctx context.Context) ([]byte, StreamMessageStatus, error) {
	if m == nil || ctx == nil {
		return nil, StreamMessageStatus{}, cryptov4.ErrConfiguration
	}
	if err := m.checkReadDependency(ctx); err != nil {
		return nil, m.Status(), err
	}
	m.mu.Lock()
	if m.abandoned {
		m.mu.Unlock()
		return nil, m.Status(), ErrUnaryResultAbandoned
	}
	if m.server {
		m.mu.Unlock()
		return nil, StreamMessageStatus{}, cryptov4.ErrConfiguration
	}
	if m.cursorRead || m.readBusy || m.iterating {
		m.mu.Unlock()
		return nil, StreamMessageStatus{}, ErrStreamMessageBusy
	}
	if m.cleanupWaiters+m.statusWaiters == 4 {
		m.mu.Unlock()
		return nil, StreamMessageStatus{}, cryptov4.ErrCapacity
	}
	if m.terminalDelivered {
		s := m.statusLocked()
		m.mu.Unlock()
		return nil, s, ErrStreamResultDelivered
	}
	m.cursorRead = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.cursorRead = false
		m.signalLocked()
		m.cleanupLocked()
		m.mu.Unlock()
	}()
	if err := m.prepareEncodedRead(ctx); err != nil {
		return nil, m.Status(), err
	}
	if status, err := m.captureNext(ctx, true); err != nil {
		return nil, status, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, m.statusLocked(), err
	}
	if !m.ready && (m.inputEOF || m.status.Terminal) {
		if m.closed {
			return nil, m.statusLocked(), m.closedErrorLocked()
		}
		m.terminalDelivered = true
		return nil, m.statusLocked(), io.EOF
	}
	if err := m.checkLocked(ctx); err != nil {
		return nil, m.statusLocked(), err
	}
	if !m.ready {
		return nil, m.statusLocked(), ErrStreamMessagePending
	}
	h, length := m.candidate, int(m.inputBytes)
	var payload []byte
	err := m.withCurrentAuthorization(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// This is the handoff of the original full buffer. A later read may
		// refill its existing reservation only after this alias leaves SDK
		// ownership; there is no simultaneous uncharged input copy.
		payload = m.input[:length:length]
		m.input = nil
		m.consumeCandidateLocked(h, uint32(length))
		return nil
	})
	status := m.statusLocked()
	status.Header = h
	return payload, status, err
}

func (m *StreamMessages) consumeCandidateLocked(h protocolv4.ApplicationHeader, length uint32) {
	if d := m.result; d != nil && !d.inputDelivered {
		d.consumed = true
		d.future.Close()
		d.future = nil
	}
	m.ready = false
	m.inputBytes = 0
	m.candidate = protocolv4.ApplicationHeader{}
	if m.resumeExchange || h.IsSDKError() || h.Fields().ApplicationErrorCode != 0 {
		m.terminalDelivered = true
	}
	if !h.IsSDKError() && h.Fields().ApplicationErrorCode == 0 {
		m.status.DeliveredItems++
		m.status.DeliveredBytes += uint64(length)
	}
	m.signalLocked()
}

func (m *StreamMessages) closedErrorLocked() error {
	if m.failure != nil {
		return m.failure
	}
	return cryptov4.ErrClosed
}

func (m *StreamMessages) terminalStatusLocked() bool {
	return m.closed || m.status.Terminal || m.inputEOF && (!m.server || m.outputClosed)
}

// WaitStatus never reads transport bytes, advances a generator, dispatches a
// decoder or consumes a pending item. Its bounded observers share the original
// lifetime wake and cannot extend the original stream deadline.
func (m *StreamMessages) WaitStatus(ctx context.Context) (StreamMessageStatus, error) {
	if m == nil || ctx == nil {
		return StreamMessageStatus{}, cryptov4.ErrConfiguration
	}
	if err := m.checkReadDependency(ctx); err != nil {
		return m.Status(), err
	}
	m.mu.Lock()
	if m.terminalStatusLocked() {
		s := m.statusLocked()
		m.mu.Unlock()
		return s, nil
	}
	count := m.cleanupWaiters + m.statusWaiters
	if m.cursorRead {
		count++
	}
	if count == 4 {
		m.mu.Unlock()
		return StreamMessageStatus{}, cryptov4.ErrCapacity
	}
	m.statusWaiters++
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.statusWaiters--; m.cleanupLocked(); m.mu.Unlock() }()
	for {
		m.mu.Lock()
		if m.terminalStatusLocked() {
			s := m.statusLocked()
			m.mu.Unlock()
			return s, nil
		}
		changed := m.stateChanged
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return m.Status(), ctx.Err()
		case <-changed:
		}
	}
}
