package sessionv4

import (
	"context"
	"errors"
	"io"
	"iter"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

type StreamItem struct {
	Value  any
	Status StreamMessageStatus
}

// Items owns one typed consumption scope. Early range exit abandons remaining
// output on this same stream. It never sends business cancellation or starts
// another request. Direct reads cannot interleave with an active iterator.
func (m *StreamMessages) Items(ctx context.Context) iter.Seq2[StreamItem, error] {
	return func(yield func(StreamItem, error) bool) {
		if m == nil || ctx == nil {
			yield(StreamItem{}, cryptov4.ErrConfiguration)
			return
		}
		if err := m.checkReadDependency(ctx); err != nil {
			yield(StreamItem{Status: m.Status()}, err)
			return
		}
		m.mu.Lock()
		var err error
		if m.server || m.result == nil {
			err = cryptov4.ErrConfiguration
		} else if m.iterating || m.cursorRead || m.readBusy {
			err = ErrStreamMessageBusy
		} else if m.closed {
			err = m.closedErrorLocked()
		}
		if err == nil {
			m.iterating = true
		}
		m.mu.Unlock()
		if err != nil {
			yield(StreamItem{Status: m.Status()}, err)
			return
		}
		defer func() {
			m.mu.Lock()
			m.iterating = false
			m.closeLocked()
			m.mu.Unlock()
		}()
		for {
			value, status, err := m.readNext(ctx, true)
			if errors.Is(err, io.EOF) {
				return
			}
			if !yield(StreamItem{Value: value, Status: status}, err) || err != nil || status.TerminalDelivered {
				return
			}
		}
	}
}

// AbandonResult closes the single local delivery gate. It preserves prior
// item counts and execution facts, and cleanup continues on the original task.
func (m *StreamMessages) AbandonResult() (StreamMessageStatus, error) {
	if m == nil {
		return StreamMessageStatus{}, cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server {
		return m.statusLocked(), cryptov4.ErrConfiguration
	}
	if m.terminalDelivered {
		return m.statusLocked(), ErrStreamResultDelivered
	}
	m.closeLocked()
	return m.statusLocked(), nil
}
