package sessionv4

import (
	"context"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// One preadmitted publisher is the only message writer. Encoding completion
// never reorders the FIFO, and waiter cancellation after submission never
// interleaves another prefix with the original suffix.
func (m *TypedMessageStream) publishTypedMessages() {
	defer func() { m.mu.Lock(); m.publisherExited = true; m.signal(); m.mu.Unlock() }()
	for {
		m.mu.Lock()
		if m.ioEnded {
			m.mu.Unlock()
			return
		}
		e := m.firstSend
		if e == nil && m.sendSealed && !m.outputClosed {
			o := m.owner
			m.mu.Unlock()
			err := o.queue.waitCloseOwned(m.ioContext, false, o)
			m.mu.Lock()
			m.finError = err
			if err != nil {
				m.closeLocked(err)
			} else {
				m.outputClosed = true
			}
			close(m.finDone)
			m.signal()
			m.mu.Unlock()
			return
		}
		if e == nil || !e.ready {
			m.mu.Unlock()
			select {
			case <-m.publishWake:
			case <-m.ioContext.Done():
			}
			continue
		}
		e.publishing = true
		o := m.owner
		m.mu.Unlock()
		err := m.publishMessage(e, o)
		m.mu.Lock()
		e.publishing = false
		e.mu.Lock()
		submitted := e.accepted != 0
		if !e.finished {
			e.failure, e.finished = err, true
			close(e.done)
		}
		e.mu.Unlock()
		m.unlinkSendLocked(e)
		if err != nil && submitted {
			m.closeLocked(err)
		}
		m.signal()
		m.mu.Unlock()
	}
}

func (m *TypedMessageStream) publishMessage(e *typedMessageSend, o *StreamOwnership) error {
	q := o.queue
	if err := q.beginWriteMethod(o); err != nil {
		return err
	}
	defer q.endWriteMethod()
	write := func(input []byte) error {
		for len(input) != 0 {
			n, err := q.writeTypedMessageOwned(e.publication, input, o, e)
			input = input[n:]
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrNoProgress
			}
		}
		return nil
	}
	if err := write(e.prefix[:]); err != nil {
		return err
	}
	for i := 0; i < int(e.segments.count); i++ {
		if err := write(e.segments.blocks[i][:e.segments.used[i]]); err != nil {
			return err
		}
	}
	return nil
}

// CloseWrite seals entry admission once. The original publisher drains the
// logical FIFO before issuing the single underlying FIN, even if this wait is
// canceled. Revoked encoders retain their actual charges without delaying FIN.
func (m *TypedMessageStream) CloseWrite(ctx context.Context) error {
	if m == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	if m.closed || m.ioEnded || !m.bound {
		err := m.errorLocked()
		m.mu.Unlock()
		return err
	}
	if m.closeWaiters == 4 {
		m.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	if !m.sendSealed {
		clock := m.owner.admission.engine.Clock()
		start, err := clock.Sample()
		if err == nil {
			if m.owner.deadline != nil {
				m.closeDeadline, err = m.owner.deadline.ForkAgeAt(start, m.config.SendTimeoutMS)
			} else {
				m.closeDeadline, err = timev4.NewAgeAt(clock, start, m.config.SendTimeoutMS, m.owner.admission.engine.SessionParameters().SessionNotAfterMS)
			}
		}
		if err != nil {
			m.mu.Unlock()
			return err
		}
		m.sendSealed = true
		m.wakePublisher()
		m.signal()
	}
	m.closeWaiters++
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.closeWaiters--; m.signal(); m.mu.Unlock() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.ioContext.Done():
		m.mu.Lock()
		err := m.errorLocked()
		m.mu.Unlock()
		return err
	case <-m.finDone:
		m.mu.Lock()
		err := m.finError
		m.mu.Unlock()
		return err
	}
}

func (m *TypedMessageStream) Finish(ctx context.Context) error {
	if err := m.CloseWrite(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed || m.owner == nil {
		err := m.errorLocked()
		m.mu.Unlock()
		return err
	}
	if m.closeWaiters == 4 {
		m.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	m.closeWaiters++
	o := m.owner
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.closeWaiters--; m.signal(); m.mu.Unlock() }()
	return o.queue.waitCloseOwned(ctx, true, o)
}
