package sessionv4

import (
	"context"
	"iter"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

func (s *StreamOperation) messages() (*StreamMessages, error) {
	if s == nil || s.owner == nil {
		return nil, cryptov4.ErrClosed
	}
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stream != nil && o.stream.messages != nil {
		return o.stream.messages, nil
	}
	if o.failure != nil {
		return nil, o.failure
	}
	if o.closed {
		return nil, cryptov4.ErrClosed
	}
	return nil, ErrUnaryNotStarted
}

func (s *StreamOperation) Status() StreamMessageStatus {
	m, err := s.messages()
	if err != nil {
		return StreamMessageStatus{Error: err}
	}
	return m.Status()
}

func (s *StreamOperation) ReadNext(ctx context.Context) (any, StreamMessageStatus, error) {
	m, err := s.messages()
	if err != nil {
		return nil, StreamMessageStatus{Error: err}, err
	}
	return m.ReadNext(ctx)
}

func (s *StreamOperation) ReadNextEncoded(ctx context.Context) ([]byte, StreamMessageStatus, error) {
	m, err := s.messages()
	if err != nil {
		return nil, StreamMessageStatus{Error: err}, err
	}
	return m.ReadNextEncoded(ctx)
}

func (s *StreamOperation) WaitStatus(ctx context.Context) (StreamMessageStatus, error) {
	m, err := s.messages()
	if err != nil {
		return StreamMessageStatus{Error: err}, err
	}
	return m.WaitStatus(ctx)
}

func (s *StreamOperation) AbandonResult() (StreamMessageStatus, error) {
	m, err := s.messages()
	if err != nil {
		return StreamMessageStatus{Error: err}, err
	}
	return m.AbandonResult()
}

func (s *StreamOperation) Items(ctx context.Context) iter.Seq2[StreamItem, error] {
	return func(yield func(StreamItem, error) bool) {
		defer s.Close()
		m, err := s.messages()
		if err != nil {
			yield(StreamItem{Status: StreamMessageStatus{Error: err}}, err)
			return
		}
		m.Items(ctx)(yield)
	}
}

func (s *StreamOperation) Snapshot() UnaryOperationSnapshot {
	if s == nil {
		return (*UnaryOperation)(nil).Snapshot()
	}
	return s.owner.Snapshot()
}

func (s *StreamOperation) WaitCleanup(ctx context.Context) error {
	if s == nil || s.owner == nil {
		return cryptov4.ErrClosed
	}
	if m, err := s.messages(); err == nil {
		if ctx == nil {
			return cryptov4.ErrConfiguration
		}
		if err := m.checkReadDependency(ctx); err != nil {
			return err
		}
		if err := m.waitCleanup(ctx); err != nil {
			return err
		}
	}
	return s.owner.WaitCleanup(ctx)
}
