package rpc

import (
	"context"
	"sync"
)

type requestScheduler[T any] struct {
	ctx           context.Context
	cancel        context.CancelFunc
	maxConcurrent int
	maxQueued     int
	handle        func(context.Context, T)

	mu      sync.Mutex
	pending []T
	active  int
	closed  bool
	wg      sync.WaitGroup
}

func newRequestScheduler[T any](
	ctx context.Context,
	maxConcurrent int,
	maxQueued int,
	handle func(context.Context, T),
) *requestScheduler[T] {
	workerCtx, cancel := context.WithCancel(ctx)
	return &requestScheduler[T]{
		ctx:           workerCtx,
		cancel:        cancel,
		maxConcurrent: maxConcurrent,
		maxQueued:     maxQueued,
		handle:        handle,
	}
}

func (s *requestScheduler[T]) Submit(env T) bool {
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return false
	}
	if s.active < s.maxConcurrent {
		s.active++
		s.wg.Add(1)
		s.mu.Unlock()
		go s.run(env)
		return true
	}
	if len(s.pending) >= s.maxQueued {
		s.mu.Unlock()
		return false
	}
	s.pending = append(s.pending, env)
	s.mu.Unlock()
	return true
}

func (s *requestScheduler[T]) run(env T) {
	defer s.wg.Done()
	if s.ctx.Err() == nil {
		s.handle(s.ctx, env)
	}

	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || len(s.pending) == 0 {
		s.active--
		if s.ctx.Err() != nil {
			clear(s.pending)
			s.pending = nil
		}
		s.mu.Unlock()
		return
	}
	next := s.pending[0]
	var zero T
	s.pending[0] = zero
	s.pending = s.pending[1:]
	s.wg.Add(1)
	s.mu.Unlock()
	go s.run(next)
}

func (s *requestScheduler[T]) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		clear(s.pending)
		s.pending = nil
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
