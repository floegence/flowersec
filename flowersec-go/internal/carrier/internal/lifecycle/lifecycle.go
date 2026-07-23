package lifecycle

import (
	"context"
	"errors"
	"io"
	"sync"
)

// Stream keeps full-duplex lifetime independent from carrier APIs that cancel
// their native context as soon as only the send half is closed.
type Stream struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	mu         sync.Mutex
	sendClosed bool
	recvClosed bool
}

func NewStream(parent context.Context) *Stream {
	ctx, cancel := context.WithCancelCause(parent)
	return &Stream{ctx: ctx, cancel: cancel}
}

func (stream *Stream) Context() context.Context { return stream.ctx }

func (stream *Stream) ReadResult(err error) {
	if err == nil {
		return
	}
	if !errors.Is(err, io.EOF) {
		stream.cancel(err)
		return
	}
	stream.mu.Lock()
	stream.recvClosed = true
	finished := stream.sendClosed
	stream.mu.Unlock()
	if finished {
		stream.cancel(io.EOF)
	}
}

func (stream *Stream) WriteResult(err error) {
	if err != nil {
		stream.cancel(err)
	}
}

func (stream *Stream) CloseWriteResult(err error) {
	if err != nil {
		stream.cancel(err)
		return
	}
	stream.mu.Lock()
	stream.sendClosed = true
	finished := stream.recvClosed
	stream.mu.Unlock()
	if finished {
		stream.cancel(io.EOF)
	}
}

func (stream *Stream) Terminate(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	stream.cancel(err)
}
