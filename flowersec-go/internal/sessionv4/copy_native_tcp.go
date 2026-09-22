package sessionv4

import (
	"context"
	"errors"
	"io"
	"math"
	"net"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// runNative uses the same single chunk and synchronous acceptance accounting
// as Stream/Stream Copy. The socket and Stream methods stay pinned throughout
// the actual pump, including any syscall made runnable by cancellation.
func (s *copyState) runNative(ctx context.Context, stream *StreamOwnership, native *nativeTCPOwnership, nativeSource bool) (result CopyResult, err error) {
	s.mu.Lock()
	if s.started || s.complete {
		s.mu.Unlock()
		return result, ErrStreamOwned
	}
	s.started = true
	s.mu.Unlock()
	result.SourceTerminal = protocolv4.V4ReadTerminalUnknown
	defer func() {
		if s.final.SourceTerminal == "" {
			s.result(protocolv4.V4ReadTerminalUnknown)
		}
		s.mu.Lock()
		s.sourceOwner, s.targetOwner, s.nativeOwner, s.targetDone = nil, nil, nil, nil
		s.complete = true
		s.mu.Unlock()
	}()
	_, _, flow, queue, err := stream.begin()
	if err != nil {
		return result, err
	}
	defer stream.end()
	conn, err := native.begin()
	if err != nil {
		return result, err
	}
	defer native.end()
	s.nativeOwner = native
	if err = s.reservation.CheckSameEnvironment(native.reservation); err != nil {
		return result, err
	}
	if nativeSource {
		s.targetOwner, s.targetDone = stream, queue.writeDone
		if err = queue.beginWriteMethod(stream); err != nil {
			return result, err
		}
		defer queue.endWriteMethod()
		queue.mu.Lock()
		err = s.reservation.CheckSameEnvironment(queue.reservation)
		queue.mu.Unlock()
		if err != nil {
			return result, err
		}
	} else {
		s.sourceOwner = stream
		source := flow.receive
		source.pool.mu.Lock()
		err = source.readOwnershipLocked(stream)
		if err == nil && source.readPending {
			err = ErrReadInProgress
		}
		if err == nil {
			err = s.reservation.CheckSameEnvironment(source.reservation)
		}
		if err == nil {
			source.readPending = true
		}
		source.pool.mu.Unlock()
		if err != nil {
			return result, err
		}
		defer func() { source.pool.mu.Lock(); source.readPending = false; stream.notify(); source.pool.mu.Unlock() }()
	}
	for {
		terminal := protocolv4.V4ReadTerminalUnknown
		if nativeSource {
			terminal, err = s.readNative(ctx, conn, stream)
		} else {
			terminal, err = flow.receive.copyRead(ctx, s)
		}
		if err != nil {
			return s.result(terminal), boundedReadCause(err)
		}
		for s.accepted < s.filled {
			if nativeSource {
				_, err = queue.writeMethodOwned(ctx, s.storage[s.accepted:s.filled], s, stream, true)
			} else {
				err = s.writeNative(ctx, conn)
			}
			if err != nil {
				return s.result(terminal), boundedReadCause(err)
			}
		}
		if terminal == protocolv4.V4ReadTerminalEof {
			return s.result(terminal), nil
		}
	}
}

func (s *copyState) nativeGate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkOwners(); err != nil {
		return err
	}
	return s.reservation.Check()
}

func (s *copyState) readNative(ctx context.Context, conn *net.TCPConn, stream *StreamOwnership) (protocolv4.V4ReadTerminal, error) {
	select {
	case <-s.targetDone:
		stream.queue.mu.Lock()
		err := stream.queue.requestErrorLocked(stream)
		stream.queue.mu.Unlock()
		if err == nil {
			err = ErrFlowClosed
		}
		return protocolv4.V4ReadTerminalUnknown, err
	default:
	}
	// The one participating Session still owns bridge dispatch authority. Check
	// it before consuming native source bytes, then recheck the original lifetime
	// after that potentially blocked Session gate.
	if err := stream.admission.engine.CheckApplicationAuthorization(); err != nil {
		return protocolv4.V4ReadTerminalUnknown, err
	}
	n := s.nativeOwner.endpoint
	n.mu.Lock()
	if err := s.nativeGate(ctx); err != nil {
		n.mu.Unlock()
		return protocolv4.V4ReadTerminalUnknown, err
	}
	if n.closed {
		n.mu.Unlock()
		return protocolv4.V4ReadTerminalUnknown, ErrNativeTCPClosed
	}
	s.mu.Lock()
	size := min(uint64(len(s.storage)), math.MaxUint64-s.sourceRead)
	if size == 0 || s.accepted != s.filled {
		s.mu.Unlock()
		n.mu.Unlock()
		return protocolv4.V4ReadTerminalUnknown, ErrStreamData
	}
	dst := s.storage[:int(size)]
	s.mu.Unlock()
	n.mu.Unlock()
	count, err := conn.Read(dst)
	// Commit even a nonzero failed read before dropping the actual native alias.
	terminal, err := s.commitNativeRead(count, err)
	n.mu.Lock()
	if terminal == protocolv4.V4ReadTerminalEof {
		s.nativeOwner.eof = true
	}
	if err != nil && !s.nativeOwner.revoked.Load() && s.nativeOwner.operationContext.Err() == nil {
		s.nativeOwner.readFailed = true
	}
	n.mu.Unlock()
	return terminal, err
}

func (s *copyState) commitNativeRead(n int, err error) (protocolv4.V4ReadTerminal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	terminal := protocolv4.V4ReadTerminalOpen
	s.filled, s.accepted = n, 0
	s.sourceRead += uint64(n) // capacity was checked before the native invocation
	if errors.Is(err, io.EOF) {
		terminal, err = protocolv4.V4ReadTerminalEof, nil
	} else if err != nil {
		terminal, err = protocolv4.V4ReadTerminalUnknown, ErrNativeTCPFailure
	} else if n == 0 {
		err = io.ErrNoProgress
	}
	s.terminal = terminal
	return terminal, err
}

func (s *copyState) writeNative(ctx context.Context, conn *net.TCPConn) error {
	if err := s.sourceOwner.admission.engine.CheckApplicationAuthorization(); err != nil {
		return err
	}
	n := s.nativeOwner.endpoint
	n.mu.Lock()
	if err := s.nativeGate(ctx); err != nil {
		n.mu.Unlock()
		return err
	}
	if n.closed || s.nativeOwner.sendFinished {
		n.mu.Unlock()
		return ErrNativeTCPClosed
	}
	s.mu.Lock()
	size := s.filled - s.accepted
	if uint64(size) > math.MaxUint64-s.targetTaken {
		s.mu.Unlock()
		n.mu.Unlock()
		return ErrStreamData
	}
	input := s.storage[s.accepted:s.filled]
	s.mu.Unlock()
	n.mu.Unlock()
	count, err := conn.Write(input)
	// An admitted Write may return a committed prefix together with a timeout.
	// Never recheck cancellation before recording that irreversible fact.
	s.accept(count)
	if err != nil {
		return ErrNativeTCPFailure
	}
	if count == 0 {
		return io.ErrNoProgress
	}
	return nil
}
