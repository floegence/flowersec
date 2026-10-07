package rawquic

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/internal/quicfailure"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	quic "github.com/quic-go/quic-go"
)

func streamDirectionFailure(err error) error {
	return quicfailure.Stream(err, quic.StreamErrorCode(native.NormalDrainedCode))
}

func (s *OwnedStream) StopSendingDrained() error {
	actual, err := s.begin(ownedStop)
	if err != nil {
		return err
	}
	defer s.end(ownedStop)
	stream := actual.(*Stream)
	stream.stopOnce.Do(func() {
		stream.stream.CancelRead(quic.StreamErrorCode(native.NormalDrainedCode))
		stream.lifecycle.StopSendingResult(nil)
	})
	return stream.stopErr
}

// This is the original native send context, whose cause records the remote
// STOP_SENDING even while the application is idle. The handle generation is
// checked before retrieving it; retired aliases cannot observe another stream.
func (s *OwnedStream) WriteContext() context.Context {
	if s == nil || s.owner == nil {
		return deadStreamContext
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	slot, err := s.slotLocked()
	if err != nil || slot.closed || s.owner.closed {
		return deadStreamContext
	}
	if slot.native == nil {
		return s.owner.session.conn.Context()
	}
	stream := slot.native.(*Stream)
	return stream.stream.Context()
}

func (s *OwnedStream) WriteStopReason() error {
	if s == nil || s.owner == nil {
		return resourcev4.ErrOwner
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	slot, err := s.slotLocked()
	if err != nil {
		return resourcev4.ErrOwner
	}
	if slot.native == nil {
		return streamDirectionFailure(context.Cause(s.owner.session.conn.Context()))
	}
	stream := slot.native.(*Stream)
	reason := streamDirectionFailure(context.Cause(stream.stream.Context()))
	if reason == native.ErrNormalDrained || reason == native.ErrDirectionReset {
		stream.lifecycle.CloseWriteResult(nil)
	}
	return reason
}

var _ native.DirectionalStream = (*OwnedStream)(nil)

// Physical cleanup after an ended pair of halves must not send RESET_STREAM
// over a previously queued FIN. The same provider slot remains pinned until
// every actual method has exited, after which Retire can release that slot.
func (s *OwnedStream) CloseDirections() error {
	if s == nil || s.owner == nil {
		return resourcev4.ErrOwner
	}
	p := s.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	slot, err := s.slotLocked()
	if err != nil {
		return err
	}
	if slot.closed {
		return nil
	}
	if slot.calls != 0 || slot.native == nil || !slot.native.(*Stream).lifecycle.DirectionsEnded() {
		return resourcev4.ErrCapacity
	}
	slot.closed, slot.closeReturned = true, true
	p.cleanupLocked()
	return nil
}
