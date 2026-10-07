package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func (n *relayNativePair) notifyLocked() {
	for i := 0; i < 2; i++ {
		select {
		case n.wake <- struct{}{}:
		default:
		}
	}
}

func (n *relayNativePair) countCreationLocked(s *relayNativeSlot) error {
	if s.counted {
		return cryptov4.ErrTransition
	}
	if n.total >= n.pair.c.MaxTotalNativeMappings {
		return cryptov4.ErrCapacity
	}
	n.total++
	s.counted = true
	return nil
}

func (n *relayNativePair) accept(side int) {
	for {
		// The original pending mapping/task/handle position is occupied before
		// invoking Accept. Partial OPEN readers cannot spawn unbounded work.
		var s *relayNativeSlot
		for s == nil {
			n.mu.Lock()
			var err error
			s, err = n.claimLocked(side)
			n.mu.Unlock()
			if err == nil {
				break
			}
			if err != cryptov4.ErrCapacity {
				return
			}
			select {
			case <-n.ctx.Done():
				return
			case <-n.wake:
			}
		}
		stream, err := n.connections[side].AcceptNativeStream(n.ctx)
		if err != nil {
			n.retireSlot(s)
			if n.ctx.Err() == nil {
				n.fail(err)
			}
			return
		}
		actual, ok := stream.(native.DirectionalStream)
		if !ok {
			_ = stream.Close()
			_ = stream.WaitCleanup(context.Background())
			_ = stream.Retire()
			n.retireSlot(s)
			n.fail(protocolv4.ErrRequiredGuaranteeUnavailable)
			return
		}
		n.mu.Lock()
		s.streams[side] = actual
		err = n.countCreationLocked(s)
		if err == nil && n.closed {
			err = cryptov4.ErrClosed
		}
		n.mu.Unlock()
		if err != nil {
			n.retireSlot(s)
			n.fail(err)
			return
		}
		n.launch(func() { n.runSlot(s, 0) })
	}
}

func (n *relayNativePair) runSlot(s *relayNativeSlot, first int) {
	// This supervisor owns all stream methods and both forwarding tails until
	// their actual completion. The generation cannot be reused in that interval.
	active := 0
	defer func() {
		if active > 0 {
			n.pair.Close()
			for active > 0 {
				<-s.done
				active--
			}
		}
		n.retireSlot(s)
	}()
	if s.streams[s.opener] != nil {
		var err error
		first, err = readRelayEnvelope(relayNativeIO{n.hops[s.opener], s.streams[s.opener]}, s.buffers[s.opener])
		if err != nil {
			return
		}
		frame, header, _, err := protocolv4.ParseRecord(s.buffers[s.opener][:first], n.hops[s.opener].c.Initial.Profile, n.pair.c.MaxEnvelopeBytes-protocolv4.EnvelopePrefixSize)
		if err == nil && frame != protocolv4.FrameOpenStream {
			err = ErrOpenAssociation
		}
		if err == nil {
			n.mu.Lock()
			err = n.bindScopeLocked(s, header, s.opener)
			n.mu.Unlock()
		}
		if err != nil {
			n.fail(err)
			return
		}
	}
	peer := 1 - s.opener
	if connection := n.connections[peer]; connection != nil {
		var protection [1]native.StreamProtection
		if err := connection.ProtectNativeStreams(protection[:]); err != nil {
			n.fail(err)
			return
		}
		// Store the original protected provider position before invoking Open.
		// Cancellation never moves its eventual result to a different scope.
		n.mu.Lock()
		s.protections[peer] = protection[0]
		closed := n.closed
		n.mu.Unlock()
		if closed {
			return
		}
		stream, err := protection[0].Open(n.ctx)
		if err != nil {
			n.fail(err)
			return
		}
		actual, ok := stream.(native.DirectionalStream)
		if !ok {
			_ = stream.Close()
			_ = stream.WaitCleanup(context.Background())
			_ = stream.Retire()
			n.fail(protocolv4.ErrRequiredGuaranteeUnavailable)
			return
		}
		n.mu.Lock()
		s.streams[peer] = actual
		n.mu.Unlock()
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	s.pending = false
	n.pending--
	n.notifyLocked()
	n.mu.Unlock()
	var writes [2]<-chan struct{}
	for side := 0; side < 2; side++ {
		if stream := s.streams[side]; stream != nil {
			writes[side] = stream.WriteContext().Done()
		}
	}
	for direction := 0; direction < 2; direction++ {
		direction := direction
		initial := 0
		if direction == s.opener {
			initial = first
		}
		active++
		n.launch(func() { n.forwardDirection(s, direction, initial) })
	}
	closed := n.ctx.Done()
	for active > 0 {
		select {
		case direction := <-s.done:
			active--
			// The corresponding output writer is now done. Its local FIN's context
			// cancellation is not a second remote stop signal.
			writes[1-direction] = nil
		case <-writes[0]:
			reason := s.streams[0].WriteStopReason()
			writes[0] = nil
			n.stopDirection(s, 1, reason)
		case <-writes[1]:
			reason := s.streams[1].WriteStopReason()
			writes[1] = nil
			n.stopDirection(s, 0, reason)
		case <-closed:
			closed = nil
			n.stopDirection(s, 0, cryptov4.ErrClosed)
			n.stopDirection(s, 1, cryptov4.ErrClosed)
		}
	}
}

func (n *relayNativePair) retireSlot(s *relayNativeSlot) {
	n.mu.Lock()
	s.closing = true
	n.mu.Unlock()
	if err := n.cleanupSlot(context.Background(), s); err != nil {
		n.fail(err)
	}
}

// Called only after the original supervisor and its two workers have joined,
// or by pair cleanup after Run has returned. No cancellation releases live I/O.
func (n *relayNativePair) cleanupSlot(ctx context.Context, s *relayNativeSlot) error {
	for side := 0; side < 2; side++ {
		stream := s.streams[side]
		if stream != nil {
			closeNativeStream(stream)
			if err := stream.WaitCleanup(ctx); err != nil {
				return err
			}
			if err := stream.Retire(); err != nil {
				return err
			}
			n.mu.Lock()
			s.streams[side] = nil
			n.mu.Unlock()
		}
		if protection := s.protections[side]; protection != nil {
			protection.Close()
			s.protections[side] = nil
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !s.active {
		return nil
	}
	// Publish ended-direction facts under the same lock as slot reuse, after
	// all original workers and native handles have joined. Buffered provider
	// DATA can still name this scope; its tombstone never permits another OPEN.
	if s.scope != 0 {
		index, known := n.usedIndex(s.scope)
		if !known || index < 0 {
			return ErrOpenAssociation
		}
		n.retired[index] = 0b11
	}
	if s.pending {
		n.pending--
	}
	if s.live {
		n.resident--
	}
	for d := 0; d < 2; d++ {
		n.discardQueueLocked(s, d)
		select {
		case <-s.frames[d]:
		default:
		}
		// WS slabs are shared; another mapping may still own this physical buffer.
		if n.connections[d] != nil {
			clear(s.buffers[d])
		}
	}
	buffers, frames := s.buffers, s.frames
	*s = relayNativeSlot{buffers: buffers, frames: frames, queueHead: [2]int{-1, -1}, queueTail: [2]int{-1, -1}}
	n.notifyLocked()
	return nil
}

func (n *relayNativePair) waitCleanup(ctx context.Context) error {
	if n == nil {
		return nil
	}
	for i := range n.slots {
		s := &n.slots[i]
		if s.active {
			if err := n.cleanupSlot(ctx, s); err != nil {
				return err
			}
		}
	}
	return nil
}
