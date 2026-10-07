package sessionv4

import (
	"encoding/binary"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Inspect only the finite, visible framing. Ciphertext is borrowed, never
// decrypted, rewritten or treated as an authenticated endpoint decision.
func relayEnvelopeType(b []byte) (protocolv4.FrameType, error) {
	if len(b) < protocolv4.EnvelopePrefixSize || uint64(binary.BigEndian.Uint32(b[:4]))+protocolv4.EnvelopePrefixSize != uint64(len(b)) {
		return 0, protocolv4.ErrTruncated
	}
	if b[5] != 0 || b[6] != 0 || b[7] != 0 {
		return 0, protocolv4.ErrInvalidFlags
	}
	f := protocolv4.FrameType(b[4])
	if f < protocolv4.FrameNegotiate || f >= protocolv4.FrameHopAuth {
		return 0, protocolv4.ErrUnknownFrame
	}
	return f, nil
}

func readRelayEnvelope(r io.Reader, b []byte) (int, error) {
	size := protocolv4.EnvelopePrefixSize
	if len(b) < size {
		return 0, protocolv4.ErrTruncated
	}
	n, err := io.ReadFull(r, b[:size])
	if err != nil {
		return n, err
	}
	payload := uint64(binary.BigEndian.Uint32(b[:4]))
	if payload > uint64(len(b)-size) {
		return size, protocolv4.ErrPayloadTooLarge
	}
	m, err := io.ReadFull(r, b[size:size+int(payload)])
	return n + m, err
}

func writeRelayEnvelope(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return cryptov4.ErrConfiguration
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

type relayNativeIO struct {
	hop    *RelayHop
	stream native.Stream
}

func (s relayNativeIO) Read(b []byte) (n int, err error) {
	if err = s.hop.guard.Check(); err != nil {
		return
	}
	receipt, err := s.hop.budget.reserveWait(uint64(len(b)))
	if err != nil {
		return 0, err
	}
	returned := false
	defer func() { settleRelayIO(receipt, n, len(b), !returned, &err) }()
	n, err = s.stream.Read(b)
	returned = true
	return
}
func (s relayNativeIO) Write(b []byte) (n int, err error) {
	if err = s.hop.guard.Check(); err != nil {
		return
	}
	receipt, err := s.hop.budget.reserveWait(uint64(len(b)))
	if err != nil {
		return 0, err
	}
	returned := false
	defer func() { settleRelayIO(receipt, n, len(b), !returned, &err) }()
	n, err = s.stream.Write(b)
	returned = true
	return
}

func (n *relayNativePair) writeLane(side int, b []byte) error {
	n.write[side].Lock()
	defer n.write[side].Unlock()
	hop := n.hops[side]
	if err := hop.guard.Check(); err != nil {
		return err
	}
	if hop.prepared.binding.MessageCarrier {
		return hop.prepared.messageAdapter.WriteMessage(n.ctx, b)
	}
	return writeRelayEnvelope(&hop.prepared.streamAdapter, b)
}

func (n *relayNativePair) readLane(side int) {
	hop := n.hops[side]
	buffer := n.pair.buffers[side]
	for {
		if err := hop.guard.Check(); err != nil {
			n.fail(err)
			return
		}
		var count int
		var err error
		if hop.prepared.binding.MessageCarrier {
			count, err = hop.prepared.messageAdapter.ReadMessage(n.ctx, buffer)
		} else {
			count, err = readRelayEnvelope(&hop.prepared.streamAdapter, buffer)
		}
		if err != nil {
			n.fail(err)
			return
		}
		if count < 0 || count > len(buffer) {
			n.fail(cryptov4.ErrConfiguration)
			return
		}
		b := buffer[:count:count]
		frame, err := relayEnvelopeType(b)
		if err != nil {
			n.fail(err)
			return
		}
		switch frame {
		case protocolv4.FrameOpenStream, protocolv4.FrameStreamData:
			if n.connections[side] != nil {
				n.fail(ErrOpenAssociation)
				return
			}
			err = n.enqueueMessage(side, frame, b)
		case protocolv4.FrameDatagram:
			err = protocolv4.ErrUnknownFrame
		default:
			err = n.writeLane(1-side, b)
		}
		if err != nil {
			n.fail(err)
			return
		}
	}
}

func (n *relayNativePair) enqueueMessage(side int, frame protocolv4.FrameType, b []byte) error {
	_, header, _, err := protocolv4.ParseRecord(b, n.hops[side].c.Initial.Profile, n.pair.c.MaxEnvelopeBytes-protocolv4.EnvelopePrefixSize)
	if err != nil {
		return err
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return cryptov4.ErrClosed
	}
	var s *relayNativeSlot
	for i := range n.slots {
		candidate := &n.slots[i]
		if candidate.active && candidate.scope == header.Scope {
			s = candidate
			break
		}
	}
	created := false
	if s == nil {
		// Provider input can retain DATA after both original directions have
		// joined and the mapping slot has been reused. Its signed ingress
		// meter was already charged; only a known retired direction may drop it.
		if frame == protocolv4.FrameStreamData {
			index, known := n.usedIndex(header.Scope)
			if known && index >= 0 && n.retired[index]&(1<<side) != 0 {
				n.mu.Unlock()
				return nil
			}
		}
		if frame != protocolv4.FrameOpenStream {
			n.mu.Unlock()
			return ErrOpenAssociation
		}
		s, err = n.claimLocked(side)
		if err == nil {
			err = n.countCreationLocked(s)
		}
		if err == nil {
			err = n.bindScopeLocked(s, header, side)
		}
		if err != nil {
			n.mu.Unlock()
			if s != nil {
				n.retireSlot(s)
			}
			return err
		}
		created = true
	} else if frame == protocolv4.FrameOpenStream {
		n.mu.Unlock()
		return ErrOpenAssociation
	}
	if s.stopped[side] || s.closing {
		n.mu.Unlock()
		return nil
	}
	if err = n.queueMessageLocked(s, side, b); err != nil {
		n.mu.Unlock()
		return err
	}
	n.mu.Unlock()
	if created {
		n.launch(func() { n.runSlot(s, 0) })
	}
	return nil
}

func (n *relayNativePair) forwardDatagrams(side int) {
	from, to := n.hops[side], n.hops[1-side]
	buffer := n.datagrams[side]
	for {
		if err := from.guard.Check(); err != nil {
			n.fail(err)
			return
		}
		size, err := n.readDatagram(side, buffer)
		if err != nil {
			n.fail(err)
			return
		}
		if size < 0 || size > len(buffer) {
			n.fail(cryptov4.ErrConfiguration)
			return
		}
		frame, _, _, err := protocolv4.ParseRecord(buffer[:size], from.c.Initial.Profile, n.pair.c.MaxEnvelopeBytes-protocolv4.EnvelopePrefixSize)
		if err != nil || frame != protocolv4.FrameDatagram {
			if err == nil {
				err = protocolv4.ErrUnknownFrame
			}
			n.fail(err)
			return
		}
		if err = to.guard.Check(); err != nil {
			n.fail(err)
			return
		}
		if err = n.writeDatagram(1-side, buffer[:size:size]); err != nil {
			n.fail(err)
			return
		}
	}
}
func (n *relayNativePair) readDatagram(side int, b []byte) (size int, err error) {
	receipt, err := n.hops[side].budget.reserveWait(uint64(len(b)))
	if err != nil {
		return 0, err
	}
	returned := false
	defer func() { settleRelayIO(receipt, size, len(b), !returned, &err) }()
	size, err = n.connections[side].ReceiveDatagram(n.ctx, b)
	returned = true
	return
}
func (n *relayNativePair) writeDatagram(side int, b []byte) (err error) {
	receipt, err := n.hops[side].budget.reserveWait(uint64(len(b)))
	if err != nil {
		return err
	}
	returned := false
	defer func() { settleRelayIO(receipt, len(b), len(b), !returned || err != nil, &err) }()
	err = n.connections[side].SendDatagram(b)
	returned = true
	return
}

// A stopped direction retains its original handle/generation until both
// forwarding calls and its supervisor finish. It cannot release the reverse.
func (n *relayNativePair) stopDirection(s *relayNativeSlot, direction int, reason error) {
	n.mu.Lock()
	if !s.active || s.stopped[direction] {
		n.mu.Unlock()
		return
	}
	s.stopped[direction] = true
	n.discardQueueLocked(s, direction)
	close(s.stop[direction])
	source := s.streams[direction]
	n.mu.Unlock()
	if source != nil {
		if reason == native.ErrNormalDrained {
			_ = source.StopSendingDrained()
		} else {
			_ = source.StopSending()
		}
	}
}

func (n *relayNativePair) stopped(s *relayNativeSlot, direction int) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closed || s.stopped[direction]
}

func (n *relayNativePair) forwardDirection(s *relayNativeSlot, direction, first int) {
	queuedIndex := -1
	defer func() {
		if queuedIndex >= 0 {
			n.releaseMessage(direction, queuedIndex)
		}
		s.done <- direction
	}()
	from, to := s.streams[direction], s.streams[1-direction]
	buffer := s.buffers[direction]
	firstFrame := true
	for {
		if n.stopped(s, direction) {
			return
		}
		size := first
		first = 0
		if size == 0 {
			if from == nil {
				for {
					queuedIndex, buffer = n.nextMessage(s, direction)
					if queuedIndex >= 0 {
						size = len(buffer)
						break
					}
					select {
					case <-s.frames[direction]:
					case <-s.stop[direction]:
						return
					case <-n.ctx.Done():
						return
					}
				}
			} else {
				var err error
				size, err = readRelayEnvelope(relayNativeIO{n.hops[direction], from}, buffer)
				if err != nil {
					if err != io.EOF && err != io.ErrUnexpectedEOF && err != native.ErrDirectionReset && err != native.ErrNormalDrained {
						n.fail(err)
					}
					if to != nil && !n.stopped(s, direction) {
						// No read-ahead exists in this direction: earlier envelopes have
						// returned from Write before EOF, so FIN cannot overtake a queue.
						if err == io.EOF && size == 0 {
							_ = to.CloseWrite()
						} else {
							_ = to.ResetWrite()
						}
					}
					return
				}
			}
		}
		frame, err := relayEnvelopeType(buffer[:size:size])
		if err == nil && frame != protocolv4.FrameOpenStream && frame != protocolv4.FrameStreamData {
			err = protocolv4.ErrUnknownFrame
		}
		if err == nil {
			_, header, _, parse := protocolv4.ParseRecord(buffer[:size:size], n.hops[direction].c.Initial.Profile, n.pair.c.MaxEnvelopeBytes-protocolv4.EnvelopePrefixSize)
			err = parse
			if err == nil && header.Scope != s.scope {
				err = ErrOpenAssociation
			}
			if err == nil && frame == protocolv4.FrameOpenStream && (direction != s.opener || !firstFrame || header.Epoch != s.openEpoch) {
				err = ErrOpenAssociation
			}
		}
		firstFrame = false
		if err == nil && !n.stopped(s, direction) {
			if to != nil {
				err = writeRelayEnvelope(relayNativeIO{n.hops[1-direction], to}, buffer[:size:size])
			} else {
				err = n.writeLane(1-direction, buffer[:size:size])
			}
		}
		if queuedIndex >= 0 {
			n.releaseMessage(direction, queuedIndex)
			queuedIndex = -1
		}
		if err != nil {
			if err == native.ErrNormalDrained || err == native.ErrDirectionReset {
				n.stopDirection(s, direction, err)
			} else {
				n.fail(err)
			}
			return
		}
	}
}
