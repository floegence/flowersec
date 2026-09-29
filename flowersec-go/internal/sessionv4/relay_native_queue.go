package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"

// A WS input side shares its already reserved frame slab across all mappings.
// A single busy native writer can use currently idle queue positions, but can
// never allocate another buffer or consume the independent maintenance lane.
// A dequeued item remains used until the actual output method returns.
type relayQueuedFrame struct {
	buffer     []byte
	size, next int
	used       bool
}

func (n *relayNativePair) queueMessageLocked(s *relayNativeSlot, d int, b []byte) error {
	for index := range n.queued[d] {
		q := &n.queued[d][index]
		if q.used {
			continue
		}
		q.used, q.size, q.next = true, len(b), -1
		copy(q.buffer, b)
		if s.queueTail[d] < 0 {
			s.queueHead[d] = index
		} else {
			n.queued[d][s.queueTail[d]].next = index
		}
		s.queueTail[d] = index
		select {
		case s.frames[d] <- 0:
		default:
		}
		return nil
	}
	return cryptov4.ErrCapacity
}

func (n *relayNativePair) nextMessage(s *relayNativeSlot, d int) (int, []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || s.stopped[d] || s.queueHead[d] < 0 {
		return -1, nil
	}
	index := s.queueHead[d]
	q := &n.queued[d][index]
	s.queueHead[d] = q.next
	if q.next < 0 {
		s.queueTail[d] = -1
	}
	q.next = -1
	return index, q.buffer[:q.size:q.size]
}

func (n *relayNativePair) releaseMessageLocked(d, index int) {
	q := &n.queued[d][index]
	clear(q.buffer[:q.size])
	q.used, q.size, q.next = false, 0, -1
}
func (n *relayNativePair) releaseMessage(d, index int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.releaseMessageLocked(d, index)
}
func (n *relayNativePair) discardQueueLocked(s *relayNativeSlot, d int) {
	for s.queueHead[d] >= 0 {
		index := s.queueHead[d]
		s.queueHead[d] = n.queued[d][index].next
		n.releaseMessageLocked(d, index)
	}
	s.queueTail[d] = -1
}
