package cryptov4

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// DatagramQueue is installed once on the original Engine before READY. Its
// backing is supplied by the separately admitted Session datagram owner. Every
// queue decision, replay commit and application delivery uses the Engine gate.
type DatagramQueue struct {
	engine               *Engine
	entries              []datagramEntry
	storage              []byte
	maximum, head, count int
	closed               bool
	wake                 chan struct{}
}

type datagramEntry struct {
	epoch uint32
	size  int
}

func DatagramQueueBackingBytes(slots, maximum int) (uint64, error) {
	if slots < 1 || slots > 64 || maximum < 1 || maximum > 949 {
		return 0, ErrConfiguration
	}
	return uint64(unsafe.Sizeof(DatagramQueue{})) + uint64(slots)*(uint64(unsafe.Sizeof(datagramEntry{}))+uint64(maximum)), nil
}

func (e *Engine) datagramWorkspace(direction protocolv4.Direction) (*workspace, error) {
	w := e.datagramWork[direction]
	if w == nil {
		return nil, ErrCapacity
	}
	e.datagramWork[direction] = nil
	e.borrowedWork++
	return w, nil
}

func (e *Engine) DatagramSelected() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	selected, err := protocolv4.SelectedDatagram(e.config.Features)
	return err == nil && selected && e.config.Datagrams
}

func (e *Engine) NewDatagramQueue(storage []byte, slots, maximum int) (*DatagramQueue, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.serviceInitializationLive(); err != nil {
		return nil, err
	}
	selected, err := protocolv4.SelectedDatagram(e.config.Features)
	if err != nil || !selected || !e.config.Datagrams || e.datagrams != nil || slots < 1 || slots > 64 || maximum < 1 || maximum > 949 || len(storage) != slots*maximum || len(e.free) < 3 {
		return nil, ErrConfiguration
	}
	q := &DatagramQueue{engine: e, entries: make([]datagramEntry, slots), storage: storage, maximum: maximum, wake: make(chan struct{}, 1)}
	for direction := range 2 {
		last := len(e.free) - 1
		w := e.free[last]
		e.free[last] = nil
		e.free = e.free[:last]
		w.datagram, w.direction = true, protocolv4.Direction(direction)
		e.datagramWork[direction] = w
	}
	e.datagrams = q
	return q, nil
}

// Open authenticates a single native envelope. The bounded SDK validator runs
// before the final gate and returns a view into that job's original plaintext.
// Queue-full consumes replay/good-use exactly once and never becomes a retry.
func (q *DatagramQueue) Open(input []byte, validate func(protocolv4.RecordHeader, []byte) ([]byte, error)) error {
	if q == nil || validate == nil {
		return ErrConfiguration
	}
	frame, _, _, err := protocolv4.ParseRecord(input, q.engine.config.Profile, q.engine.config.MaxFrame)
	if err != nil {
		return err
	}
	if frame != protocolv4.FrameDatagram {
		return ErrScope
	}
	var payload []byte
	packet, _, _, err := q.engine.openReservedDatagram(input, func(frame protocolv4.FrameType, h protocolv4.RecordHeader, plain []byte) error {
		var err error
		payload, err = validate(h, plain)
		if err == nil && len(payload) > q.maximum {
			err = protocolv4.ErrPayloadTooLarge
		}
		return err
	}, nil, nil, q, &payload)
	if packet != nil {
		packet.Release()
	}
	return err
}

func (q *DatagramQueue) notifyLocked() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *DatagramQueue) appendLocked(epoch uint32, payload []byte) {
	if q.count < len(q.entries) {
		index := (q.head + q.count) % len(q.entries)
		copy(q.storage[index*q.maximum:(index+1)*q.maximum], payload)
		q.entries[index] = datagramEntry{epoch, len(payload)}
		q.count++
	}
	q.notifyLocked()
}

// Take copies a message into caller-owned bounded storage at the original
// delivery gate. It never authenticates or updates a replay window again.
func (q *DatagramQueue) Take(ctx context.Context, dst []byte) (int, bool, error) {
	if q == nil || ctx == nil || len(dst) < q.maximum {
		return 0, false, ErrConfiguration
	}
	e := q.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	if q.closed {
		return 0, false, ErrClosed
	}
	if err := e.live(); err != nil {
		return 0, false, err
	}
	if err := e.datagramGate(); err != nil {
		return 0, false, err
	}
	key := e.current.keys.get(protocolv4.DatagramScope()).keys[1-e.config.SendDirection]
	if key.usage.calls >= e.limits.Key.Open {
		return 0, false, ErrUsage
	}
	for q.count != 0 {
		entry := q.entries[q.head]
		buffer := q.storage[q.head*q.maximum : (q.head+1)*q.maximum]
		q.entries[q.head] = datagramEntry{}
		q.head, q.count = (q.head+1)%len(q.entries), q.count-1
		if entry.epoch == e.current.number {
			n := copy(dst, buffer[:entry.size])
			clear(buffer)
			return n, true, nil
		}
		clear(buffer)
	}
	return 0, false, nil
}

func (q *DatagramQueue) Wake() <-chan struct{} { return q.wake }

func (q *DatagramQueue) Close() {
	if q == nil {
		return
	}
	q.engine.mu.Lock()
	q.closeLocked()
	q.engine.mu.Unlock()
}

func (q *DatagramQueue) closeLocked() {
	q.closed = true
	clear(q.storage)
	clear(q.entries)
	q.storage, q.entries = nil, nil
	q.head, q.count = 0, 0
	q.notifyLocked()
}
