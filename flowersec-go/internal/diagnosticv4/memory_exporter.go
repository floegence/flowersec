package diagnosticv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

var ErrEventExpired = errors.New("diagnosticv4: event expired")

// MemoryExporter is an explicit volatile diagnostic destination. It stores
// only the original event whitelist and expires each value at its original
// UTC bucket boundary, including a late callback. It never renews retention
// at export or read. Callers own any copies they retrieve; closing the exporter
// cannot erase those copies. It provides no management authentication itself.
type MemoryExporter struct {
	mu                sync.Mutex
	events            []Event
	used, bytes       uint32
	reservation       resourcev4.Reference
	closed            bool
	wake, stop, done  chan struct{}
	now               func() time.Time
	dropped           atomic.Uint64
	bucketEnd         int64
	ids               []exporterID
	idCount, accepted uint32
}

type exporterID struct {
	id      [16]byte
	expires time.Time
}

type MemoryExporterConfig struct {
	Events       uint32
	RuntimeBytes uint64
}

func MemoryExporterCharge(c MemoryExporterConfig) (resourcev4.Vector, error) {
	if c.Events == 0 || c.Events > 4096 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(MemoryExporter{})) + 1024*uint64(unsafe.Sizeof(exporterID{})) + uint64(c.Events)*uint64(unsafe.Sizeof(Event{})), resourcev4.Items: uint64(c.Events) + 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewMemoryExporter(c MemoryExporterConfig, reservation resourcev4.Reference) (*MemoryExporter, error) {
	charge, err := MemoryExporterCharge(c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	e := &MemoryExporter{events: make([]Event, c.Events), ids: make([]exporterID, 1024), reservation: owned, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), now: time.Now}
	go e.expire()
	return e, nil
}

// Append is a bounded try-now storage operation suitable for the diagnostic
// executor callback. A full or busy store refuses; transport never waits here.
func (e *MemoryExporter) Append(ctx context.Context, event Event) error {
	if e == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !e.mu.TryLock() {
		e.drop()
		return resourcev4.ErrCapacity
	}
	defer e.mu.Unlock()
	if err := e.checkLocked(); err != nil {
		return err
	}
	now := e.now()
	e.sweepLocked(now)
	if event.id == ([16]byte{}) || event.expires.IsZero() || !now.Before(event.expires) || event.expires.Unix() != e.bucketEnd {
		return ErrEventExpired
	}
	known := false
	for _, id := range e.ids[:e.idCount] {
		known = known || id.id == event.id
	}
	var encoded [MaxEncodedEvent]byte
	n := uint32(len(event.AppendJSON(encoded[:0])))
	if e.used == uint32(len(e.events)) || n > 2<<20-e.bytes || e.accepted == 4096 || !known && e.idCount == 1024 {
		e.drop()
		return resourcev4.ErrCapacity
	}
	for i := range e.events {
		if e.events[i].expires.IsZero() {
			if !known {
				e.ids[e.idCount] = exporterID{id: event.id, expires: event.expires}
				e.idCount++
			}
			e.accepted++
			e.events[i] = event
			e.used++
			e.bytes += n
			select {
			case e.wake <- struct{}{}:
			default:
			}
			return nil
		}
	}
	return resourcev4.ErrCapacity
}

// Copy supplies at most 64 original values into caller-owned memory. Offset is
// an observation cursor for this volatile table, not an event or authority ID.
// It does not allocate a retained snapshot or preserve expired data for paging.
func (e *MemoryExporter) Copy(ctx context.Context, offset uint32, dst []Event) (written int, next uint32, err error) {
	if e == nil || ctx == nil || len(dst) == 0 || len(dst) > 64 {
		return 0, 0, resourcev4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLocked(); err != nil {
		return 0, 0, err
	}
	e.sweepLocked(e.now())
	if offset > uint32(len(e.events)) {
		return 0, 0, resourcev4.ErrConfiguration
	}
	for next = offset; next < uint32(len(e.events)); next++ {
		if written == len(dst) {
			return written, next, nil
		}
		if event := e.events[next]; !event.expires.IsZero() {
			dst[written] = event
			written++
		}
	}
	return written, next, nil
}

// CorrelationDeadline resolves only an ID already retained in this exact
// exporter scope. A management incident cannot register arbitrary external
// identifiers or renew an event's original storage deadline. This is trusted
// management composition, never a public diagnostic field or lookup API.
func (e *MemoryExporter) CorrelationDeadline(ctx context.Context, id [16]byte) (time.Time, error) {
	if e == nil || ctx == nil || id == ([16]byte{}) {
		return time.Time{}, resourcev4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLocked(); err != nil {
		return time.Time{}, err
	}
	e.sweepLocked(e.now())
	for _, stored := range e.ids[:e.idCount] {
		if stored.id == id {
			return stored.expires, nil
		}
	}
	return time.Time{}, ErrEventExpired
}

// DeleteCorrelation and DeleteAll remove this destination's actual stored
// values. Only the trusted owner exposes them through its authorized surface.
func (e *MemoryExporter) DeleteCorrelation(ctx context.Context, id [16]byte) error {
	if e == nil || ctx == nil || id == ([16]byte{}) {
		return resourcev4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLocked(); err != nil {
		return err
	}
	for i, event := range e.events {
		if event.id == id {
			e.deleteLocked(i)
		}
	}
	// Erase retained identifiers too. The consumed high-water count does not
	// move backwards: deletion cannot replenish the original bucket's quota.
	for i := range e.idCount {
		if e.ids[i].id == id {
			e.ids[i] = exporterID{}
		}
	}
	return nil
}

func (e *MemoryExporter) DeleteAll(ctx context.Context) error {
	if e == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLocked(); err != nil {
		return err
	}
	clear(e.events)
	clear(e.ids[:])
	e.used, e.bytes = 0, 0
	return nil
}

func (e *MemoryExporter) drop() {
	for {
		n := e.dropped.Load()
		if n == math.MaxUint64 || e.dropped.CompareAndSwap(n, n+1) {
			return
		}
	}
}

// MemoryExporterSnapshot contains only finite aggregate storage observations.
// It carries no event, identifier or management authorization.
type MemoryExporterSnapshot struct {
	StoredEvents        uint32 `json:"stored_events"`
	EncodedBytes        uint32 `json:"encoded_bytes"`
	AcceptedInBucket    uint32 `json:"accepted_in_bucket"`
	IDsConsumedInBucket uint32 `json:"ids_consumed_in_bucket"`
	Dropped             uint64 `json:"dropped"`
	Closed              bool   `json:"closed"`
}

func (e *MemoryExporter) Snapshot() MemoryExporterSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		e.sweepLocked(e.now())
	}
	return MemoryExporterSnapshot{StoredEvents: e.used, EncodedBytes: e.bytes, AcceptedInBucket: e.accepted, IDsConsumedInBucket: e.idCount, Dropped: e.dropped.Load(), Closed: e.closed}
}

func (e *MemoryExporter) checkLocked() error {
	if e.closed {
		return resourcev4.ErrClosed
	}
	return e.reservation.Check()
}

func (e *MemoryExporter) deleteLocked(i int) {
	event := e.events[i]
	if event.expires.IsZero() {
		return
	}
	var encoded [MaxEncodedEvent]byte
	e.bytes -= uint32(len(event.AppendJSON(encoded[:0])))
	e.used--
	e.events[i] = Event{}
}

func (e *MemoryExporter) sweepLocked(now time.Time) time.Duration {
	end := diagnosticBucketEnd(now).Unix()
	if e.bucketEnd != end {
		clear(e.events)
		clear(e.ids[:])
		e.used, e.bytes, e.idCount, e.accepted = 0, 0, 0, 0
		e.bucketEnd = end
	}
	next := time.Minute
	for i := range e.idCount {
		id := &e.ids[i]
		if id.id != ([16]byte{}) && (!now.Before(id.expires) || id.expires.Sub(now) > 15*time.Minute) {
			*id = exporterID{}
		}
	}
	for i, event := range e.events {
		if event.expires.IsZero() {
			continue
		}
		remaining := event.expires.Sub(now)
		if remaining <= 0 || remaining > 15*time.Minute {
			e.deleteLocked(i)
		} else {
			next = min(next, remaining)
		}
	}
	return next
}

func (e *MemoryExporter) expire() {
	timer := time.NewTimer(0)
	defer func() {
		timer.Stop()
		e.mu.Lock()
		e.reservation.Release()
		e.reservation = resourcev4.Reference{}
		close(e.done)
		e.mu.Unlock()
	}()
	for {
		e.mu.Lock()
		if e.closed || e.reservation.Check() != nil {
			e.closed = true
			clear(e.events)
			clear(e.ids[:])
			e.events, e.ids = nil, nil
			e.used, e.bytes = 0, 0
			e.mu.Unlock()
			return
		}
		delay := e.sweepLocked(e.now())
		e.mu.Unlock()
		timer.Reset(delay)
		select {
		case <-timer.C:
		case <-e.wake:
		case <-e.stop:
		}
	}
}

func (e *MemoryExporter) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		e.closed = true
		clear(e.events)
		clear(e.ids[:])
		e.used, e.bytes = 0, 0
		close(e.stop)
	}
}

func (e *MemoryExporter) WaitCleanup(ctx context.Context) error {
	if e == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*MemoryExporter) String() string               { return "Flowersec.DiagnosticMemoryExporter" }
func (*MemoryExporter) GoString() string             { return "Flowersec.DiagnosticMemoryExporter" }
func (*MemoryExporter) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// BorrowOperations retains this original exporter's storage responsibility
// through a same-root management service. It grants no read or delete right.
func (e *MemoryExporter) BorrowOperations(ref resourcev4.Reference) (resourcev4.Reference, error) {
	if e == nil {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkLocked(); err != nil {
		return resourcev4.Reference{}, err
	}
	if err := e.reservation.CheckSameRoot(ref); err != nil {
		return resourcev4.Reference{}, err
	}
	return e.reservation.Borrow()
}
