package sessionv4

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

const diagnosticBucket = 15 * time.Minute
const diagnosticMaxIDs = 1024
const diagnosticMaxEvents = 4096
const diagnosticMaxQueueBytes = 2 * 1024 * 1024

var ErrDiagnosticCleanupIncomplete = errors.New("sessionv4: diagnostic cleanup incomplete")

type DiagnosticSinkConfig struct {
	// Nil selects 1%. An explicit value is in basis points, from 0 through 100.
	SampleBasisPoints *uint16
	// Zero selects 64 live operations and 64 queued events. Larger local bounds
	// need their complete reservation; the ceilings are 1024 and 4096.
	OperationSlots, QueueEvents uint32
	// These qualified allowances cover channels, allocator overhead and the
	// SDK pump's actual stack. Callback stacks belong to the root executor.
	RuntimeBytes, RuntimeBytesPerTask uint64
}

type diagnosticSinkPolicy struct {
	operations, queue uint32
	sample            uint16
}

func diagnosticPolicy(c DiagnosticSinkConfig) (diagnosticSinkPolicy, error) {
	p := diagnosticSinkPolicy{operations: c.OperationSlots, queue: c.QueueEvents, sample: 100}
	if p.operations == 0 {
		p.operations = 64
	}
	if p.queue == 0 {
		p.queue = 64
	}
	if c.SampleBasisPoints != nil {
		p.sample = *c.SampleBasisPoints
	}
	if p.operations > diagnosticMaxIDs || p.queue > diagnosticMaxEvents || p.sample > 100 || c.RuntimeBytes == 0 || c.RuntimeBytesPerTask == 0 {
		return diagnosticSinkPolicy{}, cryptov4.ErrConfiguration
	}
	return p, nil
}

type diagnosticOperationSlot struct {
	handle *DiagnosticOperation
	id     [16]byte
}

type diagnosticQueuedEvent struct {
	event  diagnosticv4.Event
	length uint16
}

type diagnosticDelivery struct {
	event      diagnosticv4.Event
	task       *diagnosticTask
	generation uint64
	pending    bool
}

// DiagnosticSink owns one bounded queue and UTC correlation table. Explicit
// construction enables detailed events; Environments without a sink allocate
// no diagnostic callback service. Producers never wait for this gate or invoke
// application code, randomness or I/O. The pump samples independently and uses
// only the existing root executor's fixed diagnostic lane.
type DiagnosticSink struct {
	mu                        sync.Mutex
	policy                    diagnosticSinkPolicy
	operations                []diagnosticOperationSlot
	queue                     []diagnosticQueuedEvent
	deliveries                [diagnosticRunning + diagnosticReady]diagnosticDelivery
	ids                       [][16]byte
	nextID, events            uint32
	first, queued, queueBytes uint32
	bucket                    int64
	generation                uint64
	closed, cleaned           bool
	ctx                       context.Context
	cancel                    context.CancelFunc
	wake, done                chan struct{}
	executor                  *ApplicationExecutor
	executorClosing           <-chan struct{}
	callback                  func(context.Context, diagnosticv4.Event)
	reservation               resourcev4.Reference
	counters                  diagnosticv4.Counters
	// Only the SDK and package tests supply these functions. They never run
	// arbitrary application code and are not exposed as configuration hooks.
	now    func() time.Time
	sample func(uint16) bool
}

// A closed operation is a detached alias. Slot identity prevents ABA reuse.
// Callers create a new operation for every connection attempt/application call;
// there is no API to inject an identity, Session ID or parent correlation ID.
type DiagnosticOperation struct {
	sink  atomic.Pointer[DiagnosticSink]
	index uint32
}

func (*DiagnosticSink) String() string        { return "DiagnosticSink" }
func (*DiagnosticSink) GoString() string      { return "DiagnosticSink" }
func (*DiagnosticOperation) String() string   { return "DiagnosticOperation" }
func (*DiagnosticOperation) GoString() string { return "DiagnosticOperation" }

func DiagnosticSinkCharge(c DiagnosticSinkConfig) (resourcev4.Vector, error) {
	p, err := diagnosticPolicy(c)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge := resourcev4.Vector{
		resourcev4.SDKBytes:  uint64(unsafe.Sizeof(DiagnosticSink{})) + diagnosticMaxIDs*16 + uint64(p.operations)*(uint64(unsafe.Sizeof(diagnosticOperationSlot{}))+uint64(unsafe.Sizeof(DiagnosticOperation{}))) + uint64(p.queue)*uint64(unsafe.Sizeof(diagnosticQueuedEvent{})),
		resourcev4.Items:     1 + uint64(p.operations) + uint64(p.queue) + diagnosticRunning + diagnosticReady,
		resourcev4.Tasks:     1,
		resourcev4.WorkSlots: 1,
		resourcev4.Timers:    1,
	}
	charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytesPerTask})
}

func NewDiagnosticSink(c DiagnosticSinkConfig, executor *ApplicationExecutor, reservation resourcev4.Reference, callback func(context.Context, diagnosticv4.Event)) (*DiagnosticSink, error) {
	return newDiagnosticSink(c, executor, reservation, callback, time.Now, diagnosticSample)
}

func newDiagnosticSink(c DiagnosticSinkConfig, executor *ApplicationExecutor, reservation resourcev4.Reference, callback func(context.Context, diagnosticv4.Event), now func() time.Time, sample func(uint16) bool) (*DiagnosticSink, error) {
	charge, err := DiagnosticSinkCharge(c)
	if err != nil || callback == nil || now == nil || sample == nil {
		return nil, cryptov4.ErrConfiguration
	}
	closing, err := executor.diagnosticService(reservation)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p, _ := diagnosticPolicy(c)
	s := &DiagnosticSink{policy: p, operations: make([]diagnosticOperationSlot, p.operations), queue: make([]diagnosticQueuedEvent, p.queue), wake: make(chan struct{}, 1), done: make(chan struct{}), executor: executor, executorClosing: closing, callback: callback, reservation: owned, now: now, sample: sample, bucket: utcDiagnosticBucket(now()), generation: 1}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.ids = make([][16]byte, diagnosticMaxIDs)
	fillDiagnosticIDs(s.ids)
	go s.run()
	return s, nil
}

func utcDiagnosticBucket(now time.Time) int64 {
	seconds := now.UTC().Unix()
	bucket := seconds / int64(diagnosticBucket/time.Second)
	if seconds < 0 && seconds%int64(diagnosticBucket/time.Second) != 0 {
		bucket--
	}
	return bucket
}

func fillDiagnosticIDs(ids [][16]byte) {
	for i := range ids {
		rand.Read(ids[i][:])
	}
}

// One independent CSPRNG draw runs only on the admitted SDK pump. Rounding the
// threshold down makes the probability no greater than the configured rate;
// there is no rejection loop or application-supplied entropy provider.
func diagnosticSample(basisPoints uint16) bool {
	if basisPoints == 0 {
		return false
	}
	var bytes [8]byte
	rand.Read(bytes[:])
	return binary.BigEndian.Uint64(bytes[:]) < (math.MaxUint64/10000)*uint64(basisPoints)
}

func (s *DiagnosticSink) wakePump() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *DiagnosticSink) drop() {
	s.counters.Observe(diagnosticv4.MetricDiagnosticDrop, diagnosticv4.Fields{Code: diagnosticv4.CodeDiagnosticDropped})
}

// Begin is best effort and never waits for a diagnostic lock. Nil is a disabled
// observation, not failure of the connection/application operation itself.
func (s *DiagnosticSink) Begin() *DiagnosticOperation {
	if s == nil {
		return nil
	}
	if !s.mu.TryLock() {
		s.drop()
		return nil
	}
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	now := s.now()
	if s.bucket != utcDiagnosticBucket(now) {
		s.wakePump()
		s.drop()
		return nil
	}
	if s.nextID == diagnosticMaxIDs {
		s.drop()
		return nil
	}
	for i := range s.operations {
		slot := &s.operations[i]
		if slot.handle != nil {
			continue
		}
		h := &DiagnosticOperation{index: uint32(i)}
		h.sink.Store(s)
		*slot = diagnosticOperationSlot{handle: h, id: s.ids[s.nextID]}
		clear(s.ids[s.nextID][:])
		s.nextID++
		return h
	}
	s.drop()
	return nil
}

func (o *DiagnosticOperation) Emit(fields diagnosticv4.Fields) bool {
	if o == nil {
		return false
	}
	s := o.sink.Load()
	if s == nil {
		return false
	}
	if !s.mu.TryLock() {
		s.drop()
		return false
	}
	defer s.mu.Unlock()
	if s.closed || o.sink.Load() != s || s.operations[o.index].handle != o {
		return false
	}
	now := s.now()
	if s.bucket != utcDiagnosticBucket(now) {
		s.wakePump()
		s.drop()
		return false
	}
	if s.policy.sample == 0 {
		return false
	}
	if s.queued == s.policy.queue || s.events == diagnosticMaxEvents {
		s.drop()
		return false
	}
	event := diagnosticv4.NewEventAt(fields, s.operations[o.index].id, now)
	var encoded [diagnosticv4.MaxEncodedEvent]byte
	n := len(event.AppendJSON(encoded[:0]))
	if n > diagnosticv4.MaxEncodedEvent || uint64(s.queueBytes)+uint64(n) > diagnosticMaxQueueBytes {
		s.drop()
		return false
	}
	s.queue[(s.first+s.queued)%s.policy.queue] = diagnosticQueuedEvent{event: event, length: uint16(n)}
	s.queued++
	s.queueBytes += uint32(n)
	s.wakePump()
	return true
}

func (o *DiagnosticOperation) Close() {
	if o == nil {
		return
	}
	s := o.sink.Swap(nil)
	if s == nil {
		return
	}
	// Retirement is bounded SDK bookkeeping; Emit/Begin never wait for it.
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.operations) > int(o.index) && s.operations[o.index].handle == o {
		s.operations[o.index] = diagnosticOperationSlot{}
	}
}

func (s *DiagnosticSink) discardQueueLocked() {
	s.counters.Add(diagnosticv4.MetricDiagnosticDrop, diagnosticv4.Fields{Code: diagnosticv4.CodeDiagnosticDropped}, uint64(s.queued))
	clear(s.queue)
	s.first, s.queued, s.queueBytes = 0, 0, 0
}

func (s *DiagnosticSink) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	s.cancel()
	s.discardQueueLocked()
	clear(s.ids[:])
	for i := range s.operations {
		if h := s.operations[i].handle; h != nil {
			h.sink.Store(nil)
		}
		s.operations[i] = diagnosticOperationSlot{}
	}
	for i := range s.deliveries {
		d := &s.deliveries[i]
		if d.pending {
			s.drop()
		}
		d.pending = false
		d.event = diagnosticv4.Event{}
		if d.task != nil {
			d.task.cancel(context.Canceled)
		}
	}
	s.wakePump()
}

// Close returns an immediate, honest snapshot. Cancellation never refunds a
// running callback or claims that its application defers have returned.
func (s *DiagnosticSink) Close() protocolv4.V4CleanupStatus {
	s.mu.Lock()
	s.closeLocked()
	s.mu.Unlock()
	return s.CleanupStatus()
}

func (s *DiagnosticSink) CleanupStatus() protocolv4.V4CleanupStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if s.cleaned {
		status.Status, status.CoreCleanup = protocolv4.V4CleanupStateComplete, protocolv4.V4CoreCleanupComplete
		return status
	}
	if s.closed {
		status.Status = protocolv4.V4CleanupStateCleanupIncomplete
	}
	for i := range s.deliveries {
		if s.deliveries[i].task != nil {
			status.PendingCallbacks++
		}
	}
	return status
}

func (s *DiagnosticSink) WaitCleanup(ctx context.Context) (protocolv4.V4CleanupStatus, error) {
	if ctx == nil {
		return s.CleanupStatus(), cryptov4.ErrConfiguration
	}
	select {
	case <-s.done:
		return s.CleanupStatus(), nil
	case <-ctx.Done():
		status := s.CleanupStatus()
		if status.Status == protocolv4.V4CleanupStateComplete {
			return status, nil
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			s.counters.Observe(diagnosticv4.MetricCleanupTimeout, diagnosticv4.Fields{Code: diagnosticv4.CodeCleanupIncomplete})
		}
		status.Status = protocolv4.V4CleanupStateCleanupIncomplete
		return status, ErrDiagnosticCleanupIncomplete
	}
}

func (s *DiagnosticSink) Done() <-chan struct{} { return s.done }

// Counter snapshots contain neither IDs nor access-controlled audit facts.
func (s *DiagnosticSink) Counters(metric diagnosticv4.Metric) diagnosticv4.Counts {
	return s.counters.Snapshot(metric)
}
