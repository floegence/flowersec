package sessionv4

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type nativeAuthSlot struct {
	assembly                                                       *NativeDataAssembly
	busy, capacityRetry, epochRetry, capacityBlocked, epochBlocked bool
}

// NativeAuthService implements the full-slot-only (n_small=0) ordinary input
// service. All legal DATA sizes share one bounded direction rotation. Each
// worker owns an original full receiver; partial reads and app consumers never
// hold it. Maintenance and unbound/shared carrier ingress remain separate.
type NativeAuthService struct {
	mu                                                   sync.Mutex
	admission                                            *OpenAdmission
	reservation                                          resourcev4.Reference
	slots                                                []nativeAuthSlot
	receivers                                            []*RecordReceiver
	workers                                              uint32
	cursor                                               int
	wake, stop, done                                     chan struct{}
	started, closed, closing, cleaned, coordinatorActive bool
	activeWorkers                                        uint32
}

func NativeAuthServiceCharge(streams, workers uint32) (resourcev4.Vector, error) {
	if streams == 0 || uint64(streams) > uint64(math.MaxInt) || workers == 0 || workers > 128 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	bytes := uint64(unsafe.Sizeof(NativeAuthService{})) + uint64(streams)*uint64(unsafe.Sizeof(nativeAuthSlot{})) + uint64(workers)*uint64(unsafe.Sizeof((*RecordReceiver)(nil)))
	return resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: uint64(streams) + 1, resourcev4.Tasks: uint64(workers) + 1, resourcev4.WorkSlots: uint64(workers) + 1}, nil
}

// Receiver backing is admitted separately in the same original Environment.
// Native reader tasks/H_DATA are charged by each original Stream preparation.
func NewNativeAuthService(a *OpenAdmission, nodes int, decode protocolv4.DecodeContext, reservation resourcev4.Reference, receivers []resourcev4.Reference) (_ *NativeAuthService, err error) {
	if a == nil || len(receivers) == 0 || len(receivers) > 128 {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.sharedIngress != nil || a.nativeAuth != nil || a.active != 0 || a.pending != 0 || a.positiveProofs != 0 || a.rejectionProofs != 0 || a.bootstrap != nil || len(receivers) > int(a.engine.OrdinaryWorkSlots()) {
		return nil, cryptov4.ErrConfiguration
	}
	for _, ref := range receivers {
		if err := reservation.CheckSameEnvironment(ref); err != nil {
			return nil, err
		}
	}
	charge, err := NativeAuthServiceCharge(a.limits.Active, uint32(len(receivers)))
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	s := &NativeAuthService{admission: a, reservation: owned, workers: uint32(len(receivers)), slots: make([]nativeAuthSlot, int(a.limits.Active)), receivers: make([]*RecordReceiver, len(receivers)), wake: make(chan struct{}, len(receivers)), stop: make(chan struct{}), done: make(chan struct{})}
	defer func() {
		if err != nil {
			for _, receiver := range s.receivers {
				if receiver != nil {
					receiver.Close()
					_ = receiver.retire()
				}
			}
			owned.Release()
		}
	}()
	for i, ref := range receivers {
		s.receivers[i], err = NewRecordReceiver(a.engine, 1-a.direction, a.engine.MaxFrame(), nodes, decode, ref)
		if err != nil {
			return nil, err
		}
	}
	a.nativeAuth = s
	return s, nil
}

func (s *NativeAuthService) notify() {
	for range s.workers {
		select {
		case s.wake <- struct{}{}:
		default:
			return
		}
	}
}

func (s *NativeAuthService) attach(x *NativeDataAssembly) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return cryptov4.ErrClosed
	}
	if err := s.reservation.CheckSameEnvironment(x.reservation); err != nil {
		return err
	}
	x.pool.mu.Lock()
	defer x.pool.mu.Unlock()
	if x.service != nil || x.phase != nativeDataPrepared || x.closed {
		return cryptov4.ErrConfiguration
	}
	for i := range s.slots {
		if s.slots[i].assembly == nil {
			s.slots[i].assembly, x.service = x, s
			return nil
		}
	}
	return cryptov4.ErrCapacity
}

func (s *NativeAuthService) pick() (int, *NativeDataAssembly) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return -1, nil
	}
	for scanned := range len(s.slots) {
		i := (s.cursor + scanned) % len(s.slots)
		slot := &s.slots[i]
		x := slot.assembly
		if x == nil || slot.busy || slot.capacityBlocked || slot.epochBlocked {
			continue
		}
		x.pool.mu.Lock()
		ready := !x.closed && x.phase == nativeDataReady
		x.pool.mu.Unlock()
		if ready {
			slot.busy, slot.capacityRetry, slot.epochRetry = true, false, false
			s.cursor = (i + 1) % len(s.slots)
			return i, x
		}
	}
	return -1, nil
}

func (s *NativeAuthService) returned(index int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := &s.slots[index]
	slot.busy = false
	slot.capacityBlocked = errors.Is(err, cryptov4.ErrCapacity) && !slot.capacityRetry
	slot.epochBlocked = errors.Is(err, cryptov4.ErrInputPending) && !slot.epochRetry
	if slot.capacityRetry || slot.epochRetry {
		s.notify()
	}
	s.cleanupLocked()
}

// A wake that races an active no-attempt refusal survives its return. It never
// creates a replacement candidate or resets the existing rotation cursor.
func (s *NativeAuthService) available(epoch bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.slots {
		slot := &s.slots[i]
		if epoch {
			slot.epochBlocked = false
			slot.epochRetry = slot.busy
		} else {
			slot.capacityBlocked = false
			slot.capacityRetry = slot.busy
		}
	}
	s.notify()
}

func (s *NativeAuthService) worker(ctx context.Context, receiver *RecordReceiver) {
	defer func() {
		s.mu.Lock()
		s.activeWorkers--
		s.cleanupLocked()
		s.mu.Unlock()
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		index, x := s.pick()
		if x != nil {
			err := x.authenticate(ctx, receiver, s)
			if err != nil && !errors.Is(err, cryptov4.ErrCapacity) && !errors.Is(err, cryptov4.ErrInputPending) {
				x.pool.mu.Lock()
				x.failLocked(err)
				x.pool.mu.Unlock()
				x.Close()
			}
			s.returned(index, err)
			s.admission.Collect()
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-s.wake:
		}
	}
}

func (s *NativeAuthService) Run(ctx context.Context) (err error) {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if err := s.reservation.Check(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.started, s.coordinatorActive = true, true
	for _, receiver := range s.receivers {
		s.activeWorkers++
		go s.worker(ctx, receiver)
	}
	s.mu.Unlock()
	defer func() {
		s.admission.closeWithCause(err)
		s.mu.Lock()
		s.coordinatorActive = false
		s.cleanupLocked()
		s.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stop:
			return cryptov4.ErrClosed
		case <-s.admission.engine.Done():
			return cryptov4.ErrClosed
		case <-s.admission.engine.ReceiveWake():
			s.available(false)
		}
	}
}

func (s *NativeAuthService) detach(x *NativeDataAssembly) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x.pool.mu.Lock()
	defer x.pool.mu.Unlock()
	if !x.cleaned {
		return cryptov4.ErrCapacity
	}
	for i := range s.slots {
		slot := &s.slots[i]
		if slot.assembly == x {
			if slot.busy {
				return cryptov4.ErrCapacity
			}
			*slot = nativeAuthSlot{}
			x.service = nil
			return nil
		}
	}
	return nil
}

func (s *NativeAuthService) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed, s.closing = true, true
	close(s.stop)
	s.mu.Unlock()
	for i := range s.slots {
		s.mu.Lock()
		x := s.slots[i].assembly
		s.mu.Unlock()
		if x != nil {
			x.Close()
		}
	}
	for _, receiver := range s.receivers {
		receiver.Close()
	}
	s.mu.Lock()
	s.closing = false
	s.cleanupLocked()
	s.mu.Unlock()
}

func (s *NativeAuthService) cleanupLocked() {
	if !s.closed || s.closing || s.cleaned || s.coordinatorActive || s.activeWorkers != 0 {
		return
	}
	for i := range s.slots {
		if x := s.slots[i].assembly; x != nil {
			x.pool.mu.Lock()
			clean := x.cleaned
			x.pool.mu.Unlock()
			if !clean {
				return
			}
		}
	}
	s.cleaned = true
	close(s.done)
}

func (s *NativeAuthService) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *NativeAuthService) retire() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cleaned {
		return cryptov4.ErrCapacity
	}
	for _, receiver := range s.receivers {
		if err := receiver.retire(); err != nil {
			return err
		}
	}
	for i := range s.slots {
		if x := s.slots[i].assembly; x != nil {
			x.pool.mu.Lock()
			x.service = nil
			x.pool.mu.Unlock()
		}
	}
	s.slots, s.receivers = nil, nil
	s.reservation.Release()
	return nil
}

// ReadNativeData runs in the original pre-admitted native reader task. It has
// one outstanding Read/candidate and waits for that same candidate's service
// result before reading another prefix. It creates no goroutine per frame.
func (a *OpenAdmission) ReadNativeData(ctx context.Context, h OpenHandle, carrier *CarrierAssociation, reader io.Reader) (err error) {
	if ctx == nil || reader == nil {
		return cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	configured, closed := a.nativeAuth != nil, a.closed
	if configured && !closed {
		a.beginTailLocked()
		defer a.endTail()
	}
	a.mu.Unlock()
	if closed {
		return cryptov4.ErrClosed
	}
	if !configured {
		return cryptov4.ErrConfiguration
	}
	x, err := a.NativeDataAssembly(h, carrier)
	if err != nil {
		return err
	}
	x.pool.mu.Lock()
	if err := x.checkLocked(); err != nil {
		x.pool.mu.Unlock()
		return err
	}
	s := x.service
	if s == nil {
		x.pool.mu.Unlock()
		x.Close()
		return cryptov4.ErrConfiguration
	}
	x.readerActive = true
	x.pool.mu.Unlock()
	defer func() {
		x.Close()
		x.pool.mu.Lock()
		x.readerActive = false
		x.cleanupLocked()
		x.pool.mu.Unlock()
		s.mu.Lock()
		s.cleanupLocked()
		s.mu.Unlock()
		if err != nil {
			if errors.Is(err, cryptov4.ErrUsage) || a.engine.CheckApplicationAuthorization() != nil || s.reservation.Check() != nil {
				a.closeWithCause(err)
			} else {
				_ = a.cancelStream(h)
			}
		}
		a.Collect()
	}()
	for {
		x.pool.mu.Lock()
		terminal := x.flow != nil && x.flow.hasTerminal && x.flow.observed == x.flow.terminal
		x.pool.mu.Unlock()
		if terminal {
			return nil
		}
		if err := x.read(ctx, reader, s); err != nil {
			if err == errNativeDataTerminal {
				return nil
			}
			return err
		}
		if err := x.waitAuthenticated(ctx); err != nil {
			return err
		}
	}
}
