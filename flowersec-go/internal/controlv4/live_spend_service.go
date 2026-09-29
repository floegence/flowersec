package controlv4

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// LiveSpendServiceConfig fixes one independently authenticated control service's
// capacity. Multiple instances must receive finite shares of the deployment's
// real aggregate limit. Constructing another instance does not restore a
// previous instance's admission, rate budget, or original activation rights.
type LiveSpendServiceConfig struct {
	Store             *ledgerv4.SQLiteStore
	Clock             *timev4.Clock
	MaxRecordBytes    uint32
	RequestsPerMinute uint16
	Burst             uint16
	WorkMS            uint64
	RuntimeBytes      uint64
	Tunnel            bool
}

// LiveSpendService owns one physical read and response position, with no queue
// or automatic retry. A cancelled provider/writer retains that position and
// its original buffers until it actually returns. Receipt reads and original
// client material reads share the same aggregate rate and resource boundary.
// This service never creates an authority invocation or dispatches policy.
type LiveSpendService struct {
	mu                  sync.Mutex
	config              LiveSpendServiceConfig
	reservation, shared resourcev4.Reference
	storeReference      resourcev4.Reference
	workspace           *resourcev4.ProtectedReservation
	codec               *protocolv4.SpendReceiptCodec
	origin              timev4.Mark
	creditedMS          uint64
	credit              uint64
	reader              *ledgerv4.SQLiteLiveSpendRead
	cancel              context.CancelFunc
	done                chan struct{}
	terminal            error
	busy, closed        bool
	cleaned             bool
}

// LiveSpendServiceCharges returns the fixed service and reusable read budgets.
// Both must already exist in the same original Environment before construction.
func LiveSpendServiceCharges(c LiveSpendServiceConfig) (service, read resourcev4.Vector, err error) {
	if c.Store == nil || c.Clock == nil || c.RequestsPerMinute == 0 || c.RequestsPerMinute > 600 || c.Burst == 0 || c.Burst > c.RequestsPerMinute || c.WorkMS == 0 || c.WorkMS > 2000 || c.RuntimeBytes == 0 {
		return service, read, resourcev4.ErrConfiguration
	}
	read, err = ledgerv4.SQLiteLiveSpendReadCharge(c.MaxRecordBytes, c.RuntimeBytes, c.Tunnel)
	if err != nil {
		return service, read, err
	}
	read, err = resourcev4.ProtectedCharge(read)
	if err != nil {
		return service, read, err
	}
	codec, err := protocolv4.SpendReceiptCodecBackingBytes()
	if err != nil {
		return service, read, err
	}
	service, err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(LiveSpendService{})) + controlCallContextBytes + uint64(unsafe.Sizeof(timev4.Window{})) + codec, resourcev4.Items: 1, resourcev4.Tasks: 2, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	return
}

func NewLiveSpendService(c LiveSpendServiceConfig, reservation, readReservation, dependencies resourcev4.Reference) (*LiveSpendService, error) {
	service, _, err := LiveSpendServiceCharges(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(readReservation); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	storeReference, limit, err := c.Store.LiveSpendReadReference(dependencies)
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			storeReference.Release()
		}
	}()
	if limit != c.MaxRecordBytes {
		return nil, resourcev4.ErrConfiguration
	}
	origin, err := c.Clock.Monotonic()
	if err != nil {
		return nil, err
	}
	if _, err = timev4.NewWindowAt(c.Clock, origin, c.WorkMS); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(service)
	if err != nil {
		shared.Release()
		return nil, err
	}
	codec, err := protocolv4.NewSpendReceiptCodec()
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	minimum, _ := ledgerv4.SQLiteLiveSpendReadCharge(c.MaxRecordBytes, c.RuntimeBytes, c.Tunnel)
	workspace, err := resourcev4.NewProtectedReservation(readReservation, minimum)
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	adopted = true
	return &LiveSpendService{config: c, reservation: owned, shared: shared, storeReference: storeReference, workspace: workspace, codec: codec, origin: origin, credit: uint64(c.Burst) * 60000, done: make(chan struct{})}, nil
}

func (s *LiveSpendService) checkLocked() error {
	if s.closed {
		return resourcev4.ErrClosed
	}
	if s.terminal != nil {
		return s.terminal
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	if err := s.storeReference.Check(); err != nil {
		return err
	}
	return s.shared.Check()
}

func (s *LiveSpendService) takeRateLocked(now timev4.Mark, sampleErr error) error {
	if sampleErr != nil || !now.SameEra(s.origin) || now.Milliseconds < s.origin.Milliseconds {
		s.terminal = timev4.ErrContinuity
		return s.terminal
	}
	lower, _, err := s.config.Clock.Profile().Rate.Elapsed(now.Milliseconds - s.origin.Milliseconds)
	if err != nil {
		s.terminal = err
		return err
	}
	if lower < s.creditedMS {
		s.terminal = timev4.ErrContinuity
		return s.terminal
	}
	elapsed := lower - s.creditedMS
	capacity := uint64(s.config.Burst) * 60000
	// Clamp before multiplication; every operand is independently bounded.
	if elapsed >= 60000 {
		s.credit = capacity
	} else {
		s.credit = min(capacity, s.credit+uint64(s.config.RequestsPerMinute)*elapsed)
	}
	s.creditedMS = lower
	if s.credit < 60000 {
		return resourcev4.ErrCapacity
	}
	s.credit -= 60000
	return nil
}

// withRead owns setup, the exact reader and the entire publication callback.
// No user context, clock or access method runs before this finite position is
// claimed and its unconditional cleanup is installed.
func (s *LiveSpendService) withRead(ctx context.Context, access ledgerv4.LiveSpendReadAccess, deadline *timev4.Deadline, use func(*ledgerv4.SQLiteLiveSpendRead, *controlCallContext, *timev4.Window) error) (err error) {
	if s == nil || ctx == nil || access == nil || use == nil {
		return resourcev4.ErrConfiguration
	}
	if !s.mu.TryLock() {
		return resourcev4.ErrCapacity
	}
	if err = s.checkLocked(); err == nil && s.busy {
		err = resourcev4.ErrCapacity
	}
	if err == nil && !deadline.BelongsTo(s.config.Clock) {
		err = resourcev4.ErrOwner
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	ref, err := s.workspace.Checkout()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	c := s.config
	call := newControlCallContext(time.Duration(c.WorkMS) * time.Millisecond)
	s.busy, s.cancel = true, call.stopCall
	s.mu.Unlock()
	var reader *ledgerv4.SQLiteLiveSpendRead
	var window *timev4.Window
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err = ErrControlTaskExit
			call.cancel(err)
		}
		call.finish()
		ref.Release()
		if window != nil {
			window.Cancel()
		}
		// Closing the reader cannot refund a position still owned by a real
		// reader tail. finish preserves that reader and its original charge.
		if cleanup := s.finish(reader, call); err == nil {
			err = cleanup
		}
	}()
	err = func() error {
		if err := call.start(ctx); err != nil {
			return err
		}
		now, sampleErr := c.Clock.Monotonic()
		s.mu.Lock()
		err := s.checkLocked()
		if err == nil {
			err = call.cause()
		}
		if err == nil {
			err = s.takeRateLocked(now, sampleErr)
		}
		s.mu.Unlock()
		if err != nil {
			return err
		}
		window, err = timev4.NewWindowAt(c.Clock, now, c.WorkMS)
		if err != nil {
			return err
		}
		reader, err = ledgerv4.NewSQLiteLiveSpendRead(call, c.Store, access, c.Clock, deadline, c.RuntimeBytes, ref, s.reservation, c.Tunnel)
		s.mu.Lock()
		s.reader = reader
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if err = s.check(call, window); err != nil {
			return err
		}
		return use(reader, call, window)
	}()
	returned = true
	return err
}

func (s *LiveSpendService) check(call *controlCallContext, window *timev4.Window) error {
	if err := window.Check(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLocked(); err != nil {
		return err
	}
	return call.cause()
}

// QuerySpendReceipt reads facts only. Recovery and raw material are deliberately
// absent from the public query surface. A missing row is an unavailable history
// observation, never permission to use the lease again.
func (s *LiveSpendService) QuerySpendReceipt(ctx context.Context, access ledgerv4.LiveSpendReadAccess, deadline *timev4.Deadline) (receipt ledgerv4.SpendReceipt, err error) {
	err = s.withRead(ctx, access, deadline, func(reader *ledgerv4.SQLiteLiveSpendRead, call *controlCallContext, window *timev4.Window) error {
		var err error
		receipt, err = reader.Receipt()
		if err == nil {
			err = reader.CheckReceiptPublication()
		}
		if err == nil {
			err = s.check(call, window)
		}
		return err
	})
	if err != nil {
		return ledgerv4.SpendReceipt{}, err
	}
	return receipt, nil
}

// QuerySpendReceiptBytes writes only the shared canonical receipt map. The
// authenticated application/HTTPS response owner supplies request binding and
// any required response signature; these bytes alone are not a control reply.
func (s *LiveSpendService) QuerySpendReceiptBytes(ctx context.Context, access ledgerv4.LiveSpendReadAccess, deadline *timev4.Deadline, dst []byte) (n int, err error) {
	if len(dst) < 61 {
		return 0, resourcev4.ErrConfiguration
	}
	returned := false
	defer func() {
		if !returned || err != nil {
			clear(dst[:61])
			n = 0
		}
	}()
	err = s.withRead(ctx, access, deadline, func(reader *ledgerv4.SQLiteLiveSpendRead, call *controlCallContext, window *timev4.Window) error {
		r, err := reader.Receipt()
		if err == nil {
			n, err = s.codec.Encode(dst[:61], r)
		}
		if err == nil {
			err = reader.CheckReceiptPublication()
		}
		if err == nil {
			err = s.check(call, window)
		}
		return err
	})
	returned = true
	return n, err
}

// DeliverOriginalClientMaterial is internal to the authenticated original
// ControlCall adapter. attemptNo is only its finite physical send number; it is
// not a lease key, a durable counter, or evidence of remote Activate ownership.
// The callback must finish its original bounded response handoff before return.
func (s *LiveSpendService) DeliverOriginalClientMaterial(ctx context.Context, access ledgerv4.LiveSpendReadAccess, deadline *timev4.Deadline, attemptNo uint8, publish func(context.Context, []byte) error) error {
	if attemptNo < 1 || attemptNo > 3 || publish == nil {
		return resourcev4.ErrConfiguration
	}
	return s.withRead(ctx, access, deadline, func(reader *ledgerv4.SQLiteLiveSpendRead, call *controlCallContext, window *timev4.Window) error {
		err := reader.DeliverClientMaterial(func(ctx context.Context, bytes []byte) error {
			if err := s.check(call, window); err != nil {
				return err
			}
			return publish(ctx, bytes)
		})
		if err == nil {
			err = s.check(call, window)
		}
		return err
	})
}

func (s *LiveSpendService) DeliverOriginalClientTunnelMaterial(ctx context.Context, access ledgerv4.LiveTunnelSpendReadAccess, deadline *timev4.Deadline, attemptNo uint8, publish func(context.Context, [2][]byte) error) error {
	if s == nil || !s.config.Tunnel || attemptNo < 1 || attemptNo > 3 || publish == nil {
		return resourcev4.ErrConfiguration
	}
	return s.withRead(ctx, access, deadline, func(reader *ledgerv4.SQLiteLiveSpendRead, call *controlCallContext, window *timev4.Window) error {
		err := reader.DeliverClientTunnelMaterial(func(ctx context.Context, material [2][]byte) error {
			if err := s.check(call, window); err != nil {
				return err
			}
			return publish(ctx, material)
		})
		if err == nil {
			err = s.check(call, window)
		}
		return err
	})
}

// CaptureOriginalRelayLeg is a trusted issuer registration operation. It uses
// the same bounded read admission, but returns only detached public provenance.
// The client receipt/query surface does not expose this operation.
func (s *LiveSpendService) CaptureOriginalRelayLeg(ctx context.Context, access ledgerv4.LiveTunnelSpendReadAccess, deadline *timev4.Deadline, expected ledgerv4.SQLiteIdentity, projection *protocolv4.RelayParentProjection, role protocolv4.Direction, reservation, dependencies resourcev4.Reference) (receipt *ledgerv4.SQLiteCommittedRelayLeg, err error) {
	if s == nil || !s.config.Tunnel {
		return nil, resourcev4.ErrConfiguration
	}
	defer func() {
		if err != nil && receipt != nil {
			receipt.Close()
			receipt = nil
		}
	}()
	err = s.withRead(ctx, access, deadline, func(reader *ledgerv4.SQLiteLiveSpendRead, call *controlCallContext, window *timev4.Window) error {
		var err error
		receipt, err = reader.CaptureRelayLeg(expected, projection, role, reservation, dependencies)
		if err == nil {
			err = s.check(call, window)
		}
		return err
	})
	return receipt, err
}

func (s *LiveSpendService) finish(reader *ledgerv4.SQLiteLiveSpendRead, call *controlCallContext) error {
	var cleanup error
	if reader != nil {
		cleanup = reader.Cleanup()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := call.cause()
	if err == nil {
		err = s.checkLocked()
	}
	call.stopCall()
	s.cancel = nil
	if cleanup != nil {
		// The physical owner remains reachable and charged if cleanup cannot
		// prove that its actual reader has left.
		s.reader, s.terminal = reader, cleanup
		return cleanup
	}
	s.reader, s.busy = nil, false
	s.cleanupLocked()
	return err
}

func (s *LiveSpendService) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	if s.reader != nil {
		s.reader.Close()
	}
	s.workspace.Close()
	s.cleanupLocked()
}

func (s *LiveSpendService) cleanupLocked() {
	if !s.closed || s.busy || s.cleaned || !s.workspace.CleanupComplete() {
		return
	}
	s.reservation.Release()
	s.shared.Release()
	s.storeReference.Release()
	s.reservation, s.shared, s.storeReference = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	s.config.Store = nil
	s.codec = nil
	s.cleaned = true
	close(s.done)
}

func (s *LiveSpendService) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SpendQueryFailure is a finite application projection. Provider error text and
// internal storage identities do not cross the public control service boundary.
type SpendQueryFailure string

func (e SpendQueryFailure) Error() string { return "flowersec: spend query " + string(e) }

func PublicSpendQueryFailure(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ledgerv4.ErrDenied):
		return SpendQueryFailure("permission_denied")
	case errors.Is(err, ledgerv4.ErrConflict):
		return SpendQueryFailure("operation_conflict")
	case errors.Is(err, ledgerv4.ErrSpendNotObserved):
		return SpendQueryFailure("history_unknown")
	case errors.Is(err, resourcev4.ErrCapacity), errors.Is(err, ledgerv4.ErrCapacity):
		return SpendQueryFailure("resource_exhausted")
	case errors.Is(err, context.Canceled):
		return SpendQueryFailure("cancelled")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, timev4.ErrExpired):
		return SpendQueryFailure("deadline_exceeded")
	default:
		return SpendQueryFailure("unavailable")
	}
}
