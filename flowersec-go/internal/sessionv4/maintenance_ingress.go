package sessionv4

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// MaintenanceIngressPolicy bounds actual native assembly. Burst frames each
// contain at most the signed max_frame plus one envelope, deriving a finite
// byte/work burst as well. Idle waiting for the first byte uses Session idle;
// the partial-frame window starts once actual input begins.
type MaintenanceIngressPolicy struct {
	FrameTimeoutMS, RefillMS uint64
	Burst                    uint32
}

// MaintenanceIngress owns one depth-one assembly in B_maintenance and a
// separately admitted full authentication receiver. Only the original trusted
// native association can use this path; a peer header never selects it.
type MaintenanceIngress struct {
	mu                                                sync.Mutex
	admission                                         *OpenAdmission
	carrier                                           *CarrierAssociation
	receiver                                          *RecordReceiver
	reservation                                       resourcev4.Reference
	policy                                            MaintenanceIngressPolicy
	storage                                           []byte
	length                                            int
	ready, active, closed, cleaned, watching, started bool
	tokens                                            uint32
	refill                                            *timev4.Delay
	window                                            *timev4.Window
	cause                                             error
	wake, stop, done                                  chan struct{}
}

func MaintenanceIngressCharge(maxFrame uint32) (resourcev4.Vector, error) {
	if maxFrame == 0 || maxFrame > protocolv4.MaxPayloadLength {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	bytes := uint64(protocolv4.EnvelopePrefixSize) + uint64(maxFrame) + uint64(unsafe.Sizeof(MaintenanceIngress{})) + uint64(unsafe.Sizeof(timev4.Window{})) + uint64(unsafe.Sizeof(timev4.Delay{}))
	return resourcev4.Vector{resourcev4.Timers: 1, resourcev4.SDKBytes: bytes, resourcev4.Items: 3, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2}, nil
}

func NewMaintenanceIngress(a *OpenAdmission, carrier *CarrierAssociation, policy MaintenanceIngressPolicy, nodes int, decode protocolv4.DecodeContext, reservation, receiverReservation resourcev4.Reference) (*MaintenanceIngress, error) {
	if a == nil || carrier == nil || policy.FrameTimeoutMS == 0 || policy.RefillMS == 0 || policy.Burst == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	if err := reservation.CheckSameEnvironment(receiverReservation); err != nil {
		return nil, err
	}
	if _, err := timev4.NewWindow(a.engine.Clock(), policy.FrameTimeoutMS); err != nil {
		return nil, err
	}
	if _, err := timev4.NewDelay(a.engine.Clock(), policy.RefillMS); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.sharedIngress != nil || a.maintenanceIngress != nil || a.active != 0 || a.pending != 0 || a.positiveProofs != 0 || a.rejectionProofs != 0 || a.bootstrap != nil {
		return nil, cryptov4.ErrConfiguration
	}
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	if carrier.bound != nil {
		return nil, ErrOpenAssociation
	}
	charge, err := MaintenanceIngressCharge(a.engine.MaxFrame())
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	receiver, err := NewRecordReceiver(a.engine, 1-a.direction, a.engine.MaxFrame(), nodes, decode, receiverReservation)
	if err != nil {
		owned.Release()
		return nil, err
	}
	p := &MaintenanceIngress{admission: a, carrier: carrier, receiver: receiver, reservation: owned, policy: policy, storage: make([]byte, protocolv4.EnvelopePrefixSize+int(a.engine.MaxFrame())), tokens: policy.Burst, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	carrier.bound, carrier.scope = a, 0
	a.maintenanceIngress = p
	return p, nil
}

func (p *MaintenanceIngress) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *MaintenanceIngress) checkLocked() error {
	if p.cause != nil {
		return p.cause
	}
	if p.closed {
		return cryptov4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if p.window != nil {
		if err := p.window.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (p *MaintenanceIngress) consumeLocked() error {
	if p.refill != nil {
		if err := p.refill.Check(); err == nil {
			p.tokens = min(p.tokens+1, p.policy.Burst)
			p.refill = nil
		} else if !errors.Is(err, timev4.ErrPending) {
			return err
		}
	}
	if p.tokens == 0 {
		return ErrMaintenanceRate
	}
	if p.refill == nil {
		var err error
		p.refill, err = timev4.NewDelay(p.admission.engine.Clock(), p.policy.RefillMS)
		if err != nil {
			return err
		}
	}
	p.tokens--
	return nil
}

type maintenanceAssemblyReader struct {
	owner  *MaintenanceIngress
	ctx    context.Context
	reader io.Reader
}

func (r maintenanceAssemblyReader) Read(dst []byte) (int, error) {
	p := r.owner
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	p.mu.Lock()
	err := p.checkLocked()
	p.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if err := p.admission.engine.CheckApplicationAuthorization(); err != nil {
		return 0, err
	}
	dst = dst[:min(len(dst), nativeDataReadQuantum)]
	n, err := r.reader.Read(dst)
	if n < 0 || n > len(dst) {
		return 0, io.ErrShortBuffer
	}
	if n == 0 && err == nil && len(dst) != 0 {
		return 0, io.ErrNoProgress
	}
	p.mu.Lock()
	if n != 0 && p.window == nil && !p.closed {
		var clockErr error
		p.window, clockErr = timev4.NewWindow(p.admission.engine.Clock(), p.policy.FrameTimeoutMS)
		if clockErr != nil {
			err = clockErr
		}
		p.notify()
	}
	if e := p.checkLocked(); e != nil {
		err = e
	}
	p.mu.Unlock()
	return n, err
}

// Read runs in the original native reader task. It never acquires its complete
// decoder/crypto position until every byte of one candidate has been read.
// Before-attempt crypto contention retains that same candidate for retry.
// The caller dispatches and releases the returned record before its next Read.
func (p *MaintenanceIngress) Read(ctx context.Context, carrier *CarrierAssociation, reader io.Reader) (record *ReceivedRecord, err error) {
	if ctx == nil || reader == nil || carrier != p.carrier {
		return nil, ErrOpenAssociation
	}
	p.mu.Lock()
	if err = p.checkLocked(); err != nil {
		p.mu.Unlock()
		return nil, err
	}
	p.receiver.mu.Lock()
	occupied := p.receiver.active
	p.receiver.mu.Unlock()
	if p.active || occupied {
		p.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	p.active = true
	ready := p.ready
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if err == nil {
			err = ctx.Err()
			if err == nil {
				err = p.checkLocked()
			}
		}
		if err != nil && !errors.Is(err, cryptov4.ErrCapacity) {
			if p.cause == nil {
				p.cause = err
			}
		}
		failed := p.cause != nil
		if failed {
			err = p.cause
		}
		p.active = false
		if err == nil || failed {
			clear(p.storage)
			p.ready, p.length, p.window = false, 0, nil
		}
		p.cleanupLocked()
		p.mu.Unlock()
		if failed {
			if record != nil {
				record.Release()
				record = nil
			}
			p.admission.closeWithCause(err)
		}
	}()
	if !ready {
		input := maintenanceAssemblyReader{p, ctx, reader}
		prefix, e := ReadRecordPrefix(input, p.admission.engine.MaxFrame())
		if e != nil {
			return nil, e
		}
		// Frame family is checked on the designated maintenance association
		// before reading a body. This grants no scope/key/authentication fact.
		if e := protocolv4.ValidateRecordScope(protocolv4.FrameType(prefix.bytes[4]), 0); e != nil {
			return nil, e
		}
		p.mu.Lock()
		err = p.consumeLocked()
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
		wire, e := prefix.ReadBody(input, p.storage)
		if e != nil {
			return nil, e
		}
		p.mu.Lock()
		p.length, p.ready = len(wire), true
		err = p.checkLocked()
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return p.receiver.receiveMaintenance(ctx, p.storage[:p.length])
}

// Watch is the pre-admitted lifetime task, independent of native Read. A stuck
// partial frame can expire while its original provider still owns the buffer.
// Session idle and root/authorization remain their own earlier bounds.
func (p *MaintenanceIngress) Watch(ctx context.Context) (err error) {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.started || p.closed {
		p.mu.Unlock()
		return cryptov4.ErrClosed
	}
	p.started, p.watching = true, true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.cause == nil {
			p.cause = err
		}
		p.mu.Unlock()
		p.admission.closeWithCause(err)
		p.mu.Lock()
		p.watching = false
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		p.mu.Lock()
		err := p.checkLocked()
		var remaining uint64
		if err == nil && p.window != nil {
			remaining, err = p.window.RemainingMS()
		}
		p.mu.Unlock()
		if err != nil {
			return err
		}
		security, err := p.admission.engine.AuthorizationRemainingMS()
		if err != nil {
			return err
		}
		if remaining == 0 {
			remaining = security
		} else {
			remaining = min(remaining, security)
		}
		timer.Reset(idleTimerChunk(remaining))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.stop:
			return cryptov4.ErrClosed
		case <-p.admission.engine.Done():
			return cryptov4.ErrClosed
		case <-p.wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (p *MaintenanceIngress) Close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.stop)
	}
	p.cleanupLocked()
	p.mu.Unlock()
	p.receiver.Close()
}

func (p *MaintenanceIngress) cleanupLocked() {
	if p.closed && !p.cleaned && !p.active && !p.watching {
		clear(p.storage)
		p.storage, p.window, p.refill = nil, nil, nil
		p.cleaned = true
		close(p.done)
	}
}

func (p *MaintenanceIngress) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
	}
	return p.receiver.WaitCleanup(ctx)
}

func (p *MaintenanceIngress) retire() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cleaned {
		return cryptov4.ErrCapacity
	}
	if err := p.receiver.retire(); err != nil {
		return err
	}
	p.reservation.Release()
	return nil
}
