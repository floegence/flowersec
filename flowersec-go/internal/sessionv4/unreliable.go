package sessionv4

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var (
	ErrUnreliableUnavailable = errors.New("sessionv4: unreliable messages unavailable")
	ErrUnreliableTooLarge    = errors.New("sessionv4: unreliable message too large")
	ErrUnreliableExpiry      = errors.New("sessionv4: invalid unreliable expiry")
)

type UnreliableSendStatus string

const (
	UnreliableAccepted       UnreliableSendStatus = "accepted"
	UnreliableDroppedExpired UnreliableSendStatus = "dropped_expired"
	UnreliableDroppedBudget  UnreliableSendStatus = "dropped_budget"
	UnreliableDroppedCarrier UnreliableSendStatus = "dropped_carrier"
)

type datagramSendSlot struct {
	ctx                      context.Context
	deadline                 *timev4.Deadline
	result                   UnreliableSendStatus
	err                      error
	done                     chan struct{}
	size                     int
	active, waiter, complete bool
}

// UnreliableMessages retains one original native connection and Engine. Fixed
// send positions include queued, encrypting and provider-owned tails. No
// cancellation, dropped result or rekey retries a consumed message.
type UnreliableMessages struct {
	mu                                                    sync.Mutex
	admission                                             *OpenAdmission
	engine                                                *cryptov4.Engine
	connection                                            native.Connection
	reservation                                           resourcev4.Reference
	queue                                                 *cryptov4.DatagramQueue
	decoder                                               *protocolv4.Decoder
	input, sends                                          []byte
	slots                                                 []datagramSendSlot
	jobs                                                  chan int
	context                                               context.Context
	cancel                                                context.CancelFunc
	stop, cleanup                                         chan struct{}
	maximum, envelope                                     int
	active                                                int
	started, running, receiving, closed, cleaned, retired bool
}

func unreliableCharge(c SessionCoreConfig) (resourcev4.Vector, error) {
	if !c.Native || !c.Datagrams || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	envelope, maximum, pending, err := protocolv4.DatagramLimits(c.Session.Profile, carrier.MaxUnreliableWireBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	queue, err := cryptov4.DatagramQueueBackingBytes(pending, maximum)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	decoder, err := protocolv4.RecordDecoderBackingBytes(envelope, 32)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	bytes := uint64(unsafe.Sizeof(UnreliableMessages{})) + uint64(pending)*(uint64(unsafe.Sizeof(datagramSendSlot{}))+uint64(unsafe.Sizeof(timev4.Deadline{}))+uint64(maximum)+128) + uint64(envelope+maximum) + queue + decoder + uint64(unsafe.Sizeof(time.Timer{}))
	return (resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: uint64(2*pending + 8), resourcev4.Tasks: uint64(pending + 3), resourcev4.WorkSlots: uint64(pending + 3), resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func newUnreliableMessages(admission *OpenAdmission, connection native.Connection, c SessionCoreConfig, reservation resourcev4.Reference) (_ *UnreliableMessages, err error) {
	if admission == nil || admission.engine == nil || connection == nil || !admission.engine.DatagramSelected() {
		return nil, ErrUnreliableUnavailable
	}
	engine := admission.engine
	charge, err := unreliableCharge(c)
	if err != nil {
		return nil, err
	}
	if err = engine.CheckEnvironment(reservation); err != nil {
		return nil, err
	}
	if err = connection.CheckEnvironment(reservation); err != nil {
		return nil, err
	}
	envelope, maximum, pending, err := protocolv4.DatagramLimits(c.Session.Profile, connection.MaxDatagramBytes())
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			owned.Release()
		}
	}()
	d := &UnreliableMessages{admission: admission, engine: engine, connection: connection, reservation: owned, envelope: envelope, maximum: maximum,
		input: make([]byte, carrier.MaxUnreliableWireBytes), sends: make([]byte, maximum*pending), slots: make([]datagramSendSlot, pending), jobs: make(chan int, pending), stop: make(chan struct{}), cleanup: make(chan struct{})}
	d.decoder, err = protocolv4.NewRecordDecoder(envelope, 32)
	if err != nil {
		return nil, err
	}
	d.queue, err = engine.NewDatagramQueue(make([]byte, maximum*pending), pending, maximum)
	if err != nil {
		return nil, err
	}
	d.context, d.cancel = context.WithCancel(context.Background())
	return d, nil
}

func (d *UnreliableMessages) MaxMessageBytes() int {
	_, maximum, _, err := protocolv4.DatagramLimits(d.engine.SessionParameters().Profile, d.connection.MaxDatagramBytes())
	if err != nil {
		return 0
	}
	return min(d.maximum, maximum)
}

func (d *UnreliableMessages) expiry(expires time.Time) (uint64, error) {
	if expires.IsZero() || expires.UnixMilli() <= 0 {
		return 0, ErrUnreliableExpiry
	}
	now, err := d.engine.Clock().Sample()
	if err != nil {
		return 0, err
	}
	cap := uint64(expires.UnixMilli())
	if now.UpperMS >= cap {
		return 0, timev4.ErrExpired
	}
	return cap, nil
}

func (d *UnreliableMessages) Send(ctx context.Context, payload []byte, expires time.Time) (UnreliableSendStatus, error) {
	if ctx == nil {
		return "", cryptov4.ErrConfiguration
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return "", cryptov4.ErrClosed
	}
	// Expiry is evaluated before pending budget, using the original trusted clock.
	cap, err := d.expiry(expires)
	if errors.Is(err, timev4.ErrExpired) {
		d.mu.Unlock()
		return UnreliableDroppedExpired, nil
	}
	if err != nil {
		d.mu.Unlock()
		return "", err
	}
	if err = ctx.Err(); err != nil {
		d.mu.Unlock()
		return "", err
	}
	if len(payload) > d.maximum {
		d.mu.Unlock()
		return "", ErrUnreliableTooLarge
	}
	index := -1
	for i := range d.slots {
		if !d.slots[i].active {
			index = i
			break
		}
	}
	if index < 0 {
		d.mu.Unlock()
		return UnreliableDroppedBudget, nil
	}
	deadline, err := timev4.NewDeadline(d.engine.Clock(), cap)
	if err != nil {
		d.mu.Unlock()
		if errors.Is(err, timev4.ErrExpired) {
			return UnreliableDroppedExpired, nil
		}
		return "", err
	}
	s := &d.slots[index]
	*s = datagramSendSlot{ctx: ctx, deadline: deadline, done: make(chan struct{}), size: len(payload), active: true, waiter: true}
	copy(d.sends[index*d.maximum:(index+1)*d.maximum], payload)
	d.active++
	done := s.done
	d.jobs <- index
	d.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
	case <-d.stop:
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	status, resultErr := s.result, s.err
	if !s.complete {
		resultErr = ctx.Err()
		if resultErr == nil {
			resultErr = cryptov4.ErrClosed
		}
	}
	s.waiter = false
	d.releaseSlotLocked(index)
	d.finishLocked()
	return status, resultErr
}

func (d *UnreliableMessages) releaseSlotLocked(index int) {
	s := &d.slots[index]
	if s.complete && !s.waiter {
		clear(d.sends[index*d.maximum : (index+1)*d.maximum])
		*s = datagramSendSlot{}
		d.active--
	}
}

type datagramTicket struct {
	channel *UnreliableMessages
	slot    *datagramSendSlot
}

func (g datagramTicket) LockTicket() error {
	d := g.channel
	d.mu.Lock()
	err := g.checkLocked()
	if err != nil {
		d.mu.Unlock()
	}
	return err
}
func (g datagramTicket) checkLocked() error {
	if g.channel.closed {
		return cryptov4.ErrClosed
	}
	if err := g.slot.ctx.Err(); err != nil {
		return err
	}
	if !g.slot.waiter {
		return context.Canceled
	}
	return g.slot.deadline.Check()
}
func (g datagramTicket) UnlockTicket(bool) { g.channel.mu.Unlock() }

func (d *UnreliableMessages) publish(index int) (UnreliableSendStatus, error) {
	s := &d.slots[index]
	guard := datagramTicket{d, s}
	d.mu.Lock()
	err := guard.checkLocked()
	size := s.size
	d.mu.Unlock()
	if err != nil {
		return unreliableSendFailure(err)
	}
	payload := d.sends[index*d.maximum : index*d.maximum+size]
	fields := protocolv4.DatagramFields(protocolv4.RecordHeader{Epoch: ^uint32(0), Scope: protocolv4.DatagramScope(), Sequence: ^uint64(0)}, payload)
	n, err := protocolv4.MeasureMapByteString("DATAGRAM", fields[:], "data", size)
	if err != nil {
		return "", err
	}
	p, err := d.engine.SealBuildGuard(protocolv4.FrameDatagram, protocolv4.DatagramScope(), n, func(h protocolv4.RecordHeader, dst []byte) (int, error) {
		fields := protocolv4.DatagramFields(h, payload)
		out, err := protocolv4.EncodeMap(dst, "DATAGRAM", fields[:])
		return len(out), err
	}, nil, guard)
	if err != nil {
		return unreliableSendFailure(err)
	}
	defer p.Release()
	d.mu.Lock()
	err = guard.checkLocked()
	d.mu.Unlock()
	if err != nil {
		return unreliableSendFailure(err)
	}
	wire, err := p.Bytes()
	if err != nil {
		return unreliableSendFailure(err)
	}
	if len(wire) > d.connection.MaxDatagramBytes() {
		return UnreliableDroppedCarrier, nil
	}
	if err = d.connection.SendDatagram(wire); err != nil {
		return UnreliableDroppedCarrier, nil
	}
	_ = p.Published()
	return UnreliableAccepted, nil
}

func unreliableSendFailure(err error) (UnreliableSendStatus, error) {
	if errors.Is(err, timev4.ErrExpired) || errors.Is(err, cryptov4.ErrExpired) {
		return UnreliableDroppedExpired, nil
	}
	if errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, cryptov4.ErrTransition) || errors.Is(err, cryptov4.ErrEpoch) || errors.Is(err, cryptov4.ErrUsage) {
		return UnreliableDroppedBudget, nil
	}
	return "", err
}

func (d *UnreliableMessages) sender() {
	for {
		select {
		case <-d.stop:
			return
		case index := <-d.jobs:
			status, err := d.publish(index)
			d.mu.Lock()
			s := &d.slots[index]
			s.result, s.err, s.complete = status, err, true
			close(s.done)
			d.releaseSlotLocked(index)
			d.mu.Unlock()
		}
	}
}

func (d *UnreliableMessages) Run(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	d.mu.Lock()
	if d.closed || d.started {
		d.mu.Unlock()
		return cryptov4.ErrClosed
	}
	d.started, d.running = true, true
	d.mu.Unlock()
	sent := make(chan struct{})
	go func() { defer close(sent); d.sender() }()
	defer func() {
		d.Close()
		<-sent
		d.mu.Lock()
		for index := range d.slots {
			s := &d.slots[index]
			if s.active && !s.complete {
				s.complete, s.err = true, cryptov4.ErrClosed
				close(s.done)
				d.releaseSlotLocked(index)
			}
		}
		d.running = false
		d.finishLocked()
		d.mu.Unlock()
	}()
	for {
		n, err := d.connection.ReceiveDatagram(d.context, d.input)
		if err != nil {
			if errors.Is(err, carrier.ErrUnreliableTooLarge) {
				continue
			}
			// The original datagram receive may observe connection loss before
			// either reliable reader. Preserve its native source before cleanup.
			if controllerNetworkRetry(err) {
				d.admission.closeWithTransportCause(err)
			}
			return err
		}
		var decoded *protocolv4.Frame
		_ = d.queue.Open(d.input[:n], func(h protocolv4.RecordHeader, plain []byte) ([]byte, error) {
			body, err := d.decoder.DecodeRecordBody(plain, protocolv4.FrameDatagram, h, 0, protocolv4.DecodeContext{})
			if err != nil {
				return nil, err
			}
			decoded = body
			payload, _ := body.Field("data").ByteString()
			return payload, nil
		})
		if decoded != nil {
			decoded.Release()
		}
		clear(d.input[:n])
	}
}

func (d *UnreliableMessages) Receive(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if d.receiving {
		d.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	d.receiving = true
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.receiving = false; d.finishLocked(); d.mu.Unlock() }()
	buffer := make([]byte, d.maximum)
	transferred := false
	defer func() {
		if !transferred {
			clear(buffer)
		}
	}()
	timer := time.NewTicker(25 * time.Millisecond)
	defer timer.Stop()
	for {
		n, ok, err := d.queue.Take(ctx, buffer)
		if err != nil {
			return nil, err
		}
		if ok {
			transferred = true
			return buffer[:n:n], nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.stop:
			return nil, cryptov4.ErrClosed
		case <-d.queue.Wake():
		case <-timer.C:
		}
	}
}

func (d *UnreliableMessages) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		d.reservation.Seal()
		close(d.stop)
		d.cancel()
	}
	if !d.started {
		for index := range d.slots {
			s := &d.slots[index]
			if s.active && !s.complete {
				s.complete, s.err = true, cryptov4.ErrClosed
				close(s.done)
				d.releaseSlotLocked(index)
			}
		}
	}
	d.mu.Unlock()
	d.queue.Close()
	d.mu.Lock()
	d.finishLocked()
	d.mu.Unlock()
}

func (d *UnreliableMessages) finishLocked() {
	if !d.closed || d.cleaned || d.running || d.receiving || d.active != 0 {
		return
	}
	clear(d.input)
	clear(d.sends)
	d.input, d.sends, d.slots = nil, nil, nil
	d.cleaned = true
	close(d.cleanup)
}

func (d *UnreliableMessages) WaitCleanup(ctx context.Context) error {
	select {
	case <-d.cleanup:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *UnreliableMessages) Retire() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.cleaned {
		return cryptov4.ErrCapacity
	}
	if !d.retired {
		d.retired = true
		d.reservation.Release()
		d.admission = nil
		d.connection = nil
		d.decoder = nil
	}
	return nil
}

func (c *SessionCore) UnreliableMessages() (*UnreliableMessages, error) {
	if c == nil || c.plan == nil {
		return nil, ErrUnreliableUnavailable
	}
	p := c.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, cryptov4.ErrClosed
	}
	if p.unreliable == nil {
		return nil, ErrUnreliableUnavailable
	}
	if err := p.engine.CheckApplicationAuthorization(); err != nil {
		return nil, err
	}
	return p.unreliable, nil
}

func (s *EnvironmentSession) UnreliableMessages() (*UnreliableMessages, error) {
	core, err := s.Core()
	if err != nil {
		return nil, err
	}
	return core.UnreliableMessages()
}
