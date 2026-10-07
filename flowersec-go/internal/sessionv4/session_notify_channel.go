package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// One original protected position belongs to each opener. A rebuilt channel
// must acquire its same position only after all previous aliases have exited.
type notifyChannelOpening struct {
	services     *RPCServices
	position     int
	allocation   *internalChannelAllocation
	handle       OpenHandle
	stream       *StreamOwnership
	channel      *NotifyChannel // Published under services.mu.
	receiver     *rpcv4.NotifyReceiver
	context      context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	ready        chan struct{}
	readySettled bool
	readyError   error
	cleanupError error
}

func (r *RPCServices) reserveNotifyChannelLocked(parent context.Context, opener protocolv4.Direction) (*notifyChannelOpening, error) {
	if r.closed || r.retired {
		return nil, cryptov4.ErrClosed
	}
	if r.runtimeContext == nil || r.bootstrap == nil || r.notifications == nil {
		return nil, cryptov4.ErrNotReady
	}
	if r.publication != nil {
		select {
		case <-r.publication:
		default:
			return nil, cryptov4.ErrNotReady
		}
	}
	if opener > protocolv4.ServerToClient {
		return nil, cryptov4.ErrConfiguration
	}
	if r.notifyChannels[int(opener)] != nil {
		return nil, cryptov4.ErrCapacity
	}
	position := 8 + int(opener)
	allocation, err := r.checkoutInternalChannelLocked(position)
	if err != nil {
		return nil, err
	}
	allocation.stream.candidate, err = prepareStreamOwnership(allocation.stream.refs[streamFactoryOwnership])
	if err != nil {
		allocation.release()
		return nil, err
	}
	allocation.stream.reservation.Writer = r.bootstrap.output
	if parent == nil {
		parent = r.runtimeContext
	}
	ctx, cancel := context.WithCancel(parent)
	job := &notifyChannelOpening{services: r, position: position, allocation: allocation, context: ctx, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{})}
	r.notifyChannels[int(opener)] = job
	return job, nil
}

// Binding initialization is explicit local channel demand. It shares an
// original opening position and returns only after its publisher is usable;
// ordinary notification submission never opens or repairs a channel.
func (r *RPCServices) prepareBindingNotifyChannel(ctx context.Context, deadline *timev4.Deadline) error {
	if r == nil || ctx == nil || deadline == nil {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := deadline.Check(); err != nil {
		return err
	}
	// Connect can publish before the original RPC supervisor is scheduled.
	// Join its existing bootstrap rendezvous under the binding's unchanged
	// deadline before asking it to open a notification channel.
	r.mu.Lock()
	firstReady, initializing := r.firstReady, r.bootstrap != nil && !r.firstSettled
	r.mu.Unlock()
	if firstReady != nil && initializing {
	waiting:
		for {
			remaining, err := deadline.RemainingMS()
			if err != nil {
				return err
			}
			timer := time.NewTimer(time.Duration(min(remaining, uint64(60000))) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-firstReady:
				timer.Stop()
				if err := deadline.Check(); err != nil {
					return err
				}
				break waiting
			case <-timer.C:
			}
		}
	}
	r.mu.Lock()
	if r.closed || r.retired || r.bootstrap == nil {
		r.mu.Unlock()
		return cryptov4.ErrNotReady
	}
	var pending *notifyChannelOpening
	for _, job := range r.notifyChannels {
		if job == nil {
			continue
		}
		if job.readySettled && job.readyError == nil && job.channel.availablePublisher() != nil {
			if err := deadline.Check(); err != nil {
				r.mu.Unlock()
				return err
			}
			r.mu.Unlock()
			return nil
		}
		if !job.readySettled {
			pending = job
		}
	}
	if pending == nil {
		if err := deadline.Check(); err != nil {
			r.mu.Unlock()
			return err
		}
		var err error
		// Each Bind owns only its wait. The shared OPEN belongs to the
		// already admitted Session and keeps its first unchanged deadline.
		pending, err = r.reserveNotifyChannelLocked(nil, r.bootstrap.admission.direction)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		go pending.prepareDependency(deadline)
	}
	ready := pending.ready
	r.mu.Unlock()
readyWait:
	for {
		remaining, err := deadline.RemainingMS()
		if err != nil {
			return err
		}
		timer := time.NewTimer(time.Duration(min(remaining, uint64(60000))) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-ready:
			timer.Stop()
			if err := deadline.Check(); err != nil {
				return err
			}
			break readyWait
		case <-timer.C:
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if pending.readyError != nil {
		return pending.readyError
	}
	if err := deadline.Check(); err != nil {
		return err
	}
	if r.closed || pending.channel.availablePublisher() == nil {
		return cryptov4.ErrNotReady
	}
	return nil
}

func (job *notifyChannelOpening) settleReady(err error) {
	r := job.services
	r.mu.Lock()
	defer r.mu.Unlock()
	if !job.readySettled {
		job.readySettled, job.readyError = true, err
		close(job.ready)
	}
}

// OpenNotifyChannel is explicit local demand for the opener's one reusable
// notification channel. Opening it submits no notification and grants no
// business method authority. Accepted lifetime belongs to the original Session.
func (r *RPCServices) OpenNotifyChannel(ctx context.Context, deadline *timev4.Deadline) (*NotifyChannel, error) {
	if r == nil || ctx == nil || deadline == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec, err := protocolv4.Notify()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.bootstrap == nil {
		r.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	a := r.bootstrap.admission
	r.mu.Unlock()
	if err := a.engine.ApplicationReady(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	job, err := r.reserveNotifyChannelLocked(ctx, a.direction)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() { go job.run() }()
	job.handle, _, err = r.openInternal(job.context, InternalStream, spec.Kind, job.allocation, deadline)
	if err != nil {
		return nil, err
	}
	if err = a.WaitOutcome(job.context, job.handle); err != nil {
		return nil, err
	}
	return job.bind()
}

func (r *RPCServices) dispatchNotifyOpen(h OpenHandle, writer *RecordWriter) (bool, error) {
	spec, err := protocolv4.Notify()
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	if r.bootstrap == nil || h.owner != r.bootstrap.admission {
		r.mu.Unlock()
		return false, ErrOpenAssociation
	}
	a := r.bootstrap.admission
	r.mu.Unlock()
	a.mu.Lock()
	s, err := a.slot(h)
	if err != nil {
		a.mu.Unlock()
		return false, err
	}
	matched := string(a.metadata[s.metadataStart:s.metadataStart+s.kindSize]) == spec.Kind
	valid := s.metadataSize == s.kindSize && s.peerLimit >= 16384
	a.mu.Unlock()
	if !matched {
		return false, nil
	}
	if !valid {
		return true, cryptov4.ErrConfiguration
	}
	if err := a.engine.ApplicationReady(); err != nil {
		return true, err
	}
	r.mu.Lock()
	job, err := r.reserveNotifyChannelLocked(nil, 1-a.direction)
	r.mu.Unlock()
	if err != nil {
		return true, err
	}
	job.handle = h
	go func() {
		for {
			_, err := a.Decide(job.context, h, InternalStream, "", job.allocation.stream.reservation, writer)
			if errors.Is(err, ErrOpenPending) || errors.Is(err, errRecordWriterBusy) {
				if err = a.WaitDecisionOpportunity(job.context, h); err == nil {
					continue
				}
			}
			if err == nil {
				if err = a.WaitOutcome(job.context, h); err == nil {
					_, _ = job.bind()
				}
			}
			break
		}
		job.run()
	}()
	return true, nil
}

func (job *notifyChannelOpening) bind() (_ *NotifyChannel, err error) {
	defer func() { job.settleReady(err) }()
	r := job.services
	r.mu.Lock()
	if r.closed || job.context.Err() != nil {
		r.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	// The original opening job retains the charged allocation throughout
	// construction; Engine/endpoint checks run outside services publication.
	routes, notifications, runtimeBytes := r.routes, r.notifications, r.runtimeBytes
	instance, backing := r.owner.Instance, r.owner.Backing
	receiveConfig, publisherConfig := r.notifyReceiverConfig, r.notifyPublisherConfig
	receiveConfig.Accounts = r.accounts[:r.accountCount]
	r.mu.Unlock()
	owner, err := job.allocation.stream.bind(job.handle.owner, job.handle)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	job.stream = owner
	closed := r.closed || job.context.Err() != nil
	r.mu.Unlock()
	if closed {
		_ = owner.Cancel()
		return nil, cryptov4.ErrClosed
	}
	var seed [40]byte
	copy(seed[:16], instance[:])
	copy(seed[16:32], backing[:])
	binary.BigEndian.PutUint64(seed[32:], job.handle.scope)
	digest := sha256.Sum256(seed[:])
	var identity [16]byte
	copy(identity[:], digest[:16])
	refs := job.allocation.notify
	channel, err := NewNotifyChannel(owner, routes, identity, receiveConfig, publisherConfig, refs[0], refs[1], refs[2], refs[3], runtimeBytes)
	if err != nil {
		return nil, err
	}
	receiver := channel.Receiver()
	err = notifications.AttachChannel(receiver)
	r.mu.Lock()
	job.channel, job.receiver = channel, receiver
	closed = r.closed || job.context.Err() != nil
	if !closed && err == nil {
		err = r.protectNotifyChannelLocked(channel.Publisher(), job.position-8)
		if err == nil {
			job.cancel()
			job.context, job.cancel = context.WithCancel(r.runtimeContext)
		}
	}
	r.mu.Unlock()
	if closed || err != nil {
		channel.Close()
		if err != nil {
			return nil, err
		}
		return nil, cryptov4.ErrClosed
	}
	return channel, nil
}

// The original reader task continues through cleanup. Logical channel closure
// cannot refund a position while a provider, flow or publisher still owns it.
func (job *notifyChannelOpening) run() {
	r := job.services
	job.settleReady(cryptov4.ErrClosed)
	if job.channel != nil {
		_ = job.channel.Run(job.context)
		job.channel.Close()
	} else if job.stream != nil {
		_ = job.stream.Cancel()
	} else if job.handle.owner != nil {
		_ = job.handle.owner.Cancel(job.handle)
	}
	job.cancel()
	err := job.cleanup()
	r.mu.Lock()
	defer r.mu.Unlock()
	job.cleanupError = err
	if err == nil {
		r.notifications.DetachChannel(job.receiver)
		job.allocation.release()
		r.notifyChannels[job.position-8] = nil
		for _, slot := range r.workloadSlots {
			if slot != nil && !slot.closing {
				slot.notify[job.position-8] = rpcv4.NotifyProtection{}
			}
		}
		job.allocation, job.services, job.stream, job.channel, job.receiver = nil, nil, nil, nil, nil
		job.handle = OpenHandle{}
		job.context, job.cancel = nil, nil
	}
	close(job.done)
}

func (job *notifyChannelOpening) cleanup() error {
	if job.handle.owner == nil {
		return nil
	}
	a := job.handle.owner
	for {
		if err := a.waitStreamCleanupReady(context.Background(), job.handle); err != nil {
			// An unpublished failed OPEN may already have retired its slot.
			if errors.Is(err, ErrOpenAssociation) && job.stream == nil {
				return nil
			}
			return err
		}
		var err error
		if job.channel != nil {
			err = job.channel.WaitCleanup(context.Background())
		} else if job.stream != nil {
			err = job.stream.Cleanup(context.Background())
			if err == nil {
				err = job.stream.Release()
			}
		} else {
			err = a.CleanupStream(context.Background(), job.handle)
		}
		if err == nil && job.services.native == nil {
			err = a.CarrierClosed(job.handle)
		}
		if !errors.Is(err, ErrOpenPending) && !errors.Is(err, ErrTerminal) {
			return err
		}
	}
}
