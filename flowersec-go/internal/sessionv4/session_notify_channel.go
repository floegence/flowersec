package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
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
	if err := r.bootstrap.admission.engine.ApplicationReady(); err != nil {
		return nil, err
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
	job := &notifyChannelOpening{services: r, position: position, allocation: allocation, context: ctx, cancel: cancel, done: make(chan struct{})}
	r.notifyChannels[int(opener)] = job
	return job, nil
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
	job, err := r.reserveNotifyChannelLocked(ctx, a.direction)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() { go job.run() }()
	job.handle, _, err = a.OpenLocal(job.context, InternalStream, spec.Kind, nil, &CarrierAssociation{shared: a.sharedIngress}, job.allocation.stream.reservation, deadline)
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

func (job *notifyChannelOpening) bind() (*NotifyChannel, error) {
	r := job.services
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || job.context.Err() != nil {
		return nil, cryptov4.ErrClosed
	}
	owner, err := job.allocation.stream.bind(job.handle.owner, job.handle)
	if err != nil {
		return nil, err
	}
	job.stream = owner
	var seed [40]byte
	copy(seed[:16], r.owner.Instance[:])
	copy(seed[16:32], r.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[32:], job.handle.scope)
	digest := sha256.Sum256(seed[:])
	var identity [16]byte
	copy(identity[:], digest[:16])
	refs := job.allocation.notify
	receiveConfig := r.notifyReceiverConfig
	receiveConfig.Accounts = r.accounts[:r.accountCount]
	channel, err := NewNotifyChannel(owner, r.routes, identity, receiveConfig, r.notifyPublisherConfig, refs[0], refs[1], refs[2], refs[3], r.runtimeBytes)
	if err != nil {
		return nil, err
	}
	job.channel = channel
	job.receiver = channel.Receiver()
	if err = r.notifications.AttachChannel(job.receiver); err != nil {
		channel.Close()
		return nil, err
	}
	job.cancel()
	job.context, job.cancel = context.WithCancel(r.runtimeContext)
	return channel, nil
}

// The original reader task continues through cleanup. Logical channel closure
// cannot refund a position while a provider, flow or publisher still owns it.
func (job *notifyChannelOpening) run() {
	r := job.services
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
		if err == nil {
			err = a.CarrierClosed(job.handle)
		}
		if !errors.Is(err, ErrOpenPending) && !errors.Is(err, ErrTerminal) {
			return err
		}
	}
}
