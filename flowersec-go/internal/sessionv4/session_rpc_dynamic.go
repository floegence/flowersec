package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// RPCChannelClass is local scheduling policy. It is never supplied by a peer
// header and never grants a received message protected application execution.
type RPCChannelClass uint8

const (
	RPCInteractive RPCChannelClass = iota
	RPCBulk
)

// Positions 0..3 belong to client-opened channels; 4..7 to server-opened
// channels. Position zero is the fixed bootstrap. A closing position is still
// occupied until its original physical reader, publisher and flow have exited.
type rpcChannelOpening struct {
	services     *RPCServices
	position     int
	allocation   *internalChannelAllocation
	handle       OpenHandle
	stream       *StreamOwnership
	channel      *RPCChannel // Published under services.mu.
	receiver     *rpcv4.Receiver
	context      context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	cleanupError error
}

// Only a new request selects a live channel. Already admitted messages retain
// their original publisher/serial, including cancellation and late responses.
func (r *RPCServices) rpcPublisherLocked() *rpcv4.Publisher {
	if p := r.channel.availablePublisher(); p != nil {
		return p
	}
	for _, job := range r.dynamicChannels {
		if job != nil {
			if p := job.channel.availablePublisher(); p != nil {
				return p
			}
		}
	}
	return nil
}

func (r *RPCServices) reserveChannelLocked(parent context.Context, opener protocolv4.Direction, class RPCChannelClass, local bool) (*rpcChannelOpening, error) {
	if r.closed || r.retired {
		return nil, cryptov4.ErrClosed
	}
	if r.runtimeContext == nil || r.bootstrap == nil || r.dispatch == nil {
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
	start, end := int(opener)*4, int(opener)*4+4
	if local {
		start += int(class) * 2
		end = start + 2
	}
	for position := start; position < end; position++ {
		if r.dynamicChannels[position] != nil || position == 0 && r.firstAllocation != nil {
			continue
		}
		var allocation *internalChannelAllocation
		var err error
		if position == 0 {
			allocation, err = r.checkoutChannelAllocationLocked(&r.firstFuture, position)
		} else {
			allocation, err = r.checkoutInternalChannelLocked(position)
		}
		if errors.Is(err, resourcev4.ErrCapacity) {
			continue
		}
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
		job := &rpcChannelOpening{services: r, position: position, allocation: allocation, context: ctx, cancel: cancel, done: make(chan struct{})}
		r.dynamicChannels[position] = job
		return job, nil
	}
	return nil, cryptov4.ErrCapacity
}

// OpenChannel creates a shared ordinary RPC channel on explicit local demand.
// It does not submit or replay any application message. The caller's context
// bounds only establishment; accepted channels belong to the original Session.
func (r *RPCServices) OpenChannel(ctx context.Context, class RPCChannelClass, deadline *timev4.Deadline) (*RPCChannel, error) {
	if r == nil || ctx == nil || deadline == nil || class > RPCBulk {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.bootstrap == nil {
		r.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	a := r.bootstrap.admission
	job, err := r.reserveChannelLocked(ctx, a.direction, class, true)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() { go job.run() }()
	job.handle, _, err = a.OpenLocal(job.context, InternalStream, r.bootstrap.spec.Kind, nil, &CarrierAssociation{shared: a.sharedIngress}, job.allocation.stream.reservation, deadline)
	if err != nil {
		return nil, err
	}
	if err = a.WaitOutcome(job.context, job.handle); err != nil {
		return nil, err
	}
	return job.bind()
}

// dispatchRPCOpen is called only by the Session's sole pending-OPEN dispatcher.
// It neither competes for NextPending nor enters the ordinary handler executor.
// Trusted local policy, rather than peer metadata, selects the internal class.
func (r *RPCServices) dispatchRPCOpen(h OpenHandle, writer *RecordWriter) (handled bool, err error) {
	r.mu.Lock()
	if r.bootstrap == nil || h.owner != r.bootstrap.admission {
		r.mu.Unlock()
		return false, ErrOpenAssociation
	}
	a, kind := r.bootstrap.admission, r.bootstrap.spec.Kind
	r.mu.Unlock()
	a.mu.Lock()
	s, err := a.slot(h)
	if err != nil {
		a.mu.Unlock()
		return false, err
	}
	matched := string(a.metadata[s.metadataStart:s.metadataStart+s.kindSize]) == kind
	valid := s.metadataSize == s.kindSize && s.peerLimit >= 16384
	a.mu.Unlock()
	if !matched {
		handled, err := r.dispatchNotifyOpen(h, writer)
		if handled || err != nil {
			return handled, err
		}
		return r.dispatchManagementOpen(h, writer)
	}
	if !valid {
		return true, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	job, err := r.reserveChannelLocked(nil, 1-a.direction, RPCInteractive, false)
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

func (job *rpcChannelOpening) bind() (*RPCChannel, error) {
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
	refs := job.allocation.rpc
	channel, err := NewRPCChannel(owner, r.network, identity, r.inputs, refs[0], refs[1], refs[2], refs[3], r.runtimeBytes)
	if err != nil {
		return nil, err
	}
	job.channel = channel
	job.receiver = channel.Receiver()
	if err = r.dispatch.AttachChannel(job.receiver, channel.Publisher()); err != nil {
		channel.Close()
		return nil, err
	}
	job.cancel()
	job.context, job.cancel = context.WithCancel(r.runtimeContext)
	return channel, nil
}

// The original reader task continues through cleanup. Logical channel closure
// cannot refund a position while a provider, flow or publisher still owns it.
func (job *rpcChannelOpening) run() {
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
		r.dispatch.detachChannel(job.receiver)
		if r.firstAllocation == job.allocation {
			r.firstAllocation = nil
		}
		job.allocation.release()
		r.dynamicChannels[job.position] = nil
		job.allocation, job.services, job.stream, job.channel, job.receiver = nil, nil, nil, nil, nil
		job.handle = OpenHandle{}
		job.context, job.cancel = nil, nil
	}
	close(job.done)
}

func (job *rpcChannelOpening) cleanup() error {
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
