package sessionv4

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type managementChannelOpening struct {
	services     *RPCServices
	allocation   *internalChannelAllocation
	handle       OpenHandle
	stream       *StreamOwnership
	channel      *ManagementChannel
	context      context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	cleanupError error
}

func (r *RPCServices) signalManagementLocked() {
	if r.managementChanged != nil {
		close(r.managementChanged)
		r.managementChanged = make(chan struct{})
	}
}
func (r *RPCServices) reserveManagementLocked() (*managementChannelOpening, error) {
	if r.closed || r.retired {
		return nil, cryptov4.ErrClosed
	}
	if r.session.Limits().ApplicationProfile != "execution" {
		return nil, cryptov4.ErrConfiguration
	}
	if r.runtimeContext == nil || r.bootstrap == nil {
		return nil, cryptov4.ErrNotReady
	}
	if r.publication != nil {
		select {
		case <-r.publication:
		default:
			return nil, cryptov4.ErrNotReady
		}
	}
	if r.management != nil {
		return nil, cryptov4.ErrCapacity
	}
	a := r.bootstrap.admission
	a.mu.Lock()
	draining := a.draining || a.peerGoAway.set || a.closed
	a.mu.Unlock()
	if draining {
		return nil, cryptov4.ErrClosed
	}
	allocation, err := r.checkoutInternalChannelLocked(10)
	if err != nil {
		return nil, err
	}
	allocation.stream.candidate, err = prepareStreamOwnership(allocation.stream.refs[streamFactoryOwnership])
	if err != nil {
		allocation.release()
		return nil, err
	}
	allocation.stream.reservation.Writer = r.bootstrap.output
	ctx, cancel := context.WithCancel(r.runtimeContext)
	job := &managementChannelOpening{services: r, allocation: allocation, context: ctx, cancel: cancel, done: make(chan struct{})}
	r.management = job
	return job, nil
}

// ManagementRequest waits only within the caller's original finite deadline.
// The client initializer runs independently; the server never opens an M ID.
// Neither readiness waiting nor a local retry automatically republishes a call.
func (r *RPCServices) ManagementRequest(ctx context.Context, cancel bool, target rpcv4.ExecutionTarget, deadline *timev4.Deadline, access rpcv4.ExecutionAccess) (rpcv4.ManagementResponse, error) {
	if r == nil || ctx == nil || deadline == nil || access == nil {
		return rpcv4.ManagementResponse{}, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.session.Limits().ApplicationProfile != "execution" || !deadline.BelongsTo(r.clock) {
		r.mu.Unlock()
		return rpcv4.ManagementResponse{}, rpcv4.ErrExecutionUnsupported
	}
	if r.managementCalls >= 2 {
		r.mu.Unlock()
		return rpcv4.ManagementResponse{}, rpcv4.ErrCapacity
	}
	r.managementCalls++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.managementCalls--
		if r.closed && r.managementCalls == 0 {
			close(r.managementCallsDone)
		}
		r.mu.Unlock()
	}()
	// Bound and detach identifier backing before waiting for initialization.
	for _, value := range []string{target.Service.Tenant, target.Service.Audience, target.Service.Namespace, target.Caller.Subject} {
		if len(value) == 0 || len(value) > 128 {
			return rpcv4.ManagementResponse{}, cryptov4.ErrConfiguration
		}
	}
	target.Service.Tenant = strings.Clone(target.Service.Tenant)
	target.Service.Audience = strings.Clone(target.Service.Audience)
	target.Service.Namespace = strings.Clone(target.Service.Namespace)
	target.Caller.Subject = strings.Clone(target.Caller.Subject)
	original, err := deadline.Fork(deadline.Cap())
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	deadline = original
	now, err := deadline.Sample()
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	if deadline.Cap() <= now.LowerMS || deadline.Cap()-now.LowerMS > 30000 {
		return rpcv4.ManagementResponse{}, cryptov4.ErrConfiguration
	}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return rpcv4.ManagementResponse{}, err
		}
		remaining, err := deadline.RemainingMS()
		if err != nil {
			return rpcv4.ManagementResponse{}, err
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return rpcv4.ManagementResponse{}, rpcv4.ErrManagementClosed
		}
		if r.management != nil && r.management.channel != nil {
			channel := r.management.channel
			r.mu.Unlock()
			return channel.Request(ctx, cancel, target, deadline, access)
		}
		stopped, changed := r.managementStopped, r.managementChanged
		if r.bootstrap != nil {
			a := r.bootstrap.admission
			a.mu.Lock()
			stopped = stopped || a.draining || a.peerGoAway.set
			a.mu.Unlock()
		}
		r.mu.Unlock()
		if stopped {
			return rpcv4.ManagementResponse{}, rpcv4.ErrManagementClosed
		}
		timer.Reset(time.Duration(min(remaining, uint64((1<<63-1)/time.Millisecond))) * time.Millisecond)
		select {
		case <-ctx.Done():
			return rpcv4.ManagementResponse{}, ctx.Err()
		case <-changed:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// runManagement reuses the one admitted Session supervisor. Every retry uses
// the original initialization deadline; each actual allocation is charged by
// OpenAdmission before ticket/native work, including burns and refusals.
func (r *RPCServices) runManagement(ctx context.Context) {
	defer func() { r.mu.Lock(); r.managementStopped = true; r.signalManagementLocked(); r.mu.Unlock() }()
	spec, err := protocolv4.Management()
	if err != nil {
		return
	}
	a := r.bootstrap.admission
	for {
		deadline, err := timev4.NewAge(r.clock, spec.MaxLifetimeMS, a.engine.SessionParameters().SessionNotAfterMS)
		if err != nil {
			return
		}
		var job *managementChannelOpening
		for {
			a.mu.Lock()
			stop := a.closed || a.draining || a.peerGoAway.set || a.lifetime[protocolv4.ClientToServer][ManagementStream] >= uint64(spec.LifetimeChannels)
			a.mu.Unlock()
			if stop || ctx.Err() != nil {
				return
			}
			if err = deadline.Check(); err != nil {
				return
			}
			// A real application ticket freeze waits on this same finite owner; it
			// must not allocate a replacement ordinal on every wake.
			err = a.engine.ApplicationReady()
			if err == nil {
				r.mu.Lock()
				job, err = r.reserveManagementLocked()
				r.mu.Unlock()
			}
			if err == nil {
				break
			}
			if !errors.Is(err, cryptov4.ErrCapacity) && !errors.Is(err, resourcev4.ErrCapacity) && !errors.Is(err, cryptov4.ErrNotReady) && !errors.Is(err, cryptov4.ErrTransition) {
				return
			}
			if !r.managementRetry(ctx, deadline) {
				return
			}
		}
		remaining, err := deadline.RemainingMS()
		if err != nil {
			job.cancel()
			job.run()
			return
		}
		openCtx, stopOpen := context.WithTimeout(job.context, time.Duration(remaining)*time.Millisecond)
		for {
			job.handle, _, err = a.OpenLocal(openCtx, ManagementStream, spec.Kind, nil, &CarrierAssociation{shared: a.sharedIngress}, job.allocation.stream.reservation, deadline)
			// A handle means the actual allocation has already spent its lifetime
			// count. Finish that owner before considering another generation.
			if err == nil || job.handle.owner != nil {
				break
			}
			if !errors.Is(err, cryptov4.ErrCapacity) && !errors.Is(err, ErrOpenPending) {
				break
			}
			if !r.managementRetry(openCtx, deadline) {
				break
			}
		}
		if err == nil {
			err = a.WaitOutcome(openCtx, job.handle)
		}
		if err == nil {
			_, err = job.bind()
		}
		stopOpen()
		if err != nil {
			job.cancel()
		}
		job.run()
		if job.cleanupError != nil || err != nil && job.handle.owner == nil {
			return
		}
	}
}
func (r *RPCServices) managementRetry(ctx context.Context, deadline *timev4.Deadline) bool {
	remaining, err := deadline.RemainingMS()
	if err != nil {
		return false
	}
	// One finite initializer timer also covers protected-reference release,
	// whose actual borrowers need not produce a new transport event.
	timer := time.NewTimer(time.Duration(min(remaining, uint64(20))) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-r.runtimeStop:
		return false
	case <-r.bootstrap.admission.engine.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (r *RPCServices) dispatchManagementOpen(h OpenHandle, writer *RecordWriter) (bool, error) {
	spec, err := protocolv4.Management()
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
	valid := a.direction == protocolv4.ServerToClient && s.metadataSize == s.kindSize && s.peerLimit >= spec.ReceiveLimit
	a.mu.Unlock()
	if !matched {
		return false, nil
	}
	if !valid {
		return true, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	job, err := r.reserveManagementLocked()
	r.mu.Unlock()
	if err != nil {
		return true, err
	}
	job.handle = h
	go func() {
		for {
			_, err := a.Decide(job.context, h, ManagementStream, "", job.allocation.stream.reservation, writer)
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
func (job *managementChannelOpening) bind() (*ManagementChannel, error) {
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
	channel, err := NewManagementChannel(owner, r.clock, r.managementResolver, job.allocation.management, r.runtimeBytes)
	if err != nil {
		return nil, err
	}
	job.channel = channel
	r.signalManagementLocked()
	return channel, nil
}
func (job *managementChannelOpening) run() {
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
		job.allocation.release()
		r.management = nil
		job.allocation, job.services, job.stream, job.channel = nil, nil, nil, nil
		// Keep the allocated handle as a bounded fact for the original supervisor.
		job.context, job.cancel = nil, nil
	}
	r.signalManagementLocked()
	close(job.done)
}
func (job *managementChannelOpening) cleanup() error {
	if job.handle.owner == nil {
		return nil
	}
	a := job.handle.owner
	for {
		if err := a.waitStreamCleanupReady(context.Background(), job.handle); err != nil {
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
