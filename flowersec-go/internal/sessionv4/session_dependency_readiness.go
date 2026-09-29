package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// An invocation observes existing structural readiness before its encoder can
// run. This does not reserve a channel, checkout a Stream, or promise that Start
// will win the subsequent admission race. Preparation outside an invocation
// remains independent of channel establishment.
func (r *RPCServices) checkInvocationReadiness(ctx context.Context, route rpcv4.ContractRoute, stream *streamPreparationPlan) error {
	if err := route.WithRegistered(func() error { return nil }); err != nil {
		return err
	}
	_, policy, err := route.Policy()
	if err != nil {
		return err
	}
	return r.checkDependencyPath(ctx, policy.Digest, stream)
}

func (r *RPCServices) checkDependencyPath(ctx context.Context, digest [32]byte, stream *streamPreparationPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	plan, bootstrap := r.plan, r.bootstrap
	closed, draining := r.closed || r.retired, r.draining.Load()
	r.mu.Unlock()
	if closed {
		return cryptov4.ErrClosed
	}
	if draining {
		return ErrSessionDraining
	}
	if plan == nil {
		return cryptov4.ErrNotReady
	}
	lease, authorization, err := plan.queryAuthorization()
	if err != nil {
		return err
	}
	if err := authorization.Check(); err != nil {
		return err
	}
	lease.mu.Lock()
	live := lease.reserved && lease.authorized && !lease.revoked && lease.authorization == authorization
	lease.mu.Unlock()
	if !live {
		return ErrApplicationAuthorization
	}
	if bootstrap != nil {
		a := bootstrap.admission
		a.mu.Lock()
		closed, draining = a.closed, a.draining || a.peerGoAway.set
		a.mu.Unlock()
		if closed {
			return cryptov4.ErrClosed
		}
		if draining {
			return ErrSessionDraining
		}
		// A legal rekey freezes record tickets, not the accepted structural
		// channel. Start still takes its complete original publication vector.
		if err := a.engine.CheckApplicationAuthorization(); err != nil {
			return err
		}
	}
	// Both callers have already checked their original registered route.
	// Direct component assemblies need not carry a second registry pointer.
	if stream != nil && !stream.notify {
		if stream.resume != nil {
			// Resume has no application encoder and claims its exact original
			// target in claimResumeTarget, never the ordinary preaccepted pool.
			return nil
		}
		return stream.core.plan.checkPreaccepted(ctx, stream.kind, stream.metadata, digest, stream.workload)
	}
	r.mu.Lock()
	if r.closed || r.retired {
		r.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if r.draining.Load() {
		r.mu.Unlock()
		return ErrSessionDraining
	}
	if stream != nil && stream.notify {
		var channels [2]*NotifyChannel
		if r.notifications != nil {
			for i, job := range r.notifyChannels {
				if job != nil {
					channels[i] = job.channel
				}
			}
		}
		r.mu.Unlock()
		for _, channel := range channels {
			if channel.dependencyReady() {
				return nil
			}
		}
	} else {
		// The lower-level RPC component can be assembled directly over an
		// admitted BatchSink. A Session-owned channel also proves its actual
		// carrier/prefix and continuous reader/credit responsibilities.
		if bootstrap == nil {
			publisher := r.rpcPublisherLocked()
			r.mu.Unlock()
			if publisher != nil && publisher.CheckReady() == nil {
				return nil
			}
		} else {
			var channels [9]*RPCChannel
			channels[0] = r.channel
			for i, job := range r.dynamicChannels {
				if job != nil {
					channels[i+1] = job.channel
				}
			}
			r.mu.Unlock()
			for _, channel := range channels {
				if channel.dependencyReady() {
					return nil
				}
			}
		}
	}
	return cryptov4.ErrNotReady
}
