package sessionv4

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
	"sync"
)

// PreparationDeadlineFor returns only the original local preauth deadline.
// It gives a Serve ingress the same time owner before waiting for server allow;
// it cannot authorize preparation, reconstruct a recipient or replay dispatch.
func (r *TunnelServerAllowRegistration) PreparationDeadlineFor(clock *timev4.Clock, environment resourcev4.Reference) (*timev4.Deadline, error) {
	if r == nil || clock == nil {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.state == tunnelAllowTaken || clock != r.config.Clock {
		return nil, resourcev4.ErrOwner
	}
	if err := r.reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if err := r.config.Runtime.Err(); err != nil {
		return nil, err
	}
	if err := r.deadline.Check(); err != nil {
		return nil, err
	}
	return r.deadline, nil
}

// TunnelAcceptedIngressFactory consumes one original registration result in
// the existing Serve/Environment ingress position. HOP_AUTH, ClientHello, FSB,
// durable admission, Noise and READY continue on that same physical carrier.
type TunnelAcceptedIngressFactory struct {
	mu              sync.Mutex
	result          *TunnelServerAllowRecipient
	plan            *TunnelAcceptedEntrancePlan
	started, closed bool
	Registration    *TunnelServerAllowRegistration
	Entrance        AcceptedEntranceConfig
	Root            *resourcev4.Root
	Owner           resourcev4.OwnerKey
	Environment     resourcev4.Reference
	Accounts        []resourcev4.Account
}

func (f *TunnelAcceptedIngressFactory) PrepareAccepted(ctx context.Context, deadline *timev4.Deadline) (*AcceptedEntrance, error) {
	if f == nil || ctx == nil || f.Registration == nil || f.Root == nil || deadline == nil || f.Entrance.Initial.Deadline != deadline {
		return nil, cryptov4.ErrConfiguration
	}
	f.mu.Lock()
	if f.closed || f.started {
		f.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	f.started = true
	f.mu.Unlock()
	prepared, err := f.Registration.TakePrepared(ctx)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.result = prepared.Recipient
	f.plan = prepared.Entrance
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return nil, resourcev4.ErrClosed
	}
	if prepared.Deadline != deadline || prepared.Recipient == nil || prepared.Entrance == nil {
		return nil, resourcev4.ErrOwner
	}
	if err = prepared.Entrance.matchAdmission(f.Entrance, f.Root, nil, f.Environment, f.Accounts); err != nil {
		return nil, err
	}
	entrance, err := prepared.Entrance.Build(ctx, prepared.Recipient)
	if entrance != nil {
		f.mu.Lock()
		f.result = nil
		f.plan = nil
		f.mu.Unlock()
	}
	return entrance, err
}

// A failed entrance construction still owns the taken original recipient and
// physical carrier. The existing Environment cleanup task joins that tail;
// canceled caller waits never discard it or re-dispatch a server preparation.
func (f *TunnelAcceptedIngressFactory) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}
func (f *TunnelAcceptedIngressFactory) WaitCleanup(ctx context.Context) error {
	if f == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	f.mu.Lock()
	result, plan, closed := f.result, f.plan, f.closed
	f.mu.Unlock()
	if !closed {
		return cryptov4.ErrTransition
	}
	if result != nil {
		if err := result.abortUnadopted(ctx); err != nil {
			return err
		}
	}
	if plan != nil {
		plan.Close()
		if err := plan.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	f.mu.Lock()
	if f.result == result {
		f.result = nil
		f.plan = nil
	}
	f.mu.Unlock()
	return nil
}

func (r *TunnelServerAllowRecipient) abortUnadopted(ctx context.Context) error {
	if r == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.cleaned {
		r.mu.Unlock()
		return nil
	}
	if r.entranceActive || r.busy {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	r.closed, r.aborting, r.busy = true, true, true
	prepared := r.prepared
	if r.subscriptions != nil {
		r.subscriptions.NotifyPreparation()
	}
	r.mu.Unlock()
	completed := false
	defer func() {
		r.mu.Lock()
		r.busy = false
		if completed {
			r.aborting = false
		}
		r.cleanupLocked()
		r.mu.Unlock()
	}()
	if prepared != nil {
		_ = prepared.Close()
		if err := prepared.WaitCleanup(ctx); err != nil {
			return err
		}
		if err := prepared.Retire(); err != nil {
			return err
		}
	}
	completed = true
	return nil
}

// TunnelServerMaterialSource reports the already captured immutable lease
// profile for admission sizing. It is neither acquisition nor a source selector.
func TunnelServerMaterialSource(material *ConnectionMaterial, environment resourcev4.Reference) (string, error) {
	pin, identity, err := captureTunnelServerMaterial(material, environment)
	if err != nil {
		return "", err
	}
	defer pin.release()
	defer identity.release()
	return pin.lease.source, nil
}
