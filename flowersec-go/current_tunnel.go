package flowersec

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// TunnelRuntimeOptions admits the finite relay service aggregate. Each pair
// separately admits its original two legs, forwarding buffers and native maps.
// A caller supplies already admitted routes or current pairs; this runtime acquires no
// application identity, end-to-end Session or reusable admission proof.
type TunnelRuntimeOptions struct {
	MaxActivePairs            uint32
	RuntimeBytes              uint64
	Reservation, Dependencies ResourceReference
}

type tunnelRuntimeSlot struct {
	pair    *TunnelPair
	route   *TunnelRoute
	running bool
	cleaned bool
}

// TunnelRuntime retains each pair until its original forwarding and provider
// tails exit. It admits no extra per-leg queue and does not interpret e2e data.
type TunnelRuntime struct {
	mu                        sync.Mutex
	reservation, dependencies ResourceReference
	slots                     []tunnelRuntimeSlot
	wake                      chan struct{}
	done                      chan struct{}
	closed, cleaned, waiting  bool
}

func TunnelRuntimeCharge(options TunnelRuntimeOptions) (ResourceVector, error) {
	if options.MaxActivePairs == 0 || options.MaxActivePairs > 4096 || options.RuntimeBytes == 0 {
		return ResourceVector{}, cryptov4.ErrConfiguration
	}
	fixed := uint64(unsafe.Sizeof(TunnelRuntime{})) + uint64(options.MaxActivePairs)*uint64(unsafe.Sizeof(tunnelRuntimeSlot{}))
	return (ResourceVector{resourcev4.SDKBytes: fixed, resourcev4.Items: uint64(options.MaxActivePairs) + 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1}).Add(ResourceVector{resourcev4.SDKBytes: options.RuntimeBytes})
}

func NewTunnelRuntime(options TunnelRuntimeOptions) (*TunnelRuntime, error) {
	charge, err := TunnelRuntimeCharge(options)
	if err != nil {
		return nil, err
	}
	if err = options.Reservation.CheckSameEnvironment(options.Dependencies); err != nil {
		return nil, err
	}
	shared, err := options.Dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := options.Reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	return &TunnelRuntime{reservation: owned, dependencies: shared, slots: make([]tunnelRuntimeSlot, options.MaxActivePairs), wake: make(chan struct{}, 1), done: make(chan struct{})}, nil
}

// ServePair transfers one original pair to this finite service slot. The
// caller's already admitted pair Run remains the sole forwarding executor.
// Refusal leaves the supplied pair untouched; successful transfer owns Close
// and the actual cleanup tail even when the caller cancels its wait.
func (r *TunnelRuntime) ServePair(ctx context.Context, pair *TunnelPair) error {
	if r == nil || ctx == nil || pair == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return resourcev4.ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		r.mu.Unlock()
		return err
	}
	index := -1
	for i := range r.slots {
		if r.slots[i].pair == pair {
			r.mu.Unlock()
			return cryptov4.ErrTransition
		}
		if index < 0 && r.slots[i].pair == nil && r.slots[i].route == nil {
			index = i
		}
	}
	if index < 0 {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	run, claimErr := pair.ClaimRun(r.reservation)
	if claimErr != nil {
		r.mu.Unlock()
		return claimErr
	}
	r.slots[index] = tunnelRuntimeSlot{pair: pair, running: true}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.slots[index].running = false
		if r.slots[index].cleaned {
			r.slots[index] = tunnelRuntimeSlot{}
		}
		r.notifyLocked()
		r.cleanupLocked()
		r.mu.Unlock()
	}()
	err := run.Run(ctx)
	pair.Close()
	if cleanupErr := pair.WaitCleanup(ctx); cleanupErr == nil {
		r.mu.Lock()
		r.slots[index].cleaned = true
		r.mu.Unlock()
	} else if err == nil {
		err = cleanupErr
	}
	return err
}

func (r *TunnelRuntime) notifyLocked() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *TunnelRuntime) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		for i := range r.slots {
			r.slots[i].close()
		}
		r.notifyLocked()
		r.cleanupLocked()
	}
	r.mu.Unlock()
}

// WaitCleanup observes original pair cleanup without canceling another
// caller's forwarding work. Only one cleanup waiter uses this admitted slot.
func (r *TunnelRuntime) WaitCleanup(ctx context.Context) error {
	if r == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.cleaned {
		r.mu.Unlock()
		return nil
	}
	if r.waiting {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	r.waiting = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.waiting = false; r.mu.Unlock() }()
	for {
		r.mu.Lock()
		if r.cleaned {
			r.mu.Unlock()
			return nil
		}
		index := -1
		var pending tunnelRuntimeSlot
		for i := range r.slots {
			if (r.slots[i].pair != nil || r.slots[i].route != nil) && !r.slots[i].running && !r.slots[i].cleaned {
				index, pending = i, r.slots[i]
				break
			}
		}
		r.mu.Unlock()
		// ServePair owns the first cleanup attempt through its actual Run and
		// provider tails. Join that method before taking over a canceled wait;
		// two callers must not compete for the pair's sole cleanup position.
		if pending.pair != nil || pending.route != nil {
			if err := pending.waitCleanup(ctx); err != nil {
				return err
			}
			r.mu.Lock()
			if r.slots[index].pair == pending.pair && r.slots[index].route == pending.route {
				r.slots[index].cleaned = true
				if !r.slots[index].running {
					r.slots[index] = tunnelRuntimeSlot{}
				}
			}
			r.cleanupLocked()
			r.mu.Unlock()
			continue
		}
		select {
		case <-r.done:
			return nil
		case <-r.wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (r *TunnelRuntime) cleanupLocked() {
	if !r.closed || r.cleaned {
		return
	}
	for i := range r.slots {
		if r.slots[i].pair != nil || r.slots[i].route != nil {
			return
		}
	}
	r.cleaned = true
	clear(r.slots)
	r.slots = nil
	r.dependencies.Release()
	r.reservation.Release()
	r.dependencies, r.reservation = ResourceReference{}, ResourceReference{}
	close(r.done)
}

// ServeRoute transfers a fully admitted original relay route into one finite
// service position. The route performs both physical preparations, HOP_AUTH,
// original durable claims and pair forwarding under this same service owner.
// A failed local admission leaves the supplied route with its caller.
func (r *TunnelRuntime) ServeRoute(ctx context.Context, route *TunnelRoute) error {
	if r == nil || ctx == nil || route == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return resourcev4.ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		r.mu.Unlock()
		return err
	}
	if err := route.CheckEnvironment(r.reservation); err != nil {
		r.mu.Unlock()
		return err
	}
	index := -1
	for i := range r.slots {
		if r.slots[i].route == route {
			r.mu.Unlock()
			return cryptov4.ErrTransition
		}
		if index < 0 && r.slots[i].route == nil && r.slots[i].pair == nil {
			index = i
		}
	}
	if index < 0 {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	run, claimErr := route.ClaimRun(r.reservation)
	if claimErr != nil {
		r.mu.Unlock()
		return claimErr
	}
	r.slots[index] = tunnelRuntimeSlot{route: route, running: true}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.slots[index].running = false
		if r.slots[index].cleaned {
			r.slots[index] = tunnelRuntimeSlot{}
		}
		r.notifyLocked()
		r.cleanupLocked()
		r.mu.Unlock()
	}()
	err := run.Run(ctx)
	route.Close()
	if cleanupErr := route.WaitCleanup(ctx); cleanupErr == nil {
		r.mu.Lock()
		r.slots[index].cleaned = true
		r.mu.Unlock()
	} else if err == nil {
		err = cleanupErr
	}
	return err
}

func (s tunnelRuntimeSlot) close() {
	if s.route != nil {
		s.route.Close()
	} else if s.pair != nil {
		s.pair.Close()
	}
}
func (s tunnelRuntimeSlot) waitCleanup(ctx context.Context) error {
	if s.route != nil {
		return s.route.WaitCleanup(ctx)
	}
	if s.pair != nil {
		return s.pair.WaitCleanup(ctx)
	}
	return nil
}
