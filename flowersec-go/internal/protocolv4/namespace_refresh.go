package protocolv4

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// NamespaceRefreshRequest selects an independently installed namespace, never
// a URL or a signer supplied by an unauthenticated peer.
type NamespaceRefreshRequest struct{ Tenant, Authority string }

// NamespaceRefreshProvider has the same bounded, synchronous buffer and cleanup
// contract as NamespaceBootstrapProvider. These ordinary signed reads do not
// confer cold-start or recovery authority.
type NamespaceRefreshProvider interface {
	Trust(context.Context, NamespaceRefreshRequest, []byte) (int, error)
	Head(context.Context, NamespaceRefreshRequest, []byte) (int, error)
	Fetch(context.Context, NamespaceContent, []byte) (int, error)
}

type NamespaceRefreshLimits struct {
	HeadIntervalMS, TrustIntervalMS, DurationMS uint64
	RuntimeBytes                                uint64
	Provider                                    resourcev4.Vector
}

// NamespaceRefresh is the one original Environment refresh service for a live
// namespace. Requests coalesce; even untrusted push hints cannot bypass its
// minimum cadence. It owns no Session and never restarts bootstrap, changes
// generation, or replaces a selected content pin after a newer observation.
type NamespaceRefresh struct {
	mu                sync.Mutex
	namespace         *LiveNamespace
	trust             *NamespaceTrustStore
	clock             *timev4.Clock
	limits            NamespaceRefreshLimits
	reservation       resourcev4.Reference
	ctx               context.Context
	cancel            context.CancelCauseFunc
	wake, done        chan struct{}
	input             []byte
	decoder           *Decoder
	codec             *SignedMapCodec
	trustDelay        *timev4.Delay
	started, closed   bool
	finished, retired bool
	completed         uint64
	last              error
}

func NamespaceRefreshCharge(l NamespaceRefreshLimits, configBytes int) (resourcev4.Vector, error) {
	if l.HeadIntervalMS == 0 || l.HeadIntervalMS > 3600000 || l.TrustIntervalMS < l.HeadIntervalMS || l.TrustIntervalMS > 86400000 || l.DurationMS == 0 || l.DurationMS > 90000 || l.RuntimeBytes == 0 || configBytes < 1024 || configBytes > 262144 {
		return resourcev4.Vector{}, CBORFailure("configuration_capacity")
	}
	limit, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := SignedMapBackingBytes("FreshnessHead", limit, limit)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	decoder, err := DecoderBackingBytes(limit, limit)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	head, err := NamespaceHeadBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespaceRefresh{})) + uint64(max(limit, configBytes)) + codec + decoder + head + 2*uint64(unsafe.Sizeof(timev4.Delay{})) + uint64(unsafe.Sizeof(timev4.Window{})), resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 2, resourcev4.Timers: 2}
	charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: l.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(l.Provider)
}

func NewNamespaceRefresh(n *LiveNamespace, trust *NamespaceTrustStore, limits NamespaceRefreshLimits, reservation resourcev4.Reference) (_ *NamespaceRefresh, err error) {
	if n == nil || trust == nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	trust.mu.Lock()
	defer trust.mu.Unlock()
	if n.destroyed || n.terminal != nil || n.refresh != nil || trust.closed || trust.retired || trust.namespace != n || n.trust != trust {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err = reservation.CheckSameEnvironment(n.reservation); err == nil {
		err = reservation.CheckSameEnvironment(trust.reservation)
	}
	if err != nil {
		return nil, err
	}
	charge, err := NamespaceRefreshCharge(limits, trust.limits.ConfigBytes)
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
	r := &NamespaceRefresh{namespace: n, trust: trust, clock: n.clock, limits: limits, reservation: owned, wake: make(chan struct{}, 1), done: make(chan struct{})}
	limit, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return nil, err
	}
	r.input = make([]byte, max(limit, trust.limits.ConfigBytes))
	r.decoder, err = NewDecoder(limit, limit)
	if err != nil {
		return nil, err
	}
	r.codec, err = NewSignedMapCodec("FreshnessHead", limit, limit)
	if err != nil {
		return nil, err
	}
	r.ctx, r.cancel = context.WithCancelCause(n.ctx)
	n.refresh = r
	return r, nil
}

func (r *NamespaceRefresh) Start(provider NamespaceRefreshProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if provider == nil || r.started || r.closed || r.retired {
		return CBORFailure("revocation_namespace_owner")
	}
	if err := r.reservation.Check(); err != nil {
		return err
	}
	r.namespace.mu.Lock()
	defer r.namespace.mu.Unlock()
	if r.namespace.terminal != nil || r.ctx.Err() != nil {
		return CBORFailure("revocation_namespace_owner")
	}
	r.namespace.refreshActive = true
	r.started = true
	go r.run(provider)
	return nil
}

// Request is a coalesced hint only. The original worker and delay own all work.
func (r *NamespaceRefresh) Request() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired {
		return
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Status describes completed original refresh turns, not freshness authority.
// Every credential gate still checks the actual active pair and current trust.
func (r *NamespaceRefresh) Status() (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.completed, r.last
}

func (r *NamespaceRefresh) run(provider NamespaceRefreshProvider) {
	returned := false
	defer func() {
		abnormal := recover() != nil || !returned
		r.mu.Lock()
		defer r.mu.Unlock()
		if abnormal {
			r.last = CBORFailure("revocation_refresh_provider")
		}
		r.cancel(r.last)
		r.finished = true
		close(r.done)
		r.namespace.mu.Lock()
		r.namespace.refreshActive = false
		r.namespace.cleanup()
		r.namespace.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		if r.ctx.Err() != nil {
			returned = true
			return
		}
		refreshErr := r.refresh(provider)
		delay, err := timev4.NewDelay(r.clock, r.limits.HeadIntervalMS)
		r.mu.Lock()
		r.last, r.completed = refreshErr, r.completed+1
		r.mu.Unlock()
		if err != nil {
			r.mu.Lock()
			r.last = err
			r.mu.Unlock()
			returned = true
			return
		}
		for {
			left, err := delay.RemainingMS()
			if err == nil {
				break
			}
			if !errors.Is(err, timev4.ErrPending) {
				r.mu.Lock()
				r.last = err
				r.mu.Unlock()
				returned = true
				return
			}
			timer.Reset(time.Duration(min(left, 1000)) * time.Millisecond)
			select {
			case <-r.ctx.Done():
				timer.Stop()
				returned = true
				return
			case <-r.wake:
				timer.Stop()
			case <-timer.C:
			}
		}
	}
}

// refresh performs a finite original control turn. The watchdog joins before
// this stack exits, and canceled provider calls keep their buffers and charge.
func (r *NamespaceRefresh) refresh(provider NamespaceRefreshProvider) (err error) {
	window, err := timev4.NewWindow(r.clock, r.limits.DurationMS)
	if err != nil {
		return err
	}
	call, cancel := context.WithCancelCause(r.ctx)
	stop, exited := make(chan struct{}), make(chan struct{})
	var pinMu sync.Mutex
	var pin *NamespacePin
	go func() {
		defer close(exited)
		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		for {
			remaining, failure := window.RemainingMS()
			if failure == nil {
				failure = r.reservation.Check()
			}
			pinMu.Lock()
			p := pin
			pinMu.Unlock()
			var canceled <-chan struct{}
			if p != nil {
				canceled = p.ctx.Done()
				if failure == nil {
					failure = context.Cause(p.ctx)
					if failure == CBORFailure("revocation_candidate_complete") {
						failure, canceled = nil, nil
					}
				}
			}
			if failure == nil {
				failure = context.Cause(call)
			}
			if failure != nil {
				cancel(failure)
				if p != nil {
					r.namespace.mu.Lock()
					if r.namespace.pin == p && p.terminal == nil {
						r.namespace.finishPin(p, failure)
					}
					r.namespace.mu.Unlock()
				}
				return
			}
			timer.Reset(time.Duration(max(1, min(remaining, 100))) * time.Millisecond)
			select {
			case <-stop:
				return
			case <-call.Done():
			case <-canceled:
			case <-timer.C:
			}
		}
	}()
	installed := false
	defer func() {
		close(stop)
		<-exited
		if cause := context.Cause(call); cause != nil && !installed {
			err = cause
		}
		cancel(err)
		clear(r.input)
	}()
	check := func() error {
		if cause := context.Cause(call); cause != nil {
			return cause
		}
		if err := r.reservation.Check(); err != nil {
			return err
		}
		return window.Check()
	}
	if err = check(); err != nil {
		return err
	}
	request := NamespaceRefreshRequest{Tenant: r.trust.root.Tenant, Authority: r.trust.root.Authority}
	trustDue := r.trustDelay == nil
	if !trustDue {
		_, err = r.trustDelay.RemainingMS()
		trustDue = err == nil
		if err != nil && !errors.Is(err, timev4.ErrPending) {
			return err
		}
	}
	var trustErr error
	defer func() {
		if err == nil {
			err = trustErr
		}
	}()
	if trustDue {
		trustErr = func() error {
			size, readErr := provider.Trust(call, request, r.input[:r.trust.limits.ConfigBytes:r.trust.limits.ConfigBytes])
			if err = check(); err != nil {
				return err
			}
			if readErr != nil {
				return readErr
			}
			if size < 1 || size > r.trust.limits.ConfigBytes {
				return CBORFailure("map_size")
			}
			if err = r.trust.Update(r.input[:size:size]); err != nil {
				return err
			}
			r.trustDelay, err = timev4.NewDelay(r.clock, r.limits.TrustIntervalMS)
			return err
		}()
		if trustErr != nil {
			if err = check(); err != nil {
				return err
			}
			// Failed control transport does not revoke an independently valid
			// existing configuration or cancel its selected content task.
			r.trust.mu.Lock()
			current := r.trust.checkCurrentLocked()
			r.trust.mu.Unlock()
			if current != nil {
				return trustErr
			}
		}
	}

	p, err := r.namespace.Pending()
	if err != nil {
		return err
	}
	if p == nil {
		r.namespace.mu.Lock()
		advance := r.namespace.observed.sequence > max(r.namespace.active.head.sequence, r.namespace.settledSequence)
		r.namespace.mu.Unlock()
		if advance {
			p, err = r.namespace.Advance()
			if err != nil {
				return err
			}
		}
	}
	if p == nil {
		limit, _ := SchemaByteLimit("FreshnessHead")
		size, readErr := provider.Head(call, request, r.input[:limit:limit])
		if err = check(); err != nil {
			return err
		}
		if readErr != nil {
			return readErr
		}
		if size < 1 || size > limit {
			return CBORFailure("map_size")
		}
		head, err := r.trust.bindHead(r.decoder, r.codec, nil, r.input[:size:size])
		if err != nil {
			return err
		}
		if err = check(); err != nil {
			return err
		}
		if err = r.namespace.Observe(head); err != nil {
			return err
		}
		p, err = r.namespace.Pending()
		if err != nil || p == nil {
			return err
		}
	}
	pinMu.Lock()
	pin = p
	pinMu.Unlock()
	if err = check(); err != nil {
		return err
	}
	err = p.fetchOriginal(func(_ context.Context, content NamespaceContent, out []byte) (int, error) {
		size, readErr := provider.Fetch(call, content, out)
		if post := check(); post != nil {
			return 0, post
		}
		return size, readErr
	}, true, check)
	installed = err == nil
	return err
}

func (r *NamespaceRefresh) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired {
		return
	}
	r.closed = true
	r.cancel(context.Canceled)
	if !r.started {
		r.finished = true
		close(r.done)
	}
}

func (r *NamespaceRefresh) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *NamespaceRefresh) Retire() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired {
		return nil
	}
	if !r.finished {
		return CBORFailure("revocation_namespace_owner")
	}
	r.namespace.mu.Lock()
	r.namespace.refresh = nil
	r.namespace.mu.Unlock()
	clear(r.input)
	r.namespace, r.trust, r.clock, r.input, r.decoder, r.codec, r.trustDelay = nil, nil, nil, nil, nil, nil, nil
	r.ctx, r.cancel = nil, nil
	r.reservation.Release()
	r.reservation = resourcev4.Reference{}
	r.retired = true
	return nil
}
