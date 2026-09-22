package sessionv4

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// RuntimeInput is the original provider reader. InterruptRead must request
// cancellation without waiting for an outstanding Read to return. A provider
// that retains a buffer after interruption remains charged until actual exit.
type RuntimeInput interface {
	io.Reader
	InterruptRead()
}

type runtimeService struct {
	run  func(context.Context) error
	wait func(context.Context) error
}

// The original Run caller observes parent cancellation. This private context
// needs no standard-library propagation task for an opaque parent. Its mutex
// is independent of the runtime/admission gates used by service callers.
type sessionRuntimeContext struct {
	mu     sync.Mutex
	parent context.Context
	done   chan struct{}
	err    error
}

func (c *sessionRuntimeContext) Done() <-chan struct{} { return c.done }

func (c *sessionRuntimeContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil && c.parent != nil {
		if err := c.parent.Err(); err != nil {
			c.err = err
			close(c.done)
		}
	}
	return c.err
}

func (c *sessionRuntimeContext) cancel() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return
	}
	if c.parent != nil {
		c.err = c.parent.Err()
	}
	if c.err == nil {
		c.err = context.Canceled
	}
	close(c.done)
}

func (c *sessionRuntimeContext) Deadline() (time.Time, bool) {
	c.mu.Lock()
	parent := c.parent
	c.mu.Unlock()
	if parent == nil {
		return time.Time{}, false
	}
	return parent.Deadline()
}

func (c *sessionRuntimeContext) Value(key any) any {
	c.mu.Lock()
	parent := c.parent
	c.mu.Unlock()
	if parent == nil {
		return nil
	}
	return parent.Value(key)
}

// SessionRuntime starts the previously reserved Session services and exactly
// one ingress task. Cancellation ends Run promptly; WaitCleanup separately
// observes actual reader and worker exits. It never substitutes a new reader
// for a blocked or failed provider.
type SessionRuntime struct {
	mu                       sync.Mutex
	admission                *OpenAdmission
	input                    RuntimeInput
	dispatchTimeoutMS        uint64
	shared                   *SharedIngress
	maint                    *MaintenanceIngress
	reservation              resourcev4.Reference
	services                 [12]runtimeService
	handlers                 *sessionStreamDispatcher
	rpc                      *RPCServices
	applicationPublication   <-chan struct{}
	count                    int
	started, closed, retired bool
	context                  sessionRuntimeContext
	parent                   context.Context
	stop, cleanup            chan struct{}
	result                   error
}

// SessionRuntimeCharge covers only the supervisor and lifetime watchdog.
// Every other service retains its own same-Environment checked reservation.
// Complete profiles additionally account for host stacks and runtime overhead.
func SessionRuntimeCharge() resourcev4.Vector {
	return resourcev4.Vector{
		resourcev4.SDKBytes: uint64(unsafe.Sizeof(SessionRuntime{})) + uint64(unsafe.Sizeof(IdleWatchdog{})) + 13*uint64(unsafe.Sizeof(error(nil))),
		resourcev4.Items:    2, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 1,
	}
}

type SessionRuntimeConfig struct {
	Admission          *OpenAdmission
	Input              RuntimeInput
	SharedIngress      *SharedIngress
	MaintenanceIngress *MaintenanceIngress
	DispatchTimeoutMS  uint64
	Reservation        resourcev4.Reference
	handlers           *sessionStreamDispatcher
	rpc                *RPCServices
}

// NewSessionRuntime captures one immutable service set under the admission
// gate. Construction is one-shot, before Run. Independent roots and a second
// runtime cannot supply an alternative budget or reader for the same Session.
func NewSessionRuntime(config SessionRuntimeConfig) (*SessionRuntime, error) {
	a := config.Admission
	if a == nil || config.Input == nil || (config.SharedIngress == nil) == (config.MaintenanceIngress == nil) {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil {
		return nil, cryptov4.ErrConfiguration
	}
	if config.DispatchTimeoutMS == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err := timev4.NewAge(a.engine.Clock(), config.DispatchTimeoutMS, math.MaxUint64); err != nil {
		return nil, err
	}
	var refs [10]resourcev4.Reference
	nrefs := 1
	if a.lifecycle != nil {
		refs[nrefs] = a.lifecycle.reservation
		nrefs++
	}
	if g := config.SharedIngress; g != nil {
		if a.sharedIngress != g || g.admission != a || a.maintenanceIngress != nil {
			return nil, cryptov4.ErrConfiguration
		}
		refs[0] = g.receiver.reservation
	} else {
		g := config.MaintenanceIngress
		if a.maintenanceIngress != g || g.admission != a || a.sharedIngress != nil {
			return nil, cryptov4.ErrConfiguration
		}
		refs[0] = g.reservation
	}
	if a.sendService != nil {
		refs[nrefs] = a.sendService.reservation
		nrefs++
	}
	if a.nativeAuth != nil {
		refs[nrefs] = a.nativeAuth.reservation
		nrefs++
	}
	if a.termination != nil {
		refs[nrefs] = a.termination.reservation
		nrefs++
	}
	if a.rekeyService != nil {
		refs[nrefs] = a.rekeyService.reservation
		nrefs++
	}
	if a.liveness != nil {
		refs[nrefs] = a.liveness.reservation
		nrefs++
	}
	if a.maintenanceMessages != nil {
		refs[nrefs] = a.maintenanceMessages.reservation
		nrefs++
	}
	if a.retirement != nil && a.retirementService == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if a.retirementService != nil {
		refs[nrefs] = a.retirementService.reservation
		nrefs++
	}
	if config.handlers != nil {
		if config.handlers.core.plan.admission != a {
			return nil, cryptov4.ErrConfiguration
		}
		refs[nrefs] = config.handlers.reservation
		nrefs++
	}
	for _, ref := range refs[:nrefs] {
		if err := config.Reservation.CheckSameEnvironment(ref); err != nil {
			return nil, err
		}
	}
	if a.idleWatchdog != nil && a.idleWatchdog.started.Load() {
		return nil, cryptov4.ErrConfiguration
	}
	owned, err := config.Reservation.Take(SessionRuntimeCharge())
	if err != nil {
		return nil, err
	}
	r := &SessionRuntime{admission: a, input: config.Input, dispatchTimeoutMS: config.DispatchTimeoutMS, shared: config.SharedIngress, maint: config.MaintenanceIngress, reservation: owned, context: sessionRuntimeContext{done: make(chan struct{})}, stop: make(chan struct{}), cleanup: make(chan struct{})}
	r.handlers = config.handlers
	r.rpc = config.rpc
	add := func(run func(context.Context) error, wait func(context.Context) error) {
		r.services[r.count] = runtimeService{run, wait}
		r.count++
	}
	if a.idleWatchdog == nil {
		a.idleWatchdog = &IdleWatchdog{admission: a}
	}
	add(a.idleWatchdog.Run, nil)
	if a.sendService != nil {
		add(a.sendService.Run, a.sendService.WaitCleanup)
	}
	if a.nativeAuth != nil {
		add(a.nativeAuth.Run, a.nativeAuth.WaitCleanup)
	}
	if a.termination != nil {
		add(a.termination.Run, a.termination.WaitCleanup)
	}
	if r.maint != nil {
		add(r.maint.Watch, r.maint.WaitCleanup)
	}
	if a.liveness != nil && a.liveness.automatic != nil {
		add(a.liveness.RunAutomatic, a.liveness.WaitAutomaticCleanup)
	}
	if a.maintenanceMessages != nil {
		add(a.maintenanceMessages.Run, a.maintenanceMessages.WaitCleanup)
	}
	if a.rekeyService != nil {
		add(a.rekeyService.Run, a.rekeyService.WaitCleanup)
	}
	if a.retirementService != nil {
		add(a.retirementService.Run, a.retirementService.WaitCleanup)
	}
	if r.handlers != nil {
		add(r.handlers.Run, r.handlers.WaitCleanup)
	}
	if r.rpc != nil {
		add(r.rpc.run, r.rpc.waitChannel)
	}
	a.runtime = r
	if a.lifecycle != nil {
		add(a.lifecycle.Run, a.lifecycle.WaitCleanup)
	}
	return r, nil
}

func (r *SessionRuntime) ingress(ctx context.Context) error {
	for {
		if r.shared != nil {
			record, err := r.shared.Read(ctx, r.input)
			if errors.Is(err, errSharedDiscarded) {
				continue
			}
			if err != nil {
				return err
			}
			deadline, err := r.dispatchDeadline(record)
			if err == nil {
				err = r.shared.Dispatch(ctx, record, deadline)
			}
			record.Release()
			if err != nil {
				return err
			}
			continue
		}
		record, err := r.maint.Read(ctx, r.maint.carrier, r.input)
		if errors.Is(err, cryptov4.ErrCapacity) {
			// Retain the original candidate and rate token until real capacity returns.
			select {
			case <-r.admission.engine.MaintenanceReceiveWake():
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err != nil {
			return err
		}
		deadline, err := r.dispatchDeadline(record)
		if err == nil {
			err = r.admission.dispatchControl(ctx, record, deadline)
		}
		record.Release()
		if err != nil {
			return err
		}
	}
}

// The original Environment installs its host handoff before Run can launch
// services. The transport reader and maintenance keep their own progress; only
// application dispatch waits for the unique successful publication claim.
func (r *SessionRuntime) bindApplicationPublication(published <-chan struct{}) error {
	if r == nil || published == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.closed || r.applicationPublication != nil {
		return cryptov4.ErrTransition
	}
	r.applicationPublication = published
	if r.handlers != nil {
		r.handlers.publication = published
	}
	if r.rpc != nil {
		r.rpc.mu.Lock()
		r.rpc.publication = published
		r.rpc.mu.Unlock()
	}
	return nil
}

// Each newly authenticated owner gets its own finite original deadline. A
// duplicate retirement input keeps the deadline already retained by Retirement.
func (r *SessionRuntime) dispatchDeadline(record *ReceivedRecord) (*timev4.Deadline, error) {
	body, err := record.Body()
	if err != nil {
		return nil, err
	}
	if record.incoming == nil && body.Schema != "STREAM_ACK_RETIRE_BATCH" {
		return nil, nil
	}
	return timev4.NewAge(r.admission.engine.Clock(), r.dispatchTimeoutMS, math.MaxUint64)
}

// Run ends when the Session is sealed, independently of provider cleanup.
func (r *SessionRuntime) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.started || r.closed || r.retired {
		r.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		r.mu.Unlock()
		return err
	}
	r.started = true
	r.parent = ctx
	r.context.parent = ctx
	go r.supervise(&r.context)
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		r.stopWith(ctx.Err())
	case <-r.stop:
	}
	<-r.stop
	r.mu.Lock()
	err := r.result
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return cryptov4.ErrClosed
}

func (r *SessionRuntime) supervise(ctx context.Context) {
	events := make(chan error, r.count+1)
	for _, service := range r.services[:r.count] {
		go func() { events <- service.run(ctx) }()
	}
	go func() { events <- r.ingress(ctx) }()
	for remaining := r.count + 1; remaining > 0; remaining-- {
		r.stopWith(<-events)
	}
	<-r.stop
	r.finishCleanup()
}

func (r *SessionRuntime) stopWith(cause error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	// A service may observe the engine's cancellation-induced close before
	// Run wins its own select. Preserve the original parent cancellation when
	// that service only reports the generic closed consequence.
	if (cause == nil || errors.Is(cause, cryptov4.ErrClosed)) && r.parent != nil && r.parent.Err() != nil {
		cause = r.parent.Err()
	}
	r.admission.mu.Lock()
	if r.admission.failure != nil {
		cause = r.admission.failure
	}
	r.admission.mu.Unlock()
	if cause != nil && !errors.Is(cause, cryptov4.ErrClosed) {
		r.result = cause
	}
	started := r.started
	r.mu.Unlock()
	r.context.cancel()
	if r.handlers != nil {
		r.handlers.Close()
	}
	if r.rpc != nil {
		r.rpc.Close()
	}
	r.admission.closeWithCause(cause)
	r.input.InterruptRead()
	close(r.stop)
	if !started {
		// The one reserved coordinator observes original external tails even when
		// the runtime was closed before its services started.
		go r.finishCleanup()
	}
}

func (r *SessionRuntime) finishCleanup() {
	ctx := context.Background()
	for _, service := range r.services[:r.count] {
		if service.wait != nil {
			_ = service.wait(ctx)
		}
	}
	if r.shared != nil {
		_ = r.shared.WaitCleanup(ctx)
	} else {
		_ = r.maint.WaitCleanup(ctx)
	}
	if r.admission.liveness != nil {
		_ = r.admission.liveness.WaitCleanup(ctx)
	}
	_ = r.admission.engine.WaitCleanup(ctx)
	if err := r.admission.cleanupClosed(ctx); err != nil {
		// Preserve the incomplete owner on a cleanup invariant failure.
		r.mu.Lock()
		if r.result == nil {
			r.result = err
		}
		r.mu.Unlock()
		return
	}
	close(r.cleanup)
}

func (r *SessionRuntime) Close() {
	if r != nil {
		r.stopWith(nil)
	}
}

func (r *SessionRuntime) WaitCleanup(ctx context.Context) error {
	if r == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-r.cleanup:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Retire drops the graph only after real cleanup. Service owners separately
// retire their charges; no copied reservation refunds them here.
func (r *SessionRuntime) Retire() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.cleanup:
	default:
		return cryptov4.ErrCapacity
	}
	if !r.retired {
		r.retired = true
		r.admission, r.input, r.shared, r.maint = nil, nil, nil, nil
		r.handlers = nil
		r.rpc = nil
		r.applicationPublication = nil
		clear(r.services[:])
		r.context.mu.Lock()
		r.context.parent = nil
		r.context.mu.Unlock()
		r.parent = nil
		r.reservation.Release()
	}
	return nil
}

func (r *SessionRuntime) Err() error {
	if r == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.result
}
