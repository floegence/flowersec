package sessionv4

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/unicode151"
)

var (
	ErrStreamHandlerKind         = errors.New("sessionv4: unregistered Stream kind")
	ErrStreamHandlerCallbackExit = errors.New("sessionv4: Stream callback exited without returning")
)

// RawStreamHandlerConfig is trusted local registration, independent of the
// signed client/server role. Slots bounds authorizing and subsequent handling
// together. Both callbacks reuse the invocation's original ordinary permit.
// Metadata is the authenticated preparation's borrowed immutable byte snapshot;
// only Handler receives the original accepted Stream capability.
type RawStreamHandlerConfig struct {
	Resume        *ResumeStreamBinding
	Messages      *MessageStreamHandlerConfig
	Kind          string
	Slots         uint32
	WorkClass     ApplicationWorkClass
	AuthorizeOpen func(context.Context, any, []byte) error
	Handler       func(context.Context, any, []byte, *StreamOwnership) error
}

// StreamHandlerPlanConfig freezes the complete raw registration set before
// READY. ApplicationContext is an opaque local binding already authenticated
// and frozen by the trusted adapter; this plan never derives it from metadata
// or clones arbitrary application object graphs. RuntimeBytes covers qualified
// allocator/channel overhead; delegate backing is separately preadmitted.
type StreamHandlerPlanConfig struct {
	Handlers           []RawStreamHandlerConfig
	ApplicationContext any
	RuntimeBytes       uint64
}

type streamHandlerRegistration struct {
	config     RawStreamHandlerConfig
	start, end int
}

type streamHandlerCaptureSlot struct {
	generation                                             uint64
	registration                                           int
	used, busy, releasing, authorized, authorizationCalled bool
	accepted, handlerCalled                                bool
	failure                                                error
}

// StreamHandlerPlan owns one immutable registration generation. It adds no
// worker, queue, Session authority or alternate executor. The Session's original
// authenticated pending gate captures a registration and its finite position;
// its dispatcher supplies proof, lifetime, ordinary execution and outcome gates.
type StreamHandlerPlan struct {
	mu                     sync.Mutex
	registrations          []streamHandlerRegistration
	slots                  []streamHandlerCaptureSlot
	executor               *ApplicationExecutor
	group                  *applicationGroup
	binding                any
	application            *SessionPlan
	applicationBound       bool
	reservation, delegates resourcev4.Reference
	active                 uint32
	closed, cleaned        bool
	claimed, retired       bool
	done                   chan struct{}
}

// StreamHandlerCapture is a value reference to one original registration and
// slot generation. Copies share that ownership and cannot act on a recycled
// slot. Release relinquishes the capture only after its active callback exits.
type StreamHandlerCapture struct {
	plan       *StreamHandlerPlan
	slot       int
	generation uint64
}

func canonicalStreamHandlerKind(kind string) bool {
	if len(kind) == 0 || len(kind) > 128 {
		return false
	}
	var raw [128]byte
	var work, scratch [128 * unicode151.MaxCanonicalDecomposition]rune
	copy(raw[:], kind)
	return unicode151.IsNFC(raw[:len(kind)], work[:], scratch[:])
}

// StreamHandlerPlanCharge validates canonical Unicode 15.1 NFC registration
// names without allocating or rewriting them. Wire kinds use those exact names.
// The complete fixed slab includes the capture metadata and delegate references.
func StreamHandlerPlanCharge(config StreamHandlerPlanConfig) (resourcev4.Vector, error) {
	if len(config.Handlers) == 0 || config.RuntimeBytes == 0 || uint64(len(config.Handlers)) > math.MaxUint32 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	size := uint64(unsafe.Sizeof(StreamHandlerPlan{})) + uint64(unsafe.Sizeof(applicationGroup{}))
	add := func(n uint64) bool {
		if n > math.MaxUint64-size {
			return false
		}
		size += n
		return true
	}
	if !add(config.RuntimeBytes) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	var slots uint64
	for i, handler := range config.Handlers {
		if handler.Slots == 0 || handler.WorkClass > ApplicationResident || !canonicalStreamHandlerKind(handler.Kind) {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		if binding := handler.Resume; binding != nil {
			if handler.Messages != nil || binding.Kind != handler.Kind || !executionIdentityText(binding.Namespace) || binding.Type == 0 || binding.ContractDigest == ([32]byte{}) {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
			if !add(uint64(unsafe.Sizeof(ResumeStreamBinding{})) + uint64(len(binding.Kind)+len(binding.Namespace))) {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
		if handler.Messages == nil {
			if handler.Handler == nil {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		} else {
			if handler.Handler != nil || handler.Messages.Handler == nil || handler.Kind != handler.Messages.Messages.Definition.Kind() {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
			if _, err := typedMessageCharges(handler.Messages.Messages); err != nil {
				return resourcev4.Vector{}, err
			}
			if !add(uint64(unsafe.Sizeof(MessageStreamHandlerConfig{}))) {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
		for _, previous := range config.Handlers[:i] {
			if previous.Kind == handler.Kind {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
		slots += uint64(handler.Slots)
		if slots > math.MaxUint32 || !add(uint64(unsafe.Sizeof(streamHandlerRegistration{}))+uint64(len(handler.Kind))) {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
	}
	slotBytes := uint64(unsafe.Sizeof(streamHandlerCaptureSlot{})) + uint64(unsafe.Sizeof(StreamHandlerCapture{}))
	if slots > uint64(math.MaxInt)/slotBytes || !add(slots*slotBytes) || size > uint64(math.MaxInt) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: size, resourcev4.Items: 2 + uint64(len(config.Handlers)) + 2*slots}, nil
}

// NewStreamHandlerPlan consumes the complete metadata reservation and moves
// the caller's preadmitted delegate borrow before allocating its immutable
// snapshot. The delegate borrow and plan belong to the same Environment; the
// actual shared executor belongs to their root. Failure after a successful
// ownership move releases that moved reference, never creates a replacement.
func NewStreamHandlerPlan(config StreamHandlerPlanConfig, executor *ApplicationExecutor, reservation, delegatesBorrow resourcev4.Reference) (*StreamHandlerPlan, error) {
	charge, err := StreamHandlerPlanCharge(config)
	if err != nil || executor == nil || reservation == delegatesBorrow {
		return nil, cryptov4.ErrConfiguration
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.closed {
		return nil, resourcev4.ErrClosed
	}
	if err := executor.reservation.CheckSameRoot(reservation); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(delegatesBorrow); err != nil {
		return nil, err
	}
	delegates, err := delegatesBorrow.TakeBorrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		delegates.Release()
		return nil, err
	}
	count := 0
	for _, handler := range config.Handlers {
		count += int(handler.Slots)
	}
	p := &StreamHandlerPlan{executor: executor, binding: config.ApplicationContext, reservation: owned, delegates: delegates,
		registrations: make([]streamHandlerRegistration, len(config.Handlers)), slots: make([]streamHandlerCaptureSlot, count), done: make(chan struct{})}
	p.group = &applicationGroup{executor: executor, head: [2]int{-1, -1}, tail: [2]int{-1, -1}, done: make(chan struct{})}
	start := 0
	for i, handler := range config.Handlers {
		handler.Kind = strings.Clone(handler.Kind)
		if handler.Resume != nil {
			binding := *handler.Resume
			binding.Kind, binding.Namespace = strings.Clone(binding.Kind), strings.Clone(binding.Namespace)
			handler.Resume = &binding
		}
		if handler.Messages != nil {
			copy := *handler.Messages
			copy.Messages, err = handler.Messages.Messages.capture(owned)
			if err != nil {
				for _, previous := range p.registrations {
					if previous.config.Messages != nil {
						previous.config.Messages.Messages.releaseCodecs()
					}
				}
				owned.Release()
				delegates.Release()
				return nil, err
			}
			handler.Messages = &copy
		}
		end := start + int(handler.Slots)
		p.registrations[i] = streamHandlerRegistration{config: handler, start: start, end: end}
		for j := start; j < end; j++ {
			p.slots[j].registration = i
		}
		start = end
	}
	return p, nil
}

func (p *StreamHandlerPlan) CheckEnvironment(ref resourcev4.Reference) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return resourcev4.ErrClosed
	}
	return p.reservation.CheckSameEnvironment(ref)
}

func (p *StreamHandlerPlan) claimSession() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return resourcev4.ErrClosed
	}
	if p.claimed {
		return cryptov4.ErrTransition
	}
	if err := p.checkResourcesLocked(); err != nil {
		return err
	}
	p.claimed = true
	return nil
}

func (p *StreamHandlerPlan) Executor() *ApplicationExecutor {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.executor
}

// Capture is called by the original authenticated pending preparation gate.
// It grants no Stream I/O, proof or execution authority. Its single per-kind
// position remains charged across authorization, outcome and handler cleanup.
func (p *StreamHandlerPlan) Capture(kind string) (StreamHandlerCapture, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.application != nil && !p.applicationBound {
		return StreamHandlerCapture{}, ErrApplicationAuthorization
	}
	if p.closed {
		return StreamHandlerCapture{}, resourcev4.ErrClosed
	}
	if err := p.checkResourcesLocked(); err != nil {
		return StreamHandlerCapture{}, err
	}
	for _, registration := range p.registrations {
		if registration.config.Kind != kind {
			continue
		}
		for i := registration.start; i < registration.end; i++ {
			s := &p.slots[i]
			if !s.used && s.generation != math.MaxUint64 {
				s.generation++
				s.used, s.authorized = true, registration.config.AuthorizeOpen == nil
				p.active++
				return StreamHandlerCapture{p, i, s.generation}, nil
			}
		}
		return StreamHandlerCapture{}, cryptov4.ErrCapacity
	}
	return StreamHandlerCapture{}, ErrStreamHandlerKind
}

func (p *StreamHandlerPlan) checkResourcesLocked() error {
	if err := p.reservation.Check(); err != nil {
		return err
	}
	return p.delegates.Check()
}

func (c StreamHandlerCapture) slotLocked() (*streamHandlerCaptureSlot, error) {
	if c.plan == nil || c.slot < 0 || c.slot >= len(c.plan.slots) {
		return nil, resourcev4.ErrClosed
	}
	s := &c.plan.slots[c.slot]
	if !s.used || s.generation != c.generation || s.releasing {
		return nil, resourcev4.ErrClosed
	}
	return s, nil
}

func (c StreamHandlerCapture) projection() (RawStreamHandlerConfig, *ApplicationExecutor) {
	if c.plan == nil {
		return RawStreamHandlerConfig{}, nil
	}
	c.plan.mu.Lock()
	defer c.plan.mu.Unlock()
	s, err := c.slotLocked()
	if err != nil {
		return RawStreamHandlerConfig{}, nil
	}
	return c.plan.registrations[s.registration].config, c.plan.executor
}

func (c StreamHandlerCapture) Kind() string {
	registration, _ := c.projection()
	return registration.Kind
}
func (c StreamHandlerCapture) WorkClass() ApplicationWorkClass {
	registration, _ := c.projection()
	return registration.WorkClass
}
func (c StreamHandlerCapture) Executor() *ApplicationExecutor {
	_, executor := c.projection()
	return executor
}

// Generation is the immutable initial registration generation. The capture's
// separate private slot generation protects against release/reuse aliases.
func (c StreamHandlerCapture) Generation() uint64 {
	if registration, _ := c.projection(); registration.Kind != "" {
		return 1
	}
	return 0
}

func (c StreamHandlerCapture) begin(ctx context.Context, handling bool) (RawStreamHandlerConfig, any, error) {
	if c.plan == nil || ctx == nil {
		return RawStreamHandlerConfig{}, nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return RawStreamHandlerConfig{}, nil, err
	}
	p := c.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	s, err := c.slotLocked()
	if err != nil {
		return RawStreamHandlerConfig{}, nil, err
	}
	if !handling && p.closed {
		return RawStreamHandlerConfig{}, nil, resourcev4.ErrClosed
	}
	if s.busy || handling && (!s.accepted || s.handlerCalled) || !handling && (s.accepted || s.authorizationCalled) {
		return RawStreamHandlerConfig{}, nil, cryptov4.ErrTransition
	}
	if err := p.checkResourcesLocked(); err != nil {
		return RawStreamHandlerConfig{}, nil, err
	}
	s.busy = true
	if handling {
		s.handlerCalled = true
	} else {
		s.authorizationCalled = true
	}
	return p.registrations[s.registration].config, p.binding, nil
}

// Authorize runs inline on the dispatcher's original ordinary application
// permit, after proof and input-delivery gates. It never receives a Stream.
func (c StreamHandlerCapture) Authorize(ctx context.Context, metadata []byte) (err error) {
	registration, binding, err := c.begin(ctx, false)
	if err != nil {
		return err
	}
	err = ErrStreamHandlerCallbackExit
	defer func() {
		// Isolate application panics without retaining or formatting their values.
		if recover() != nil {
			err = ErrStreamHandlerCallbackExit
		}
		registration = RawStreamHandlerConfig{}
		binding = nil
		c.finish(false, &err)
	}()
	if registration.AuthorizeOpen != nil {
		err = registration.AuthorizeOpen(ctx, binding, metadata)
	} else {
		err = nil
	}
	if err == nil {
		err = ctx.Err()
	}
	return err
}

// Accept belongs inside the actual accepted OPEN submission/Resolve gate.
// It invokes no callback and allocates nothing. Closing the plan before this
// gate wins; closing it afterward preserves the already accepted registration.
func (c StreamHandlerCapture) Accept() error {
	if c.plan == nil {
		return resourcev4.ErrClosed
	}
	p := c.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	s, err := c.slotLocked()
	if err != nil {
		return err
	}
	if p.closed {
		return resourcev4.ErrClosed
	}
	if s.failure != nil {
		return s.failure
	}
	if s.busy || !s.authorized || s.accepted {
		return cryptov4.ErrTransition
	}
	if err := p.checkResourcesLocked(); err != nil {
		return err
	}
	s.accepted = true
	return nil
}

// Handle runs once inline after real acceptance, on the same admitted ordinary
// execution owner. The original Stream and invocation still gate user entry.
func (c StreamHandlerCapture) Handle(ctx context.Context, metadata []byte, stream *StreamOwnership) (err error) {
	if stream == nil {
		return cryptov4.ErrConfiguration
	}
	registration, binding, err := c.begin(ctx, true)
	if err != nil {
		return err
	}
	err = ErrStreamHandlerCallbackExit
	defer func() {
		if recover() != nil {
			err = ErrStreamHandlerCallbackExit
		}
		registration = RawStreamHandlerConfig{}
		binding = nil
		c.finish(true, &err)
	}()
	if err = stream.enterCallback(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Goexit runs the tail above without assigning a callback result.
	err = ErrStreamHandlerCallbackExit
	if registration.Messages != nil {
		stream.mu.Lock()
		messages := stream.typed
		stream.mu.Unlock()
		if messages == nil {
			return ErrStreamOwned
		}
		err = registration.Messages.Handler(ctx, binding, metadata, messages)
	} else {
		err = registration.Handler(ctx, binding, metadata, stream)
	}
	return err
}

func (c StreamHandlerCapture) finish(handling bool, err *error) {
	p := c.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	s := &p.slots[c.slot] // The original busy method retains this exact slot.
	s.busy = false
	if !handling {
		if *err == nil && (p.closed || s.releasing) {
			*err = resourcev4.ErrClosed
		}
		s.authorized = *err == nil
	}
	if s.failure == nil {
		s.failure = *err
	}
	if s.releasing {
		p.releaseLocked(c.slot)
	}
}

func (c StreamHandlerCapture) Release() {
	if c.plan == nil {
		return
	}
	p := c.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	s, err := c.slotLocked()
	if err != nil {
		return
	}
	s.releasing = true
	if !s.busy {
		p.releaseLocked(c.slot)
	}
}

func (p *StreamHandlerPlan) releaseLocked(index int) {
	s := &p.slots[index]
	*s = streamHandlerCaptureSlot{generation: s.generation, registration: s.registration}
	p.active--
	p.cleanupLocked()
}

func (p *StreamHandlerPlan) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cleanupLocked()
}

func (p *StreamHandlerPlan) cleanupLocked() {
	if !p.closed || p.cleaned || p.active != 0 {
		return
	}
	p.cleaned = true
	close(p.done)
}

func (p *StreamHandlerPlan) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Retire drops the immutable snapshot and original delegate borrow only after
// the plan is closed and every capture and application callback has exited.
func (p *StreamHandlerPlan) Retire() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired {
		return nil
	}
	if !p.cleaned {
		return cryptov4.ErrCapacity
	}
	p.retired = true
	for _, registration := range p.registrations {
		if registration.config.Messages != nil {
			registration.config.Messages.Messages.releaseCodecs()
		}
	}
	clear(p.registrations)
	p.registrations, p.slots, p.executor, p.binding, p.application = nil, nil, nil, nil, nil
	p.group = nil
	p.delegates.Release()
	p.reservation.Release()
	p.delegates, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	return nil
}

func (p *StreamHandlerPlan) Done() <-chan struct{} { return p.done }

// The declaration is frozen before the core claims it. Only its original
// application authorization may install the context, before any capture exists.
func (p *StreamHandlerPlan) requireApplication(application *SessionPlan) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.claimed || p.active != 0 || p.application != nil || p.binding != nil {
		return cryptov4.ErrTransition
	}
	if err := p.reservation.CheckSameEnvironment(application.reservation); err != nil {
		return err
	}
	p.application = application
	return nil
}
func (p *StreamHandlerPlan) bindApplication(application *SessionPlan, binding any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.claimed || p.active != 0 || p.application != application || p.applicationBound {
		return cryptov4.ErrTransition
	}
	p.binding, p.applicationBound = binding, true
	return nil
}
func (p *StreamHandlerPlan) detachApplication(application *SessionPlan) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.application == application {
		p.application = nil
		p.closed = true
		p.cleanupLocked()
	}
}
