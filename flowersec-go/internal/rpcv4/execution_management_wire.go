package rpcv4

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

const managementEnvelopeBytes = 2 + 512 + 1024

var (
	ErrManagementFraming     = errors.New("rpcv4: invalid execution management framing")
	ErrManagementSerial      = errors.New("rpcv4: invalid execution management serial")
	ErrManagementBinding     = errors.New("rpcv4: execution management response binding mismatch")
	ErrManagementClosed      = errors.New("rpcv4: execution management wire closed")
	ErrExecutionUnauthorized = errors.New("rpcv4: execution history access denied")
)

// ManagementSink is installed only by the admitted M Stream. Acceptance is a
// finite, all-or-nothing copy into its original SendService ring, with no I/O
// or application callback. The complete envelope includes its first prefix
// byte. Success irrevocably transfers its complete publication responsibility.
type ManagementSink interface {
	TryAcceptManagement(context.Context, []byte, ManagementPublicationGate) (uint64, error)
}

// ManagementPublicationGate runs after the sink's original Stream/crypto and
// capacity checks, around the bounded ring copy. It must not reenter the sink.
// A nil gate is used only for responses containing no authorized history fact.
type ManagementPublicationGate func(transfer func() error) error

// ExecutionManagementResolver derives authority from the current authenticated
// Session. Wire fields never grant permission or select a replacement store.
// It is a finite SDK callback and must not run application code or wait on it.
// Resolving a current RAM owner supplies no continuity evidence for an incoming
// remote operation. Absence remains history_unknown; only real records speak.
type ExecutionManagementResolver interface {
	ResolveExecutionManagement(context.Context, ExecutionTarget, bool) (*VolatileExecutions, ExecutionAccess, error)
}
type ExecutionManagementResolverFunc func(context.Context, ExecutionTarget, bool) (*VolatileExecutions, ExecutionAccess, error)

func (f ExecutionManagementResolverFunc) ResolveExecutionManagement(ctx context.Context, t ExecutionTarget, cancel bool) (*VolatileExecutions, ExecutionAccess, error) {
	if f == nil {
		return nil, nil, ErrOwner
	}
	return f(ctx, t, cancel)
}

// ExecutionManagementBindingResolver supports the exact registered durable or
// volatile owner. Resolution itself remains finite and performs no provider I/O.
// The older narrow resolver is retained for explicitly volatile compositions.
type ExecutionManagementBindingResolver interface {
	ResolveExecutionManagementBinding(context.Context, ExecutionTarget, bool) (ServiceBinding, ExecutionAccess, error)
}

// Each generation is constructed from the accepted channel's protected budget.
// Fixed SDK method bindings are distinct from the business target contract
// carried inside the request body. No binding comes from peer input.
type ExecutionManagementWireConfig struct {
	Clock        *timev4.Clock
	Sink         ManagementSink
	RuntimeBytes uint64
}
type managementWirePending struct {
	serial    uint64
	request   protocolv4.ApplicationHeader
	target    ExecutionTarget
	access    ExecutionAccess
	authority resourcev4.Reference
	deadline  *timev4.Deadline
	abandoned bool
}
type managementWireReply struct {
	serial       uint64
	length       int
	running      bool
	ready        bool
	cancel       bool
	target       ExecutionTarget
	access       ExecutionAccess
	deadline     *timev4.Deadline
	request      protocolv4.ApplicationHeaderFields
	requestError error
	wire         [managementEnvelopeBytes]byte
}

// ExecutionManagementWire is one actual channel generation, with two original
// response owners and two admitted short service positions. Completed response
// classification uses only the published high-water mark and bounded pending
// index; there are no historical per-serial tombstones or per-request tasks.
type ExecutionManagementWire struct {
	mu                 sync.Mutex
	spec               protocolv4.ManagementSpec
	config             ExecutionManagementWireConfig
	reservation        resourcev4.Reference
	headers            *protocolv4.ApplicationHeaderCodec
	bodies             *protocolv4.ManagementCodec
	pending            [2]managementWirePending
	replies            [2]managementWireReply
	outgoing           [managementEnvelopeBytes]byte
	highwater, inbound uint64
	closed, cleaned    bool
}

func ExecutionManagementWireCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	h, err := protocolv4.ApplicationHeaderBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	b, err := protocolv4.ManagementCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	// Four detached target strings and one original deadline per pending owner;
	// concurrent inbound SDK projections also remain inside this fixed allowance.
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ExecutionManagementWire{})) + h + b + 4*(512+uint64(unsafe.Sizeof(timev4.Deadline{}))), resourcev4.Items: 5, resourcev4.WorkSlots: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func NewExecutionManagementWire(c ExecutionManagementWireConfig, ref resourcev4.Reference) (*ExecutionManagementWire, error) {
	if c.Clock == nil || c.Sink == nil {
		return nil, ErrConfiguration
	}
	spec, err := protocolv4.Management()
	if err != nil {
		return nil, err
	}
	charge, err := ExecutionManagementWireCharge(c.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	owned, err := ref.Take(charge)
	if err != nil {
		return nil, err
	}
	h, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		owned.Release()
		return nil, err
	}
	b, err := protocolv4.NewManagementCodec()
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &ExecutionManagementWire{spec: spec, config: c, reservation: owned, headers: h, bodies: b}, nil
}
func managementTarget(t ExecutionTarget) protocolv4.ManagementTarget {
	return protocolv4.ManagementTarget{Tenant: t.Service.Tenant, Audience: t.Service.Audience, Namespace: t.Service.Namespace, Subject: t.Caller.Subject, Authority: t.Caller.Authority, Operation: t.Operation, RequestDigest: t.RequestDigest, ContractDigest: t.ContractDigest}
}
func executionTarget(t protocolv4.ManagementTarget) ExecutionTarget {
	return ExecutionTarget{Service: ExecutionService{Tenant: t.Tenant, Audience: t.Audience, Namespace: t.Namespace}, Caller: ExecutionPrincipal{Authority: t.Authority, Subject: t.Subject}, Operation: t.Operation, RequestDigest: t.RequestDigest, ContractDigest: t.ContractDigest}
}
func (w *ExecutionManagementWire) binding(cancel bool) QueryBinding {
	if cancel {
		return QueryBinding{Type: w.spec.Cancel.Type, Contract: w.spec.Cancel.Contract}
	}
	return QueryBinding{Type: w.spec.Query.Type, Contract: w.spec.Query.Contract}
}
func managementKind(cancel, response bool) string {
	if cancel {
		if response {
			return "request_cancel_response"
		}
		return "request_cancel_request"
	}
	if response {
		return "query_operation_response"
	}
	return "query_operation_request"
}
func (w *ExecutionManagementWire) encodeEnvelope(dst []byte, cancel, response bool, serial, deadline uint64, body []byte) (int, protocolv4.ApplicationHeader, error) {
	binding := w.binding(cancel)
	n, h, err := w.headers.Encode(dst[2:514], managementKind(cancel, response), protocolv4.ApplicationHeaderFields{Type: binding.Type, PayloadBytes: uint32(len(body)), ServiceContractDigest: binding.Contract, ControlSerial: serial, DeadlineAtMS: deadline})
	if err != nil {
		return 0, h, err
	}
	binary.BigEndian.PutUint16(dst[:2], uint16(n))
	copy(dst[2+n:], body)
	return n + 2 + len(body), h, nil
}
func (w *ExecutionManagementWire) decodeEnvelope(wire []byte) (protocolv4.ApplicationHeader, []byte, bool, error) {
	if len(wire) < 2 {
		return protocolv4.ApplicationHeader{}, nil, false, ErrManagementFraming
	}
	n := int(binary.BigEndian.Uint16(wire))
	if n < 1 || n > 512 || n > len(wire)-2 {
		return protocolv4.ApplicationHeader{}, nil, false, ErrManagementFraming
	}
	h, err := w.headers.Decode(wire[2 : 2+n])
	if err != nil {
		return h, nil, false, err
	}
	cancel := h.Kind() == "request_cancel_request" || h.Kind() == "request_cancel_response"
	if h.Kind() != managementKind(cancel, h.IsResponse()) {
		return h, nil, false, ErrManagementFraming
	}
	f := h.Fields()
	b := w.binding(cancel)
	if f.Type != b.Type || f.ServiceContractDigest != b.Contract {
		return h, nil, cancel, ErrManagementBinding
	}
	limit := uint32(1024)
	if h.IsResponse() {
		limit = 512
	}
	if f.PayloadBytes > limit || uint64(f.PayloadBytes) != uint64(len(wire)-2-n) {
		return h, nil, cancel, ErrManagementFraming
	}
	return h, wire[2+n:], cancel, nil
}

// TryRequest returns a serial only after the entire request is irrevocably
// accepted. A canceled/denied/full prepublication gate leaves no serial gap.
// Access and its original backing remain pinned through a full response or
// generation cleanup, even if the caller abandons its local wait.
func (w *ExecutionManagementWire) TryRequest(ctx context.Context, cancel bool, target ExecutionTarget, deadlineMS uint64, access ExecutionAccess) (uint64, error) {
	return w.tryRequest(ctx, cancel, target, deadlineMS, nil, access)
}

// TryRequestDeadline forks the caller's original clock projection rather than
// recreating an absolute deadline after waiting for channel initialization.
func (w *ExecutionManagementWire) TryRequestDeadline(ctx context.Context, cancel bool, target ExecutionTarget, deadline *timev4.Deadline, access ExecutionAccess) (uint64, error) {
	if deadline == nil {
		return 0, ErrConfiguration
	}
	return w.tryRequest(ctx, cancel, target, deadline.Cap(), deadline, access)
}
func (w *ExecutionManagementWire) tryRequest(ctx context.Context, cancel bool, target ExecutionTarget, deadlineMS uint64, original *timev4.Deadline, access ExecutionAccess) (uint64, error) {
	if w == nil || ctx == nil || access == nil {
		return 0, ErrConfiguration
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrManagementClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if w.highwater == math.MaxUint64 {
		return 0, ErrSerialExhausted
	}
	index := -1
	for i := range w.pending {
		if w.pending[i].serial == 0 {
			index = i
			break
		}
	}
	if index < 0 {
		return 0, ErrCapacity
	}
	var deadline *timev4.Deadline
	var err error
	if original == nil {
		deadline, err = w.newDeadline(deadlineMS)
	} else {
		if !original.BelongsTo(w.config.Clock) {
			return 0, ErrConfiguration
		}
		deadline, err = original.Fork(deadlineMS)
		if err == nil {
			now, sampleErr := deadline.Sample()
			err = sampleErr
			if err == nil && (deadlineMS <= now.LowerMS || deadlineMS-now.LowerMS > w.spec.MaxLifetimeMS) {
				err = ErrManagementFraming
			}
		}
	}
	if err != nil {
		return 0, err
	}
	if err = deadline.Check(); err != nil {
		return 0, err
	}
	// The payload is built at the end so prefix/header compaction is overlap-safe.
	body := w.outgoing[514:]
	n, err := w.bodies.EncodeTarget(body, managementTarget(target))
	if err != nil {
		return 0, err
	}
	defer clear(w.outgoing[:])
	serial := w.highwater + 1
	length, h, err := w.encodeEnvelope(w.outgoing[:], cancel, false, serial, deadlineMS, body[:n])
	if err != nil {
		return 0, err
	}
	// Copy string backing before the irreversible gate; user substrings cannot
	// retain arbitrarily large buffers in a bounded pending association.
	target.Service.Tenant = strings.Clone(target.Service.Tenant)
	target.Service.Audience = strings.Clone(target.Service.Audience)
	target.Service.Namespace = strings.Clone(target.Service.Namespace)
	target.Caller.Subject = strings.Clone(target.Caller.Subject)
	_, err = w.config.Sink.TryAcceptManagement(ctx, w.outgoing[:length], func(transfer func() error) error {
		return access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
			if err := w.reservation.CheckSameEnvironment(authority); err != nil {
				return err
			}
			pinned, err := authority.Borrow()
			if err != nil {
				return err
			}
			if err = deadline.Check(); err == nil {
				err = transfer()
			}
			if err != nil {
				pinned.Release()
				return err
			}
			w.highwater = serial
			w.pending[index] = managementWirePending{serial: serial, request: h, target: target, access: access, authority: pinned, deadline: deadline}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return serial, nil
}

// Abandon never refunds an unfinished response or deletes its late association.
func (w *ExecutionManagementWire) Abandon(serial uint64) error {
	if w == nil {
		return ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrManagementClosed
	}
	for i := range w.pending {
		if w.pending[i].serial == serial && serial != 0 {
			w.pending[i].abandoned = true
			return nil
		}
	}
	return ErrManagementSerial
}

type ManagementResponseDisposition uint8

const (
	ManagementResponseDelivered ManagementResponseDisposition = iota
	ManagementResponseDiscarded
	ManagementResponseRejected
)

// AcceptResponse validates the complete canonical payload before releasing an
// association. Out-of-order completion is legal; canceled and fully completed
// duplicates are consumed once without producing another result value.
func (w *ExecutionManagementWire) AcceptResponse(wire []byte) (ManagementResponse, uint64, ManagementResponseDisposition, error) {
	if w == nil {
		return ManagementResponse{}, 0, 0, ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ManagementResponse{}, 0, 0, ErrManagementClosed
	}
	h, body, cancel, err := w.decodeEnvelope(wire)
	if err != nil {
		return ManagementResponse{}, 0, 0, err
	}
	serial := h.Fields().ControlSerial
	if !h.IsResponse() {
		return ManagementResponse{}, serial, 0, ErrManagementFraming
	}
	if serial == 0 || serial > w.highwater {
		return ManagementResponse{}, serial, 0, ErrManagementSerial
	}
	decoded, err := w.bodies.DecodeResult(body, cancel)
	if err != nil {
		return ManagementResponse{}, serial, 0, err
	}
	index := -1
	for i := range w.pending {
		if w.pending[i].serial == serial {
			index = i
			break
		}
	}
	if index < 0 {
		return ManagementResponse{}, serial, ManagementResponseDiscarded, nil
	}
	p := &w.pending[index]
	if err = p.request.MatchResponse(h); err != nil {
		return ManagementResponse{}, serial, 0, ErrManagementBinding
	}
	defer func() { p.authority.Release(); *p = managementWirePending{} }()
	if p.abandoned {
		return ManagementResponse{}, serial, ManagementResponseDiscarded, nil
	}
	err = p.access.WithExecutionAccess(p.target, func(authority resourcev4.Reference) error {
		if err := p.authority.CheckSameEnvironment(authority); err != nil {
			return err
		}
		return p.deadline.Check()
	})
	if err != nil {
		return ManagementResponse{}, serial, ManagementResponseRejected, err
	}
	o := decoded.Observation
	obs := ExecutionObservation{Found: o.Found, State: ExecutionState(o.State), CancelRequested: o.CancelRequested, Dispatched: o.Dispatched, WorkActive: o.WorkActive, HistoryNotBeforeGCMS: o.HistoryNotBeforeGCMS, ResultNotAfterMS: o.ResultNotAfterMS, ResultAvailable: o.ResultAvailable, ResultDeleted: o.ResultDeleted, ResultBytes: o.ResultBytes, ApplicationErrorCode: o.ApplicationErrorCode, ResultDigest: o.ResultDigest, Reason: o.Reason}
	return ManagementResponse{Serial: serial, Observation: obs, Cancel: ExecutionCancelResult{Kind: decoded.CancelKind, Observation: obs}, IsCancel: cancel, Status: decoded.Status}, serial, ManagementResponseDelivered, nil
}

// ManagementReply retains one protected service/result position until its
// complete response is transferred to the original channel's sending ring.
// Its generation is object identity and serial; the peer cannot choose either.
type ManagementReply struct {
	wire   *ExecutionManagementWire
	index  int
	serial uint64
}

func (r ManagementReply) Publish(ctx context.Context) error {
	w := r.wire
	if w == nil || ctx == nil {
		return ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := r.checkLocked(); err != nil {
		return err
	}
	p := &w.replies[r.index]
	var gate ManagementPublicationGate
	var denied error
	if p.access != nil {
		gate = func(transfer func() error) error {
			denied = p.access.WithExecutionAccess(p.target, func(authority resourcev4.Reference) error {
				if err := w.reservation.CheckSameEnvironment(authority); err != nil {
					return err
				}
				if err := p.deadline.Check(); err != nil {
					return err
				}
				return transfer()
			})
			return denied
		}
	}
	_, err := w.config.Sink.TryAcceptManagement(ctx, p.wire[:p.length], gate)
	if denied != nil {
		// An authorization/expiry refusal cannot publish the prepared history
		// facts. The same protected slot sends a bounded failure instead.
		if err := w.encodeReplyLocked(p, protocolv4.ManagementResult{Status: managementError(denied)}); err != nil {
			return err
		}
		p.access = nil
		_, err = w.config.Sink.TryAcceptManagement(ctx, p.wire[:p.length], nil)
	}
	if err != nil {
		return err
	}
	*p = managementWireReply{}
	return nil
}

func (r ManagementReply) checkLocked() error {
	if r.wire.closed {
		return ErrManagementClosed
	}
	if r.index < 0 || r.index >= len(r.wire.replies) {
		return ErrOwner
	}
	p := &r.wire.replies[r.index]
	if p.serial != r.serial || p.running || p.length == 0 {
		return ErrOwner
	}
	return nil
}

func (w *ExecutionManagementWire) encodeReplyLocked(p *managementWireReply, result protocolv4.ManagementResult) error {
	clear(p.wire[:])
	n, err := w.bodies.EncodeResult(p.wire[514:], result, p.cancel)
	if err == nil {
		p.length, _, err = w.encodeEnvelope(p.wire[:], p.cancel, true, p.serial, 0, p.wire[514:514+n])
	}
	return err
}
func managementResult(r ManagementResponse) protocolv4.ManagementResult {
	o := r.Observation
	status := r.Status
	if status == "" {
		status = "ok"
	}
	return protocolv4.ManagementResult{Status: status, CancelKind: r.Cancel.Kind, Observation: protocolv4.ManagementObservation{Found: o.Found, State: uint8(o.State), CancelRequested: o.CancelRequested, Dispatched: o.Dispatched, WorkActive: o.WorkActive, HistoryNotBeforeGCMS: o.HistoryNotBeforeGCMS, ResultNotAfterMS: o.ResultNotAfterMS, ResultAvailable: o.ResultAvailable, ResultDeleted: o.ResultDeleted, ResultBytes: o.ResultBytes, ApplicationErrorCode: o.ApplicationErrorCode, ResultDigest: o.ResultDigest, Reason: o.Reason}}
}
func managementError(err error) string {
	switch {
	case errors.Is(err, ErrExecutionUnauthorized):
		return "unauthorized"
	case errors.Is(err, timev4.ErrExpired), errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, ErrExecutionConflict):
		return "operation_conflict"
	case errors.Is(err, ErrExecutionUnsupported):
		return "unsupported"
	default:
		return "unavailable"
	}
}

// BeginRequestHeader runs on the sole reader before payload consumption. It
// fixes the original deadline and service position independently of worker
// scheduling. Partial messages keep their original position until cleanup.
func (w *ExecutionManagementWire) BeginRequestHeader(h protocolv4.ApplicationHeader) (ManagementJob, error) {
	if w == nil {
		return ManagementJob{}, ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.beginRequestLocked(h)
}
func (w *ExecutionManagementWire) newDeadline(cap uint64) (*timev4.Deadline, error) {
	d, err := timev4.NewDeadline(w.config.Clock, cap)
	if err != nil {
		return nil, err
	}
	now, err := d.Sample()
	if err != nil {
		return nil, err
	}
	if cap <= now.LowerMS || cap-now.LowerMS > w.spec.MaxLifetimeMS {
		return nil, ErrManagementFraming
	}
	return d, nil
}
func (w *ExecutionManagementWire) beginRequestLocked(h protocolv4.ApplicationHeader) (ManagementJob, error) {
	if w.closed {
		return ManagementJob{}, ErrManagementClosed
	}
	cancel := h.Kind() == "request_cancel_request"
	if h.Kind() != managementKind(cancel, false) {
		return ManagementJob{}, ErrManagementFraming
	}
	f, binding := h.Fields(), w.binding(cancel)
	if f.Type != binding.Type || f.ServiceContractDigest != binding.Contract || f.PayloadBytes > 1024 {
		return ManagementJob{}, ErrManagementBinding
	}
	if w.inbound == math.MaxUint64 || f.ControlSerial != w.inbound+1 {
		return ManagementJob{}, ErrManagementSerial
	}
	index := -1
	for i := range w.replies {
		if w.replies[i].serial == 0 {
			index = i
			break
		}
	}
	if index < 0 {
		return ManagementJob{}, ErrCapacity
	}
	deadline, err := w.newDeadline(f.DeadlineAtMS)
	w.inbound = f.ControlSerial
	w.replies[index] = managementWireReply{serial: f.ControlSerial, cancel: cancel, deadline: deadline, requestError: err, request: f}
	return ManagementJob{wire: w, index: index, serial: f.ControlSerial}, nil
}

// ManagementJob is a bounded original position, never an application task.
// Admit completes its canonical body; Run claims it exactly once.
type ManagementJob struct {
	wire   *ExecutionManagementWire
	index  int
	serial uint64
}

// RemainingMS exposes only the original receive/work cap, never a fresh
// projection. A stalled body cannot hold a protected position indefinitely.
func (j ManagementJob) RemainingMS() (uint64, error) {
	w := j.wire
	if w == nil {
		return 0, ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrManagementClosed
	}
	p := &w.replies[j.index]
	if p.serial != j.serial {
		return 0, ErrOwner
	}
	if p.requestError != nil {
		return 0, p.requestError
	}
	return p.deadline.RemainingMS()
}
func (j ManagementJob) Admit(wire []byte) error {
	w := j.wire
	if w == nil {
		return ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrManagementClosed
	}
	p := &w.replies[j.index]
	if p.serial != j.serial || p.ready || p.running || p.length != 0 {
		return ErrOwner
	}
	h, body, cancel, err := w.decodeEnvelope(wire)
	if err != nil {
		return err
	}
	if h.IsResponse() || h.Fields() != p.request || cancel != p.cancel {
		return ErrManagementBinding
	}
	target, err := w.bodies.DecodeTarget(body)
	if err != nil {
		return err
	}
	p.target, p.ready = executionTarget(target), true
	return nil
}
func (w *ExecutionManagementWire) BeginRequest(wire []byte) (ManagementJob, error) {
	if w == nil {
		return ManagementJob{}, ErrOwner
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ManagementJob{}, ErrManagementClosed
	}
	h, _, _, err := w.decodeEnvelope(wire)
	var job ManagementJob
	if err == nil {
		job, err = w.beginRequestLocked(h)
	}
	w.mu.Unlock()
	if err == nil {
		err = job.Admit(wire)
	}
	return job, err
}
func (w *ExecutionManagementWire) HandleRequest(ctx context.Context, resolver ExecutionManagementResolver, wire []byte) (ManagementReply, error) {
	if ctx == nil || resolver == nil {
		return ManagementReply{}, ErrConfiguration
	}
	job, err := w.BeginRequest(wire)
	if err != nil {
		return ManagementReply{}, err
	}
	return job.Run(ctx, resolver)
}
func (j ManagementJob) Run(ctx context.Context, resolver ExecutionManagementResolver) (reply ManagementReply, err error) {
	w := j.wire
	if w == nil || ctx == nil || resolver == nil {
		return reply, ErrConfiguration
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return reply, ErrManagementClosed
	}
	p := &w.replies[j.index]
	if p.serial != j.serial || !p.ready || p.running || p.length != 0 {
		w.mu.Unlock()
		return reply, ErrOwner
	}
	p.ready, p.running = false, true
	index, serial, cancel := j.index, j.serial, p.cancel
	target, deadline, callErr := p.target, p.deadline, p.requestError
	w.mu.Unlock()
	// The admitted short SDK service executes outside the channel gate. Cleanup
	// retains its entire owner if resolution is still in progress during Close.
	completed := false
	defer func() {
		if !completed {
			w.mu.Lock()
			w.replies[index] = managementWireReply{}
			w.closeLocked()
			w.mu.Unlock()
		}
	}()
	result := protocolv4.ManagementResult{Status: "unavailable"}
	var access ExecutionAccess
	if callErr == nil {
		callErr = deadline.Check()
	}
	if callErr == nil {
		callErr = ctx.Err()
	}
	if callErr == nil {
		var binding ServiceBinding
		var resolveErr error
		if bound, ok := resolver.(ExecutionManagementBindingResolver); ok {
			binding, access, resolveErr = bound.ResolveExecutionManagementBinding(ctx, target, cancel)
		} else {
			binding.History, access, resolveErr = resolver.ResolveExecutionManagement(ctx, target, cancel)
		}
		callErr = resolveErr
		if callErr == nil {
			callErr = deadline.Check()
		}
		if callErr == nil {
			callErr = ctx.Err()
		}
		if callErr == nil {
			request := ManagementRequest{Serial: serial, Target: target, History: binding.History, DurableHistory: binding.DurableHistory, Access: access, Cancel: cancel}
			var response ManagementResponse
			response, callErr = executeManagement(ctx, request)
			if callErr == nil {
				result = managementResult(response)
			}
		}
	}
	if callErr != nil {
		result = protocolv4.ManagementResult{Status: managementError(callErr)}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	p = &w.replies[index]
	p.running = false
	if w.closed {
		*p = managementWireReply{}
		w.cleanupLocked()
		completed = true
		return reply, ErrManagementClosed
	}
	// Conflicts also reveal a fact about this key. Keep the resolved permission
	// for every response derived from the authority, including bounded errors.
	p.access = access
	err = w.encodeReplyLocked(p, result)
	if err != nil {
		*p = managementWireReply{}
		w.closeLocked()
		completed = true
		return reply, err
	}
	completed = true
	return ManagementReply{wire: w, index: index, serial: serial}, nil
}
func (w *ExecutionManagementWire) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closeLocked()
}
func (w *ExecutionManagementWire) closeLocked() {
	w.closed = true
	for i := range w.pending {
		w.pending[i].authority.Release()
		w.pending[i] = managementWirePending{}
	}
	for i := range w.replies {
		if !w.replies[i].running {
			w.replies[i] = managementWireReply{}
		}
	}
	w.cleanupLocked()
}
func (w *ExecutionManagementWire) cleanupLocked() {
	if !w.closed || w.cleaned {
		return
	}
	for i := range w.replies {
		if w.replies[i].running {
			return
		}
	}
	clear(w.outgoing[:])
	w.config = ExecutionManagementWireConfig{}
	w.headers = nil
	w.bodies = nil
	w.reservation.Release()
	w.reservation = resourcev4.Reference{}
	w.cleaned = true
}
func (w *ExecutionManagementWire) CleanupComplete() bool {
	if w == nil {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cleaned
}
