package rpcv4

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
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

// AuthorizedManagementSink is implemented by the original writer when the
// caller already holds the complete endpoint/lease authorization gate. It
// performs only the final bounded ownership/capacity/ring transfer and must
// not reacquire the same non-reentrant Engine authorization lock.
type AuthorizedManagementSink interface {
	TryAcceptAuthorizedManagement(context.Context, []byte, ManagementPublicationGate) (uint64, error)
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
	Clock *timev4.Clock
	Sink  ManagementSink
	// Original Session gates are bounded SDK reads and execute no application code.
	DrainDeadline func() *timev4.Deadline
	AdmissionOpen func() bool
	RuntimeBytes  uint64
}
type managementWirePending struct {
	ownerToken    uint64
	serial        uint64
	request       protocolv4.ApplicationHeader
	target        ExecutionTarget
	access        ExecutionAccess
	authority     resourcev4.Reference
	deadline      *timev4.Deadline
	publishing    bool
	processing    bool
	abandoned     bool
	earlyReady    bool
	earlyResponse ManagementResponse
}
type managementWireReply struct {
	serial              uint64
	length              int
	running             bool
	publishing          bool
	timedOut, published bool
	ready               bool
	cancel              bool
	target              ExecutionTarget
	access              ExecutionAccess
	deadline            *timev4.Deadline
	request             protocolv4.ApplicationHeaderFields
	requestError        error
	wire                [managementEnvelopeBytes]byte
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
	sampleActive       uint32
	sampleDone         chan struct{}
	responseActive     uint32
	responseDone       chan struct{}
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
	return &ExecutionManagementWire{spec: spec, config: c, reservation: owned, headers: h, bodies: b, sampleDone: make(chan struct{}), responseDone: make(chan struct{})}, nil
}
func managementTarget(t ExecutionTarget) protocolv4.ManagementTarget {
	return protocolv4.ManagementTarget{Tenant: t.Service.Tenant, Audience: t.Service.Audience, Namespace: t.Service.Namespace, Subject: t.Caller.Subject, Authority: t.Caller.Authority, Operation: t.Operation, RequestDigest: t.RequestDigest, ContractDigest: t.ContractDigest}
}
func executionTarget(t protocolv4.ManagementTarget) ExecutionTarget {
	return ExecutionTarget{Service: ExecutionService{Tenant: t.Tenant, Audience: t.Audience, Namespace: t.Namespace}, Caller: ExecutionPrincipal{Authority: t.Authority, Subject: t.Subject}, Operation: t.Operation, RequestDigest: t.RequestDigest, ContractDigest: t.ContractDigest}
}
func (w *ExecutionManagementWire) acceptManagement(ctx context.Context, wire []byte, gate ManagementPublicationGate) (uint64, error) {
	if sink, ok := w.config.Sink.(AuthorizedManagementSink); ok {
		return sink.TryAcceptAuthorizedManagement(ctx, wire, gate)
	}
	return w.config.Sink.TryAcceptManagement(ctx, wire, gate)
}

func (w *ExecutionManagementWire) checkDeadlineAt(deadline *timev4.Deadline, sample timev4.Sample) error {
	if w.config.AdmissionOpen != nil && !w.config.AdmissionOpen() {
		return ErrManagementClosed
	}
	if deadline == nil {
		return ErrManagementFraming
	}
	if w.config.DrainDeadline != nil {
		if original := w.config.DrainDeadline(); original != nil {
			return deadline.TightenFromAt(original, sample)
		}
	}
	return deadline.CheckAt(sample)
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
	return w.tryRequest(ctx, cancel, target, deadlineMS, nil, access, 0)
}

// TryRequestDeadline forks the caller's original clock projection rather than
// recreating an absolute deadline after waiting for channel initialization.
func (w *ExecutionManagementWire) TryRequestDeadline(ctx context.Context, cancel bool, target ExecutionTarget, deadline *timev4.Deadline, access ExecutionAccess) (uint64, error) {
	if deadline == nil {
		return 0, ErrConfiguration
	}
	return w.tryRequest(ctx, cancel, target, deadline.Cap(), deadline, access, 0)
}

// TryRequestDeadlineOwned binds the wire reservation to the channel-owned call token.
// The token is carried with the pending serial before publication starts, so a
// response arriving during the finite send gate can be returned to its owner.
func (w *ExecutionManagementWire) TryRequestDeadlineOwned(ctx context.Context, cancel bool, target ExecutionTarget, deadline *timev4.Deadline, access ExecutionAccess, ownerToken uint64) (uint64, error) {
	if ownerToken == 0 {
		return 0, ErrOwner
	}
	return w.tryRequest(ctx, cancel, target, deadline.Cap(), deadline, access, ownerToken)
}
func (w *ExecutionManagementWire) tryRequest(ctx context.Context, cancel bool, target ExecutionTarget, deadlineMS uint64, original *timev4.Deadline, access ExecutionAccess, ownerToken uint64) (uint64, error) {
	if w == nil || ctx == nil || access == nil {
		return 0, ErrConfiguration
	}
	sample, sampleErr, releaseSample := w.sampleClock()
	defer releaseSample()
	clock := w.sampleClockOwner()
	if sampleErr != nil {
		return 0, sampleErr
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	var wire [managementEnvelopeBytes]byte
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, ErrManagementClosed
	}
	if w.highwater == math.MaxUint64 {
		w.mu.Unlock()
		return 0, ErrSerialExhausted
	}
	index := -1
	for i := range w.pending {
		if w.pending[i].publishing {
			// The peer requires contiguous control serials. Keep the single
			// serial reservation gate held until this publication commits.
			w.mu.Unlock()
			return 0, ErrCapacity
		}
		if index < 0 && w.pending[i].serial == 0 {
			index = i
		}
		if ownerToken != 0 && w.pending[i].ownerToken == ownerToken && w.pending[i].serial != 0 {
			w.mu.Unlock()
			return 0, ErrOwner
		}
	}
	if index < 0 {
		w.mu.Unlock()
		return 0, ErrCapacity
	}
	serial := w.highwater + 1
	var deadline *timev4.Deadline
	var err error
	if original == nil {
		deadline, err = w.newDeadlineAt(clock, deadlineMS, sample, sampleErr)
	} else {
		if !original.BelongsTo(clock) {
			w.mu.Unlock()
			return 0, ErrConfiguration
		}
		deadline, err = original.ForkAt(deadlineMS, sample)
		if err == nil && (deadlineMS <= sample.LowerMS || deadlineMS-sample.LowerMS > w.spec.MaxLifetimeMS) {
			err = ErrManagementFraming
		}
	}
	if err == nil {
		err = w.checkDeadlineAt(deadline, sample)
	}
	if err != nil {
		w.mu.Unlock()
		return 0, err
	}
	deadlineMS = deadline.Cap()
	body := wire[514:]
	n, err := w.bodies.EncodeTarget(body, managementTarget(target))
	if err == nil {
		var h protocolv4.ApplicationHeader
		var length int
		length, h, err = w.encodeEnvelope(wire[:], cancel, false, serial, deadlineMS, body[:n])
		if err == nil {
			target.Service.Tenant = strings.Clone(target.Service.Tenant)
			target.Service.Audience = strings.Clone(target.Service.Audience)
			target.Service.Namespace = strings.Clone(target.Service.Namespace)
			target.Caller.Subject = strings.Clone(target.Caller.Subject)
			w.pending[index] = managementWirePending{ownerToken: ownerToken, serial: serial, request: h, target: target, access: access, deadline: deadline, publishing: true}
			w.mu.Unlock()

			var pinned resourcev4.Reference
			err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
				if err := w.reservation.CheckSameEnvironment(authority); err != nil {
					return err
				}
				var borrowErr error
				pinned, borrowErr = authority.Borrow()
				if borrowErr != nil {
					return borrowErr
				}
				if err := w.checkDeadlineAt(deadline, sample); err != nil {
					pinned.Release()
					pinned = resourcev4.Reference{}
					return err
				}
				w.mu.Lock()
				p := &w.pending[index]
				if p.serial != serial || !p.publishing {
					w.mu.Unlock()
					pinned.Release()
					pinned = resourcev4.Reference{}
					return ErrOwner
				}
				p.authority, pinned = pinned, resourcev4.Reference{}
				w.mu.Unlock()
				gate := func(transfer func() error) error {
					fresh, err := clock.Sample()
					if err != nil {
						return err
					}
					if err := w.checkDeadlineAt(deadline, fresh); err != nil {
						return err
					}
					return transfer()
				}
				_, err = w.acceptManagement(ctx, wire[:length], gate)
				return err
			})
			w.mu.Lock()
			p := &w.pending[index]
			if err == nil && !w.closed && p.serial == serial && p.publishing {
				p.publishing = false
				w.highwater = serial
				if p.earlyReady {
					p.authority.Release()
					*p = managementWirePending{}
				}
				w.mu.Unlock()
				return serial, nil
			}
			if pinned != (resourcev4.Reference{}) {
				pinned.Release()
			}
			if p.serial == serial {
				if p.authority != (resourcev4.Reference{}) {
					p.authority.Release()
				}
				*p = managementWirePending{}
			}
			closed := w.closed
			w.mu.Unlock()
			if closed && err == nil {
				return 0, ErrManagementClosed
			}
			return 0, err
		}
	}
	w.mu.Unlock()
	return 0, err
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
	response, serial, _, disposition, err := w.acceptResponseWithOwner(wire)
	return response, serial, disposition, err
}

// AcceptResponseWithOwner is the channel-facing response gate. The returned
// owner token is the token recorded with the wire reservation, including when
// a response races the finite publication gate. Callers must use it to route
// an early response; choosing the first publishing caller is unsafe.
func (w *ExecutionManagementWire) AcceptResponseWithOwner(wire []byte) (ManagementResponse, uint64, uint64, ManagementResponseDisposition, error) {
	return w.acceptResponseWithOwner(wire)
}

func (w *ExecutionManagementWire) acceptResponseWithOwner(wire []byte) (ManagementResponse, uint64, uint64, ManagementResponseDisposition, error) {
	if w == nil {
		return ManagementResponse{}, 0, 0, 0, ErrOwner
	}
	sample, sampleErr, releaseSample := w.sampleClock()
	defer releaseSample()
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ManagementResponse{}, 0, 0, 0, ErrManagementClosed
	}
	w.mu.Unlock()
	h, body, cancel, err := w.decodeEnvelope(wire)
	if err != nil {
		return ManagementResponse{}, 0, 0, 0, err
	}
	serial := h.Fields().ControlSerial
	if !h.IsResponse() {
		return ManagementResponse{}, serial, 0, 0, ErrManagementFraming
	}
	decoded, err := w.bodies.DecodeResult(body, cancel)
	if err != nil {
		return ManagementResponse{}, serial, 0, 0, err
	}

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ManagementResponse{}, serial, 0, 0, ErrManagementClosed
	}
	index := -1
	for i := range w.pending {
		if w.pending[i].serial == serial {
			index = i
			break
		}
	}
	if index < 0 {
		if serial == 0 || serial > w.highwater {
			w.mu.Unlock()
			return ManagementResponse{}, serial, 0, 0, ErrManagementSerial
		}
		w.mu.Unlock()
		return ManagementResponse{}, serial, 0, ManagementResponseDiscarded, nil
	}
	p := &w.pending[index]
	ownerToken := p.ownerToken
	if err = p.request.MatchResponse(h); err != nil {
		w.mu.Unlock()
		return ManagementResponse{}, serial, ownerToken, 0, ErrManagementBinding
	}
	if p.publishing {
		o := decoded.Observation
		obs := ExecutionObservation{Found: o.Found, State: ExecutionState(o.State), CancelRequested: o.CancelRequested, Dispatched: o.Dispatched, WorkActive: o.WorkActive, HistoryNotBeforeGCMS: o.HistoryNotBeforeGCMS, ResultNotAfterMS: o.ResultNotAfterMS, ResultAvailable: o.ResultAvailable, ResultDeleted: o.ResultDeleted, ResultBytes: o.ResultBytes, ApplicationErrorCode: o.ApplicationErrorCode, ResultDigest: o.ResultDigest, Reason: o.Reason}
		response := ManagementResponse{Serial: serial, Observation: obs, Cancel: ExecutionCancelResult{Kind: decoded.CancelKind, Observation: obs}, IsCancel: cancel, Status: decoded.Status}
		p.earlyReady, p.earlyResponse = true, response
		w.mu.Unlock()
		return response, serial, ownerToken, ManagementResponseDiscarded, nil
	}
	if p.processing {
		w.mu.Unlock()
		return ManagementResponse{}, serial, ownerToken, ManagementResponseDiscarded, nil
	}
	if p.abandoned {
		p.authority.Release()
		*p = managementWirePending{}
		w.mu.Unlock()
		return ManagementResponse{}, serial, ownerToken, ManagementResponseDiscarded, nil
	}
	p.processing = true
	target, access, authority, deadline := p.target, p.access, p.authority, p.deadline
	w.responseActive++
	w.mu.Unlock()

	err = access.WithExecutionAccess(target, func(current resourcev4.Reference) error {
		return authority.CheckSameEnvironment(current)
	})
	if err == nil {
		if sampleErr != nil {
			err = sampleErr
		} else {
			err = w.checkDeadlineAt(deadline, sample)
		}
	}

	w.mu.Lock()
	p = &w.pending[index]
	if p.serial == serial && p.processing {
		p.authority.Release()
		*p = managementWirePending{}
	}
	w.responseActive--
	if w.closed && w.responseActive == 0 && w.responseDone != nil {
		select {
		case <-w.responseDone:
		default:
			close(w.responseDone)
		}
	}
	w.cleanupLocked()
	w.mu.Unlock()
	if err != nil {
		return ManagementResponse{}, serial, ownerToken, ManagementResponseRejected, err
	}
	o := decoded.Observation
	obs := ExecutionObservation{Found: o.Found, State: ExecutionState(o.State), CancelRequested: o.CancelRequested, Dispatched: o.Dispatched, WorkActive: o.WorkActive, HistoryNotBeforeGCMS: o.HistoryNotBeforeGCMS, ResultNotAfterMS: o.ResultNotAfterMS, ResultAvailable: o.ResultAvailable, ResultDeleted: o.ResultDeleted, ResultBytes: o.ResultBytes, ApplicationErrorCode: o.ApplicationErrorCode, ResultDigest: o.ResultDigest, Reason: o.Reason}
	return ManagementResponse{Serial: serial, Observation: obs, Cancel: ExecutionCancelResult{Kind: decoded.CancelKind, Observation: obs}, IsCancel: cancel, Status: decoded.Status}, serial, ownerToken, ManagementResponseDelivered, nil
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
	_, sampleErr, releaseSample := w.sampleClock()
	defer releaseSample()
	w.mu.Lock()
	if err := r.checkLocked(); err != nil {
		w.mu.Unlock()
		return err
	}
	p := &w.replies[r.index]
	if p.deadline == nil {
		w.mu.Unlock()
		return ErrManagementFraming
	}
	if p.publishing {
		w.mu.Unlock()
		return ErrOwner
	}
	p.publishing = true
	length := p.length
	var wire [managementEnvelopeBytes]byte
	copy(wire[:length], p.wire[:length])
	target, access, deadline := p.target, p.access, p.deadline
	w.mu.Unlock()

	// Any exceptional exit before the final state transition must release the
	// original publishing owner so this bounded reply can be retried or cleaned.
	settled := false
	defer func() {
		if settled {
			return
		}
		w.mu.Lock()
		if r.index >= 0 && r.index < len(w.replies) && w.replies[r.index].serial == r.serial {
			w.replies[r.index].publishing = false
		}
		w.cleanupLocked()
		w.mu.Unlock()
	}()

	var gate ManagementPublicationGate
	if deadline != nil {
		gate = func(transfer func() error) error {
			fresh, err := w.config.Clock.Sample()
			if err != nil {
				return err
			}
			if err := w.checkDeadlineAt(deadline, fresh); err != nil {
				return err
			}
			return transfer()
		}
	}
	var denied, publishErr, err error
	entered := false
	if access != nil {
		denied = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
			if err := w.reservation.CheckSameEnvironment(authority); err != nil {
				return err
			}
			if deadline != nil && sampleErr != nil {
				return sampleErr
			}
			entered = true
			_, publishErr = w.acceptManagement(ctx, wire[:length], gate)
			return publishErr
		})
		if entered {
			err = publishErr
		} else {
			err = denied
		}
	} else {
		_, err = w.config.Sink.TryAcceptManagement(ctx, wire[:length], gate)
	}
	if denied != nil && !entered {
		w.mu.Lock()
		if err := r.checkLocked(); err != nil {
			w.mu.Unlock()
			return err
		}
		p = &w.replies[r.index]
		if err := w.encodeReplyLocked(p, protocolv4.ManagementResult{Status: managementError(denied)}); err != nil {
			w.mu.Unlock()
			return err
		}
		length = p.length
		copy(wire[:length], p.wire[:length])
		p.access = nil
		w.mu.Unlock()
		_, err = w.config.Sink.TryAcceptManagement(ctx, wire[:length], gate)
	}
	if err != nil {
		return err
	}
	w.mu.Lock()
	if r.index < 0 || r.index >= len(w.replies) || w.replies[r.index].serial != r.serial {
		w.mu.Unlock()
		return ErrOwner
	}
	p = &w.replies[r.index]
	if p.running {
		p.publishing = false
		p.published = true
		p.length = 0
		clear(p.wire[:])
	} else {
		*p = managementWireReply{}
	}
	w.cleanupLocked()
	settled = true
	w.mu.Unlock()
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
	if p.serial != r.serial || p.running && !p.timedOut || p.published || p.length == 0 {
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
	sample, sampleErr, releaseSample := w.sampleClock()
	defer releaseSample()
	clock := w.sampleClockOwner()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.beginRequestLocked(h, clock, sample, sampleErr)
}
func (w *ExecutionManagementWire) sampleClock() (sample timev4.Sample, err error, release func()) {
	noop := func() {}
	if w == nil {
		return timev4.Sample{}, timev4.ErrUnavailable, noop
	}
	w.mu.Lock()
	clock := w.config.Clock
	if clock == nil {
		w.mu.Unlock()
		return timev4.Sample{}, timev4.ErrUnavailable, noop
	}
	w.sampleActive++
	w.mu.Unlock()
	released := false
	release = func() {
		if released {
			return
		}
		released = true
		w.mu.Lock()
		w.sampleActive--
		if w.closed && w.sampleActive == 0 && w.sampleDone != nil {
			select {
			case <-w.sampleDone:
			default:
				close(w.sampleDone)
			}
		}
		w.cleanupLocked()
		w.mu.Unlock()
	}
	completed := false
	defer func() {
		// A blocked or panicking clock must never strand the installed sample
		// lease. Normal return transfers release ownership to the caller.
		if !completed {
			release()
		}
	}()
	sample, err = clock.Sample()
	completed = true
	return sample, err, release
}
func (w *ExecutionManagementWire) sampleClockOwner() *timev4.Clock {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.config.Clock
}
func (w *ExecutionManagementWire) newDeadlineAt(clock *timev4.Clock, cap uint64, sample timev4.Sample, sampleErr error) (*timev4.Deadline, error) {
	if sampleErr != nil {
		return nil, sampleErr
	}
	if cap <= sample.LowerMS || cap-sample.LowerMS > w.spec.MaxLifetimeMS {
		return nil, ErrManagementFraming
	}
	return timev4.NewDeadlineAt(clock, sample, cap)
}
func (w *ExecutionManagementWire) beginRequestLocked(h protocolv4.ApplicationHeader, clock *timev4.Clock, sample timev4.Sample, sampleErr error) (ManagementJob, error) {
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
	deadline, err := w.newDeadlineAt(clock, f.DeadlineAtMS, sample, sampleErr)
	if err == nil {
		err = w.checkDeadlineAt(deadline, sample)
	}
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

// Unavailable resolves only the original small response. A running provider
// retains the same slot and wire owner until its actual return. Late results
// cannot overwrite this outcome, free its position early, or publish twice.
func (j ManagementJob) Unavailable() (ManagementReply, error) {
	w := j.wire
	if w == nil {
		return ManagementReply{}, ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ManagementReply{}, ErrManagementClosed
	}
	p := &w.replies[j.index]
	if p.serial != j.serial || p.published {
		return ManagementReply{}, ErrOwner
	}
	if err := w.unavailableReplyLocked(p); err != nil {
		return ManagementReply{}, err
	}
	return ManagementReply{wire: w, index: j.index, serial: j.serial}, nil
}

// unavailableReplyLocked preserves the original slot, serial and provider
// tail. Repetition reads the same finite output without issuing another result.
func (w *ExecutionManagementWire) unavailableReplyLocked(p *managementWireReply) error {
	if p.timedOut {
		return nil
	}
	p.timedOut, p.ready, p.access = true, false, nil
	return w.encodeReplyLocked(p, protocolv4.ManagementResult{Status: "unavailable"})
}

// RemainingMS exposes only the original receive/work cap, never a fresh
// projection. A stalled body cannot hold a protected position indefinitely.
func (j ManagementJob) RemainingMS() (uint64, error) {
	w := j.wire
	if w == nil {
		return 0, ErrOwner
	}
	sample, sampleErr, releaseSample := w.sampleClock()
	defer releaseSample()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrManagementClosed
	}
	p := &w.replies[j.index]
	if p.serial != j.serial {
		return 0, ErrOwner
	}
	if p.timedOut {
		return 0, timev4.ErrExpired
	}
	if p.requestError != nil {
		return 0, p.requestError
	}
	if p.deadline == nil {
		return 0, ErrManagementFraming
	}
	if sampleErr != nil {
		return 0, sampleErr
	}
	if err := w.checkDeadlineAt(p.deadline, sample); err != nil {
		return 0, err
	}
	return p.deadline.RemainingMSAt(sample)
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
	sample, sampleErr, releaseSample := w.sampleClock()
	defer releaseSample()
	clock := w.sampleClockOwner()
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ManagementJob{}, ErrManagementClosed
	}
	h, _, _, err := w.decodeEnvelope(wire)
	var job ManagementJob
	if err == nil {
		job, err = w.beginRequestLocked(h, clock, sample, sampleErr)
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
		if deadline == nil {
			callErr = ErrManagementFraming
		} else {
			sample, sampleErr, releaseSample := w.sampleClock()
			if sampleErr != nil {
				callErr = sampleErr
			} else {
				callErr = w.checkDeadlineAt(deadline, sample)
			}
			releaseSample()
		}
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
			if deadline == nil {
				callErr = ErrManagementFraming
			} else {
				sample, sampleErr, releaseSample := w.sampleClock()
				if sampleErr != nil {
					callErr = sampleErr
				} else {
					callErr = w.checkDeadlineAt(deadline, sample)
				}
				releaseSample()
			}
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
	// A provider may finish after the original request cap. Convert that
	// completed-but-expired outcome into the same finite Unavailable response
	// used by the scheduler. The original deadline still gates publication.
	finiteFailure := errors.Is(callErr, timev4.ErrExpired) || errors.Is(callErr, context.DeadlineExceeded)
	if !finiteFailure && deadline != nil {
		sample, sampleErr, releaseSample := w.sampleClock()
		if sampleErr != nil {
			callErr, finiteFailure = sampleErr, true
		} else if err := w.checkDeadlineAt(deadline, sample); err != nil {
			callErr, finiteFailure = err, true
		}
		releaseSample()
	}
	if finiteFailure {
		result = protocolv4.ManagementResult{Status: "unavailable"}
	} else if callErr != nil {
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
	if p.timedOut {
		completed = true
		if p.published {
			*p = managementWireReply{}
			return reply, nil
		}
		return ManagementReply{wire: w, index: index, serial: serial}, nil
	}
	if finiteFailure {
		err = w.unavailableReplyLocked(p)
	} else {
		// Conflicts also reveal a fact about this key. Keep the resolved
		// permission for every response derived from the authority.
		p.access = access
		err = w.encodeReplyLocked(p, result)
	}
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
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closeLocked()
	// Close is a finite state transition. Active sample leases and response
	// callbacks retire themselves through cleanupLocked; callers that require
	// reclamation observe CleanupComplete instead of blocking this close path.
	w.cleanupLocked()
	w.mu.Unlock()
}
func (w *ExecutionManagementWire) closeLocked() {
	w.closed = true
	for i := range w.pending {
		if w.pending[i].processing {
			continue
		}
		w.pending[i].authority.Release()
		w.pending[i] = managementWirePending{}
	}
	for i := range w.replies {
		if !w.replies[i].running && !w.replies[i].publishing {
			w.replies[i] = managementWireReply{}
		}
	}
	w.cleanupLocked()
}
func (w *ExecutionManagementWire) cleanupLocked() {
	if !w.closed || w.cleaned || w.sampleActive != 0 {
		return
	}
	for i := range w.replies {
		if w.replies[i].running || w.replies[i].publishing {
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
