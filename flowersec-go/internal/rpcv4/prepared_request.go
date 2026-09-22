package rpcv4

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrAdmissionOfferUnavailable = errors.New("rpcv4: admission offer unavailable")
	ErrAdmissionWindowClosed     = errors.New("rpcv4: admission window closed")
	ErrPreparationIncomplete     = errors.New("rpcv4: request encoding incomplete")
)

// UnaryPreparation comes from an exact local method binding. Offer is the
// selected authenticated snapshot, not a credential or caller wire field.
// Explicit deadlines are rejected when oversized; only an omitted deadline
// uses the binding's finite default. Zero is a legal chosen response limit.
// ExplicitAdmissionMode distinguishes a requested queued mode from the local
// default. A live application context rejects explicit queued before encoding;
// its default is fixed to try_now before immutable header construction.
type UnaryPreparation struct {
	Clock                                                *timev4.Clock
	DeadlineAtMS, DefaultLifetimeMS, AdmissionNotAfterMS uint64
	ResponseLimitBytes                                   uint32
	AdmissionMode                                        uint8
	ExplicitAdmissionMode                                bool
	RequireExecution, RequireDurable                     bool
	Offer                                                protocolv4.AdmissionOfferBounds
	RuntimeBytes                                         uint64
}

// PreparedRequest owns the immutable bytes and exact route until Start transfers
// them or Close abandons them. It performs no acquisition, OPEN, serial
// allocation or publication. The Session operation supplies single-flight
// Start and result ownership; a query-only reference cannot construct it.
type PreparedRequest struct {
	mu           sync.Mutex
	reservation  resourcev4.Reference
	route        ContractRoute
	deadline     *timev4.Deadline
	preparation  *timev4.Deadline
	codec        *protocolv4.ApplicationHeaderCodec
	header       protocolv4.ApplicationHeader
	wire         [512]byte
	wireBytes    int
	payload      []byte
	payloadLimit uint32
	ready        bool
	finalized    bool
	policy       protocolv4.ServiceContractPolicy
	offer        protocolv4.AdmissionOfferBounds
	closed       bool
	users        uint8
}

func PreparedRequestCharge(payloadBytes uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if payloadBytes > 1048576 || runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	codec, err := protocolv4.ApplicationHeaderBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	hash, err := protocolv4.ExecutionRequestVerifierBackingBytes(runtimeBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	c, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PreparedRequest{})) + 2*uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(payloadBytes), resourcev4.Items: 4}).Add(resourcev4.Vector{resourcev4.SDKBytes: codec})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	c, err = c.Add(resourcev4.Vector{resourcev4.SDKBytes: hash})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return c.Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func PrepareUnary(route ContractRoute, payload []byte, options UnaryPreparation, reservation, routeReservation resourcev4.Reference) (_ *PreparedRequest, err error) {
	if uint64(len(payload)) > 1048576 {
		return nil, ErrConfiguration
	}
	p, err := BeginUnaryPreparation(route, uint32(len(payload)), options, reservation, routeReservation)
	if err != nil {
		return nil, err
	}
	if err = p.FinalizePayload(payload); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// BeginUnaryPreparation fixes the original route, deadline, admission window
// and execution identity before a trusted local encoder can run. The complete
// output allowance is taken now; FinalizePayload cannot grow it or renew time.
// No request is startable until finalization has copied the encoded value.
func BeginUnaryPreparation(route ContractRoute, payloadLimit uint32, options UnaryPreparation, reservation, routeReservation resourcev4.Reference) (*PreparedRequest, error) {
	return beginRequestPreparation(route, payloadLimit, options, 0, reservation, routeReservation)
}

func beginRequestPreparation(route ContractRoute, payloadLimit uint32, options UnaryPreparation, shape uint8, reservation, routeReservation resourcev4.Reference) (_ *PreparedRequest, err error) {
	if options.Clock == nil || options.AdmissionMode > 1 || payloadLimit > 1048576 {
		return nil, ErrConfiguration
	}
	resume := shape == 3
	if resume {
		shape = 0
	}
	_, policy, err := route.Policy()
	if err != nil {
		return nil, err
	}
	if policy.Shape != shape || payloadLimit > policy.RequestMaxBytes || options.ResponseLimitBytes < policy.MinResponseBytes || options.ResponseLimitBytes > policy.MaxResponseBytes {
		return nil, ErrMethod
	}
	execution := policy.Semantics == 1
	if resume && !execution {
		return nil, ErrMethod
	}
	if (options.RequireExecution || options.RequireDurable) && !execution || options.RequireDurable && policy.ExecutionMode != 1 {
		return nil, protocolv4.ErrRequiredGuaranteeUnavailable
	}
	if !execution && (options.AdmissionNotAfterMS != 0 || options.Offer != (protocolv4.AdmissionOfferBounds{})) {
		return nil, ErrConfiguration
	}
	charge, err := PreparedRequestCharge(payloadLimit, options.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &PreparedRequest{reservation: owned, policy: policy, offer: options.Offer, payloadLimit: payloadLimit}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()
	p.route, err = route.Clone(routeReservation, options.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	if err = p.route.WithRegistered(func() error { return nil }); err != nil {
		return nil, err
	}
	now, err := options.Clock.Sample()
	if err != nil {
		return nil, err
	}
	horizon := policy.MessageLifetimeMS
	if execution {
		horizon = policy.ExecutionHorizonMS
	}
	if horizon == 0 || horizon > math.MaxUint64-now.LowerMS {
		return nil, timev4.ErrExpired
	}
	deadline := options.DeadlineAtMS
	if deadline == 0 {
		if options.DefaultLifetimeMS == 0 {
			return nil, ErrConfiguration
		}
		deadline = now.LowerMS + min(options.DefaultLifetimeMS, horizon)
	}
	if deadline <= now.UpperMS || deadline > now.LowerMS+horizon {
		return nil, timev4.ErrExpired
	}
	p.deadline, err = timev4.NewDeadline(options.Clock, deadline)
	if err != nil {
		return nil, err
	}
	preparationCap := deadline
	if now.LowerMS <= math.MaxUint64-60000 {
		preparationCap = min(preparationCap, now.LowerMS+60000)
	}
	p.preparation, err = p.deadline.Fork(preparationCap)
	if err != nil {
		return nil, err
	}
	fields := protocolv4.ApplicationHeaderFields{Type: policy.Type, DeadlineAtMS: deadline, AdmissionMode: options.AdmissionMode, ResponseLimitBytes: options.ResponseLimitBytes, ServiceContractDigest: policy.Digest}
	kind := "transient_unary_request"
	if shape == 2 {
		kind = "observation_notify"
		fields.AdmissionMode = 0
	}
	if shape == 1 {
		kind = "transient_stream_request"
	}
	if execution {
		offer := options.Offer
		if offer.Digest != policy.Digest || offer.NotBeforeMS >= offer.NotAfterMS {
			return nil, ErrAdmissionOfferUnavailable
		}
		if policy.AdmissionWindowMS == 0 || policy.AdmissionWindowMS > math.MaxUint64-now.LowerMS {
			return nil, ErrAdmissionWindowClosed
		}
		cutoff := options.AdmissionNotAfterMS
		if cutoff == 0 {
			cutoff = now.LowerMS + policy.AdmissionWindowMS
		}
		cutoff = min(cutoff, offer.NotAfterMS, deadline)
		if cutoff <= now.UpperMS || cutoff <= offer.NotBeforeMS || cutoff > now.LowerMS+policy.AdmissionWindowMS {
			return nil, ErrAdmissionWindowClosed
		}
		binary.BigEndian.PutUint64(fields.OperationID[:8], cutoff)
		if _, err = rand.Read(fields.OperationID[8:]); err != nil {
			return nil, err
		}
		kind = "execution_unary_request"
		if shape == 2 {
			kind = "execution_notify"
			fields.AdmissionMode = options.AdmissionMode
		}
		if shape == 1 {
			kind = "execution_stream_request"
		}
	}
	if resume {
		kind = "resume_request"
	}
	p.codec, err = protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		return nil, err
	}
	p.wireBytes, p.header, err = p.codec.Encode(p.wire[:], kind, fields)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// FinalizePayload accepts one complete value, copying application-owned bytes
// into the original preadmitted output. It invokes no application code. An
// expired/revoked preparation cannot become a request after a slow encoder.
func (p *PreparedRequest) FinalizePayload(payload []byte) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	if p.finalized {
		return ErrOwner
	}
	if uint64(len(payload)) > uint64(p.payloadLimit) {
		return ErrCapacity
	}
	if err := p.checkPreparedLifetimeLocked(); err != nil {
		return err
	}
	if err := p.route.WithRegistered(func() error { return nil }); err != nil {
		return err
	}
	p.finalized = true
	p.payload = append([]byte(nil), payload...)
	fields := p.header.Fields()
	fields.PayloadBytes = uint32(len(payload))
	kind := p.header.Kind()
	var err error
	p.wireBytes, p.header, err = p.codec.Encode(p.wire[:], kind, fields)
	if err != nil {
		return err
	}
	if p.policy.Semantics == 1 {
		s := p.route.capture
		s.mu.Lock()
		fields.RequestDigest, err = protocolv4.ComputeExecutionRequestDigest(p.header, s.entry.contract, p.payload)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		p.wireBytes, p.header, err = p.codec.Encode(p.wire[:], kind, fields)
		if err != nil {
			return err
		}
	}
	p.ready = true
	return nil
}

// WithStart uses the original immutable bytes and selected window. The action
// is the trusted Session admission function, never an application callback.
// The original immutable backing remains pinned through the actual action,
// including Close races. No preparation mutex is held across that action.
func (p *PreparedRequest) WithStart(ctx context.Context, action func(ContractRoute, protocolv4.ApplicationHeader, []byte, []byte) error) error {
	if p == nil || ctx == nil || action == nil {
		return ErrConfiguration
	}
	p.mu.Lock()
	if p.closed || p.users != 0 {
		p.mu.Unlock()
		return ErrClosed
	}
	if !p.ready {
		p.mu.Unlock()
		return ErrPreparationIncomplete
	}
	if err := ctx.Err(); err != nil {
		p.mu.Unlock()
		return err
	}
	if err := p.checkPreparedLifetimeLocked(); err != nil {
		p.mu.Unlock()
		return err
	}
	now, err := p.deadline.Sample()
	if err == nil && p.header.HasExecutionIdentity() {
		id := p.header.Fields().OperationID
		if now.UpperMS >= binary.BigEndian.Uint64(id[:8]) {
			err = ErrAdmissionWindowClosed
		} else if now.LowerMS < p.offer.NotBeforeMS {
			err = timev4.ErrPending
		}
	}
	if err != nil {
		p.mu.Unlock()
		return err
	}
	p.users++
	route, h, wire, payload := p.route, p.header, p.wire[:p.wireBytes], p.payload
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.users--
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	return action(route, h, wire, payload)
}

func (p *PreparedRequest) Header() protocolv4.ApplicationHeader {
	if p == nil {
		return protocolv4.ApplicationHeader{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.header
}

// CaptureReference copies only query metadata from the immutable original
// request. It does not transfer Start rights or retain its route/Session.
func (p *PreparedRequest) CaptureReference(codec *protocolv4.OperationReferenceCodec, domain string, target protocolv4.ManagementTarget) (protocolv4.OperationReference, error) {
	if p == nil || codec == nil {
		return protocolv4.OperationReference{}, ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ready || !p.finalized {
		return protocolv4.OperationReference{}, ErrPreparationIncomplete
	}
	if err := p.checkPreparedLifetimeLocked(); err != nil {
		return protocolv4.OperationReference{}, err
	}
	if err := p.route.WithRegistered(func() error { return nil }); err != nil {
		return protocolv4.OperationReference{}, err
	}
	return codec.Capture(domain, target, p.header, p.policy)
}

func (p *PreparedRequest) ServiceNamespace() (string, error) {
	if p == nil {
		return "", ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return "", ErrClosed
	}
	return p.policy.Namespace, nil
}

// CheckPreparedLifetime lets the existing Session coordinator expire an
// unstarted owner; it does not create a private watcher or renew its deadline.
func (p *PreparedRequest) CheckPreparedLifetime() error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checkPreparedLifetimeLocked()
}

func (p *PreparedRequest) checkPreparedLifetimeLocked() error {
	if p.closed {
		return ErrClosed
	}
	if err := p.preparation.Check(); err != nil {
		return err
	}
	now, err := p.deadline.Sample()
	if err != nil {
		return err
	}
	if p.header.HasExecutionIdentity() {
		id := p.header.Fields().OperationID
		if now.UpperMS >= binary.BigEndian.Uint64(id[:8]) {
			return ErrAdmissionWindowClosed
		}
	}
	return nil
}

func (p *PreparedRequest) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.cleanupLocked()
}

func (p *PreparedRequest) cleanupLocked() {
	if !p.closed || p.users != 0 {
		return
	}
	clear(p.payload)
	p.payload = nil
	clear(p.wire[:])
	p.route.Release()
	p.route = ContractRoute{}
	p.deadline = nil
	p.preparation = nil
	p.codec = nil
	p.reservation.Release()
	p.reservation = resourcev4.Reference{}
}

func (*PreparedRequest) String() string               { return "Flowersec.PreparedRequest" }
func (*PreparedRequest) GoString() string             { return "Flowersec.PreparedRequest" }
func (*PreparedRequest) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// StartDeadline lends the immutable preparation's earlier projection only
// during WithStart. The receiving SDK owner forks it before that borrow ends.
func (p *PreparedRequest) StartDeadline() (*timev4.Deadline, error) {
	if p == nil {
		return nil, ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.users != 1 || !p.ready {
		return nil, ErrOwner
	}
	return p.deadline, nil
}
