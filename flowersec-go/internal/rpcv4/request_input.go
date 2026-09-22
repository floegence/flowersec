package rpcv4

import (
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// InputConfig declares actual backing before input is accepted. Capture=false
// is the bounded rejection/discard path: execution still hashes every original
// payload byte. RuntimeBytes and HashRuntimeBytes are deployment allowances,
// not a claim that this source-sized minimum qualifies the Go runtime.
type InputConfig struct {
	Clock                          *timev4.Clock
	Capture                        bool
	RuntimeBytes, HashRuntimeBytes uint64
}

type InputState uint8

const (
	InputCollecting InputState = iota
	InputComplete
	InputAborted
	InputFailed
	InputTransferred
	InputClosed
	// InputRejected has complete framing, but no known execution contract body
	// with which to verify the declared request digest. It is refusal-only.
	InputRejected
)

// RequestInput holds the one original authenticated message input. It performs
// no application decode, service lookup, authorization or execution admission.
// The trusted caller selects the exact registered contract before construction;
// an untrusted contract object does not become a service registration here.
type RequestInput struct {
	deadline     *timev4.Deadline
	mu           sync.Mutex
	header       protocolv4.ApplicationHeader
	verifier     *protocolv4.ExecutionRequestVerifier
	reservation  resourcev4.Reference
	payload      []byte
	next         uint32
	capture      bool
	state        InputState
	ticket       Ticket
	pool         *ServiceInputs
	query        *ContractQueryService
	queryIndex   uint8
	refusal      string
	unverifiable bool
	method       uint32
	methodBound  bool
	policy       protocolv4.ServiceContractPolicy
}

func RequestInputCharge(h protocolv4.ApplicationHeader, c InputConfig) (resourcev4.Vector, error) {
	if h.Kind() == "" || h.IsResponse() || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return requestInputEnvelopeCharge(h.Fields().PayloadBytes, h.HasExecutionIdentity(), c)
}

// RequestInputEnvelopeCharge protects the largest supported input shape,
// including execution hashing, before a concrete request header is received.
// The same geometry computes the actual per-message dynamic charge.
func RequestInputEnvelopeCharge(payloadBytes uint32, c InputConfig) (resourcev4.Vector, error) {
	if payloadBytes > 1048576 || c.RuntimeBytes == 0 || !c.Capture {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return requestInputEnvelopeCharge(payloadBytes, true, c)
}

func requestInputEnvelopeCharge(payloadBytes uint32, execution bool, c InputConfig) (resourcev4.Vector, error) {
	n := uint64(unsafe.Sizeof(RequestInput{})) + uint64(unsafe.Sizeof(VerifiedInput{})) + uint64(unsafe.Sizeof(InputBorrow{})) + 128
	if c.Clock != nil {
		n += uint64(unsafe.Sizeof(timev4.Deadline{}))
	}
	if execution {
		cost, err := protocolv4.ExecutionRequestVerifierBackingBytes(c.HashRuntimeBytes)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		if cost > math.MaxUint64-n {
			return resourcev4.Vector{}, ErrConfiguration
		}
		n += cost
	}
	// Hash/copy work executes synchronously on the channel's already admitted
	// reader service; a retained message does not create another worker slot.
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 3}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err == nil && c.Capture {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(payloadBytes)})
	}
	return charge, err
}

// NewRequestInput consumes the original pre-admitted hash/input responsibility.
// Any constructor failure precedes consumption or releases the taken owner;
// it never waits for new payload capacity on a shared RPC reader.
func NewRequestInput(h protocolv4.ApplicationHeader, contract *protocolv4.ServiceContract, c InputConfig, reservation resourcev4.Reference) (*RequestInput, error) {
	return newRequestInput(h, contract, c, reservation, nil, nil)
}

func newRequestInput(h protocolv4.ApplicationHeader, contract *protocolv4.ServiceContract, c InputConfig, reservation resourcev4.Reference, storage []byte, original *timev4.Deadline) (*RequestInput, error) {
	charge, err := RequestInputCharge(h, c)
	if storage != nil {
		if !c.Capture || len(storage) != cap(storage) || len(storage) > 1048576 || len(storage) < int(h.Fields().PayloadBytes) {
			return nil, ErrConfiguration
		}
		charge, err = requestInputEnvelopeCharge(uint32(len(storage)), h.HasExecutionIdentity(), c)
	}
	if err != nil {
		return nil, err
	}
	if err := contract.CheckRequest(h); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &RequestInput{header: h, reservation: owned, capture: c.Capture}
	if c.Clock != nil && h.HasDeadline() {
		if original != nil {
			if !original.BelongsTo(c.Clock) {
				owned.Release()
				return nil, ErrOwner
			}
			p.deadline, err = original.Fork(min(original.Cap(), h.Fields().DeadlineAtMS))
		} else {
			p.deadline, err = timev4.NewDeadline(c.Clock, h.Fields().DeadlineAtMS)
		}
		if err != nil {
			owned.Release()
			return nil, err
		}
		if h.Kind() == "transient_unary_request" || h.Kind() == "transient_stream_request" || h.Kind() == "observation_notify" {
			policy, e := contract.Policy()
			if e != nil {
				owned.Release()
				return nil, e
			}
			now, e := p.deadline.Sample()
			if e != nil {
				owned.Release()
				return nil, e
			}
			if policy.MessageLifetimeMS == 0 || policy.MessageLifetimeMS > math.MaxUint64-now.LowerMS || h.Fields().DeadlineAtMS > now.LowerMS+policy.MessageLifetimeMS {
				owned.Release()
				return nil, timev4.ErrExpired
			}
		}
	}
	if h.HasExecutionIdentity() {
		p.verifier, err = protocolv4.NewExecutionRequestVerifier(h, contract)
		if err != nil {
			owned.Release()
			return nil, err
		}
	}
	if c.Capture {
		if storage == nil {
			p.payload = make([]byte, int(h.Fields().PayloadBytes))
		} else {
			p.payload = storage[:h.Fields().PayloadBytes:h.Fields().PayloadBytes]
		}
	}
	return p, nil
}

// NewReadResultInput constructs the fixed SDK result-read input. It has the
// same bounded capture and deadline ownership as ordinary RPC input, but it
// deliberately has no application route or method binding. The completed
// target is decoded only by the trusted result-read service after the whole
// payload has passed the original input gate.
func NewReadResultInput(h protocolv4.ApplicationHeader, c InputConfig, reservation resourcev4.Reference) (*RequestInput, error) {
	if h.Kind() != "read_result_request" || h.Fields().PayloadBytes > 4096 || h.IsResponse() || !h.OrdinaryRPC() || c.Clock == nil || !c.Capture {
		return nil, ErrConfiguration
	}
	charge, err := RequestInputCharge(h, c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &RequestInput{header: h, reservation: owned, capture: c.Capture}
	if h.HasDeadline() {
		p.deadline, err = timev4.NewDeadline(c.Clock, h.Fields().DeadlineAtMS)
		if err != nil {
			owned.Release()
			return nil, err
		}
	}
	if c.Capture {
		p.payload = make([]byte, int(h.Fields().PayloadBytes))
	}
	return p, nil
}
func (*RequestInput) String() string               { return "Flowersec.RPCRequestInput" }
func (*RequestInput) GoString() string             { return "Flowersec.RPCRequestInput" }
func (*RequestInput) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (p *RequestInput) failLocked(err error) error {
	p.state = InputFailed
	if p.verifier != nil {
		p.verifier.Close()
		p.verifier = nil
	}
	clear(p.payload)
	return err
}

// WriteAt consumes a borrowed DATA piece synchronously. The caller may release
// that original Stream credit immediately afterward. No input slice is kept,
// and payload=0 completes through Finish without an invented empty DATA.
func (p *RequestInput) WriteAt(offset uint32, data []byte) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != InputCollecting {
		return ErrOwner
	}
	if err := p.reservation.Check(); err != nil {
		return p.failLocked(err)
	}
	if offset != p.next || len(data) == 0 || uint64(len(data)) > uint64(p.header.Fields().PayloadBytes-p.next) {
		return p.failLocked(protocolv4.CBORFailure("application_payload_length"))
	}
	if p.verifier != nil {
		if err := p.verifier.WriteAt(offset, data); err != nil {
			return p.failLocked(err)
		}
	}
	if p.capture {
		copy(p.payload[int(p.next):], data)
	}
	p.next += uint32(len(data))
	return nil
}

// Finish validates the complete original input, including the execution-only
// request digest. It grants neither a handler permit nor permission to register
// execution; those still require current authorization and result responsibility.
func (p *RequestInput) Finish() error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != InputCollecting {
		return ErrOwner
	}
	if err := p.reservation.Check(); err != nil {
		return p.failLocked(err)
	}
	if p.next != p.header.Fields().PayloadBytes {
		return p.failLocked(protocolv4.CBORFailure("application_payload_length"))
	}
	if p.verifier != nil {
		if err := p.verifier.Finish(); err != nil {
			return p.failLocked(err)
		}
		p.verifier = nil
	}
	p.state = InputComplete
	if p.unverifiable {
		p.state = InputRejected
	}
	return nil
}

// Abort accepts only the exact incomplete prefix. It never verifies the
// missing payload or reports an operation-wide not-executed fact. The original
// ReplySlot remains responsible for its small request_message_aborted response.
func (p *RequestInput) Abort(offset uint32) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != InputCollecting {
		return ErrOwner
	}
	if offset != p.next || p.next >= p.header.Fields().PayloadBytes {
		return p.failLocked(protocolv4.CBORFailure("abort_offset"))
	}
	if p.verifier != nil {
		p.verifier.Close()
		p.verifier = nil
	}
	clear(p.payload)
	p.state = InputAborted
	return nil
}

// Take transfers the same input backing/reference exactly once. The detached
// verified input still cannot execute application code; its borrower must run
// under the original admitted executor and hold the borrow through actual exit.
func (p *RequestInput) Take() (*VerifiedInput, error) {
	if p == nil {
		return nil, ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != InputComplete || !p.capture || p.query != nil {
		return nil, ErrOwner
	}
	if err := p.reservation.Check(); err != nil {
		return nil, err
	}
	v := &VerifiedInput{deadline: p.deadline, header: p.header, ticket: p.ticket, payload: p.payload, reservation: p.reservation, method: p.method, methodBound: p.methodBound, policy: p.policy}
	p.header = protocolv4.ApplicationHeader{}
	p.deadline = nil
	p.ticket = Ticket{}
	p.payload = nil
	p.policy = protocolv4.ServiceContractPolicy{}
	p.reservation = resourcev4.Reference{}
	p.state = InputTransferred
	return v, nil
}
func (p *RequestInput) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == InputTransferred || p.state == InputClosed {
		return
	}
	if p.verifier != nil {
		p.verifier.Close()
		p.verifier = nil
	}
	clear(p.payload)
	p.payload = nil
	p.header = protocolv4.ApplicationHeader{}
	p.deadline = nil
	p.ticket = Ticket{}
	if p.query != nil {
		p.query.releaseInput(p.queryIndex, p)
		p.query = nil
	} else if p.pool != nil {
		p.pool.releaseInput()
		p.pool = nil
	} else {
		p.reservation.Release()
	}
	p.reservation = resourcev4.Reference{}
	p.policy = protocolv4.ServiceContractPolicy{}
	p.state = InputClosed
}
func (p *RequestInput) Progress() (InputState, uint32) {
	if p == nil {
		return InputClosed, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state, p.next
}

// VerifiedInput provides one bounded internal byte borrow at a time. Logical
// Close prevents new borrows, but neither clears nor refunds live callback or
// codec aliases. The actual borrower releases its token only after it stops
// using all derived slices; borrowed bytes are immutable and cannot be retained.
type VerifiedInput struct {
	deadline                  *timev4.Deadline
	ticket                    Ticket
	mu                        sync.Mutex
	header                    protocolv4.ApplicationHeader
	payload                   []byte
	reservation               resourcev4.Reference
	generation                uint64
	method                    uint32
	methodBound               bool
	policy                    protocolv4.ServiceContractPolicy
	borrowed, closed, cleaned bool
}
type InputBorrow struct {
	owner      *VerifiedInput
	generation uint64
}

func (*VerifiedInput) String() string               { return "Flowersec.VerifiedRPCInput" }
func (*VerifiedInput) GoString() string             { return "Flowersec.VerifiedRPCInput" }
func (*VerifiedInput) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
func (InputBorrow) String() string                  { return "Flowersec.RPCInputBorrow" }
func (InputBorrow) GoString() string                { return "Flowersec.RPCInputBorrow" }
func (InputBorrow) MarshalJSON() ([]byte, error)    { return []byte("{}"), nil }

func (v *VerifiedInput) Borrow() (InputBorrow, error) {
	if v == nil {
		return InputBorrow{}, ErrOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.borrowed || v.generation == math.MaxUint64 {
		return InputBorrow{}, ErrOwner
	}
	if err := v.reservation.Check(); err != nil {
		return InputBorrow{}, err
	}
	v.generation++
	v.borrowed = true
	return InputBorrow{v, v.generation}, nil
}
func (b InputBorrow) Bytes() ([]byte, protocolv4.ApplicationHeader, error) {
	v := b.owner
	if v == nil {
		return nil, protocolv4.ApplicationHeader{}, ErrOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.borrowed || b.generation != v.generation {
		return nil, protocolv4.ApplicationHeader{}, ErrOwner
	}
	if err := v.reservation.Check(); err != nil {
		return nil, protocolv4.ApplicationHeader{}, err
	}
	return v.payload[:len(v.payload):len(v.payload)], v.header, nil
}
func (b InputBorrow) Release() {
	v := b.owner
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.borrowed || b.generation != v.generation {
		return
	}
	v.borrowed = false
	v.cleanupLocked()
}
func (v *VerifiedInput) cleanupLocked() {
	if !v.closed || v.borrowed || v.cleaned {
		return
	}
	clear(v.payload)
	v.payload = nil
	v.header = protocolv4.ApplicationHeader{}
	v.deadline = nil
	v.ticket = Ticket{}
	v.policy = protocolv4.ServiceContractPolicy{}
	v.reservation.Release()
	v.reservation = resourcev4.Reference{}
	v.cleaned = true
}
func (v *VerifiedInput) Close() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	v.cleanupLocked()
}
func (v *VerifiedInput) CleanupComplete() bool {
	if v == nil {
		return true
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.cleaned
}

// OriginalMethod exposes the immutable local route selected at input capture.
// It does not establish current authorization, admission or dispatch rights.
func (v *VerifiedInput) OriginalMethod() (uint32, protocolv4.ServiceContractPolicy, error) {
	if v == nil {
		return 0, protocolv4.ServiceContractPolicy{}, ErrOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || !v.methodBound {
		return 0, protocolv4.ServiceContractPolicy{}, ErrOwner
	}
	if err := v.reservation.Check(); err != nil {
		return 0, protocolv4.ServiceContractPolicy{}, err
	}
	return v.method, v.policy, nil
}

// MessageDeadline returns the original collector's fixed deadline projection.
// Completing a slow body or improving a wall anchor never creates a new age.
func (v *VerifiedInput) MessageDeadline(clock *timev4.Clock) (*timev4.Deadline, error) {
	if v == nil {
		return nil, ErrOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.deadline == nil || !v.deadline.BelongsTo(clock) {
		return nil, ErrOwner
	}
	if err := v.reservation.Check(); err != nil {
		return nil, err
	}
	return v.deadline, nil
}
