package rpcv4

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var ErrResponseLimit = errors.New("rpcv4: response exceeds original limit")

// AcceptedResult owns the original unary response generation obligation. The
// exact registered contract, complete response backing and publisher metadata
// exist before any request decoder or handler may start. Execution registration,
// current authorization and deadline gates remain the Session dispatcher's
// responsibility; acquiring this owner alone never authorizes application work.
type AcceptedResult struct {
	mu                             sync.Mutex
	publisher                      *Publisher
	ticket                         Ticket
	routes                         *ContractRoutes
	entry                          *contractRouteEntry
	reservation, source            resourcev4.Reference
	payload                        []byte
	limit, written                 uint32
	runtimeBytes                   uint64
	tail                           *acceptedResultTail
	publication                    *Publication
	writer                         ResponseWriter
	opened, sealed, failed, closed bool
}

// ResponseWriter is a bounded, once-only output capability. Write copies its
// argument synchronously; no mutable alias to the accepted backing is exposed.
// Finalize transfers that same immutable backing to the original publisher.
// Retaining this handle cannot append after Finalize, refusal or Close.
type ResponseWriter struct{ owner *AcceptedResult }
type acceptedResultTail struct{ done atomic.Bool }

func (s *acceptedResultTail) finish() {
	if s != nil {
		s.done.Store(true)
	}
}

func AcceptedResultCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(AcceptedResult{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func AcceptedResultSourceCharge(responseLimit uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if responseLimit > 1048576 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	v, err := MessageSourceCharge(max(responseLimit, 256), runtimeBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return v.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(acceptedResultTail{})), resourcev4.Items: 1})
}

// NewAcceptedResult accepts only the actual complete input from this Network's
// installed method table. Equal headers from another physical request cannot
// acquire its ReplySlot. The constructor pins the exact original registry body;
// later table closure cannot substitute semantics or refund the pinned bytes.
func (p *Publisher) NewAcceptedResult(t Ticket, input *VerifiedInput, metadata, source resourcev4.Reference, runtimeBytes uint64) (*AcceptedResult, error) {
	if p == nil || input == nil || metadata == source {
		return nil, ErrConfiguration
	}
	charge, err := AcceptedResultCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := p.liveLocked(); err != nil {
		return nil, err
	}
	s, err := n.slotLocked(t)
	if err != nil {
		return nil, err
	}
	if t.direction != incoming || s.path.Channel != p.channel || s.class != generalUnary || s.inputState != InputComplete || s.resultAdmitted || s.message.publisher != nil || n.inputs == nil {
		return nil, ErrOwner
	}
	input.mu.Lock()
	defer input.mu.Unlock()
	if input.closed || input.ticket != t || input.header != s.header || !input.methodBound {
		return nil, ErrAssociation
	}
	if err := input.reservation.Check(); err != nil {
		return nil, err
	}
	for _, ref := range []resourcev4.Reference{metadata, source} {
		if err := ref.CheckSameEnvironment(n.reservation); err != nil {
			return nil, err
		}
	}
	n.inputs.mu.Lock()
	defer n.inputs.mu.Unlock()
	routes := n.inputs.routes
	if n.inputs.closed || routes == nil {
		return nil, ErrClosed
	}
	routes.mu.Lock()
	defer routes.mu.Unlock()
	if routes.closed || routes.captures == math.MaxUint32 {
		return nil, ErrClosed
	}
	if err := routes.reservation.Check(); err != nil {
		return nil, err
	}
	var entry *contractRouteEntry
	for i := range routes.entries {
		candidate := &routes.entries[i]
		if candidate.method == input.method && candidate.policy == input.policy && candidate.registered {
			entry = candidate
			break
		}
	}
	if entry == nil {
		return nil, ErrMethod
	}
	if err := entry.contract.CheckRequest(s.header); err != nil {
		return nil, err
	}
	sourceCharge, err := AcceptedResultSourceCharge(s.header.Fields().ResponseLimitBytes, runtimeBytes)
	if err != nil {
		return nil, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		return nil, err
	}
	output, err := source.Take(sourceCharge)
	if err != nil {
		owned.Release()
		return nil, err
	}
	o := &AcceptedResult{publisher: p, ticket: t, routes: routes, entry: entry, reservation: owned, source: output, limit: s.header.Fields().ResponseLimitBytes, runtimeBytes: runtimeBytes, tail: &acceptedResultTail{}}
	o.payload = make([]byte, max(o.limit, 256))
	o.writer.owner = o
	routes.captures++
	s.resultAdmitted = true
	return o, nil
}

func (o *AcceptedResult) Writer() (*ResponseWriter, error) {
	if o == nil {
		return nil, ErrOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.opened || o.sealed {
		return nil, ErrOwner
	}
	if err := o.reservation.Check(); err != nil {
		return nil, err
	}
	o.opened = true
	return &o.writer, nil
}

// checkOutputLocked requires both original result and Network gates. A STOP or
// an already selected fixed refusal revokes generation without changing the
// independent execution/history facts or canceling business side effects.
func (o *AcceptedResult) checkOutputLocked() (*networkSlot, error) {
	if o.closed || o.sealed {
		return nil, ErrClosed
	}
	if o.failed {
		return nil, ErrResponseLimit
	}
	if err := o.reservation.Check(); err != nil {
		return nil, err
	}
	if err := o.source.Check(); err != nil {
		return nil, err
	}
	p := o.publisher
	if err := p.liveLocked(); err != nil {
		return nil, err
	}
	s, err := p.network.slotLocked(o.ticket)
	if err != nil {
		return nil, err
	}
	if s.message.publisher != nil || s.message.stop || s.message.abort {
		return nil, ErrClosed
	}
	return s, nil
}
func (w *ResponseWriter) Write(data []byte) (int, error) {
	if w == nil || w.owner == nil {
		return 0, ErrOwner
	}
	o := w.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.sealed {
		return 0, ErrClosed
	}
	n := o.publisher.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, err := o.checkOutputLocked(); err != nil {
		return 0, err
	}
	if uint64(len(data)) > uint64(o.limit-o.written) {
		o.failed = true
		return 0, ErrResponseLimit
	}
	count := copy(o.payload[o.written:o.limit], data)
	o.written += uint32(count)
	return count, nil
}

// Finalize publishes only complete output. The error code is checked against
// this exact retained contract's closed application error catalog. Zero means
// the ordinary success variant, including a legal empty response.
func (w *ResponseWriter) Finalize(errorCode uint32) (*Publication, error) {
	if w == nil || w.owner == nil {
		return nil, ErrOwner
	}
	o := w.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.sealed {
		return nil, ErrClosed
	}
	p := o.publisher
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := o.checkOutputLocked()
	if err != nil {
		return nil, err
	}
	if err := o.entry.contract.CheckResponsePayload(errorCode, o.written); err != nil {
		return nil, err
	}
	var wire [512]byte
	values := s.header.Fields()
	values.Kind = 0
	values.PayloadBytes = o.written
	values.DeadlineAtMS = 0
	values.AdmissionMode = 0
	values.ResponseLimitBytes = 0
	values.ApplicationErrorCode = errorCode
	kind := "transient_unary_response"
	if s.header.HasExecutionIdentity() {
		kind = "execution_unary_response"
	}
	if errorCode != 0 {
		if s.header.HasExecutionIdentity() {
			kind = "execution_unary_application_error"
		} else {
			kind = "transient_unary_application_error"
		}
	}
	size, h, err := p.codec.Encode(wire[:], kind, values)
	if err != nil {
		return nil, err
	}
	if err := s.header.MatchResponse(h); err != nil {
		return nil, err
	}
	charge, err := AcceptedResultSourceCharge(o.limit, o.runtimeBytes)
	if err != nil {
		return nil, err
	}
	source, err := o.source.Take(charge)
	if err != nil {
		return nil, err
	}
	pub := &Publication{}
	s.message = sendMessage{publisher: p, header: h, headerBytes: uint16(size), payload: o.payload[:o.written:o.written], reservation: source, publication: pub, resultSource: o.tail, prev: -1, nextReady: -1}
	copy(s.message.headerWire[:], wire[:size])
	o.source = resourcev4.Reference{}
	o.payload = nil
	o.publication = pub
	o.sealed = true
	p.enqueueLocked(o.ticket, p.lane(s, o.ticket.direction))
	return pub, nil
}

// Refuse uses the original fixed ReplySlot and never replaces a response whose
// BEGIN already won. No result bytes are published after this owner is sealed.
func (o *AcceptedResult) Refuse(code string) error {
	if o == nil {
		return ErrOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.sealed {
		return ErrClosed
	}
	if err := o.publisher.QueueRefusal(o.ticket, code); err != nil {
		return err
	}
	o.sealed = true
	o.releaseSourceLocked()
	return nil
}
func (o *AcceptedResult) releaseSourceLocked() {
	clear(o.payload)
	o.payload = nil
	o.source.Release()
	o.source = resourcev4.Reference{}
	o.tail.finish()
}

// Close fences the writer and drops only this generation's private ownership.
// After successful Finalize, the original publisher retains the same complete
// source charge through its actual final Stream/provider tail.
func (o *AcceptedResult) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return
	}
	o.closed = true
	if o.publication == nil {
		o.releaseSourceLocked()
	}
	r := o.routes
	r.mu.Lock()
	r.captures--
	r.cleanupLocked()
	r.mu.Unlock()
	o.routes = nil
	o.entry = nil
	o.publisher = nil
	o.ticket = Ticket{}
	o.reservation.Release()
	o.reservation = resourcev4.Reference{}
}
func (o *AcceptedResult) CleanupComplete() bool {
	if o == nil {
		return true
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closed && o.tail.done.Load()
}
func (*AcceptedResult) String() string               { return "Flowersec.AcceptedResultOwner" }
func (*AcceptedResult) GoString() string             { return "Flowersec.AcceptedResultOwner" }
func (*AcceptedResult) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
func (*ResponseWriter) String() string               { return "Flowersec.ResponseWriter" }
func (*ResponseWriter) GoString() string             { return "Flowersec.ResponseWriter" }
func (*ResponseWriter) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
