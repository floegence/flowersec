package rpcv4

import (
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

const queryRequestBytes = 2048
const queryResponseBytes = 8 * 9216

type queryOutput struct {
	generation                           uint64
	occupied, stepping, queued, canceled bool
	ticket                               Ticket
	header                               protocolv4.ApplicationHeader
	read                                 *ContractQueryRead
	payload                              []byte
	deadline                             *timev4.Deadline
	encoded                              bool
	bytes                                int
}

// ContractQueryService supplies the Session's two complete incoming query
// response positions and two small pending inputs. Every channel shares this
// owner. A response position remains occupied until the real publisher source
// and provider tail exit, even after its ReplySlot has been transferred.
// The Session's original fixed SDK executor drives Begin/Resolve/Publish;
// this object creates no goroutine, ordinary handler job or authority source.
// Outgoing queries and the executor retain their own original responsibilities.
type ContractQueryService struct {
	mu              sync.Mutex
	network         *Network
	routes          *ContractRoutes
	reservation     resourcev4.Reference
	targets         *protocolv4.ContractQueryCodec
	snapshots       *protocolv4.ContractSnapshotEncoder
	pending         [2]*RequestInput
	outputs         [2]queryOutput
	cursor          uint8
	closed, cleaned bool
	wake            chan struct{}
	clock           *timev4.Clock
	checking        bool
	consumer        *ContractQueryConsumer
	executorWake    chan<- struct{}
	consumerStopped bool
}

// ContractQueryConsumer is the one fixed SDK executor's receive capability.
// Claiming it fences manual Begin calls without allocating another input queue.
type ContractQueryConsumer struct {
	service atomic.Pointer[ContractQueryService]
}

func (q *ContractQueryService) ClaimConsumer(wake chan<- struct{}, owner resourcev4.Reference) (*ContractQueryConsumer, error) {
	if q == nil || wake == nil {
		return nil, ErrConfiguration
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.cleaned || q.consumer != nil {
		return nil, ErrOwner
	}
	if err := owner.CheckSameEnvironment(q.reservation); err != nil {
		return nil, err
	}
	q.consumer = &ContractQueryConsumer{}
	q.consumer.service.Store(q)
	q.executorWake = wake
	q.notifyLocked()
	return q.consumer, nil
}

func (c *ContractQueryConsumer) Begin() (ContractQueryJob, error) {
	if c == nil {
		return ContractQueryJob{}, ErrOwner
	}
	q := c.service.Load()
	if q == nil {
		return ContractQueryJob{}, ErrOwner
	}
	return q.begin(c)
}

// Stop retires the original executor wake alias after its real last worker
// exits. It never grants a replacement consumer or releases live query output.
func (c *ContractQueryConsumer) Stop() {
	if c == nil {
		return
	}
	q := c.service.Swap(nil)
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.consumer == c {
		q.consumerStopped = true
		q.executorWake = nil
		q.cleanupLocked()
	}
}

// ContractQueryJob is one generation-fenced SDK read, not a business operation
// or an application execution permit. Copies cannot select a reused position.
type ContractQueryJob struct {
	service    *ContractQueryService
	generation uint64
	index      uint8
}

func ContractQueryServiceCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	target, err := protocolv4.ContractQueryCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	snapshot, err := protocolv4.ContractSnapshotEncoderBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	read, err := ContractQueryReadCharge(runtimeBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	fixed := uint64(unsafe.Sizeof(ContractQueryService{})) + uint64(unsafe.Sizeof(ContractQueryConsumer{})) + target + snapshot + 2*(queryRequestBytes+queryResponseBytes+uint64(unsafe.Sizeof(RequestInput{}))+uint64(unsafe.Sizeof(Publication{}))+uint64(unsafe.Sizeof(timev4.Deadline{})))
	charge := resourcev4.Vector{resourcev4.SDKBytes: fixed, resourcev4.Items: 6}
	for _, next := range []resourcev4.Vector{read, read, {resourcev4.SDKBytes: runtimeBytes}} {
		charge, err = charge.Add(next)
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	return charge, nil
}

// NewContractQueryService is installed once before ordinary channel admission.
// The reference is part of the Session's original aggregate RPC reserve; no
// root allocation or new reference is attempted on the reader or query path.
func (n *Network) NewContractQueryService(routes *ContractRoutes, clock *timev4.Clock, reservation resourcev4.Reference, runtimeBytes uint64) (_ *ContractQueryService, err error) {
	if n == nil || routes == nil || clock == nil {
		return nil, ErrConfiguration
	}
	charge, err := ContractQueryServiceCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return nil, err
	}
	if n.queries != nil {
		return nil, ErrAssociation
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	routes.mu.Lock()
	defer routes.mu.Unlock()
	if routes.closed || routes.cleaned || routes.captures == math.MaxUint32 {
		return nil, ErrClosed
	}
	if err := reservation.CheckSameEnvironment(routes.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	q := &ContractQueryService{network: n, routes: routes, clock: clock, reservation: owned, wake: make(chan struct{}, 1)}
	defer func() {
		if err != nil {
			owned.Release()
		}
	}()
	q.targets, err = protocolv4.NewContractQueryCodec()
	if err != nil {
		return nil, err
	}
	q.snapshots, err = protocolv4.NewContractSnapshotEncoder()
	if err != nil {
		return nil, err
	}
	routes.captures++
	n.queries = q
	return q, nil
}

// openInputLocked is called with the original Network gate, only for the exact
// trusted fixed query tuple. Pending storage does not admit the full read.
func (q *ContractQueryService) openInputLocked(t Ticket, h protocolv4.ApplicationHeader, slot *networkSlot) (*RequestInput, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.cleaned {
		return nil, ErrClosed
	}
	if err := q.reservation.Check(); err != nil {
		return nil, err
	}
	if h.Fields().PayloadBytes > queryRequestBytes || slot.class != contractQuery || slot.inputAttached {
		return nil, ErrMethod
	}
	for i, p := range q.pending {
		if p != nil {
			continue
		}
		input := &RequestInput{header: h, reservation: q.reservation, capture: true, ticket: t, query: q, queryIndex: uint8(i), payload: make([]byte, int(h.Fields().PayloadBytes))}
		q.pending[i] = input
		slot.inputAttached = true
		return input, nil
	}
	return nil, ErrCapacity
}

func (q *ContractQueryService) releaseInput(index uint8, p *RequestInput) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if index < 2 && q.pending[index] == p {
		q.pending[index] = nil
	}
	q.notifyLocked()
	q.cleanupLocked()
}

func (q *ContractQueryService) notifyLocked() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
	select {
	case q.executorWake <- struct{}{}:
	default:
	}
}
func (q *ContractQueryService) Wake() <-chan struct{} { return q.wake }

// Begin transfers one complete fixed input only when a complete original
// response position is free. Two older physical response tails can leave two
// legal new requests pending without blocking the shared reader or borrowing
// more full output capacity. Original request deadlines/authorization still
// need the fixed service's admission checks before Resolve/Publish.
func (q *ContractQueryService) Begin() (ContractQueryJob, error) {
	return q.begin(nil)
}

func (q *ContractQueryService) begin(consumer *ContractQueryConsumer) (ContractQueryJob, error) {
	if q == nil {
		return ContractQueryJob{}, ErrOwner
	}
	if _, err := q.RefuseExpired(); err != nil {
		return ContractQueryJob{}, err
	}
	// Network identity is stable until the service's actual cleanup. Read it
	// under q's gate, then acquire gates in the sole Network -> service order.
	q.mu.Lock()
	n := q.network
	q.mu.Unlock()
	if n == nil {
		return ContractQueryJob{}, ErrClosed
	}
	n.mu.Lock()
	q.mu.Lock()
	if q.closed || q.cleaned || n.closed {
		q.mu.Unlock()
		n.mu.Unlock()
		return ContractQueryJob{}, ErrClosed
	}
	if q.consumer != consumer || q.consumerStopped {
		q.mu.Unlock()
		n.mu.Unlock()
		return ContractQueryJob{}, ErrOwner
	}
	if err := q.reservation.Check(); err != nil {
		q.mu.Unlock()
		n.mu.Unlock()
		return ContractQueryJob{}, err
	}
	free := -1
	for i := range q.outputs {
		if !q.outputs[i].occupied && q.outputs[i].generation != math.MaxUint64 {
			free = i
			break
		}
	}
	if free < 0 {
		q.mu.Unlock()
		n.mu.Unlock()
		return ContractQueryJob{}, ErrCapacity
	}
	var input *RequestInput
	var receiver *Receiver
	var ticket Ticket
	start, end, _ := n.bounds(contractQuery)
	for at := 0; at < 2; at++ {
		i := start + (int(q.cursor)+at)%2
		if i >= end {
			break
		}
		s := &n.slots[incoming][i]
		m := &s.received
		if s.state == networkFree || !m.ready || m.input == nil || m.input.query != q || s.message.publisher != nil {
			continue
		}
		input = m.input
		receiver = m.receiver
		ticket = Ticket{n, s.generation, uint16(i), incoming}
		m.input = nil
		m.ready = false
		m.receiver = nil
		q.cursor = uint8((i - start + 1) % 2)
		break
	}
	if input == nil {
		q.mu.Unlock()
		n.mu.Unlock()
		return ContractQueryJob{}, ErrCapacity
	}
	s := &q.outputs[free]
	generation := s.generation + 1
	*s = queryOutput{generation: generation, occupied: true, stepping: true, ticket: ticket, header: input.header}
	job := ContractQueryJob{q, generation, uint8(free)}
	decoder := q.targets
	clock := q.clock
	q.mu.Unlock()
	n.mu.Unlock()
	returned := false
	defer func() {
		input.Close()
		if !returned {
			q.mu.Lock()
			s.stepping = false
			s.canceled = true
			q.releaseOutputLocked(uint8(free), generation)
			q.mu.Unlock()
		}
	}()
	// The shared reader has relinquished this input. The fixed decoder runs
	// outside its gates and scans at most the admitted 2 KiB canonical payload.
	input.mu.Lock()
	targets, err := decoder.DecodeTargets(input.payload)
	input.mu.Unlock()
	var deadline *timev4.Deadline
	var deadlineErr error
	if err == nil {
		deadline, deadlineErr = timev4.NewDeadline(clock, s.header.Fields().DeadlineAtMS)
	}
	q.mu.Lock()
	s = &q.outputs[free]
	s.stepping = false
	returned = true
	if err != nil || q.closed || s.canceled {
		q.releaseOutputLocked(uint8(free), generation)
		q.mu.Unlock()
		if err != nil {
			// The original receiver object is the channel generation. Poison
			// only it and wake its publisher so an idle Stream read is canceled
			// by the existing channel worker. No Session-wide failure or reply
			// can reinterpret malformed fixed SDK input as valid dispatch.
			receiver.failContractQuery()
			err = ErrContractQuerySchema
		} else {
			err = ErrClosed
		}
		return ContractQueryJob{}, err
	}
	if deadlineErr != nil {
		q.mu.Unlock()
		defer job.Close()
		if err := job.Refuse(queryTimeRefusal(deadlineErr)); err != nil {
			return ContractQueryJob{}, err
		}
		return ContractQueryJob{}, ErrCapacity
	}
	s.read = &ContractQueryRead{registry: q.routes, reservation: q.reservation, targets: targets, shared: true}
	s.payload = make([]byte, queryResponseBytes)
	s.deadline = deadline
	q.mu.Unlock()
	return job, nil
}

func (j ContractQueryJob) slotLocked() (*queryOutput, error) {
	q := j.service
	if q == nil || j.index >= 2 {
		return nil, ErrOwner
	}
	s := &q.outputs[j.index]
	if !s.occupied || s.generation != j.generation || s.canceled || q.closed {
		return nil, ErrOwner
	}
	return s, nil
}

// NextTarget exposes one original target for current authorization by the
// trusted Session service. It cannot supply a permission from peer metadata.
func (j ContractQueryJob) NextTarget() (int, protocolv4.ContractQueryTarget, error) {
	q := j.service
	if q == nil {
		return 0, protocolv4.ContractQueryTarget{}, ErrOwner
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	s, err := j.slotLocked()
	if err != nil {
		return 0, protocolv4.ContractQueryTarget{}, err
	}
	if s.stepping || s.queued || s.read == nil {
		return 0, protocolv4.ContractQueryTarget{}, ErrOwner
	}
	s.read.mu.Lock()
	defer s.read.mu.Unlock()
	index := int(s.read.resolved)
	if index == s.read.targets.Count() {
		return index, protocolv4.ContractQueryTarget{}, ErrCapacity
	}
	target, err := s.read.targets.Target(index)
	return index, target, err
}

func (j ContractQueryJob) Resolve(index int, access QueryTargetAccess) (err error) {
	q := j.service
	if q == nil {
		return ErrOwner
	}
	q.mu.Lock()
	s, err := j.slotLocked()
	if err != nil {
		q.mu.Unlock()
		return err
	}
	if s.stepping || s.queued || s.read == nil {
		q.mu.Unlock()
		return ErrOwner
	}
	s.stepping = true
	read, deadline := s.read, s.deadline
	q.mu.Unlock()
	returned := false
	defer func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		s.stepping = false
		if !returned {
			s.canceled = true
		}
		if q.closed || s.canceled {
			q.releaseOutputLocked(j.index, j.generation)
			err = ErrClosed
		}
	}()
	err = deadline.Check()
	if err == nil {
		err = read.Resolve(index, access)
	}
	returned = true
	return err
}

// Publish moves the completed original response buffer to this request's sole
// publisher, without a second 72 KiB copy or root reserve. Encoding is completed
// by bounded EncodeStep opportunities before this original publication gate.
// A racing STOP/terminal response wins the same original Network output gate.
func (j ContractQueryJob) Publish() error {
	q := j.service
	if q == nil {
		return ErrOwner
	}
	q.mu.Lock()
	s, err := j.slotLocked()
	if err != nil {
		q.mu.Unlock()
		return err
	}
	if s.stepping || s.queued || s.read == nil {
		q.mu.Unlock()
		return ErrOwner
	}
	if !s.encoded {
		q.mu.Unlock()
		return ErrCapacity
	}
	s.stepping = true
	read, buffer, n, deadline, length := s.read, s.payload, q.network, s.deadline, s.bytes
	request := s.header
	q.mu.Unlock()
	returned := false
	defer func() {
		if !returned {
			q.mu.Lock()
			s.stepping = false
			s.canceled = true
			q.releaseOutputLocked(j.index, j.generation)
			q.mu.Unlock()
		}
	}()
	err = deadline.Check()
	n.mu.Lock()
	defer n.mu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	s.stepping = false
	returned = true
	if q.closed || s.canceled {
		q.releaseOutputLocked(j.index, j.generation)
		return ErrClosed
	}
	if err != nil {
		return err
	}
	slot, err := n.slotLocked(s.ticket)
	if err != nil {
		return err
	}
	if slot.inputState != InputComplete || slot.class != contractQuery || slot.message.publisher != nil {
		return ErrOwner
	}
	var publisher *Publisher
	for _, p := range n.publishers {
		if p != nil && p.channel == slot.path.Channel {
			publisher = p
			break
		}
	}
	if publisher == nil {
		return ErrOwner
	}
	if err := publisher.liveLocked(); err != nil {
		return err
	}
	if err := q.reservation.Check(); err != nil {
		return err
	}
	var wire [512]byte
	f := request.Fields()
	headerBytes, h, err := publisher.codec.Encode(wire[:], "query_contracts_response", protocolv4.ApplicationHeaderFields{Type: f.Type, ServiceContractDigest: f.ServiceContractDigest, PayloadBytes: uint32(length)})
	if err != nil {
		return err
	}
	if err := slot.header.MatchResponse(h); err != nil {
		return err
	}
	m := sendMessage{publisher: publisher, header: h, headerBytes: uint16(headerBytes), payload: buffer[:length:length], publication: &Publication{}, querySource: j, prev: -1, nextReady: -1}
	copy(m.headerWire[:], wire[:headerBytes])
	slot.message = m
	s.queued = true
	read.Close()
	s.read = nil
	publisher.enqueueLocked(s.ticket, laneQuery)
	return nil
}

func (j ContractQueryJob) Close() {
	q := j.service
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if j.index >= 2 {
		return
	}
	s := &q.outputs[j.index]
	if !s.occupied || s.generation != j.generation || s.queued {
		return
	}
	s.canceled = true
	if !s.stepping {
		q.releaseOutputLocked(j.index, j.generation)
	}
}

// cancelOutputLocked is called under the original Network gate when STOP or
// channel retirement wins. Queued sources retain the publisher's actual tail;
// an unqueued job only retains an already active real step until it exits.
func (q *ContractQueryService) cancelOutputLocked(ticket Ticket) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.outputs {
		s := &q.outputs[i]
		if s.occupied && s.ticket == ticket && !s.queued {
			s.canceled = true
			if !s.stepping {
				q.releaseOutputLocked(uint8(i), s.generation)
			}
		}
	}
}

// releaseSource is used only after the publisher's real last source use.
func (j ContractQueryJob) releaseSource() {
	q := j.service
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.releaseOutputLocked(j.index, j.generation)
}
func (q *ContractQueryService) releaseOutputLocked(index uint8, generation uint64) {
	if index >= 2 {
		return
	}
	s := &q.outputs[index]
	if !s.occupied || s.generation != generation || s.stepping {
		return
	}
	if s.read != nil {
		s.read.Close()
	}
	clear(s.payload)
	*s = queryOutput{generation: generation}
	q.notifyLocked()
	q.cleanupLocked()
}
func (q *ContractQueryService) Close() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	for i := range q.outputs {
		s := &q.outputs[i]
		if s.occupied && !s.queued {
			s.canceled = true
			if !s.stepping {
				q.releaseOutputLocked(uint8(i), s.generation)
			}
		}
	}
	q.notifyLocked()
	q.cleanupLocked()
}
func (q *ContractQueryService) cleanupLocked() {
	if !q.closed || q.cleaned || q.checking || q.consumer != nil && !q.consumerStopped {
		return
	}
	for i := range q.outputs {
		if q.outputs[i].occupied || q.pending[i] != nil {
			return
		}
	}
	r := q.routes
	q.routes = nil
	q.network = nil
	q.targets = nil
	q.snapshots = nil
	q.clock = nil
	q.executorWake = nil
	r.mu.Lock()
	r.captures--
	r.cleanupLocked()
	r.mu.Unlock()
	q.reservation.Release()
	q.reservation = resourcev4.Reference{}
	q.cleaned = true
}
func (q *ContractQueryService) CleanupComplete() bool {
	if q == nil {
		return true
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.cleaned
}
func (*ContractQueryService) String() string               { return "Flowersec.ContractQueryService" }
func (*ContractQueryService) GoString() string             { return "Flowersec.ContractQueryService" }
func (*ContractQueryService) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
func (ContractQueryJob) String() string                    { return "Flowersec.ContractQueryJob" }
func (ContractQueryJob) GoString() string                  { return "Flowersec.ContractQueryJob" }
func (ContractQueryJob) MarshalJSON() ([]byte, error)      { return []byte("{}"), nil }

// RefuseExpired consumes only the original pending input/small ReplySlot under
// the same exclusive root consumer. It requires no full response vector.
func (c *ContractQueryConsumer) RefuseExpired() (int, error) {
	if c == nil {
		return 0, ErrOwner
	}
	q := c.service.Load()
	if q == nil {
		return 0, ErrClosed
	}
	return q.RefuseExpired()
}
