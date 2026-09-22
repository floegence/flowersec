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

type queryClientSlot struct {
	generation                                            uint64
	occupied, stepping, closed, requestDone, responseDone bool
	borrowed, taken                                       bool
	ticket                                                Ticket
	receiver                                              *Receiver
	publisher                                             *Publisher
	completion                                            *Completion
	request                                               []byte
	targets                                               protocolv4.ContractQueryTargets
	deadline                                              *timev4.Deadline
}

// ContractQueryClient owns the Session's two complete outgoing query vectors.
// Network Q2 reuse alone cannot reuse a vector held by a full response, a fixed
// decoder borrow or an old request provider tail. Environment acquisition and
// snapshot installation keep their own original positions and backing.
type ContractQueryClient struct {
	mu              sync.Mutex
	network         *Network
	reservation     resourcev4.Reference
	codec           *protocolv4.ContractQueryCodec
	reader          *protocolv4.ContractSnapshotReader
	decoding        *ContractQueryDecode
	initiator       *ContractQueryInitiator
	clock           *timev4.Clock
	slots           [2]queryClientSlot
	wake            chan struct{}
	executorWake    chan<- struct{}
	closed, cleaned bool
}

type ContractQueryCall struct {
	client     *ContractQueryClient
	generation uint64
	index      uint8
}

// ContractQueryResponseBorrow is private encoded input, not a verified or
// installable snapshot. The fixed SDK decoder retains it through its actual
// last use, including cancellation. It never enters general result ownership.
type ContractQueryResponseBorrow struct{ call ContractQueryCall }

func ContractQueryClientCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	codec, err := protocolv4.ContractQueryCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	reader, err := protocolv4.ContractSnapshotReaderBackingBytes(runtimeBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	per := uint64(queryRequestBytes+queryResponseBytes) + uint64(unsafe.Sizeof(Completion{})) + uint64(unsafe.Sizeof(Publication{})) + uint64(unsafe.Sizeof(ContractQueryResponseBorrow{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + 8*128
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ContractQueryClient{})) + uint64(unsafe.Sizeof(ContractQueryInitiator{})) + uint64(unsafe.Sizeof(ContractQueryDecode{})) + codec + reader + 2*per, resourcev4.Items: 9}
	for range 3 {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	return charge, nil
}

func (n *Network) NewContractQueryClient(clock *timev4.Clock, reservation resourcev4.Reference, runtimeBytes uint64) (*ContractQueryClient, error) {
	if n == nil || clock == nil {
		return nil, ErrConfiguration
	}
	charge, err := ContractQueryClientCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return nil, err
	}
	if n.queryClient != nil || n.count[outgoing][1] != 0 {
		return nil, ErrOwner
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	codec, err := protocolv4.NewContractQueryCodec()
	if err != nil {
		owned.Release()
		return nil, err
	}
	reader, err := protocolv4.NewContractSnapshotReader()
	if err != nil {
		owned.Release()
		return nil, err
	}
	c := &ContractQueryClient{reader: reader, network: n, reservation: owned, codec: codec, clock: clock, wake: make(chan struct{}, 1)}
	n.queryClient = c
	return c, nil
}

// Begin is called under an original Environment acquisition owner and fixed
// SDK opportunity. It starts no worker, channel, timer or retry. Both complete
// directions and the request publication are committed before returning; all
// failure paths retain or unwind the same original responsibility.
func (q *ContractQueryClient) Begin(publisher *Publisher, targets []protocolv4.ContractQueryTarget, known []*protocolv4.ServiceContract, deadlineMS uint64) (ContractQueryCall, error) {
	return q.begin(nil, publisher, targets, known, deadlineMS)
}
func (q *ContractQueryClient) begin(initiator *ContractQueryInitiator, publisher *Publisher, targets []protocolv4.ContractQueryTarget, known []*protocolv4.ServiceContract, deadlineMS uint64) (call ContractQueryCall, err error) {
	if q == nil || publisher == nil {
		return call, ErrOwner
	}
	q.mu.Lock()
	if q.closed || q.cleaned || publisher.network != q.network || q.initiator != initiator {
		q.mu.Unlock()
		return call, ErrClosed
	}
	if err := q.reservation.Check(); err != nil {
		q.mu.Unlock()
		return call, err
	}
	index := -1
	for i := range q.slots {
		if !q.slots[i].occupied && q.slots[i].generation != math.MaxUint64 {
			index = i
			break
		}
	}
	if index < 0 {
		q.mu.Unlock()
		return call, ErrCapacity
	}
	s := &q.slots[index]
	*s = queryClientSlot{generation: s.generation + 1, occupied: true, stepping: true, publisher: publisher, request: make([]byte, queryRequestBytes)}
	call = ContractQueryCall{q, s.generation, uint8(index)}
	n, codec, clock := q.network, q.codec, q.clock
	q.mu.Unlock()
	committed := false
	var ticket Ticket
	defer func() {
		if !committed {
			if ticket.network != nil {
				_ = n.Release(ticket)
			}
			q.mu.Lock()
			s.stepping = false
			clear(s.request)
			if s.completion != nil {
				clear(s.completion.payload)
			}
			*s = queryClientSlot{generation: call.generation}
			q.notifyLocked()
			q.cleanupLocked()
			q.mu.Unlock()
			call = ContractQueryCall{}
		}
	}()
	length, targetSet, err := codec.EncodeTargets(s.request, targets, known)
	if err != nil {
		return call, err
	}
	deadline, err := timev4.NewDeadline(clock, deadlineMS)
	if err != nil {
		return call, err
	}
	response := make([]byte, targetSet.ResponseBytes())
	n.mu.Lock()
	defer n.mu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || s.closed {
		return call, ErrClosed
	}
	if err := publisher.liveLocked(); err != nil {
		return call, err
	}
	for _, r := range n.receivers {
		if r != nil && r.publisher == publisher {
			s.receiver = r
			break
		}
	}
	if s.receiver == nil {
		return call, ErrOwner
	}
	if err := q.reservation.Check(); err != nil {
		return call, err
	}
	var header [512]byte
	hn, h, err := publisher.codec.Encode(header[:], "query_contracts_request", protocolv4.ApplicationHeaderFields{Type: n.config.Query.Type, ServiceContractDigest: n.config.Query.Contract, DeadlineAtMS: deadlineMS, PayloadBytes: uint32(length)})
	if err != nil {
		return call, err
	}
	ticket, err = n.acquireLocked(outgoing, h, Association{Channel: publisher.channel})
	if err != nil {
		return call, err
	}
	completion := &Completion{reservation: q.reservation, payload: response, limit: targetSet.ResponseBytes(), done: make(chan struct{}), query: call}
	s.ticket, s.completion, s.targets, s.deadline = ticket, completion, targetSet, deadline
	networkSlot, _ := n.slotLocked(ticket)
	networkSlot.completion = completion
	networkSlot.message = sendMessage{publisher: publisher, header: h, headerBytes: uint16(hn), payload: s.request[:length:length], publication: &Publication{}, queryRequest: call, prev: -1, nextReady: -1}
	copy(networkSlot.message.headerWire[:], header[:hn])
	publisher.enqueueLocked(ticket, laneQuery)
	s.stepping = false
	committed = true
	return call, nil
}

func (c ContractQueryCall) slotLocked() (*queryClientSlot, error) {
	if c.client == nil || c.index >= 2 {
		return nil, ErrOwner
	}
	s := &c.client.slots[c.index]
	if !s.occupied || s.generation != c.generation {
		return nil, ErrOwner
	}
	return s, nil
}

func (c ContractQueryCall) BorrowResponse() (ContractQueryResponseBorrow, error) {
	q := c.client
	if q == nil {
		return ContractQueryResponseBorrow{}, ErrOwner
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	s, err := c.slotLocked()
	if err != nil || s.closed || s.stepping || s.taken || q.closed {
		return ContractQueryResponseBorrow{}, ErrOwner
	}
	completion := s.completion
	completion.mu.Lock()
	defer completion.mu.Unlock()
	if !completion.terminal {
		return ContractQueryResponseBorrow{}, ErrCapacity
	}
	if completion.closed || completion.abandoned || completion.reason != "" {
		return ContractQueryResponseBorrow{}, ErrOwner
	}
	if err := q.reservation.Check(); err != nil {
		return ContractQueryResponseBorrow{}, err
	}
	s.borrowed, s.taken = true, true
	return ContractQueryResponseBorrow{c}, nil
}

// Progress reports only original response association/termination facts. A
// complete fixed response still requires the protected decoder/install gate.
func (c ContractQueryCall) Progress() (CompletionProgress, error) {
	q := c.client
	if q == nil {
		return CompletionProgress{}, ErrOwner
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	s, err := c.slotLocked()
	if err != nil || s.stepping || s.completion == nil {
		return CompletionProgress{}, ErrOwner
	}
	return s.completion.Progress(), nil
}

func (b ContractQueryResponseBorrow) Bytes() ([]byte, protocolv4.ApplicationHeader, protocolv4.ContractQueryTargets, error) {
	q := b.call.client
	if q == nil {
		return nil, protocolv4.ApplicationHeader{}, protocolv4.ContractQueryTargets{}, ErrOwner
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	s, err := b.call.slotLocked()
	if err != nil || !s.borrowed {
		return nil, protocolv4.ApplicationHeader{}, protocolv4.ContractQueryTargets{}, ErrOwner
	}
	if err := q.reservation.Check(); err != nil {
		return nil, protocolv4.ApplicationHeader{}, protocolv4.ContractQueryTargets{}, err
	}
	c := s.completion
	return c.payload[:c.next:c.next], c.header, s.targets, nil
}

func (b ContractQueryResponseBorrow) Release() {
	q := b.call.client
	if q == nil {
		return
	}
	q.mu.Lock()
	s, err := b.call.slotLocked()
	if err != nil || !s.borrowed {
		q.mu.Unlock()
		return
	}
	s.borrowed = false
	closed, completion := s.closed, s.completion
	q.mu.Unlock()
	if closed {
		completion.Close()
	}
}

func (c ContractQueryCall) Close() {
	q := c.client
	if q == nil {
		return
	}
	q.mu.Lock()
	s, err := c.slotLocked()
	if err != nil || s.closed {
		q.mu.Unlock()
		return
	}
	s.closed = true
	if s.stepping {
		q.mu.Unlock()
		return
	}
	publisher, ticket, completion, borrowed := s.publisher, s.ticket, s.completion, s.borrowed
	q.mu.Unlock()
	_, _ = publisher.CancelRequest(ticket)
	if !borrowed {
		completion.Close()
	}
}

func (c ContractQueryCall) releaseRequest() {
	q := c.client
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if s, err := c.slotLocked(); err == nil {
		s.requestDone = true
		clear(s.request)
		s.request = nil
		q.releaseSlotLocked(c.index)
	}
}

func (c ContractQueryCall) releaseResponse() {
	q := c.client
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if s, err := c.slotLocked(); err == nil {
		s.responseDone = true
		s.completion = nil
		q.releaseSlotLocked(c.index)
	}
}

func (q *ContractQueryClient) releaseSlotLocked(index uint8) {
	s := &q.slots[index]
	if s.occupied && !s.stepping && s.requestDone && s.responseDone && !s.borrowed {
		*s = queryClientSlot{generation: s.generation}
		q.notifyLocked()
		q.cleanupLocked()
	}
}

func (c ContractQueryCall) notify() {
	if c.client != nil {
		c.client.mu.Lock()
		c.client.notifyLocked()
		c.client.mu.Unlock()
	}
}

func (q *ContractQueryClient) notifyLocked() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
	select {
	case q.executorWake <- struct{}{}:
	default:
	}
}
func (q *ContractQueryClient) Wake() <-chan struct{} { return q.wake }

// closeInputs can run under the original Network gate. It seals response
// delivery but never refunds a reader, decoder borrow or request provider tail.
func (q *ContractQueryClient) closeInputs() {
	q.mu.Lock()
	q.closed = true
	var completions [2]*Completion
	for i := range q.slots {
		s := &q.slots[i]
		s.closed = s.occupied
		if s.occupied && !s.stepping && !s.borrowed {
			completions[i] = s.completion
		}
	}
	q.notifyLocked()
	q.cleanupLocked()
	q.mu.Unlock()
	for _, c := range completions {
		c.Close()
	}
}

func (q *ContractQueryClient) Close() {
	if q == nil {
		return
	}
	q.mu.Lock()
	q.closed = true
	var calls [2]ContractQueryCall
	for i, s := range q.slots {
		if s.occupied {
			calls[i] = ContractQueryCall{q, s.generation, uint8(i)}
		}
	}
	q.mu.Unlock()
	for _, c := range calls {
		c.Close()
	}
	q.closeInputs()
}

func (q *ContractQueryClient) cleanupLocked() {
	if !q.closed || q.cleaned || q.decoding != nil {
		return
	}
	for i := range q.slots {
		if q.slots[i].occupied {
			return
		}
	}
	q.network, q.codec, q.reader, q.clock, q.executorWake = nil, nil, nil, nil, nil
	if q.initiator != nil {
		q.initiator.client.CompareAndSwap(q, nil)
		q.initiator = nil
	}
	q.reservation.Release()
	q.reservation = resourcev4.Reference{}
	q.cleaned = true
}

func (q *ContractQueryClient) CleanupComplete() bool {
	if q == nil {
		return true
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.cleaned
}

// ContractQueryInitiator exclusively connects this Session to its original
// Environment acquisition owners and root fixed worker. Stop is terminal.
type ContractQueryInitiator struct {
	client atomic.Pointer[ContractQueryClient]
}

func (q *ContractQueryClient) ClaimInitiator(wake chan<- struct{}, owner resourcev4.Reference) (*ContractQueryInitiator, error) {
	if q == nil || wake == nil {
		return nil, ErrConfiguration
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.cleaned || q.initiator != nil {
		return nil, ErrOwner
	}
	for _, s := range q.slots {
		if s.occupied {
			return nil, ErrOwner
		}
	}
	if err := owner.CheckSameEnvironment(q.reservation); err != nil {
		return nil, err
	}
	x := &ContractQueryInitiator{}
	x.client.Store(q)
	q.initiator = x
	q.executorWake = wake
	return x, nil
}
func (x *ContractQueryInitiator) Begin(publisher *Publisher, targets []protocolv4.ContractQueryTarget, known []*protocolv4.ServiceContract, deadlineMS uint64) (ContractQueryCall, error) {
	if x == nil {
		return ContractQueryCall{}, ErrOwner
	}
	q := x.client.Load()
	if q == nil {
		return ContractQueryCall{}, ErrClosed
	}
	return q.begin(x, publisher, targets, known, deadlineMS)
}
func (x *ContractQueryInitiator) Stop() {
	if x == nil {
		return
	}
	if q := x.client.Swap(nil); q != nil {
		q.Close()
	}
}

// CleanupComplete includes the original request provider tail and any decoder
// borrow, rather than only the logical network Q2 association.
func (c ContractQueryCall) CleanupComplete() bool {
	if c.client == nil {
		return true
	}
	q := c.client
	q.mu.Lock()
	defer q.mu.Unlock()
	_, err := c.slotLocked()
	return err != nil
}

// CheckService binds both directions to one actual Session network, not merely
// to two unrelated pools in the same Environment.
func (q *ContractQueryClient) CheckService(service *ContractQueryService) error {
	if q == nil || service == nil {
		return ErrOwner
	}
	service.mu.Lock()
	network := service.network
	closed := service.closed
	service.mu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if closed || q.closed || network == nil || network != q.network {
		return ErrOwner
	}
	return nil
}
