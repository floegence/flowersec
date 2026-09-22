package rpcv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrSerialExhausted = errors.New("rpcv4: channel serial exhausted")

// BatchSink is implemented by the original Stream's internal RPCBatchWriter.
// Both calls are finite local gates; they must never perform provider I/O or
// call application code. The publisher invokes them under its original message
// gate so accepted bytes and their exact message facts commit together.
type BatchSink interface {
	TryAccept(context.Context, [][]byte) (uint64, error)
	Published(uint64) (bool, error)
	Wake() <-chan struct{}
}

const (
	laneQuery      = 0
	laneRequest    = 1
	laneCompletion = 2
)

type sendMessage struct {
	publisher                                           *Publisher
	header                                              protocolv4.ApplicationHeader
	headerWire                                          [512]byte
	headerBytes                                         uint16
	small                                               [8]byte
	payload                                             []byte
	reservation                                         resourcev4.Reference
	publication                                         *Publication
	requestCleanup                                      *Publication
	resultSource                                        *acceptedResultTail
	readSource                                          *ExecutionResultRead
	readDeadline                                        *timev4.Deadline
	requestGuard                                        RequestPublicationGuard
	querySource                                         ContractQueryJob
	queryRequest                                        ContractQueryCall
	serial                                              uint64
	next                                                uint32
	prev, nextReady                                     int32
	lane                                                uint8
	queued, begun, complete, stop, abort, stopSent, sdk bool
}

func (m *sendMessage) releaseSource() {
	clear(m.payload)
	m.payload = nil
	m.reservation.Release()
	m.reservation = resourcev4.Reference{}
	m.resultSource.finish()
	m.resultSource = nil
	m.readSource.close(true)
	m.readSource = nil
	m.readDeadline = nil
	m.requestGuard = nil
	m.querySource.releaseSource()
	m.querySource = ContractQueryJob{}
	m.queryRequest.releaseRequest()
	m.queryRequest = ContractQueryCall{}
}

type PublicationProgress struct {
	HeaderAccepted, MessageAccepted, Flushed, Terminal bool
	Reason                                             string
}

// Publication retains detached finite facts only. A successful small SDK
// replacement or ABORT never flushes the original business response handle.
type Publication struct {
	mu                                            sync.Mutex
	progress                                      PublicationProgress
	requestTracked, requestActive, requestPending bool
}

func (p *Publication) Progress() PublicationProgress {
	if p == nil {
		return PublicationProgress{Terminal: true, Reason: "owner_unavailable"}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.progress
}

// RequestCleanupComplete observes only the original ordinary request's
// physical responsibility. A terminal local submission/abandonment can still
// have a live late-response position or an accepted ABORT/STOP provider tail.
func (p *Publication) RequestCleanupComplete() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requestTracked && !p.requestActive && !p.requestPending
}

func (p *Publication) requestTail(pending bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.requestPending = pending
	p.mu.Unlock()
}

func (p *Publication) requestEnded() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.requestActive = false
	p.mu.Unlock()
}

func (p *Publication) update(header, message, flushed, terminal bool, reason string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.progress.Terminal {
		return
	}
	p.progress.HeaderAccepted = p.progress.HeaderAccepted || header
	p.progress.MessageAccepted = p.progress.MessageAccepted || message
	p.progress.Flushed = flushed
	p.progress.Terminal = terminal
	p.progress.Reason = reason
}

type Publisher struct {
	network                                                 *Network
	channel                                                 [16]byte
	sink                                                    BatchSink
	reservation                                             resourcev4.Reference
	codec                                                   *protocolv4.ApplicationHeaderCodec
	buffer                                                  [16384]byte
	readBuffer                                              [4096]byte
	views                                                   [1][]byte
	head, tail                                              [3]int32
	generalAhead, queryAhead, requestAhead, completionAhead uint8
	highwater, batchTail                                    uint64
	batchPending                                            bool
	pendingPublication                                      *Publication
	pendingRequestCleanup                                   *Publication
	pendingReservation                                      resourcev4.Reference
	pendingPayload                                          []byte
	pendingResultSource                                     *acceptedResultTail
	pendingReadSource                                       *ExecutionResultRead
	pendingQuerySource                                      ContractQueryJob
	pendingQueryRequest                                     ContractQueryCall
	wake                                                    chan struct{}
	failure                                                 error
	closed, retired                                         bool
}

func PublisherCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	n, err := protocolv4.ApplicationHeaderBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: n + uint64(unsafe.Sizeof(Publisher{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func MessageSourceCharge(payloadBytes uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if payloadBytes > 1048576 || runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(payloadBytes) + uint64(unsafe.Sizeof(Publication{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func (n *Network) NewPublisher(channel [16]byte, sink BatchSink, reservation resourcev4.Reference, runtimeBytes uint64) (*Publisher, error) {
	if n == nil || channel == ([16]byte{}) || sink == nil {
		return nil, ErrConfiguration
	}
	charge, err := PublisherCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return nil, err
	}
	index := -1
	for i, p := range n.publishers {
		if p != nil && p.channel == channel {
			return nil, ErrAssociation
		}
		if p == nil && index < 0 {
			index = i
		}
	}
	if index < 0 {
		return nil, ErrCapacity
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		owned.Release()
		return nil, err
	}
	p := &Publisher{network: n, channel: channel, sink: sink, reservation: owned, codec: codec, head: [3]int32{-1, -1, -1}, tail: [3]int32{-1, -1, -1}, wake: make(chan struct{}, 1)}
	n.publishers[index] = p
	return p, nil
}
func (n *Network) index(t Ticket) int32 {
	return int32(int(t.direction)*len(n.slots[0]) + int(t.index))
}
func (n *Network) indexed(id int32) (Ticket, *networkSlot) {
	width := len(n.slots[0])
	dir, index := int(id)/width, int(id)%width
	s := &n.slots[dir][index]
	return Ticket{n, s.generation, uint16(index), uint8(dir)}, s
}
func (p *Publisher) enqueueLocked(t Ticket, lane int) {
	n := p.network
	s, _ := n.slotLocked(t)
	m := &s.message
	if m.queued {
		return
	}
	id := n.index(t)
	m.lane = uint8(lane)
	m.prev = p.tail[lane]
	m.nextReady = -1
	m.queued = true
	if m.prev >= 0 {
		_, previous := n.indexed(m.prev)
		previous.message.nextReady = id
	} else {
		p.head[lane] = id
	}
	p.tail[lane] = id
	p.notifyLocked()
}
func (p *Publisher) unlinkLocked(t Ticket) {
	n := p.network
	s, err := n.slotLocked(t)
	if err != nil {
		return
	}
	m := &s.message
	if !m.queued {
		return
	}
	if m.prev >= 0 {
		_, previous := n.indexed(m.prev)
		previous.message.nextReady = m.nextReady
	} else {
		p.head[m.lane] = m.nextReady
	}
	if m.nextReady >= 0 {
		_, next := n.indexed(m.nextReady)
		next.message.prev = m.prev
	} else {
		p.tail[m.lane] = m.prev
	}
	m.queued = false
	m.prev = -1
	m.nextReady = -1
}
func (p *Publisher) Wake() <-chan struct{} { return p.wake }
func (p *Publisher) notifyLocked() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *Publisher) lane(s *networkSlot, dir uint8) int {
	if s.class == contractQuery {
		return laneQuery
	}
	if dir == outgoing && !s.message.stop && !s.message.abort {
		return laneRequest
	}
	return laneCompletion
}
func (p *Publisher) liveLocked() error {
	if p.failure != nil {
		return p.failure
	}
	if p.closed || p.retired {
		return ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	return p.network.reservation.Check()
}

func (p *Publisher) QueueRequest(t Ticket, headerWire, payload []byte, reservation resourcev4.Reference, runtimeBytes uint64) (*Publication, error) {
	return p.queue(t, headerWire, payload, reservation, runtimeBytes, false, nil)
}
func (p *Publisher) QueueReply(t Ticket, headerWire, payload []byte, reservation resourcev4.Reference, runtimeBytes uint64) (*Publication, error) {
	return p.queue(t, headerWire, payload, reservation, runtimeBytes, true, nil)
}

func (p *Publisher) queue(t Ticket, headerWire, payload []byte, reservation resourcev4.Reference, runtimeBytes uint64, reply bool, guard RequestPublicationGuard) (*Publication, error) {
	if p == nil {
		return nil, ErrOwner
	}
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := p.liveLocked(); err != nil {
		return nil, err
	}
	if !reply && n.closed {
		return nil, ErrClosed
	}
	s, err := n.slotLocked(t)
	if err != nil {
		return nil, err
	}
	if s.path.Channel != p.channel || s.class == generalStreaming || s.message.publisher != nil || reply != (t.direction == incoming) {
		return nil, ErrAssociation
	}
	if reply && s.inputState != InputComplete || !reply && (s.state != networkReserved || s.completion == nil) {
		return nil, ErrOwner
	}
	h, err := p.codec.Decode(headerWire)
	if err != nil {
		return nil, err
	}
	if !h.OrdinaryRPC() || uint64(len(payload)) != uint64(h.Fields().PayloadBytes) {
		return nil, ErrMethod
	}
	if reply {
		if h.IsSDKError() {
			return nil, ErrMethod
		}
		if err := s.header.MatchResponse(h); err != nil {
			return nil, err
		}
	} else if h != s.header {
		return nil, ErrAssociation
	}
	charge, err := MessageSourceCharge(h.Fields().PayloadBytes, runtimeBytes)
	if err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	pub := &Publication{}
	m := sendMessage{publisher: p, header: h, headerBytes: uint16(len(headerWire)), payload: make([]byte, len(payload)), reservation: owned, publication: pub, requestGuard: guard, prev: -1, nextReady: -1}
	if !reply {
		pub.requestTracked, pub.requestActive = true, true
		m.requestCleanup = pub
	}
	copy(m.headerWire[:], headerWire)
	copy(m.payload, payload)
	s.message = m
	p.enqueueLocked(t, p.lane(s, t.direction))
	return pub, nil
}

// CancelRequest is ordered with the batch acceptance gate. A never-started
// request is removed without burning a serial. Partial input chooses ABORT;
// a request whose final DATA already won chooses its one STOP_OUTPUT instead.
func (p *Publisher) CancelRequest(t Ticket) (bool, error) {
	if p == nil {
		return false, ErrOwner
	}
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return false, err
	}
	m := &s.message
	if t.direction != outgoing || m.publisher != p {
		return false, ErrOwner
	}
	return p.cancelRequestLocked(t, s), nil
}

func (p *Publisher) cancelRequestLocked(t Ticket, s *networkSlot) bool {
	n, m := p.network, &s.message
	if s.completion != nil {
		s.completion.abandon()
	}
	if !m.begun {
		m.publication.update(false, false, false, true, "not_submitted")
		n.releaseLocked(t, s)
		return true
	}
	if m.stopSent || m.abort {
		return false
	}
	p.unlinkLocked(t)
	if m.complete {
		m.stop = true
	} else {
		m.abort = true
		m.publication.update(true, false, false, true, "request_message_aborted")
	}
	m.releaseSource()
	p.enqueueLocked(t, p.lane(s, t.direction))
	if s.state == networkFull {
		s.state = networkLate
	}
	return false
}

// QueueAbortedReply consumes only an actual incomplete-input boundary. No
// execution digest or global nonexecution assertion is synthesized.
func (p *Publisher) QueueAbortedReply(t Ticket) error {
	if p == nil {
		return ErrOwner
	}
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return err
	}
	if t.direction != incoming || s.path.Channel != p.channel || s.inputState != InputAborted || s.message.publisher != nil {
		return ErrOwner
	}
	return p.smallReplyLocked(t, s, "request_message_aborted")
}

// QueueRefusal selects a registered SDK service error at the original complete
// input/output gate. It never certifies nonexecution or grants a retry. A
// response whose BEGIN already won cannot be replaced by a second message.
func (p *Publisher) QueueRefusal(t Ticket, code string) error {
	if p == nil {
		return ErrOwner
	}
	if _, err := protocolv4.ApplicationRefusalCode(code); err != nil {
		return err
	}
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := p.liveLocked(); err != nil {
		return err
	}
	s, err := n.slotLocked(t)
	if err != nil {
		return err
	}
	if t.direction != incoming || s.path.Channel != p.channel || (s.inputState != InputComplete && s.inputState != InputRejected) {
		return ErrOwner
	}
	m := &s.message
	if m.publisher != nil {
		if m.publisher != p || m.begun || m.sdk || m.abort || m.stop {
			return ErrOwner
		}
		p.unlinkLocked(t)
		m.publication.update(false, false, false, true, "response_superseded")
		m.releaseSource()
	}
	return p.smallReplyLocked(t, s, code)
}

func (p *Publisher) smallReplyLocked(t Ticket, s *networkSlot, code string) error {
	if err := p.liveLocked(); err != nil {
		return err
	}
	value, err := protocolv4.EnumValue("ApplicationSDKError", "code", code)
	if err != nil {
		return err
	}
	if err := protocolv4.ValidateApplicationSDKErrorCode(value, false); err != nil {
		return err
	}
	var small [8]byte
	payload, err := protocolv4.EncodeMap(small[:], "ApplicationSDKError", []protocolv4.Field{{Name: "code", Number: value}})
	if err != nil {
		return err
	}
	m := sendMessage{publisher: p, sdk: true, small: small, prev: -1, nextReady: -1}
	length, h, err := p.codec.EncodeSDKResponse(m.headerWire[:], s.header, uint32(len(payload)))
	if err != nil {
		return err
	}
	m.header = h
	m.headerBytes = uint16(length)
	s.message = m
	s.message.payload = s.message.small[:len(payload)]
	p.enqueueLocked(t, p.lane(s, t.direction))
	return nil
}

// StopResponse follows a validated live STOP_OUTPUT. It changes only future
// output interest and never cancels an execution or its result/history owner.
func (p *Publisher) StopResponse(t Ticket) error {
	if p == nil {
		return ErrOwner
	}
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	return p.stopResponseLocked(t)
}
func (p *Publisher) stopResponseLocked(t Ticket) error {
	n := p.network
	s, err := n.slotLocked(t)
	if err != nil {
		return err
	}
	if t.direction != incoming || s.path.Channel != p.channel || s.inputState != InputComplete {
		return ErrOwner
	}
	m := &s.message
	if m.publisher != nil && m.publisher != p {
		return ErrAssociation
	}
	if m.stop || m.abort || m.sdk {
		return nil
	}
	s.observation.lose("response_output_stopped", false)
	n.queries.cancelOutputLocked(t)
	if m.publisher == nil || !m.begun {
		if m.publisher != nil {
			p.unlinkLocked(t)
			m.publication.update(false, false, false, true, "response_superseded")
			m.releaseSource()
		}
		return p.smallReplyLocked(t, s, "response_output_stopped")
	}
	p.unlinkLocked(t)
	m.abort = true
	m.publication.update(true, false, false, true, "response_aborted")
	m.releaseSource()
	p.enqueueLocked(t, p.lane(s, t.direction))
	return nil
}

func (p *Publisher) chooseLocked() int {
	q, g := p.head[laneQuery] >= 0, p.head[laneRequest] >= 0 || p.head[laneCompletion] >= 0
	if q && (!g || p.generalAhead >= 8 || p.queryAhead < 1) {
		return laneQuery
	}
	if !g {
		return -1
	}
	r, c := p.head[laneRequest] >= 0, p.head[laneCompletion] >= 0
	if r && (!c || p.completionAhead >= 8) {
		return laneRequest
	}
	if c && (!r || p.requestAhead >= 1 || p.completionAhead < 8) {
		return laneCompletion
	}
	return laneRequest
}
func (p *Publisher) servedLocked(lane int) {
	if lane == laneQuery {
		p.generalAhead = 0
		p.queryAhead = min(p.queryAhead+1, 1)
		return
	}
	p.queryAhead = 0
	p.generalAhead = min(p.generalAhead+1, 8)
	if lane == laneRequest {
		p.completionAhead = 0
		p.requestAhead = min(p.requestAhead+1, 1)
	} else {
		p.requestAhead = 0
		p.completionAhead = min(p.completionAhead+1, 8)
	}
}

// Step advances one fair fragment using a conservative one-fragment batch.
// The common sink also accepts up to four; this policy never enlarges q_rpc or
// owns another forwarding window. The Session's one SDK runner invokes Step;
// it never waits for providers or runs handlers under the message gate.
func (p *Publisher) Step(ctx context.Context) (bool, error) {
	if p == nil || ctx == nil {
		return false, ErrConfiguration
	}
	n := p.network
	n.mu.Lock()
	locked := true
	defer func() {
		if locked {
			n.mu.Unlock()
		}
	}()
	if err := p.liveLocked(); err != nil {
		return false, err
	}
	if p.batchPending {
		done, err := p.sink.Published(p.batchTail)
		if err != nil {
			p.finishPendingLocked(false, "publish_failed")
			return false, err
		}
		if !done {
			return false, nil
		}
		p.finishPendingLocked(true, "")
	}
	lane := p.chooseLocked()
	if lane < 0 {
		return false, nil
	}
	t, s := n.indexed(p.head[lane])
	if guard := s.message.requestGuard; guard != nil && !s.message.abort && !s.message.stop {
		h, publication := s.message.header, s.message.publication
		n.mu.Unlock()
		locked = false
		return p.stepRequest(ctx, t, h, publication, guard)
	}
	if read := s.message.readSource; read != nil {
		n.mu.Unlock()
		locked = false
		return p.stepResultRead(ctx, t, read)
	}
	return p.stepLocked(ctx, t, s, lane, s.message.payload)
}

func (p *Publisher) stepLocked(ctx context.Context, t Ticket, s *networkSlot, lane int, payload []byte) (bool, error) {
	n := p.network
	m := &s.message
	if t.direction == outgoing && !m.begun && n.closed {
		return false, ErrClosed
	}
	var f protocolv4.RPCFragment
	switch {
	case m.stop:
		f = protocolv4.RPCFragment{Kind: protocolv4.RPCStopOutput, Serial: s.path.Serial}
	case m.abort:
		f = protocolv4.RPCFragment{Kind: protocolv4.RPCAbort, Serial: m.serial, Offset: m.next}
	case !m.begun:
		if p.highwater == math.MaxUint64 {
			return false, ErrSerialExhausted
		}
		f = protocolv4.RPCFragment{Kind: protocolv4.RPCBegin, Serial: p.highwater + 1, Header: m.headerWire[:m.headerBytes]}
		if t.direction == incoming {
			f.ReplyTo = s.path.Serial
		}
	default:
		if m.readSource != nil {
			if len(payload) == 0 {
				return false, ErrOwner
			}
			f = protocolv4.RPCFragment{Kind: protocolv4.RPCData, Serial: m.serial, Offset: m.next, Payload: payload}
		} else {
			end := min(int(m.next)+16367, len(payload))
			if end <= int(m.next) {
				return false, ErrOwner
			}
			f = protocolv4.RPCFragment{Kind: protocolv4.RPCData, Serial: m.serial, Offset: m.next, Payload: payload[int(m.next):end]}
		}
	}
	length, err := protocolv4.EncodeRPCFragment(p.buffer[:], f)
	if err != nil {
		return false, err
	}
	p.views[0] = p.buffer[:length]
	tail, err := p.sink.TryAccept(ctx, p.views[:])
	p.views[0] = nil
	if err != nil {
		return false, err
	}
	// The original Network gate is still held: Close, cancellation, response
	// matching and slot reuse cannot interleave accepted bytes and these facts.
	p.batchTail = tail
	p.batchPending = true
	p.pendingRequestCleanup = m.requestCleanup
	p.pendingRequestCleanup.requestTail(true)
	p.unlinkLocked(t)
	p.servedLocked(lane)
	switch f.Kind {
	case protocolv4.RPCBegin:
		p.highwater = f.Serial
		m.serial = f.Serial
		m.begun = true
		m.publication.update(true, false, false, false, "")
		if t.direction == outgoing {
			s.path.Serial = f.Serial
			s.state = networkFull
		}
		m.complete = m.header.Fields().PayloadBytes == 0
	case protocolv4.RPCData:
		m.next += uint32(len(f.Payload))
		m.complete = m.next == m.header.Fields().PayloadBytes
	case protocolv4.RPCStopOutput:
		m.stopSent = true
		return true, nil
	case protocolv4.RPCAbort:
		m.complete = true
		if t.direction == outgoing {
			return true, nil
		}
	}
	if m.complete {
		m.publication.update(true, f.Kind != protocolv4.RPCAbort, false, false, "")
		p.pendingPublication = m.publication
		p.pendingReservation = m.reservation
		p.pendingResultSource = m.resultSource
		p.pendingReadSource = m.readSource
		p.pendingQuerySource = m.querySource
		p.pendingQueryRequest = m.queryRequest
		if !m.sdk {
			p.pendingPayload = m.payload
		}
		m.publication = nil
		m.payload = nil
		m.reservation = resourcev4.Reference{}
		m.resultSource = nil
		m.readSource = nil
		m.readDeadline = nil
		m.requestGuard = nil
		m.querySource = ContractQueryJob{}
		m.queryRequest = ContractQueryCall{}
		if t.direction == incoming {
			s.observation.lose("response_complete", true)
			n.releaseLocked(t, s)
		}
	} else {
		p.enqueueLocked(t, p.lane(s, t.direction))
	}
	return true, nil
}
func (p *Publisher) finishPendingLocked(flushed bool, reason string) {
	p.pendingPublication.update(false, false, flushed, true, reason)
	clear(p.pendingPayload)
	p.pendingPayload = nil
	p.pendingReservation.Release()
	p.pendingReservation = resourcev4.Reference{}
	p.pendingResultSource.finish()
	p.pendingResultSource = nil
	p.pendingReadSource.close(true)
	p.pendingReadSource = nil
	p.pendingPublication = nil
	p.pendingQuerySource.releaseSource()
	p.pendingQuerySource = ContractQueryJob{}
	p.pendingQueryRequest.releaseRequest()
	p.pendingQueryRequest = ContractQueryCall{}
	p.pendingRequestCleanup.requestTail(false)
	p.pendingRequestCleanup = nil
	p.batchPending = false
}
func (p *Publisher) Close() {
	if p == nil {
		return
	}
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if p.batchPending {
		if done, err := p.sink.Published(p.batchTail); err == nil && done {
			p.finishPendingLocked(true, "")
		}
	}
	p.closed = true
	p.pendingPublication.update(false, false, false, true, "owner_unavailable")
	p.notifyLocked()
	for d := range n.slots {
		for i := range n.slots[d] {
			s := &n.slots[d][i]
			if s.path.Channel == p.channel {
				s.observation.lose("owner_unavailable", false)
			}
			if s.message.publisher == p {
				s.message.publication.update(false, false, false, true, "owner_unavailable")
			}
		}
	}
}
func (p *Publisher) Retire() error {
	if p == nil {
		return nil
	}
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if p.retired {
		return nil
	}
	if !p.closed {
		return ErrOwner
	}
	if p.batchPending {
		done, err := p.sink.Published(p.batchTail)
		if err == nil && !done {
			return ErrCapacity
		}
		if done {
			p.finishPendingLocked(true, "")
		} else {
			p.finishPendingLocked(false, "publish_failed")
		}
	}
	for d := range n.slots {
		for i := range n.slots[d] {
			if n.slots[d][i].message.publisher == p {
				return ErrCapacity
			}
		}
	}
	for i, live := range n.publishers {
		if live == p {
			n.publishers[i] = nil
		}
	}
	clear(p.buffer[:])
	p.codec = nil
	p.sink = nil
	p.reservation.Release()
	p.reservation = resourcev4.Reference{}
	p.retired = true
	n.cleanupLocked()
	return nil
}
