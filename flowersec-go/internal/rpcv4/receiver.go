package rpcv4

import (
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var ErrContractQuerySchema = errors.New("rpcv4: invalid fixed contract query schema")

func (r *Receiver) failContractQuery() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.failure != nil {
		return
	}
	r.failure = ErrContractQuerySchema
	r.notifyLocked()
	r.network.mu.Lock()
	defer r.network.mu.Unlock()
	if r.publisher != nil && !r.publisher.closed {
		r.publisher.failure = ErrContractQuerySchema
		r.publisher.notifyLocked()
	}
}

// IncomingAdmission is the trusted SDK service table, not an application hook.
// OpenInput must synchronously choose admitted capture or protected discard
// backing and call Network.NewIncomingInput for this exact ticket. It may not
// wait for budget, output, an executor, or invoke application code. Its protected
// discard/hash capacity covers every signed K+2 live incoming position.
type IncomingAdmission interface {
	OpenInput(Ticket, protocolv4.ApplicationHeader) (*RequestInput, error)
}

type receiveMessage struct {
	receiver *Receiver
	input    *RequestInput
	serial   uint64
	next     uint32
	header   protocolv4.ApplicationHeader
	ready    bool
}

// Receiver uses the same Session network table as all publishers and other
// channels. Only a fixed parser/header/error decoder is per channel; it creates
// no per-serial tombstones, result queues or per-message fragment buffers.
type Receiver struct {
	mu           sync.Mutex
	network      *Network
	publisher    *Publisher
	admission    IncomingAdmission
	reservation  resourcev4.Reference
	parser       *protocolv4.RPCFragmentParser
	codec        *protocolv4.ApplicationHeaderCodec
	errorDecoder *protocolv4.Decoder
	channel      [16]byte
	highwater    uint64
	cursor       int
	wake         chan struct{}
	failure      error
	closed       bool
}

func ReceiverCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	h, err := protocolv4.ApplicationHeaderBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	p, err := protocolv4.RPCFragmentParserBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	e, err := protocolv4.DecoderBackingBytes(256, 8)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: h + p + e + uint64(unsafe.Sizeof(Receiver{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func (n *Network) NewReceiver(p *Publisher, admission IncomingAdmission, reservation resourcev4.Reference, runtimeBytes uint64) (*Receiver, error) {
	if n == nil || p == nil || p.network != n || admission == nil {
		return nil, ErrConfiguration
	}
	charge, err := ReceiverCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return nil, err
	}
	if err := p.liveLocked(); err != nil {
		return nil, err
	}
	index := -1
	for i, r := range n.receivers {
		if r != nil && r.channel == p.channel {
			return nil, ErrAssociation
		}
		if r == nil && index < 0 {
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
	parser, err := protocolv4.NewRPCFragmentParser()
	if err != nil {
		owned.Release()
		return nil, err
	}
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		owned.Release()
		return nil, err
	}
	decoder, err := protocolv4.NewDecoder(256, 8)
	if err != nil {
		owned.Release()
		return nil, err
	}
	r := &Receiver{network: n, publisher: p, admission: admission, reservation: owned, parser: parser, codec: codec, errorDecoder: decoder, channel: p.channel, wake: make(chan struct{}, 1)}
	n.receivers[index] = r
	return r, nil
}
func (r *Receiver) Wake() <-chan struct{} { return r.wake }
func (r *Receiver) notifyLocked() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Feed transfers borrowed authenticated Stream bytes before the caller reuses
// its admitted read buffer. A record can split any field or contain many
// interleaved fragments. Any failure permanently poisons this channel parser.
func (r *Receiver) Feed(input []byte) (consumed int, err error) {
	if r == nil {
		return 0, ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, ErrClosed
	}
	if r.failure != nil {
		return 0, r.failure
	}
	defer func() {
		if err != nil {
			r.failure = err
			r.notifyLocked()
		}
	}()
	if err = r.reservation.Check(); err != nil {
		return 0, err
	}
	for consumed < len(input) {
		used, part, e := r.parser.Next(input[consumed:])
		consumed += used
		if e != nil {
			return consumed, e
		}
		if part.Fragment.Serial != 0 {
			if e = r.accept(part); e != nil {
				return consumed, e
			}
		}
		if used == 0 {
			return consumed, ErrOwner
		}
	}
	return consumed, nil
}
func (r *Receiver) accept(part protocolv4.RPCFragmentPart) error {
	f := part.Fragment
	if f.Kind == protocolv4.RPCBegin {
		return r.begin(f)
	}
	n := r.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if f.Kind == protocolv4.RPCStopOutput {
		return r.stopLocked(f.Serial)
	}
	t, s, err := r.messageLocked(f.Serial)
	if err != nil {
		return err
	}
	m := &s.received
	switch f.Kind {
	case protocolv4.RPCData:
		offset := uint64(f.Offset) + uint64(part.ChunkOffset)
		if offset != uint64(m.next) || uint64(len(f.Payload)) > uint64(m.header.Fields().PayloadBytes-m.next) {
			return protocolv4.CBORFailure("application_payload_length")
		}
		if t.direction == incoming {
			err = m.input.WriteAt(m.next, f.Payload)
		} else {
			err = s.completion.write(m.next, f.Payload)
		}
		if err != nil {
			return err
		}
		m.next += uint32(len(f.Payload))
		if m.next == m.header.Fields().PayloadBytes {
			if !part.Last {
				return protocolv4.CBORFailure("application_payload_length")
			}
			return r.finishLocked(t, s, false)
		}
	case protocolv4.RPCAbort:
		if f.Offset != m.next || m.next >= m.header.Fields().PayloadBytes {
			return protocolv4.CBORFailure("abort_offset")
		}
		if t.direction == incoming {
			if err := m.input.Abort(f.Offset); err != nil {
				return err
			}
		}
		return r.finishLocked(t, s, true)
	default:
		return protocolv4.CBORFailure("fragment_unknown_kind")
	}
	return nil
}
func (r *Receiver) begin(f protocolv4.RPCFragment) error {
	if r.highwater == math.MaxUint64 || f.Serial != r.highwater+1 {
		return protocolv4.CBORFailure("fragment_message_serial_range")
	}
	h, err := r.codec.Decode(f.Header)
	if err != nil {
		return err
	}
	if !h.OrdinaryRPC() || h.IsResponse() != (f.ReplyTo != 0) {
		return protocolv4.CBORFailure("application_response_kind")
	}
	n := r.network
	if !h.IsResponse() {
		t, err := n.AcceptIncoming(h, Association{r.channel, f.Serial})
		if err != nil {
			return err
		}
		// This finite SDK admission occurs outside the Network gate. The original
		// ticket and input binding are rechecked before any payload is transferred.
		input, err := r.admission.OpenInput(t, h)
		if err != nil {
			_ = n.Release(t)
			return err
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		s, err := n.slotLocked(t)
		if err != nil {
			if input != nil {
				input.Close()
			}
			return err
		}
		if input == nil {
			n.releaseLocked(t, s)
			return ErrOwner
		}
		input.mu.Lock()
		bound := input.ticket == t && input.header == h && input.state == InputCollecting
		input.mu.Unlock()
		if !bound || !s.inputAttached {
			input.Close()
			n.releaseLocked(t, s)
			return ErrAssociation
		}
		s.received = receiveMessage{receiver: r, input: input, serial: f.Serial, header: h}
		r.highwater = f.Serial
		if h.Fields().PayloadBytes == 0 {
			return r.finishLocked(t, s, false)
		}
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := range n.slots[outgoing] {
		s := &n.slots[outgoing][i]
		if s.state == networkFree || s.state == networkReserved || s.path != (Association{r.channel, f.ReplyTo}) {
			continue
		}
		if s.completion == nil || s.received.receiver != nil || !s.message.complete {
			return ErrAssociation
		}
		if err := s.header.MatchResponse(h); err != nil {
			return err
		}
		if s.message.abort && !h.IsSDKError() {
			return ErrAssociation
		}
		if err := s.completion.begin(h); err != nil {
			return err
		}
		s.received = receiveMessage{receiver: r, serial: f.Serial, header: h}
		r.highwater = f.Serial
		if h.Fields().PayloadBytes == 0 {
			return r.finishLocked(Ticket{n, s.generation, uint16(i), outgoing}, s, false)
		}
		return nil
	}
	return ErrAssociation
}
func (r *Receiver) messageLocked(serial uint64) (Ticket, *networkSlot, error) {
	n := r.network
	for d := range n.slots {
		for i := range n.slots[d] {
			s := &n.slots[d][i]
			m := &s.received
			if s.state != networkFree && m.receiver == r && m.serial == serial && !m.ready && m.next < m.header.Fields().PayloadBytes {
				return Ticket{n, s.generation, uint16(i), uint8(d)}, s, nil
			}
		}
	}
	return Ticket{}, nil, ErrAssociation
}
func (r *Receiver) finishLocked(t Ticket, s *networkSlot, aborted bool) error {
	m := &s.received
	if t.direction == incoming {
		if aborted {
			s.inputState = InputAborted
			m.input.Close()
			m.input = nil
			m.receiver = nil
			return r.publisher.smallReplyLocked(t, s, "request_message_aborted")
		}
		if err := m.input.Finish(); err != nil {
			return err
		}
		s.inputState, _ = m.input.Progress()
		if m.input.refusal != "" {
			code := m.input.refusal
			m.input.Close()
			m.input = nil
			m.receiver = nil
			return r.publisher.smallReplyLocked(t, s, code)
		}
		m.ready = true
		if m.input.query != nil {
			m.input.query.mu.Lock()
			m.input.query.notifyLocked()
			m.input.query.mu.Unlock()
		}
		r.notifyLocked()
		return nil
	}
	c := s.completion
	if aborted {
		c.finish("response_aborted")
	} else {
		if m.header.IsSDKError() {
			c.mu.Lock()
			doc, err := r.errorDecoder.DecodeMap(c.payload[:c.next], "ApplicationSDKError", protocolv4.DecodeContext{})
			c.mu.Unlock()
			if err != nil {
				return err
			}
			code, ok := doc.Root().Named("ApplicationSDKError", "code").Uint()
			doc.Release()
			if !ok {
				return ErrAssociation
			}
			if err := protocolv4.ValidateApplicationSDKErrorCode(code, false); err != nil {
				return err
			}
			requestAborted, err := protocolv4.EnumValue("ApplicationSDKError", "code", "request_message_aborted")
			if err != nil {
				return err
			}
			outputStopped, err := protocolv4.EnumValue("ApplicationSDKError", "code", "response_output_stopped")
			if err != nil {
				return err
			}
			if code == requestAborted && !s.message.abort || code == outputStopped && !s.message.stopSent || s.message.abort && code != requestAborted {
				return ErrAssociation
			}
			c.mu.Lock()
			c.refusalCode = code
			c.mu.Unlock()
		}
		c.finish("")
	}
	// Unlink any still-eligible STOP before returning the same network position.
	// An accepted marker already lives solely in the Stream batch responsibility.
	s.completion = nil
	r.network.releaseLocked(t, s)
	return nil
}
func (r *Receiver) stopLocked(serial uint64) error {
	if serial == 0 || serial > r.highwater {
		return protocolv4.CBORFailure("fragment_request_serial_range")
	}
	n := r.network
	for i := range n.slots[incoming] {
		s := &n.slots[incoming][i]
		if s.state != networkFree && s.path == (Association{r.channel, serial}) {
			if s.inputState != InputComplete {
				return ErrAssociation
			}
			return r.publisher.stopResponseLocked(Ticket{n, s.generation, uint16(i), incoming})
		}
	}
	// A live response is an invalid STOP target; a retired serial is ignored
	// without reconstructing its previous type or keeping a history entry.
	for i := range n.slots[outgoing] {
		m := &n.slots[outgoing][i].received
		if m.receiver == r && m.serial == serial {
			return ErrAssociation
		}
	}
	return nil
}

// NextRequest transfers one complete input to the SDK service dispatcher. It
// never waits or invokes application code. Take/Close of that input cannot
// release the original ReplySlot; only its response terminal or channel cleanup
// does so. The bounded table itself is the ready set, with no new input queue.
func (r *Receiver) NextRequest() (Ticket, *RequestInput, error) { return r.nextRequest(nil) }
func (r *Receiver) nextRequest(consumer *ServiceConsumer) (Ticket, *RequestInput, error) {
	if r == nil {
		return Ticket{}, nil, ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.failure != nil {
		return Ticket{}, nil, ErrClosed
	}
	n := r.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.serviceConsumer != consumer || consumer != nil && consumer.network.Load() != n {
		return Ticket{}, nil, ErrOwner
	}
	width := len(n.slots[incoming])
	for count := 0; count < width; count++ {
		i := (r.cursor + count) % width
		s := &n.slots[incoming][i]
		m := &s.received
		if s.state != networkFree && m.receiver == r && m.ready && m.input != nil && m.input.query == nil {
			input := m.input
			m.input = nil
			m.ready = false
			m.receiver = nil
			r.cursor = (i + 1) % width
			return Ticket{n, s.generation, uint16(i), incoming}, input, nil
		}
	}
	return Ticket{}, nil, ErrCapacity
}
func (r *Receiver) End() error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.failure != nil {
		return r.failure
	}
	return r.parser.End()
}
func (r *Receiver) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	n := r.network
	n.mu.Lock()
	defer n.mu.Unlock()
	for d := range n.slots {
		for i := range n.slots[d] {
			s := &n.slots[d][i]
			if s.state != networkFree && s.path.Channel == r.channel {
				n.releaseLocked(Ticket{n, s.generation, uint16(i), uint8(d)}, s)
			}
		}
	}
	for i, live := range n.receivers {
		if live == r {
			n.receivers[i] = nil
		}
	}
	r.parser.Close()
	r.parser = nil
	r.codec = nil
	r.errorDecoder = nil
	r.admission = nil
	r.publisher = nil
	r.reservation.Release()
	r.reservation = resourcev4.Reference{}
	r.notifyLocked()
	n.cleanupLocked()
}
