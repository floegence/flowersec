package protocolv4

import (
	"encoding/binary"
	"unsafe"
)

// StreamMessagePart borrows only the current authenticated reader buffer.
// First delivers the validated header before any body byte is consumed. A
// complete message is not application delivery or permission to execute it.
type StreamMessagePart struct {
	Header      ApplicationHeader
	Payload     []byte
	Offset      uint32
	First, Last bool
}

// StreamMessageParser is a single-reader parser for one dedicated call. It
// never reads ahead, stores an item, dispatches a callback or selects RPC
// fragmentation. Its original contract must remain live through the first
// request header. Response parsers retain only detached original policy.
type StreamMessageParser struct {
	codec                                 *ApplicationHeaderCodec
	sdk                                   *Decoder
	contract                              *ServiceContract
	policy                                ServiceContractPolicy
	original, header                      ApplicationHeader
	verifier                              *ExecutionRequestVerifier
	storage                               [514]byte
	errorBody                             [256]byte
	have, need                            int
	offset                                uint32
	items                                 uint32
	bytes                                 uint64
	lastSDKError                          uint64
	request, requestDone, terminal, ended bool
	framingOnly                           bool
	resume                                bool
	failure                               error
}

func (h ApplicationHeader) StreamRequest() bool {
	return h.name == "execution_stream_request" || h.name == "transient_stream_request"
}

func StreamMessageParserBackingBytes(hashRuntimeBytes uint64) (uint64, error) {
	n, err := ApplicationHeaderBackingBytes()
	if err != nil {
		return 0, err
	}
	errorBytes, err := decoderBackingBytes(256, 3, 0)
	if err != nil {
		return 0, err
	}
	n += errorBytes + uint64(unsafe.Sizeof(StreamMessageParser{})) + uint64(unsafe.Sizeof(StreamMessagePart{}))
	if hashRuntimeBytes != 0 {
		hashBytes, err := ExecutionRequestVerifierBackingBytes(hashRuntimeBytes)
		if err != nil || hashBytes > ^uint64(0)-n {
			return 0, CBORFailure("configuration_capacity")
		}
		n += hashBytes
	}
	return n, nil
}

func newStreamMessageParser(contract *ServiceContract) (*StreamMessageParser, error) {
	return newApplicationStreamParser(contract, false)
}

func newApplicationStreamParser(contract *ServiceContract, resume bool) (*StreamMessageParser, error) {
	policy, err := contract.Policy()
	if err != nil {
		return nil, err
	}
	if !resume && (policy.Shape != 1 || policy.MaxItemCount == 0 || policy.MaxStreamPayloadBytes == 0 || policy.StreamDurationMS == 0) || resume && (policy.Shape != 0 || policy.Semantics != 1 || policy.ExecutionMode != 1) {
		return nil, CBORFailure("streaming_contract_shape")
	}
	c, err := NewApplicationHeaderCodec()
	if err != nil {
		return nil, err
	}
	d, err := newDecoder(256, 3, 0)
	if err != nil {
		return nil, err
	}
	return &StreamMessageParser{codec: c, sdk: d, policy: policy, need: 2, resume: resume}, nil
}

// Resume uses the same application prefix and exact request/response matching.
// Its one complete message ends the borrowed framing qualification without FIN
// or reading a byte belonging to the caller's subsequent application protocol.
func NewResumeRequestFramer(contract *ServiceContract) (*StreamMessageParser, error) {
	p, err := newApplicationStreamParser(contract, true)
	if err == nil {
		p.request, p.framingOnly, p.contract = true, true, contract
	}
	return p, err
}

func NewResumeResponseParser(contract *ServiceContract, original ApplicationHeader) (*StreamMessageParser, error) {
	if original.Kind() != "resume_request" {
		return nil, CBORFailure("resume_request_kind")
	}
	if err := contract.CheckRequest(original); err != nil {
		return nil, err
	}
	p, err := newApplicationStreamParser(contract, true)
	if err == nil {
		p.original = original
	}
	return p, err
}

func NewStreamRequestParser(contract *ServiceContract, hashRuntimeBytes uint64) (*StreamMessageParser, error) {
	p, err := newStreamMessageParser(contract)
	if err != nil {
		return nil, err
	}
	if p.policy.Semantics == 1 && hashRuntimeBytes == 0 {
		return nil, CBORFailure("configuration_capacity")
	}
	if _, err = StreamMessageParserBackingBytes(hashRuntimeBytes); err != nil {
		return nil, err
	}
	p.request, p.contract = true, contract
	return p, nil
}

// NewStreamRequestFramer is used with the original RequestInput byte/hash
// owner. It proves framing only; Last does not certify an execution digest.
func NewStreamRequestFramer(contract *ServiceContract) (*StreamMessageParser, error) {
	p, err := newStreamMessageParser(contract)
	if err != nil {
		return nil, err
	}
	p.request, p.framingOnly, p.contract = true, true, contract
	return p, nil
}

func NewStreamResponseParser(contract *ServiceContract, original ApplicationHeader) (*StreamMessageParser, error) {
	if !original.StreamRequest() {
		return nil, CBORFailure("streaming_request_kind")
	}
	if err := contract.CheckRequest(original); err != nil {
		return nil, err
	}
	p, err := newStreamMessageParser(contract)
	if err != nil {
		return nil, err
	}
	p.original = original
	return p, nil
}

// NeedBytes is the largest read that cannot consume a subsequent item. Each
// call is bounded; a receiver stops after Last until the current item leaves.
func (p *StreamMessageParser) NeedBytes() int {
	if p == nil || p.failure != nil || p.ended {
		return 0
	}
	if p.resume && (p.requestDone || p.terminal) {
		return 0
	}
	if p.header.Kind() == "" {
		return min(p.need-p.have, 4096)
	}
	return int(min(p.header.Fields().PayloadBytes-p.offset, 4096))
}

func (p *StreamMessageParser) fail(err error) error {
	p.failure = err
	if p.verifier != nil {
		p.verifier.Close()
	}
	clear(p.storage[:])
	clear(p.errorBody[:])
	p.header, p.verifier, p.contract = ApplicationHeader{}, nil, nil
	return err
}

func (p *StreamMessageParser) beginHeader() error {
	h := p.header
	if p.request {
		if p.requestDone {
			return CBORFailure("streaming_second_request")
		}
		if !p.resume && !h.StreamRequest() || p.resume && h.Kind() != "resume_request" {
			return CBORFailure("streaming_request_kind")
		}
		if err := p.contract.CheckRequest(h); err != nil {
			return err
		}
		if h.HasExecutionIdentity() && !p.framingOnly {
			var err error
			p.verifier, err = NewExecutionRequestVerifier(h, p.contract)
			if err != nil {
				return err
			}
		}
		p.original, p.contract = h, nil
		return nil
	}
	if p.terminal {
		return CBORFailure("streaming_terminal")
	}
	if err := p.original.MatchResponse(h); err != nil {
		return err
	}
	if h.IsSDKError() {
		return nil
	}
	if p.resume {
		return nil
	}
	if uint64(h.Fields().PayloadBytes) > p.policy.MaxStreamPayloadBytes-p.bytes {
		return CBORFailure("streaming_payload_total")
	}
	if h.Fields().ApplicationErrorCode == 0 && p.items == p.policy.MaxItemCount {
		return CBORFailure("streaming_item_count")
	}
	return nil
}

func (p *StreamMessageParser) finishMessage() error {
	if p.request {
		if p.verifier != nil {
			if err := p.verifier.Finish(); err != nil {
				return err
			}
			p.verifier = nil
		}
		p.requestDone = true
	} else if p.header.IsSDKError() {
		doc, err := p.sdk.DecodeMap(p.errorBody[:p.offset], "ApplicationSDKError", DecodeContext{})
		if err != nil {
			return err
		}
		code, ok := doc.Root().Named("ApplicationSDKError", "code").Uint()
		doc.Release()
		if !ok {
			return CBORFailure("streaming_sdk_error_code")
		}
		if err := ValidateApplicationSDKErrorCode(code, !p.resume); err != nil {
			return err
		}
		p.lastSDKError = code
		clear(p.errorBody[:])
		p.terminal = true
	} else {
		p.bytes += uint64(p.header.Fields().PayloadBytes)
		if p.header.Fields().ApplicationErrorCode != 0 {
			p.terminal = true
		} else {
			p.items++
		}
		if p.resume {
			p.terminal = true
		}
	}
	p.have, p.need, p.offset = 0, 2, 0
	p.header = ApplicationHeader{}
	return nil
}

func (p *StreamMessageParser) Next(input []byte) (consumed int, part StreamMessagePart, err error) {
	if p == nil || p.codec == nil {
		return 0, part, CBORFailure("configuration_capacity")
	}
	if p.failure != nil {
		return 0, part, p.failure
	}
	if p.ended {
		return 0, part, CBORFailure("streaming_ended")
	}
	defer func() {
		if err != nil {
			p.fail(err)
		}
	}()
	if p.header.Kind() == "" {
		if len(input) != 0 && (p.terminal || p.requestDone) {
			return 0, part, CBORFailure("streaming_terminal")
		}
		for {
			n := copy(p.storage[p.have:p.need], input[consumed:])
			p.have += n
			consumed += n
			if p.have != p.need {
				return consumed, part, nil
			}
			if p.need == 2 {
				n = int(binary.BigEndian.Uint16(p.storage[:2]))
				if n == 0 || n > 512 {
					return consumed, part, CBORFailure("streaming_header_length")
				}
				p.need += n
				continue
			}
			p.header, err = p.codec.Decode(p.storage[2:p.need])
			if err != nil {
				return consumed, part, err
			}
			if err = p.beginHeader(); err != nil {
				return consumed, part, err
			}
			part = StreamMessagePart{Header: p.header, First: true, Last: p.header.Fields().PayloadBytes == 0}
			break
		}
	} else {
		n := min(len(input), int(p.header.Fields().PayloadBytes-p.offset), 4096)
		if n == 0 {
			return 0, part, nil
		}
		part = StreamMessagePart{Header: p.header, Offset: p.offset, Payload: input[:n:n]}
		if p.verifier != nil {
			if err = p.verifier.WriteAt(p.offset, part.Payload); err != nil {
				return 0, StreamMessagePart{}, err
			}
		}
		if p.header.IsSDKError() {
			copy(p.errorBody[p.offset:], part.Payload)
		}
		p.offset += uint32(n)
		consumed = n
		part.Last = p.offset == p.header.Fields().PayloadBytes
	}
	if part.Last {
		err = p.finishMessage()
	}
	return consumed, part, err
}

// End accepts authenticated FIN only at a message boundary. The receiver owns
// any complete candidate separately; normal EOF never consumes that candidate.
func (p *StreamMessageParser) End() error {
	if p == nil || p.codec == nil {
		return CBORFailure("configuration_capacity")
	}
	if p.failure != nil {
		return p.failure
	}
	if p.ended {
		return nil
	}
	if p.have != 0 || p.header.Kind() != "" || p.request && !p.requestDone {
		return p.fail(CBORFailure("streaming_partial_eof"))
	}
	p.ended = true
	return nil
}

func (p *StreamMessageParser) SDKErrorCode() uint64 { return p.lastSDKError }

func (p *StreamMessageParser) OriginalRequest() ApplicationHeader { return p.original }
func (p *StreamMessageParser) Close() {
	if p != nil {
		p.fail(CBORFailure("streaming_closed"))
	}
}

// EncodeStreamPrefix is only framing. The actual publisher must already own
// the complete bounded item and retain it through all irrevocable send tails.
func (c *ApplicationHeaderCodec) EncodeStreamPrefix(dst, header []byte) (int, error) {
	h, err := c.Decode(header)
	if err != nil {
		return 0, err
	}
	if !h.StreamRequest() && h.responseTo != c.streamRequestCode(true) && h.responseTo != c.streamRequestCode(false) {
		return 0, CBORFailure("streaming_message_kind")
	}
	if len(dst) < len(header)+2 {
		return 0, CBORFailure("configuration_capacity")
	}
	copy(dst[2:], header)
	binary.BigEndian.PutUint16(dst[:2], uint16(len(header)))
	return len(header) + 2, nil
}

func (c *ApplicationHeaderCodec) streamRequestCode(execution bool) uint8 {
	name := "transient_stream_request"
	if execution {
		name = "execution_stream_request"
	}
	for _, v := range c.registry.kinds {
		if v.name == name {
			return v.definition.Code
		}
	}
	return 0
}
