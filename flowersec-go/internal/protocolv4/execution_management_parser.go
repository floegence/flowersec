package protocolv4

import (
	"encoding/binary"
	"io"
	"unsafe"
)

// ManagementParser owns one incremental M envelope. It never probes ordinary
// RPC framing or allocates from a peer length. The complete borrowed wire must
// be consumed by its owner before the next Next call; zero-byte reads do not
// reset a partial message. A malformed envelope makes this generation sticky.
type ManagementParser struct {
	codec                *ApplicationHeaderCodec
	wire                 [1538]byte
	used, headerEnd, end int
	complete             bool
	failure              error
}

func ManagementParserBackingBytes() (uint64, error) {
	n, err := ApplicationHeaderBackingBytes()
	return n + uint64(unsafe.Sizeof(ManagementParser{})), err
}
func NewManagementParser() (*ManagementParser, error) {
	c, err := NewApplicationHeaderCodec()
	if err != nil {
		return nil, err
	}
	return &ManagementParser{codec: c}, nil
}
func (p *ManagementParser) Next(input []byte) (int, []byte, error) {
	return p.NextWithHeader(input, nil)
}

// NextWithHeader invokes the admitted reader at the header boundary, before
// any body bytes. The callback must be finite and retain no parser backing.
func (p *ManagementParser) NextWithHeader(input []byte, onHeader func(ApplicationHeader) error) (consumed int, complete []byte, err error) {
	if p == nil {
		return 0, nil, CBORFailure("configuration_capacity")
	}
	if p.failure != nil {
		return 0, nil, p.failure
	}
	if p.complete {
		clear(p.wire[:p.used])
		p.used, p.headerEnd, p.end = 0, 0, 0
		p.complete = false
	}
	fail := func(code string) (int, []byte, error) { p.failure = CBORFailure(code); return consumed, nil, p.failure }
	for len(input) > 0 {
		target := 2
		if p.headerEnd != 0 {
			target = p.headerEnd
		}
		if p.end != 0 {
			target = p.end
		}
		n := copy(p.wire[p.used:target], input)
		p.used += n
		consumed += n
		input = input[n:]
		if p.used < target {
			return consumed, nil, nil
		}
		if p.headerEnd == 0 {
			h := int(binary.BigEndian.Uint16(p.wire[:2]))
			if h < 1 || h > 512 {
				return fail("management_header_length")
			}
			p.headerEnd = 2 + h
		} else if p.end == 0 {
			h, decodeErr := p.codec.Decode(p.wire[2:p.headerEnd])
			if decodeErr != nil {
				p.failure = decodeErr
				return consumed, nil, decodeErr
			}
			limit := uint32(1024)
			switch h.Kind() {
			case "query_operation_request", "request_cancel_request":
			case "query_operation_response", "request_cancel_response":
				limit = 512
			default:
				return fail("management_kind")
			}
			if h.Fields().PayloadBytes > limit {
				return fail("management_payload_length")
			}
			if onHeader != nil {
				if err := onHeader(h); err != nil {
					p.failure = err
					return consumed, nil, err
				}
			}
			p.end = p.headerEnd + int(h.Fields().PayloadBytes)
		}
		if p.end != 0 && p.used == p.end {
			p.complete = true
			return consumed, p.wire[:p.end:p.end], nil
		}
	}
	return consumed, nil, nil
}
func (p *ManagementParser) End() error {
	if p == nil {
		return CBORFailure("configuration_capacity")
	}
	if p.failure != nil {
		return p.failure
	}
	if p.used != 0 && !p.complete {
		p.failure = io.ErrUnexpectedEOF
		return p.failure
	}
	return nil
}
