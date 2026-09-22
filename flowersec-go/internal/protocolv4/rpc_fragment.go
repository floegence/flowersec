package protocolv4

import (
	"encoding/binary"
	"encoding/json"
	"sync"
	"unsafe"
)

type RPCFragmentKind uint8

const (
	RPCBegin RPCFragmentKind = iota
	RPCData
	RPCAbort
	RPCStopOutput
)

// Compile the fixed binary layout from the same generated registry consumed
// by the other SDKs and corpus. Registry growth cannot silently gain a parser.
type fragmentGeometry struct {
	Code       uint8 `json:"value"`
	Fixed      int   `json:"body_fixed_bytes"`
	Min        int   `json:"body_min_bytes"`
	Max        int   `json:"body_max_bytes"`
	PayloadMin int   `json:"payload_min_bytes"`
	PayloadMax int   `json:"payload_max_bytes"`
	TotalMin   int   `json:"total_min_bytes"`
	TotalMax   int   `json:"total_max_bytes"`
}
type rpcFragmentRegistry struct {
	kinds   [4]fragmentGeometry
	maxBody int
}

var runtimeRPCFragments = sync.OnceValues(func() (*rpcFragmentRegistry, error) {
	var wire struct {
		Transport   string
		Prefix      int    `json:"length_prefix_bytes"`
		Counts      string `json:"length_counts"`
		MaxFragment int    `json:"max_fragment_bytes"`
		MaxBody     int    `json:"max_body_length"`
		Kinds       map[string]fragmentGeometry
	}
	if err := json.Unmarshal([]byte(FragmentRegistryJSON), &wire); err != nil {
		return nil, err
	}
	if wire.Transport != "rpc_reliable_ordered" || wire.Prefix != 4 || wire.Counts != "kind_and_body" || wire.MaxFragment != 16384 || wire.MaxBody != 16380 || len(wire.Kinds) != 4 {
		return nil, CBORFailure("registry_unresolved")
	}
	r := &rpcFragmentRegistry{maxBody: wire.MaxBody}
	expected := [...]fragmentGeometry{{0, 18, 19, 530, 1, 512, 24, 535}, {1, 12, 13, 16379, 1, 16367, 18, 16384}, {2, 12, 12, 12, 0, 0, 17, 17}, {3, 8, 8, 8, 0, 0, 13, 13}}
	for i, name := range [...]string{"BEGIN", "DATA", "ABORT", "STOP_OUTPUT"} {
		v, ok := wire.Kinds[name]
		if !ok || v != expected[i] {
			return nil, CBORFailure("registry_unresolved")
		}
		r.kinds[i] = v
	}
	return r, nil
})

// RPCFragment is a borrowed wire view. Header and Payload may not outlive or
// mutate their input. It contains framing facts, not an authenticated request
// or an execution decision. The channel owner checks serial/offset and routing.
type RPCFragment struct {
	Kind            RPCFragmentKind
	Serial, ReplyTo uint64
	Offset          uint32
	Header, Payload []byte
}

func fragmentPrefix(r *rpcFragmentRegistry, prefix []byte) (RPCFragmentKind, int, int, error) {
	if len(prefix) < 5 {
		return 0, 0, 0, CBORFailure("fragment_truncated_length")
	}
	body := uint64(binary.BigEndian.Uint32(prefix))
	if body < 1 || body > uint64(r.maxBody) {
		return 0, 0, 0, CBORFailure("fragment_body_length")
	}
	kind := RPCFragmentKind(prefix[4])
	if int(kind) >= len(r.kinds) {
		return 0, 0, 0, CBORFailure("fragment_unknown_kind")
	}
	g := r.kinds[kind]
	if int(body)-1 < g.Min || int(body)-1 > g.Max {
		return 0, 0, 0, fragmentLengthError(kind)
	}
	return kind, int(body) + 4, 5 + g.Fixed, nil
}
func fragmentLengthError(kind RPCFragmentKind) error {
	switch kind {
	case RPCBegin:
		return CBORFailure("fragment_begin_length")
	case RPCData:
		return CBORFailure("fragment_data_length")
	case RPCAbort:
		return CBORFailure("fragment_abort_length")
	default:
		return CBORFailure("fragment_stop_output_length")
	}
}
func fragmentFields(kind RPCFragmentKind, prefix []byte, total int) (RPCFragment, error) {
	f := RPCFragment{Kind: kind, Serial: binary.BigEndian.Uint64(prefix[5:13])}
	if f.Serial == 0 {
		if kind == RPCStopOutput {
			return RPCFragment{}, CBORFailure("fragment_request_serial_range")
		}
		return RPCFragment{}, CBORFailure("fragment_message_serial_range")
	}
	switch kind {
	case RPCBegin:
		f.ReplyTo = binary.BigEndian.Uint64(prefix[13:21])
		n := int(binary.BigEndian.Uint16(prefix[21:23]))
		if n == 0 || n > 512 || total != 23+n {
			return RPCFragment{}, CBORFailure("fragment_header_length")
		}
	case RPCData, RPCAbort:
		f.Offset = binary.BigEndian.Uint32(prefix[13:17])
	}
	return f, nil
}

func DecodeRPCFragment(wire []byte) (RPCFragment, error) {
	r, err := runtimeRPCFragments()
	if err != nil {
		return RPCFragment{}, err
	}
	// Preserve exact whole-fragment framing: no trailing/concatenated input.
	if len(wire) < 5 {
		return RPCFragment{}, CBORFailure("fragment_truncated_length")
	}
	body := uint64(binary.BigEndian.Uint32(wire))
	if body < 1 || body > uint64(r.maxBody) {
		return RPCFragment{}, CBORFailure("fragment_body_length")
	}
	if uint64(len(wire)) != body+4 {
		return RPCFragment{}, CBORFailure("fragment_length_mismatch")
	}
	kind, total, _, err := fragmentPrefix(r, wire)
	if err != nil {
		return RPCFragment{}, err
	}
	f, err := fragmentFields(kind, wire, total)
	if err != nil {
		return RPCFragment{}, err
	}
	switch kind {
	case RPCBegin:
		f.Header = wire[23:len(wire):len(wire)]
	case RPCData:
		f.Payload = wire[17:len(wire):len(wire)]
	}
	return f, nil
}

// EncodeRPCFragment uses admitted caller storage and validates before writing.
// It does not allocate a serial or accept a message; the single publisher owns
// that transition at first-byte acceptance. Copy payload before metadata so
// overlapping input/output storage cannot corrupt the caller's original bytes.
func EncodeRPCFragment(dst []byte, f RPCFragment) (int, error) {
	r, err := runtimeRPCFragments()
	if err != nil {
		return 0, err
	}
	if int(f.Kind) >= len(r.kinds) {
		return 0, CBORFailure("fragment_unknown_kind")
	}
	if f.Serial == 0 {
		if f.Kind == RPCStopOutput {
			return 0, CBORFailure("fragment_request_serial_range")
		}
		return 0, CBORFailure("fragment_message_serial_range")
	}
	g := r.kinds[f.Kind]
	n := 5 + g.Fixed
	switch f.Kind {
	case RPCBegin:
		if len(f.Header) < g.PayloadMin || len(f.Header) > g.PayloadMax || len(f.Payload) != 0 || f.Offset != 0 {
			return 0, CBORFailure("fragment_header_length")
		}
		n += len(f.Header)
	case RPCData:
		if len(f.Payload) < g.PayloadMin || len(f.Payload) > g.PayloadMax || len(f.Header) != 0 || f.ReplyTo != 0 {
			return 0, CBORFailure("fragment_data_length")
		}
		n += len(f.Payload)
	case RPCAbort:
		if len(f.Header) != 0 || len(f.Payload) != 0 || f.ReplyTo != 0 {
			return 0, CBORFailure("fragment_abort_length")
		}
	case RPCStopOutput:
		if len(f.Header) != 0 || len(f.Payload) != 0 || f.ReplyTo != 0 || f.Offset != 0 {
			return 0, CBORFailure("fragment_stop_output_length")
		}
	}
	if len(dst) < n {
		return 0, CBORFailure("configuration_capacity")
	}
	if f.Kind == RPCBegin {
		copy(dst[23:n], f.Header)
	}
	if f.Kind == RPCData {
		copy(dst[17:n], f.Payload)
	}
	binary.BigEndian.PutUint32(dst[:4], uint32(n-4))
	dst[4] = byte(f.Kind)
	binary.BigEndian.PutUint64(dst[5:13], f.Serial)
	switch f.Kind {
	case RPCBegin:
		binary.BigEndian.PutUint64(dst[13:21], f.ReplyTo)
		binary.BigEndian.PutUint16(dst[21:23], uint16(len(f.Header)))
	case RPCData, RPCAbort:
		binary.BigEndian.PutUint32(dst[13:17], f.Offset)
	}
	return n, nil
}

// RPCFragmentPart exposes one complete fixed fragment or a borrowed DATA
// piece. DATA Offset is the original fragment offset; ChunkOffset identifies
// the piece within it without uint32 offset arithmetic or a hidden payload
// copy. The reader must transfer/discard the piece before reusing input and
// credit. No parser callback can block the reader or invoke application code.
type RPCFragmentPart struct {
	Fragment    RPCFragment
	ChunkOffset uint32
	First, Last bool
}

// RPCFragmentParser is single-reader state. Only a <=535-byte BEGIN/fixed
// header is retained across reads; DATA aliases the original admitted input.
// Failure is terminal for this channel generation. EOF is normal only at a
// fragment boundary, independently of still-unfinished message owners.
type RPCFragmentParser struct {
	registry                       *rpcFragmentRegistry
	header                         [535]byte
	have, need, total, payloadRead int
	current                        RPCFragment
	failure                        error
}

func RPCFragmentParserBackingBytes() (uint64, error) {
	if _, err := runtimeRPCFragments(); err != nil {
		return 0, err
	}
	return uint64(unsafe.Sizeof(RPCFragmentParser{})) + uint64(unsafe.Sizeof(RPCFragmentPart{})), nil
}
func NewRPCFragmentParser() (*RPCFragmentParser, error) {
	r, err := runtimeRPCFragments()
	if err != nil {
		return nil, err
	}
	return &RPCFragmentParser{registry: r, need: 5}, nil
}
func (p *RPCFragmentParser) fail(err error) (int, RPCFragmentPart, error) {
	p.failure = err
	clear(p.header[:])
	p.current = RPCFragment{}
	return 0, RPCFragmentPart{}, err
}

// Next consumes at most one fragment/part. A zero Fragment.Serial means more
// input is required. The caller loops over unconsumed bytes; records and reads
// may split any prefix/header/body or contain multiple interleaved fragments.
func (p *RPCFragmentParser) Next(input []byte) (consumed int, part RPCFragmentPart, err error) {
	if p == nil || p.registry == nil {
		return 0, part, CBORFailure("configuration_capacity")
	}
	if p.failure != nil {
		return 0, part, p.failure
	}
	defer func() {
		if err != nil {
			_, _, err = p.fail(err)
		}
	}()
	for {
		if p.have < p.need {
			n := copy(p.header[p.have:p.need], input[consumed:])
			p.have += n
			consumed += n
			if p.have < p.need {
				return consumed, part, nil
			}
		}
		if p.need == 5 {
			kind, total, fixed, err := fragmentPrefix(p.registry, p.header[:5])
			if err != nil {
				return consumed, part, err
			}
			p.current.Kind, p.total, p.need = kind, total, fixed
			continue
		}
		if p.current.Serial == 0 {
			f, err := fragmentFields(p.current.Kind, p.header[:p.have], p.total)
			if err != nil {
				return consumed, part, err
			}
			p.current = f
			if f.Kind == RPCBegin {
				p.need = p.total
				continue
			}
		}
		part.Fragment = p.current
		part.First, part.Last = true, true
		switch p.current.Kind {
		case RPCBegin:
			part.Fragment.Header = p.header[23:p.total:p.total]
		case RPCData:
			n := min(len(input)-consumed, p.total-17-p.payloadRead)
			if n == 0 {
				return consumed, RPCFragmentPart{}, nil
			}
			part.ChunkOffset = uint32(p.payloadRead)
			part.First = p.payloadRead == 0
			part.Fragment.Payload = input[consumed : consumed+n : consumed+n]
			consumed += n
			p.payloadRead += n
			part.Last = p.payloadRead == p.total-17
		}
		if part.Last {
			// BEGIN's view remains valid until the next Next/Close. Reset only
			// cursors here, never erase backing before the owner can decode it.
			p.have, p.need, p.total, p.payloadRead = 0, 5, 0, 0
			p.current = RPCFragment{}
		}
		return consumed, part, nil
	}
}
func (p *RPCFragmentParser) End() error {
	if p == nil || p.registry == nil {
		return CBORFailure("configuration_capacity")
	}
	if p.failure != nil {
		return p.failure
	}
	if p.have != 0 {
		_, _, err := p.fail(CBORFailure("fragment_truncated"))
		return err
	}
	return nil
}
func (p *RPCFragmentParser) Close() {
	if p != nil {
		_, _, _ = p.fail(CBORFailure("fragment_closed"))
	}
}
