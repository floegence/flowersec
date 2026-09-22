package protocolv4

import (
	"encoding/binary"
	"encoding/json"
	"slices"
	"sync"
	"unsafe"
)

// NotifySpec is compiled from the common application registry. The wire kind
// selects this parser only after authenticated internal-channel admission.
type NotifySpec struct {
	Kind                  string
	Transport             string
	PrefixBytes           int      `json:"header_length_prefix_bytes"`
	ByteOrder             string   `json:"byte_order"`
	Counts                string   `json:"length_counts"`
	MinHeader             int      `json:"min_header_bytes"`
	MaxHeader             int      `json:"max_header_bytes"`
	MaxPayload            uint32   `json:"max_payload_bytes"`
	Kinds                 []string `json:"message_kinds"`
	MetadataBytes         int      `json:"metadata_bytes"`
	ChannelsPerOpener     uint32   `json:"channels_per_opener"`
	SubscribersPerType    uint32   `json:"subscribers_per_type"`
	SubscribersPerSession uint32   `json:"subscribers_per_session"`
	PendingPerSubscriber  uint32   `json:"pending_per_subscriber"`
	RunningPerSubscriber  uint32   `json:"running_per_subscriber"`
}

var runtimeNotify = sync.OnceValues(func() (NotifySpec, error) {
	var wire struct{ Notify NotifySpec }
	if err := json.Unmarshal([]byte(ApplicationHeaderRegistryJSON), &wire); err != nil {
		return NotifySpec{}, err
	}
	s := wire.Notify
	if s.Kind != "flowersec.notify.v4" || s.Transport != "notify_reliable_ordered" || s.PrefixBytes != 2 || s.ByteOrder != "big_endian" || s.Counts != "canonical_header_only" || s.MinHeader != 1 || s.MaxHeader != 512 || s.MaxPayload != 1048576 || !slices.Equal(s.Kinds, []string{"execution_notify", "observation_notify"}) || s.MetadataBytes != 0 || s.ChannelsPerOpener != 1 || s.SubscribersPerType != 32 || s.SubscribersPerSession != 128 || s.PendingPerSubscriber != 16 || s.RunningPerSubscriber != 1 {
		return NotifySpec{}, CBORFailure("registry_unresolved")
	}
	return s, nil
})

func Notify() (NotifySpec, error) {
	s, err := runtimeNotify()
	s.Kinds = nil // Do not expose shared registry backing.
	return s, err
}

func (h ApplicationHeader) Notify() bool {
	return h.Kind() == "observation_notify" || h.Kind() == "execution_notify"
}

// DecodeNotify validates exactly one complete message, using the caller's
// admitted header workspace. The payload view does not escape its wire owner.
func (c *ApplicationHeaderCodec) DecodeNotify(wire []byte) (ApplicationHeader, []byte, error) {
	if _, err := runtimeNotify(); err != nil {
		return ApplicationHeader{}, nil, err
	}
	if len(wire) < 2 {
		return ApplicationHeader{}, nil, CBORFailure("notify_truncated")
	}
	n := int(binary.BigEndian.Uint16(wire))
	if n < 1 || n > 512 {
		return ApplicationHeader{}, nil, CBORFailure("notify_header_length")
	}
	if len(wire) < n+2 {
		return ApplicationHeader{}, nil, CBORFailure("notify_truncated")
	}
	h, err := c.Decode(wire[2 : n+2])
	if err != nil {
		return ApplicationHeader{}, nil, err
	}
	if !h.Notify() {
		return ApplicationHeader{}, nil, CBORFailure("notify_kind")
	}
	total := uint64(n+2) + uint64(h.Fields().PayloadBytes)
	if uint64(len(wire)) < total {
		return ApplicationHeader{}, nil, CBORFailure("notify_truncated")
	}
	if uint64(len(wire)) > total {
		return ApplicationHeader{}, nil, CBORFailure("notify_trailing")
	}
	return h, wire[n+2 : len(wire) : len(wire)], nil
}

// EncodeNotifyPrefix writes only the immutable prefix/header. Publication and
// continued full-payload responsibility belong to the original channel owner.
func (c *ApplicationHeaderCodec) EncodeNotifyPrefix(dst, header []byte) (int, error) {
	if _, err := runtimeNotify(); err != nil {
		return 0, err
	}
	h, err := c.Decode(header)
	if err != nil {
		return 0, err
	}
	if !h.Notify() {
		return 0, CBORFailure("notify_kind")
	}
	if len(dst) < len(header)+2 {
		return 0, CBORFailure("configuration_capacity")
	}
	copy(dst[2:], header)
	binary.BigEndian.PutUint16(dst[:2], uint16(len(header)))
	return len(header) + 2, nil
}

// NotifyPart reports the header before any payload, allowing bounded admission
// or discard before the first body byte. First is true only for that header
// event; Last marks the complete physical message (including an empty one).
// Payload borrows only the current reader slice and must not be retained.
type NotifyPart struct {
	Header      ApplicationHeader
	Payload     []byte
	Offset      uint32
	First, Last bool
}

// NotifyParser keeps only the bounded header and decoder workspace. It never
// owns payload storage, blocks on callbacks, or probes ordinary RPC framing.
type NotifyParser struct {
	codec      *ApplicationHeaderCodec
	storage    [514]byte
	have, need int
	header     ApplicationHeader
	offset     uint32
	failure    error
}

func NotifyParserBackingBytes() (uint64, error) {
	if _, err := runtimeNotify(); err != nil {
		return 0, err
	}
	n, err := ApplicationHeaderBackingBytes()
	return n + uint64(unsafe.Sizeof(NotifyParser{})) + uint64(unsafe.Sizeof(NotifyPart{})), err
}

func NewNotifyParser() (*NotifyParser, error) {
	if _, err := runtimeNotify(); err != nil {
		return nil, err
	}
	c, err := NewApplicationHeaderCodec()
	if err != nil {
		return nil, err
	}
	return &NotifyParser{codec: c, need: 2}, nil
}

func (p *NotifyParser) fail(err error) error {
	p.failure = err
	clear(p.storage[:])
	p.header = ApplicationHeader{}
	return err
}

func (p *NotifyParser) Next(input []byte) (consumed int, part NotifyPart, err error) {
	if p == nil || p.codec == nil {
		return 0, part, CBORFailure("configuration_capacity")
	}
	if p.failure != nil {
		return 0, part, p.failure
	}
	defer func() {
		if err != nil {
			p.fail(err)
		}
	}()
	if p.header.Kind() == "" {
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
					return consumed, part, CBORFailure("notify_header_length")
				}
				p.need += n
				continue
			}
			p.header, err = p.codec.Decode(p.storage[2:p.need])
			if err != nil {
				return consumed, part, err
			}
			if !p.header.Notify() {
				return consumed, part, CBORFailure("notify_kind")
			}
			part = NotifyPart{Header: p.header, First: true, Last: p.header.Fields().PayloadBytes == 0}
			break
		}
	} else {
		n := min(uint64(len(input)), uint64(p.header.Fields().PayloadBytes-p.offset))
		if n == 0 {
			return 0, part, nil
		}
		part = NotifyPart{Header: p.header, Offset: p.offset, Payload: input[:n:n]}
		p.offset += uint32(n)
		consumed = int(n)
		part.Last = p.offset == p.header.Fields().PayloadBytes
	}
	if part.Last {
		p.have, p.need, p.offset = 0, 2, 0
		p.header = ApplicationHeader{}
	}
	return consumed, part, nil
}

func (p *NotifyParser) End() error {
	if p == nil || p.codec == nil {
		return CBORFailure("configuration_capacity")
	}
	if p.failure != nil {
		return p.failure
	}
	if p.have != 0 || p.header.Kind() != "" {
		return p.fail(CBORFailure("notify_truncated"))
	}
	return nil
}

func (p *NotifyParser) Close() {
	if p != nil {
		p.fail(CBORFailure("notify_closed"))
	}
}
