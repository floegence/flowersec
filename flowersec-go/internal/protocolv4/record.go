package protocolv4

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"sync"
)

var (
	ErrRecordRegistry  = errors.New("protocolv4: invalid record registry")
	ErrRecordProfile   = errors.New("protocolv4: unsupported crypto profile")
	ErrRecordScope     = errors.New("protocolv4: invalid record scope")
	ErrRecordDirection = errors.New("protocolv4: invalid record direction")
)

type Direction uint8

const (
	ClientToServer Direction = iota
	ServerToClient
)

// RecordHeader is authenticated together with the complete envelope prefix.
type RecordHeader struct {
	Epoch    uint32
	Scope    uint64
	Sequence uint64
}

type RecordProfile struct {
	DHPublicBytes         int    `json:"dh_public_bytes"`
	HandshakeMessageBytes int    `json:"handshake_message_bytes"`
	DHAlgorithm           uint8  `json:"dh_algorithm"`
	Algorithm             string `json:"record_aead"`
	KeyBytes              int    `json:"key_bytes"`
	NonceBytes            int    `json:"nonce_bytes"`
	TagBytes              int    `json:"tag_bytes"`
}

type recordWireField struct {
	Name, Type    string
	Const, Max    *uint64
	source, width int
}

type recordIntegers [5]uint64

const (
	recordPayload = iota
	recordFrame
	recordEpoch
	recordScope
	recordSequence
)

type recordDomainPart struct {
	Name, Encoding string
	Length         int
	Enum           []uint64
}

type recordDomainSpec struct {
	Name, Operation string
	Label           string                             `json:"label_bytes"`
	Input           struct{ Parts []recordDomainPart } `json:"input_schema"`
	label           []byte
}

type recordWireRegistry struct {
	Envelope      struct{ Layout []recordWireField }
	Header, Nonce []recordWireField
	Profiles      map[string]RecordProfile
	Types         map[string]FrameType `json:"frame_types"`
	Classes       map[string][]string  `json:"frame_classes"`
	Caps          struct {
		Scope struct {
			Min uint64
			Max string
		} `json:"scope_id"`
		Datagram         string `json:"datagram_scope"`
		ReplayBits       uint64 `json:"record_replay_window_bits"`
		DatagramEnvelope uint64 `json:"max_datagram_envelope"`
		DatagramPending  uint64 `json:"max_pending_datagrams"`
	} `json:"resource_caps"`
	domains            map[string]recordDomainSpec
	headerBytes        int
	datagram, maxScope uint64
}

var loadRecordRegistry = sync.OnceValues(func() (*recordWireRegistry, error) {
	r := new(recordWireRegistry)
	if json.Unmarshal([]byte(RecordRegistryJSON), r) != nil {
		return nil, ErrRecordRegistry
	}
	var domains []recordDomainSpec
	if json.Unmarshal([]byte(DomainRegistryJSON), &domains) != nil {
		return nil, ErrRecordRegistry
	}
	r.domains = make(map[string]recordDomainSpec, 2)
	for _, d := range domains {
		if d.Name != "record_key" && d.Name != "record_aad" {
			continue
		}
		var err error
		d.label, err = hex.DecodeString(d.Label)
		if err != nil || len(d.label) == 0 || d.label[len(d.label)-1] != 0 {
			return nil, ErrRecordRegistry
		}
		r.domains[d.Name] = d
	}
	if len(r.domains) != 2 || len(r.Profiles) != 2 || len(r.Types) != 16 {
		return nil, ErrRecordRegistry
	}
	for _, f := range r.Header {
		width := recordWidth(f.Type)
		if width == 0 {
			return nil, ErrRecordRegistry
		}
		r.headerBytes += width
	}
	// Compile the fixed registry's field selectors once. Live records still
	// check every width and maximum, without constructing per-record maps.
	for kind, layout := range [][]recordWireField{r.Envelope.Layout, r.Header, r.Nonce} {
		for i := range layout {
			f := &layout[i]
			f.width = recordWidth(f.Type)
			if f.width == 0 {
				return nil, ErrRecordRegistry
			}
			if f.Const != nil {
				f.source = -1
				continue
			}
			switch f.Name {
			case "payload_length":
				f.source = recordPayload
			case "frame_type":
				f.source = recordFrame
			case "epoch":
				f.source = recordEpoch
			case "sequence_scope":
				f.source = recordScope
			case "sequence":
				f.source = recordSequence
			default:
				return nil, ErrRecordRegistry
			}
			if kind == 0 && f.source != recordPayload && f.source != recordFrame || kind == 1 && f.source != recordEpoch && f.source != recordScope && f.source != recordSequence || kind == 2 && f.source != recordEpoch && f.source != recordSequence {
				return nil, ErrRecordRegistry
			}
		}
	}
	var err error
	r.datagram, err = strconv.ParseUint(r.Caps.Datagram, 10, 64)
	if err != nil {
		return nil, ErrRecordRegistry
	}
	r.maxScope, err = strconv.ParseUint(r.Caps.Scope.Max, 10, 64)
	if err != nil || r.Caps.Scope.Min != 1 || r.Caps.ReplayBits != 256 {
		return nil, ErrRecordRegistry
	}
	for _, p := range r.Profiles {
		if p.KeyBytes != 32 || p.NonceBytes != 12 || p.TagBytes != 16 {
			return nil, ErrRecordRegistry
		}
	}
	return r, nil
})

func recordWidth(kind string) int {
	switch kind {
	case "uint8":
		return 1
	case "uint16_be":
		return 2
	case "uint32_be":
		return 4
	case "uint64_be":
		return 8
	}
	return 0
}

func appendRecordLayout(out []byte, layout []recordWireField, values recordIntegers) ([]byte, error) {
	for _, f := range layout {
		var n uint64
		if f.Const != nil {
			n = *f.Const
		} else {
			n = values[f.source]
		}
		width := f.width
		if width < 8 && n >= uint64(1)<<(8*width) || f.Max != nil && n > *f.Max {
			return nil, ErrRecordRegistry
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		out = append(out, b[8-width:]...)
	}
	return out, nil
}

func Profile(profile string) (RecordProfile, error) {
	r, err := loadRecordRegistry()
	if err != nil {
		return RecordProfile{}, err
	}
	p, ok := r.Profiles[profile]
	if !ok {
		return RecordProfile{}, ErrRecordProfile
	}
	return p, nil
}

func DatagramScope() uint64 {
	r, err := loadRecordRegistry()
	if err != nil {
		panic(err)
	}
	return r.datagram
}
func RecordHeaderSize() int {
	r, err := loadRecordRegistry()
	if err != nil {
		panic(err)
	}
	return r.headerBytes
}

func ValidateRecordScope(frame FrameType, scope uint64) error {
	r, err := loadRecordRegistry()
	if err != nil {
		return err
	}
	if frame == FrameDatagram {
		if scope != r.datagram {
			return ErrRecordScope
		}
		return nil
	}
	if frame == FrameOpenStream || frame == FrameStreamData {
		if scope < r.Caps.Scope.Min || scope > r.maxScope {
			return ErrRecordScope
		}
		return nil
	}
	for _, class := range []string{"maintenance_record", "record_cipher"} {
		for _, name := range r.Classes[class] {
			if r.Types[name] == frame {
				if scope != 0 {
					return ErrRecordScope
				}
				return nil
			}
		}
	}
	return ErrUnknownFrame
}

// RecordPrefix constructs the envelope and record header with checked lengths.
// maxFrame is the immutable signed payload bound, excluding the envelope prefix.
func RecordPrefix(frame FrameType, header RecordHeader, plaintextBytes int, profile string, maxFrame uint32) ([]byte, error) {
	r, err := loadRecordRegistry()
	if err != nil {
		return nil, err
	}
	p, err := Profile(profile)
	if err != nil {
		return nil, err
	}
	if err = ValidateRecordScope(frame, header.Scope); err != nil {
		return nil, err
	}
	if plaintextBytes < 0 || maxFrame > MaxPayloadLength || uint64(plaintextBytes)+uint64(r.headerBytes+p.TagBytes) > uint64(maxFrame) {
		return nil, ErrPayloadTooLarge
	}
	payload := uint64(plaintextBytes) + uint64(r.headerBytes+p.TagBytes)
	if frame == FrameDatagram && payload+EnvelopePrefixSize > r.Caps.DatagramEnvelope {
		return nil, ErrPayloadTooLarge
	}
	values := recordIntegers{recordPayload: payload, recordFrame: uint64(frame), recordEpoch: uint64(header.Epoch), recordScope: header.Scope, recordSequence: header.Sequence}
	out, err := appendRecordLayout(make([]byte, 0, EnvelopePrefixSize+r.headerBytes), r.Envelope.Layout, values)
	if err != nil {
		return nil, err
	}
	return appendRecordLayout(out, r.Header, values)
}

// ParseRecord borrows the immutable input until the caller finishes its crypto
// job. It validates the entire length chain before looking up any key or scope.
func ParseRecord(input []byte, profile string, maxFrame uint32) (FrameType, RecordHeader, []byte, error) {
	r, err := loadRecordRegistry()
	if err != nil {
		return 0, RecordHeader{}, nil, err
	}
	p, err := Profile(profile)
	if err != nil {
		return 0, RecordHeader{}, nil, err
	}
	if maxFrame > MaxPayloadLength || len(input) < EnvelopePrefixSize+r.headerBytes+p.TagBytes {
		return 0, RecordHeader{}, nil, ErrTruncated
	}
	n := binary.BigEndian.Uint32(input[:4])
	if n > maxFrame {
		return 0, RecordHeader{}, nil, ErrPayloadTooLarge
	}
	if uint64(n)+EnvelopePrefixSize != uint64(len(input)) {
		return 0, RecordHeader{}, nil, ErrTruncated
	}
	if input[5] != 0 || binary.BigEndian.Uint16(input[6:8]) != 0 {
		return 0, RecordHeader{}, nil, ErrInvalidFlags
	}
	frame := FrameType(input[4])
	offset := EnvelopePrefixSize
	var header RecordHeader
	for _, f := range r.Header {
		width := recordWidth(f.Type)
		var b [8]byte
		copy(b[8-width:], input[offset:offset+width])
		offset += width
		n := binary.BigEndian.Uint64(b[:])
		switch f.Name {
		case "epoch":
			header.Epoch = uint32(n)
		case "sequence_scope":
			header.Scope = n
		case "sequence":
			header.Sequence = n
		default:
			return 0, RecordHeader{}, nil, ErrRecordRegistry
		}
	}
	if err = ValidateRecordScope(frame, header.Scope); err != nil {
		return 0, RecordHeader{}, nil, err
	}
	if frame == FrameDatagram && uint64(len(input)) > r.Caps.DatagramEnvelope {
		return 0, RecordHeader{}, nil, ErrPayloadTooLarge
	}
	return frame, header, input[offset:], nil
}

func RecordNonce(header RecordHeader) ([12]byte, error) {
	var nonce [12]byte
	r, err := loadRecordRegistry()
	if err != nil {
		return nonce, err
	}
	value, err := appendRecordLayout(nonce[:0], r.Nonce, recordIntegers{recordEpoch: uint64(header.Epoch), recordSequence: header.Sequence})
	if err != nil || len(value) != len(nonce) {
		return nonce, ErrRecordRegistry
	}
	return nonce, nil
}

func buildRecordDomain(name, profile string, direction Direction, bytes map[string][]byte, integers map[string]uint64) ([]byte, error) {
	r, err := loadRecordRegistry()
	if err != nil {
		return nil, err
	}
	if _, err = Profile(profile); err != nil {
		return nil, err
	}
	if direction > ServerToClient {
		return nil, ErrRecordDirection
	}
	bytes["profile"] = []byte(profile)
	integers["direction"] = uint64(direction)
	d, ok := r.domains[name]
	if !ok {
		return nil, ErrRecordRegistry
	}
	out := append([]byte(nil), d.label...)
	for _, part := range d.Input.Parts {
		switch part.Encoding {
		case "raw", "lp-ascii", "lp-bytes":
			value, ok := bytes[part.Name]
			if !ok || part.Length > 0 && len(value) != part.Length || uint64(len(value)) > math.MaxUint32 {
				return nil, ErrRecordRegistry
			}
			if part.Encoding != "raw" {
				out = binary.BigEndian.AppendUint32(out, uint32(len(value)))
			}
			out = append(out, value...)
		case "u8", "u32", "u64":
			n, ok := integers[part.Name]
			if !ok || len(part.Enum) > 0 && !slices.Contains(part.Enum, n) {
				return nil, ErrRecordRegistry
			}
			switch part.Encoding {
			case "u8":
				if n > math.MaxUint8 {
					return nil, ErrRecordRegistry
				}
				out = append(out, byte(n))
			case "u32":
				if n > math.MaxUint32 {
					return nil, ErrRecordRegistry
				}
				out = binary.BigEndian.AppendUint32(out, uint32(n))
			case "u64":
				out = binary.BigEndian.AppendUint64(out, n)
			}
		default:
			return nil, ErrRecordRegistry
		}
	}
	return out, nil
}

func RecordKeyInfo(profile string, hash [32]byte, epoch uint32, direction Direction, scope uint64) ([]byte, error) {
	r, err := loadRecordRegistry()
	if err != nil {
		return nil, err
	}
	if scope > r.maxScope && scope != r.datagram {
		return nil, ErrRecordScope
	}
	return buildRecordDomain("record_key", profile, direction, map[string][]byte{"handshake_hash": hash[:]}, map[string]uint64{"epoch": uint64(epoch), "sequence_scope": scope})
}

type recordAADTemplate struct {
	wire                 []byte
	envelopeAt, headerAt int
}

// Only registry formatting is precomputed. Every call copies its own complete
// current envelope/header into a fresh result; no record or authority is cached.
var loadRecordAADTemplates = sync.OnceValues(func() (map[string][2]recordAADTemplate, error) {
	r, err := loadRecordRegistry()
	if err != nil {
		return nil, err
	}
	d := r.domains["record_aad"]
	templates := make(map[string][2]recordAADTemplate, len(r.Profiles))
	for profile := range r.Profiles {
		var pair [2]recordAADTemplate
		for direction := range pair {
			t := recordAADTemplate{envelopeAt: -1, headerAt: -1}
			position := len(d.label)
			for _, part := range d.Input.Parts {
				switch part.Name {
				case "envelope_header", "record_header":
					width, offset := EnvelopePrefixSize, &t.envelopeAt
					if part.Name == "record_header" {
						width, offset = r.headerBytes, &t.headerAt
					}
					if *offset != -1 || part.Encoding != "raw" || part.Length != width {
						return nil, ErrRecordRegistry
					}
					*offset = position
					position += width
				case "profile":
					if part.Encoding != "lp-ascii" {
						return nil, ErrRecordRegistry
					}
					position += 4 + len(profile)
				case "direction":
					if part.Encoding != "u8" {
						return nil, ErrRecordRegistry
					}
					position++
				default:
					return nil, ErrRecordRegistry
				}
			}
			if t.envelopeAt == -1 || t.headerAt == -1 {
				return nil, ErrRecordRegistry
			}
			t.wire, err = buildRecordDomain("record_aad", profile, Direction(direction), map[string][]byte{"envelope_header": make([]byte, EnvelopePrefixSize), "record_header": make([]byte, r.headerBytes)}, map[string]uint64{})
			if err != nil || len(t.wire) != position {
				return nil, ErrRecordRegistry
			}
			pair[direction] = t
		}
		templates[profile] = pair
	}
	return templates, nil
})

func RecordAAD(profile string, direction Direction, prefix []byte) ([]byte, error) {
	if len(prefix) != EnvelopePrefixSize+RecordHeaderSize() {
		return nil, ErrTruncated
	}
	templates, err := loadRecordAADTemplates()
	if err != nil {
		return nil, err
	}
	pair, ok := templates[profile]
	if !ok {
		return nil, ErrRecordProfile
	}
	if direction > ServerToClient {
		return nil, ErrRecordDirection
	}
	t := pair[direction]
	out := slices.Clone(t.wire)
	copy(out[t.envelopeAt:t.envelopeAt+EnvelopePrefixSize], prefix[:EnvelopePrefixSize])
	copy(out[t.headerAt:t.headerAt+RecordHeaderSize()], prefix[EnvelopePrefixSize:])
	return out, nil
}
