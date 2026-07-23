// Package protocolv2 implements Flowersec v2's fixed binary wire envelopes.
package protocolv2

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	SetupPrefaceSize   = 56
	RecordHeaderSize   = 24
	InnerHeaderSize    = 8
	MaxDataBytes       = 16_384
	MaxOpenBytes       = 8_192
	MaxControlBytes    = 256
	AEADTagBytes       = 16
	MaxCiphertextBytes = InnerHeaderSize + MaxDataBytes + AEADTagBytes
)

var (
	ErrInvalidSetupPreface = errors.New("invalid FSS2 setup preface")
	ErrInvalidRecordHeader = errors.New("invalid FSR2 record header")
	ErrRecordTooLarge      = errors.New("FSR2 record too large")
	ErrInvalidInnerRecord  = errors.New("invalid FSR2 inner record")
	ErrUnknownInnerType    = errors.New("unknown FSR2 inner type")
)

type Role uint8

const (
	RoleClient Role = 1
	RoleServer Role = 2
)

type SetupPreface struct {
	OpenerRole      Role
	LogicalStreamID uint64
	InitialEpoch    uint32
	SetupMAC        [32]byte
}

func (p SetupPreface) MarshalBinary() ([]byte, error) {
	if !validLogicalID(p.OpenerRole, p.LogicalStreamID) {
		return nil, ErrInvalidSetupPreface
	}
	out := make([]byte, SetupPrefaceSize)
	copy(out[0:4], "FSS2")
	out[4] = 2
	out[5] = byte(p.OpenerRole)
	binary.BigEndian.PutUint64(out[8:16], p.LogicalStreamID)
	binary.BigEndian.PutUint32(out[16:20], p.InitialEpoch)
	copy(out[24:56], p.SetupMAC[:])
	return out, nil
}

func ParseSetupPreface(raw []byte) (SetupPreface, error) {
	if len(raw) != SetupPrefaceSize || string(raw[0:4]) != "FSS2" || raw[4] != 2 ||
		raw[6] != 0 || raw[7] != 0 || binary.BigEndian.Uint32(raw[20:24]) != 0 {
		return SetupPreface{}, ErrInvalidSetupPreface
	}
	role := Role(raw[5])
	id := binary.BigEndian.Uint64(raw[8:16])
	if !validLogicalID(role, id) {
		return SetupPreface{}, ErrInvalidSetupPreface
	}
	out := SetupPreface{
		OpenerRole:      role,
		LogicalStreamID: id,
		InitialEpoch:    binary.BigEndian.Uint32(raw[16:20]),
	}
	copy(out.SetupMAC[:], raw[24:56])
	return out, nil
}

func validLogicalID(role Role, id uint64) bool {
	switch role {
	case RoleClient:
		return id != 0 && id&1 == 1
	case RoleServer:
		return id != 0 && id&1 == 0
	default:
		return false
	}
}

type RecordHeader struct {
	Epoch            uint32
	Sequence         uint64
	CiphertextLength uint32
}

func (h RecordHeader) MarshalBinary() ([]byte, error) {
	if h.CiphertextLength < AEADTagBytes {
		return nil, ErrInvalidRecordHeader
	}
	if h.CiphertextLength > MaxCiphertextBytes {
		return nil, ErrRecordTooLarge
	}
	out := make([]byte, RecordHeaderSize)
	copy(out[0:4], "FSR2")
	out[4] = 2
	out[5] = RecordHeaderSize
	binary.BigEndian.PutUint32(out[8:12], h.Epoch)
	binary.BigEndian.PutUint64(out[12:20], h.Sequence)
	binary.BigEndian.PutUint32(out[20:24], h.CiphertextLength)
	return out, nil
}

func ParseRecordHeader(raw []byte) (RecordHeader, error) {
	if len(raw) != RecordHeaderSize || string(raw[0:4]) != "FSR2" || raw[4] != 2 ||
		raw[5] != RecordHeaderSize || raw[6] != 0 || raw[7] != 0 {
		return RecordHeader{}, ErrInvalidRecordHeader
	}
	h := RecordHeader{
		Epoch:            binary.BigEndian.Uint32(raw[8:12]),
		Sequence:         binary.BigEndian.Uint64(raw[12:20]),
		CiphertextLength: binary.BigEndian.Uint32(raw[20:24]),
	}
	if h.CiphertextLength < AEADTagBytes {
		return RecordHeader{}, ErrInvalidRecordHeader
	}
	if h.CiphertextLength > MaxCiphertextBytes {
		return RecordHeader{}, ErrRecordTooLarge
	}
	return h, nil
}

type InnerType uint8

const (
	InnerOpen            InnerType = 1
	InnerOpenACK         InnerType = 2
	InnerOpenReject      InnerType = 3
	InnerData            InnerType = 4
	InnerFIN             InnerType = 5
	InnerStreamKeyUpdate InnerType = 6

	InnerSessionReady        InnerType = 16
	InnerPing                InnerType = 17
	InnerPong                InnerType = 18
	InnerSessionKeyUpdate    InnerType = 19
	InnerStreamReset         InnerType = 20
	InnerGoAway              InnerType = 21
	InnerSessionClose        InnerType = 22
	InnerSessionReadyACK     InnerType = 23
	InnerSessionKeyUpdateACK InnerType = 24
	InnerStreamKeyUpdateACK  InnerType = 25
)

func MarshalInnerRecord(typ InnerType, payload []byte) ([]byte, error) {
	if err := validateInner(typ, len(payload)); err != nil {
		return nil, err
	}
	out := make([]byte, InnerHeaderSize+len(payload))
	out[0] = byte(typ)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
	copy(out[8:], payload)
	return out, nil
}

func ParseInnerRecord(raw []byte) (InnerType, []byte, error) {
	if len(raw) < InnerHeaderSize || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
		return 0, nil, ErrInvalidInnerRecord
	}
	payloadLen := binary.BigEndian.Uint32(raw[4:8])
	if uint64(payloadLen)+InnerHeaderSize != uint64(len(raw)) {
		return 0, nil, ErrInvalidInnerRecord
	}
	typ := InnerType(raw[0])
	if err := validateInner(typ, int(payloadLen)); err != nil {
		return 0, nil, err
	}
	return typ, raw[InnerHeaderSize:], nil
}

func validateInner(typ InnerType, payloadLen int) error {
	switch typ {
	case InnerOpen:
		if payloadLen == 0 || payloadLen > MaxOpenBytes {
			return ErrInvalidInnerRecord
		}
	case InnerData:
		if payloadLen == 0 || payloadLen > MaxDataBytes {
			return ErrInvalidInnerRecord
		}
	case InnerFIN, InnerSessionReady, InnerSessionReadyACK:
		if payloadLen != 0 {
			return ErrInvalidInnerRecord
		}
	case InnerOpenACK:
		return requirePayloadSize(payloadLen, 32)
	case InnerOpenReject:
		return requirePayloadSize(payloadLen, 34)
	case InnerStreamKeyUpdate:
		return requirePayloadSize(payloadLen, 12)
	case InnerPing, InnerPong:
		return requirePayloadSize(payloadLen, 8)
	case InnerSessionKeyUpdate, InnerSessionKeyUpdateACK, InnerStreamKeyUpdateACK:
		return requirePayloadSize(payloadLen, 20)
	case InnerStreamReset, InnerGoAway:
		return requirePayloadSize(payloadLen, 10)
	case InnerSessionClose:
		return requirePayloadSize(payloadLen, 2)
	default:
		return fmt.Errorf("%w: %d", ErrUnknownInnerType, typ)
	}
	return nil
}

func requirePayloadSize(got, want int) error {
	if got != want || got > MaxControlBytes {
		return ErrInvalidInnerRecord
	}
	return nil
}
