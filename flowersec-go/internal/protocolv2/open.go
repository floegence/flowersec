package protocolv2

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	OpenFixedPayloadBytes = 46
	MaxOpenKindBytes      = 128
)

var (
	ErrInvalidOpenPayload  = errors.New("invalid Flowersec v2 OPEN payload")
	ErrInvalidOpenKind     = errors.New("invalid Flowersec v2 OPEN kind")
	ErrInvalidOpenMetadata = errors.New("invalid Flowersec v2 OPEN metadata")
	ErrInvalidOpenACK      = errors.New("invalid Flowersec v2 OPEN_ACK payload")
	ErrInvalidOpenReject   = errors.New("invalid Flowersec v2 OPEN_REJECT payload")
)

type OpenPayload struct {
	LogicalStreamID uint64
	FSS2Hash        [32]byte
	Kind            string
	Metadata        []byte
}

type OpenRejectReason uint16

const (
	OpenRejectUnsupportedKind   OpenRejectReason = 1
	OpenRejectResourceExhausted OpenRejectReason = 2
	OpenRejectPolicyRejected    OpenRejectReason = 3
	OpenRejectInvalidMetadata   OpenRejectReason = 4
	OpenRejectGoingAway         OpenRejectReason = 5
)

type OpenReject struct {
	OpenHash    [32]byte
	Reason      OpenRejectReason
	KnownReason bool
}

func ComputeFSS2Hash(rawFSS2 []byte) ([32]byte, error) {
	if _, err := ParseSetupPreface(rawFSS2); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(rawFSS2), nil
}

func MarshalOpenPayload(open OpenPayload) ([]byte, error) {
	if open.LogicalStreamID == 0 {
		return nil, ErrInvalidOpenPayload
	}
	if err := validateOpenKind(open.Kind); err != nil {
		return nil, err
	}
	metadata, err := validateCanonicalMetadata(open.Metadata, true)
	if err != nil {
		return nil, err
	}
	total := OpenFixedPayloadBytes + len(open.Kind) + len(metadata)
	if total > MaxOpenBytes {
		return nil, ErrInvalidOpenPayload
	}
	out := make([]byte, total)
	binary.BigEndian.PutUint64(out[0:8], open.LogicalStreamID)
	copy(out[8:40], open.FSS2Hash[:])
	binary.BigEndian.PutUint16(out[40:42], uint16(len(open.Kind)))
	binary.BigEndian.PutUint32(out[42:46], uint32(len(metadata)))
	copy(out[46:46+len(open.Kind)], open.Kind)
	copy(out[46+len(open.Kind):], metadata)
	return out, nil
}

func ParseOpenPayload(raw []byte) (OpenPayload, error) {
	if len(raw) < OpenFixedPayloadBytes || len(raw) > MaxOpenBytes {
		return OpenPayload{}, ErrInvalidOpenPayload
	}
	kindLength := int(binary.BigEndian.Uint16(raw[40:42]))
	metadataLength := uint64(binary.BigEndian.Uint32(raw[42:46]))
	wantLength := uint64(OpenFixedPayloadBytes) + uint64(kindLength) + metadataLength
	if wantLength != uint64(len(raw)) {
		return OpenPayload{}, ErrInvalidOpenPayload
	}
	logicalID := binary.BigEndian.Uint64(raw[0:8])
	kind := string(raw[46 : 46+kindLength])
	if logicalID == 0 {
		return OpenPayload{}, ErrInvalidOpenPayload
	}
	if err := validateOpenKind(kind); err != nil {
		return OpenPayload{}, err
	}
	metadata, err := validateCanonicalMetadata(raw[46+kindLength:], false)
	if err != nil {
		return OpenPayload{}, err
	}
	out := OpenPayload{LogicalStreamID: logicalID, Kind: kind, Metadata: append([]byte(nil), metadata...)}
	copy(out.FSS2Hash[:], raw[8:40])
	return out, nil
}

func ComputeOpenHash(rawOpenPayload []byte) ([32]byte, error) {
	if _, err := ParseOpenPayload(rawOpenPayload); err != nil {
		return [32]byte{}, err
	}
	preimage := make([]byte, 0, len("flowersec-v2-open\x00")+4+len(rawOpenPayload))
	preimage = append(preimage, "flowersec-v2-open\x00"...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(rawOpenPayload)))
	preimage = append(preimage, size[:]...)
	preimage = append(preimage, rawOpenPayload...)
	return sha256.Sum256(preimage), nil
}

func MarshalOpenACK(openHash [32]byte) []byte {
	return append([]byte(nil), openHash[:]...)
}

func ParseOpenACK(raw []byte) ([32]byte, error) {
	if len(raw) != 32 {
		return [32]byte{}, ErrInvalidOpenACK
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}

func MarshalOpenReject(openHash [32]byte, reason OpenRejectReason) ([]byte, error) {
	if !knownOpenRejectReason(reason) {
		return nil, ErrInvalidOpenReject
	}
	out := make([]byte, 34)
	copy(out[0:32], openHash[:])
	binary.BigEndian.PutUint16(out[32:34], uint16(reason))
	return out, nil
}

func ParseOpenReject(raw []byte) (OpenReject, error) {
	if len(raw) != 34 {
		return OpenReject{}, ErrInvalidOpenReject
	}
	reason := OpenRejectReason(binary.BigEndian.Uint16(raw[32:34]))
	if reason == 0 {
		return OpenReject{}, ErrInvalidOpenReject
	}
	out := OpenReject{Reason: reason, KnownReason: knownOpenRejectReason(reason)}
	copy(out.OpenHash[:], raw[0:32])
	return out, nil
}

func knownOpenRejectReason(reason OpenRejectReason) bool {
	return reason >= OpenRejectUnsupportedKind && reason <= OpenRejectGoingAway
}

func validateOpenKind(kind string) error {
	if !validOpenUnicodeString(kind, MaxOpenKindBytes, false) {
		return ErrInvalidOpenKind
	}
	first, _ := utf8.DecodeRuneInString(kind)
	last, _ := utf8.DecodeLastRuneInString(kind)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return ErrInvalidOpenKind
	}
	return nil
}

func openHashMismatch(got, want [32]byte) error {
	if got != want {
		return fmt.Errorf("OPEN hash mismatch")
	}
	return nil
}
