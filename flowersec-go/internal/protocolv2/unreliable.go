package protocolv2

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	FeatureUnreliableMessages uint32 = 1 << 0
	SupportedFeatureMask             = FeatureUnreliableMessages

	UnreliableHeaderSize         = 32
	MaxUnreliableMessageBytes    = 976
	MaxUnreliableCiphertextBytes = MaxUnreliableMessageBytes + AEADTagBytes
	MaxUnreliableWireBytes       = UnreliableHeaderSize + MaxUnreliableCiphertextBytes
)

var (
	ErrInvalidUnreliableHeader = errors.New("invalid FSD2 unreliable message header")
	ErrUnreliableTooLarge      = errors.New("FSD2 unreliable message too large")
)

type UnreliableHeader struct {
	Epoch            uint32
	Sequence         uint64
	ExpiresAtUnixMS  uint64
	CiphertextLength uint32
}

func (header UnreliableHeader) MarshalBinary() ([]byte, error) {
	if header.CiphertextLength < AEADTagBytes || header.CiphertextLength > MaxUnreliableCiphertextBytes {
		return nil, ErrInvalidUnreliableHeader
	}
	out := make([]byte, UnreliableHeaderSize)
	copy(out[0:4], "FSD2")
	out[4] = 2
	binary.BigEndian.PutUint16(out[6:8], UnreliableHeaderSize)
	binary.BigEndian.PutUint32(out[8:12], header.Epoch)
	binary.BigEndian.PutUint64(out[12:20], header.Sequence)
	binary.BigEndian.PutUint64(out[20:28], header.ExpiresAtUnixMS)
	binary.BigEndian.PutUint32(out[28:32], header.CiphertextLength)
	return out, nil
}

func ParseUnreliableHeader(raw []byte) (UnreliableHeader, error) {
	if len(raw) != UnreliableHeaderSize || string(raw[0:4]) != "FSD2" || raw[4] != 2 || raw[5] != 0 ||
		binary.BigEndian.Uint16(raw[6:8]) != UnreliableHeaderSize {
		return UnreliableHeader{}, ErrInvalidUnreliableHeader
	}
	header := UnreliableHeader{
		Epoch:            binary.BigEndian.Uint32(raw[8:12]),
		Sequence:         binary.BigEndian.Uint64(raw[12:20]),
		ExpiresAtUnixMS:  binary.BigEndian.Uint64(raw[20:28]),
		CiphertextLength: binary.BigEndian.Uint32(raw[28:32]),
	}
	if _, err := header.MarshalBinary(); err != nil {
		return UnreliableHeader{}, err
	}
	return header, nil
}

type UnreliableMaterial struct {
	Root        [32]byte
	Secret      [32]byte
	RecordKey   [32]byte
	NoncePrefix [4]byte
}

func DeriveUnreliableMaterial(epochSecret, h3 [32]byte, direction Direction, epoch uint32) (UnreliableMaterial, error) {
	if err := direction.validate(); err != nil {
		return UnreliableMaterial{}, err
	}
	root, err := expand32(epochSecret, labelWith("flowersec v2 unreliable root"))
	if err != nil {
		return UnreliableMaterial{}, err
	}
	var epochBytes [4]byte
	binary.BigEndian.PutUint32(epochBytes[:], epoch)
	secret, err := expand32(root, labelWith("flowersec v2 unreliable", h3[:], []byte{byte(direction)}, epochBytes[:]))
	if err != nil {
		return UnreliableMaterial{}, err
	}
	key, err := expand32(secret, labelWith("flowersec v2 unreliable key"))
	if err != nil {
		return UnreliableMaterial{}, err
	}
	nonceBytes, err := unreliableNoncePrefix(secret)
	if err != nil {
		return UnreliableMaterial{}, err
	}
	return UnreliableMaterial{Root: root, Secret: secret, RecordKey: key, NoncePrefix: nonceBytes}, nil
}

func SealUnreliable(suite Suite, material UnreliableMaterial, h3 [32]byte, direction Direction, header UnreliableHeader, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxUnreliableMessageBytes || len(plaintext)+AEADTagBytes != int(header.CiphertextLength) {
		return nil, ErrUnreliableTooLarge
	}
	return sealOpenUnreliable(true, suite, material, h3, direction, header, plaintext)
}

func OpenUnreliable(suite Suite, material UnreliableMaterial, h3 [32]byte, direction Direction, header UnreliableHeader, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != int(header.CiphertextLength) {
		return nil, ErrInvalidUnreliableHeader
	}
	return sealOpenUnreliable(false, suite, material, h3, direction, header, ciphertext)
}

func sealOpenUnreliable(seal bool, suite Suite, material UnreliableMaterial, h3 [32]byte, direction Direction, header UnreliableHeader, payload []byte) ([]byte, error) {
	if err := direction.validate(); err != nil {
		return nil, err
	}
	rawHeader, err := header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(suite, material.RecordKey)
	if err != nil {
		return nil, err
	}
	nonce := recordNonce(material.NoncePrefix, header.Sequence)
	aad := labelWith("flowersec-v2-unreliable", h3[:], []byte{byte(direction)}, rawHeader)
	if seal {
		return aead.Seal(nil, nonce[:], payload, aad), nil
	}
	plaintext, err := aead.Open(nil, nonce[:], payload, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	return plaintext, nil
}
