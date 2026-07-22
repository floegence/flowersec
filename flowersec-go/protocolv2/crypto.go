package protocolv2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	internalhkdf "github.com/floegence/flowersec/flowersec-go/internal/hkdf"
	"golang.org/x/crypto/chacha20poly1305"
)

type Direction uint8

const (
	DirectionClientToServer Direction = 1
	DirectionServerToClient Direction = 2
)

type Suite uint16

const (
	SuiteChaCha20Poly1305 Suite = 1
	SuiteAES256GCM        Suite = 2
)

var (
	ErrInvalidDirection = errors.New("invalid v2 direction")
	ErrInvalidSuite     = errors.New("invalid v2 suite")
	ErrAuthentication   = errors.New("v2 record authentication failed")
)

type EpochRoots struct {
	EpochSecret  [32]byte
	ControlRoot  [32]byte
	StreamRoot   [32]byte
	SetupMACRoot [32]byte
	RekeyRoot    [32]byte
}

type RecordMaterial struct {
	Secret      [32]byte
	RecordKey   [32]byte
	NoncePrefix [4]byte
}

func DeriveEpochZero(sessionPRK [32]byte, direction Direction) (EpochRoots, error) {
	if err := direction.validate(); err != nil {
		return EpochRoots{}, err
	}
	epochSecret, err := expand32(sessionPRK, labelWith("flowersec v2 epoch zero", []byte{byte(direction)}))
	if err != nil {
		return EpochRoots{}, err
	}
	return deriveRoots(epochSecret)
}

func DeriveNextEpoch(rekeyRoot, h3 [32]byte, direction Direction, nextEpoch uint32) ([32]byte, error) {
	if err := direction.validate(); err != nil {
		return [32]byte{}, err
	}
	var epoch [4]byte
	binary.BigEndian.PutUint32(epoch[:], nextEpoch)
	return expand32(rekeyRoot, labelWith("flowersec v2 next epoch", h3[:], []byte{byte(direction)}, epoch[:]))
}

// DeriveEpochRoots expands a previously derived epoch secret into the roots
// shared by the control, stream, setup-MAC, and rekey protocols.
func DeriveEpochRoots(epochSecret [32]byte) (EpochRoots, error) {
	return deriveRoots(epochSecret)
}

func deriveRoots(epochSecret [32]byte) (EpochRoots, error) {
	control, err := expand32(epochSecret, labelWith("flowersec v2 control root"))
	if err != nil {
		return EpochRoots{}, err
	}
	stream, err := expand32(epochSecret, labelWith("flowersec v2 stream root"))
	if err != nil {
		return EpochRoots{}, err
	}
	setup, err := expand32(epochSecret, labelWith("flowersec v2 setup root"))
	if err != nil {
		return EpochRoots{}, err
	}
	rekey, err := expand32(epochSecret, labelWith("flowersec v2 rekey root"))
	if err != nil {
		return EpochRoots{}, err
	}
	return EpochRoots{
		EpochSecret:  epochSecret,
		ControlRoot:  control,
		StreamRoot:   stream,
		SetupMACRoot: setup,
		RekeyRoot:    rekey,
	}, nil
}

func DeriveStreamMaterial(streamRoot, h3 [32]byte, logicalStreamID uint64, direction Direction, epoch uint32) (RecordMaterial, error) {
	if logicalStreamID == 0 {
		return RecordMaterial{}, ErrInvalidSetupPreface
	}
	return deriveRecordMaterial(streamRoot, "flowersec v2 stream", h3, logicalStreamID, direction, epoch)
}

func DeriveControlMaterial(controlRoot, h3 [32]byte, direction Direction, epoch uint32) (RecordMaterial, error) {
	return deriveRecordMaterial(controlRoot, "flowersec v2 control", h3, 0, direction, epoch)
}

func deriveRecordMaterial(root [32]byte, secretLabel string, h3 [32]byte, logicalStreamID uint64, direction Direction, epoch uint32) (RecordMaterial, error) {
	if err := direction.validate(); err != nil {
		return RecordMaterial{}, err
	}
	var id [8]byte
	var epochBytes [4]byte
	binary.BigEndian.PutUint64(id[:], logicalStreamID)
	binary.BigEndian.PutUint32(epochBytes[:], epoch)
	secret, err := expand32(root, labelWith(secretLabel, h3[:], id[:], []byte{byte(direction)}, epochBytes[:]))
	if err != nil {
		return RecordMaterial{}, err
	}
	key, err := expand32(secret, labelWith("flowersec v2 record key"))
	if err != nil {
		return RecordMaterial{}, err
	}
	nonce, err := internalhkdf.ExpandSHA256(secret, labelWith("flowersec v2 nonce"), 4)
	if err != nil {
		return RecordMaterial{}, err
	}
	var prefix [4]byte
	copy(prefix[:], nonce)
	return RecordMaterial{Secret: secret, RecordKey: key, NoncePrefix: prefix}, nil
}

func ComputeSetupMAC(setupRoot, h3 [32]byte, preface SetupPreface) ([32]byte, error) {
	raw, err := preface.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	mac := hmac.New(sha256.New, setupRoot[:])
	_, _ = mac.Write(labelWith("flowersec-v2-setup"))
	_, _ = mac.Write(h3[:])
	_, _ = mac.Write(raw[:24])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out, nil
}

func VerifySetupMAC(setupRoot, h3 [32]byte, preface SetupPreface) bool {
	want, err := ComputeSetupMAC(setupRoot, h3, preface)
	if err != nil {
		return false
	}
	return hmac.Equal(want[:], preface.SetupMAC[:])
}

func SealRecord(suite Suite, key [32]byte, noncePrefix [4]byte, h3 [32]byte, logicalStreamID uint64, direction Direction, header RecordHeader, plaintext []byte) ([]byte, error) {
	if err := direction.validate(); err != nil {
		return nil, err
	}
	if uint64(len(plaintext))+AEADTagBytes != uint64(header.CiphertextLength) {
		return nil, ErrInvalidRecordHeader
	}
	rawHeader, err := header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	nonce := recordNonce(noncePrefix, header.Sequence)
	aad := recordAAD(h3, logicalStreamID, direction, rawHeader)
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

func OpenRecord(suite Suite, key [32]byte, noncePrefix [4]byte, h3 [32]byte, logicalStreamID uint64, direction Direction, header RecordHeader, ciphertext []byte) ([]byte, error) {
	if err := direction.validate(); err != nil {
		return nil, err
	}
	if len(ciphertext) != int(header.CiphertextLength) {
		return nil, ErrInvalidRecordHeader
	}
	rawHeader, err := header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	nonce := recordNonce(noncePrefix, header.Sequence)
	aad := recordAAD(h3, logicalStreamID, direction, rawHeader)
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	return plaintext, nil
}

func newAEAD(suite Suite, key [32]byte) (cipher.AEAD, error) {
	switch suite {
	case SuiteChaCha20Poly1305:
		return chacha20poly1305.New(key[:])
	case SuiteAES256GCM:
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, ErrInvalidSuite
	}
}

func recordNonce(prefix [4]byte, sequence uint64) [12]byte {
	var out [12]byte
	copy(out[:4], prefix[:])
	binary.BigEndian.PutUint64(out[4:], sequence)
	return out
}

func recordAAD(h3 [32]byte, logicalStreamID uint64, direction Direction, rawHeader []byte) []byte {
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], logicalStreamID)
	out := labelWith("flowersec-v2-record", h3[:], id[:], []byte{byte(direction)}, rawHeader)
	return out
}

func labelWith(label string, parts ...[]byte) []byte {
	size := len(label) + 1
	for _, part := range parts {
		size += len(part)
	}
	out := make([]byte, 0, size)
	out = append(out, label...)
	out = append(out, 0)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func expand32(prk [32]byte, info []byte) ([32]byte, error) {
	raw, err := internalhkdf.ExpandSHA256(prk, info, 32)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}

func (d Direction) validate() error {
	if d != DirectionClientToServer && d != DirectionServerToClient {
		return ErrInvalidDirection
	}
	return nil
}
