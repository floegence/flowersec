package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/internal/hkdf"
)

var (
	// ErrUnsupportedSuite signals that the requested curve or AEAD is not supported.
	ErrUnsupportedSuite = errors.New("unsupported suite")
	// ErrInvalidPSK indicates the PSK size is not 32 bytes.
	ErrInvalidPSK = errors.New("invalid psk")
)

// Suite identifies the key agreement + AEAD suite for the E2EE handshake.
type Suite uint16

const (
	// SuiteX25519HKDFAES256GCM uses X25519 for ECDH and AES-256-GCM for records.
	SuiteX25519HKDFAES256GCM Suite = 1
	// SuiteP256HKDFAES256GCM uses P-256 for ECDH and AES-256-GCM for records.
	SuiteP256HKDFAES256GCM Suite = 2
)

// SessionKeys holds the derived bidirectional keys and nonces for a channel.
type SessionKeys struct {
	C2SKey      [32]byte // Client-to-server AEAD key.
	S2CKey      [32]byte // Server-to-client AEAD key.
	C2SNoncePre [4]byte  // Client-to-server nonce prefix.
	S2CNoncePre [4]byte  // Server-to-client nonce prefix.
	RekeyBase   [32]byte // Base secret for deriving rekeyed record keys.
}

func curveForSuite(s Suite) (ecdh.Curve, error) {
	switch s {
	case SuiteX25519HKDFAES256GCM:
		return ecdh.X25519(), nil
	case SuiteP256HKDFAES256GCM:
		return ecdh.P256(), nil
	default:
		return nil, ErrUnsupportedSuite
	}
}

// GenerateEphemeralKeypair creates a per-handshake ECDH keypair.
func GenerateEphemeralKeypair(suite Suite) (priv *ecdh.PrivateKey, pub []byte, err error) {
	curve, err := curveForSuite(suite)
	if err != nil {
		return nil, nil, err
	}
	priv, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// ParsePublicKey parses a peer public key for the given suite.
func ParsePublicKey(suite Suite, pub []byte) (*ecdh.PublicKey, error) {
	curve, err := curveForSuite(suite)
	if err != nil {
		return nil, err
	}
	return curve.NewPublicKey(pub)
}

// DeriveSessionKeys expands the ECDH shared secret into C2S/S2C keys and nonces.
func DeriveSessionKeys(psk []byte, suite Suite, sharedSecret []byte, transcriptHash [32]byte) (SessionKeys, error) {
	if len(psk) != 32 {
		return SessionKeys{}, ErrInvalidPSK
	}
	ikm := make([]byte, 0, len(sharedSecret)+len(transcriptHash))
	ikm = append(ikm, sharedSecret...)
	ikm = append(ikm, transcriptHash[:]...)

	prk := hkdf.ExtractSHA256(psk, ikm)

	c2sKeyBytes, err := hkdf.ExpandSHA256(prk, []byte("flowersec-e2ee-v1:c2s:key"), 32)
	if err != nil {
		return SessionKeys{}, err
	}
	s2cKeyBytes, err := hkdf.ExpandSHA256(prk, []byte("flowersec-e2ee-v1:s2c:key"), 32)
	if err != nil {
		return SessionKeys{}, err
	}
	rekeyBytes, err := hkdf.ExpandSHA256(prk, []byte("flowersec-e2ee-v1:rekey_base"), 32)
	if err != nil {
		return SessionKeys{}, err
	}
	c2sNonce, err := hkdf.ExpandSHA256(prk, []byte("flowersec-e2ee-v1:c2s:nonce_prefix"), 4)
	if err != nil {
		return SessionKeys{}, err
	}
	s2cNonce, err := hkdf.ExpandSHA256(prk, []byte("flowersec-e2ee-v1:s2c:nonce_prefix"), 4)
	if err != nil {
		return SessionKeys{}, err
	}

	var out SessionKeys
	copy(out.C2SKey[:], c2sKeyBytes)
	copy(out.S2CKey[:], s2cKeyBytes)
	copy(out.RekeyBase[:], rekeyBytes)
	copy(out.C2SNoncePre[:], c2sNonce)
	copy(out.S2CNoncePre[:], s2cNonce)
	_ = suite
	return out, nil
}

// ComputeAuthTag builds the handshake auth tag over the transcript hash and timestamp.
func ComputeAuthTag(psk []byte, transcriptHash [32]byte, timestampUnixS uint64) ([32]byte, error) {
	if len(psk) != 32 {
		return [32]byte{}, ErrInvalidPSK
	}
	msg := make([]byte, 32+8)
	copy(msg[:32], transcriptHash[:])
	for i := 0; i < 8; i++ {
		msg[32+i] = byte(timestampUnixS >> (56 - 8*i))
	}
	m := hmac.New(sha256.New, psk)
	_, _ = m.Write(msg)
	sum := m.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out, nil
}

// NewAESGCM creates an AES-256-GCM AEAD with a fixed 12-byte nonce size.
func NewAESGCM(key [32]byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	if a.NonceSize() != 12 {
		return nil, fmt.Errorf("unexpected gcm nonce size: %d", a.NonceSize())
	}
	return a, nil
}
