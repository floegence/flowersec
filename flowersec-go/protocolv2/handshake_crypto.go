package protocolv2

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	internalhkdf "github.com/floegence/flowersec/flowersec-go/internal/hkdf"
)

var (
	ErrInvalidEphemeralKey = errors.New("invalid Flowersec v2 ephemeral key")
	ErrInvalidSharedSecret = errors.New("invalid Flowersec v2 ECDH shared secret")
	ErrInvalidHandshakePSK = errors.New("invalid Flowersec v2 handshake PSK")
	ErrInvalidTranscript   = errors.New("invalid Flowersec v2 handshake transcript")
)

func ParseEphemeralPublicKey(suite Suite, raw []byte) (*ecdh.PublicKey, error) {
	curve, err := handshakeCurve(suite)
	if err != nil {
		return nil, err
	}
	switch suite {
	case SuiteChaCha20Poly1305:
		if len(raw) != 32 {
			return nil, ErrInvalidEphemeralKey
		}
	case SuiteAES256GCM:
		if len(raw) != 65 || raw[0] != 4 {
			return nil, ErrInvalidEphemeralKey
		}
	}
	publicKey, err := curve.NewPublicKey(raw)
	if err != nil {
		return nil, ErrInvalidEphemeralKey
	}
	return publicKey, nil
}

func EphemeralPublicKey(suite Suite, privateRaw []byte) ([]byte, error) {
	curve, err := handshakeCurve(suite)
	if err != nil {
		return nil, err
	}
	if len(privateRaw) != 32 {
		return nil, ErrInvalidEphemeralKey
	}
	privateKey, err := curve.NewPrivateKey(privateRaw)
	if err != nil {
		return nil, ErrInvalidEphemeralKey
	}
	return privateKey.PublicKey().Bytes(), nil
}

// GenerateEphemeralKey creates a suite-valid private/public key pair using the
// supplied cryptographic random source.
func GenerateEphemeralKey(suite Suite, random io.Reader) ([]byte, []byte, error) {
	if random == nil {
		return nil, nil, ErrInvalidEphemeralKey
	}
	curve, err := handshakeCurve(suite)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := curve.GenerateKey(random)
	if err != nil {
		return nil, nil, ErrInvalidEphemeralKey
	}
	return privateKey.Bytes(), privateKey.PublicKey().Bytes(), nil
}

func ComputeECDHSharedSecret(suite Suite, privateRaw, peerPublicRaw []byte) ([]byte, error) {
	curve, err := handshakeCurve(suite)
	if err != nil {
		return nil, err
	}
	if len(privateRaw) != 32 {
		return nil, ErrInvalidEphemeralKey
	}
	privateKey, err := curve.NewPrivateKey(privateRaw)
	if err != nil {
		return nil, ErrInvalidEphemeralKey
	}
	publicKey, err := ParseEphemeralPublicKey(suite, peerPublicRaw)
	if err != nil {
		return nil, err
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil || len(shared) != 32 || subtle.ConstantTimeCompare(shared, make([]byte, 32)) == 1 {
		return nil, ErrInvalidSharedSecret
	}
	return shared, nil
}

func DeriveHandshakePRK(psk, sharedSecret []byte) ([32]byte, error) {
	if len(psk) != 32 {
		return [32]byte{}, ErrInvalidHandshakePSK
	}
	if len(sharedSecret) != 32 || subtle.ConstantTimeCompare(sharedSecret, make([]byte, 32)) == 1 {
		return [32]byte{}, ErrInvalidSharedSecret
	}
	return internalhkdf.ExtractSHA256(psk, sharedSecret), nil
}

func ComputeHandshakeH0(fsc2Raw, clientInitRaw []byte) ([32]byte, error) {
	if err := ParseControlPreface(fsc2Raw); err != nil {
		return [32]byte{}, err
	}
	if _, err := ParseClientInit(clientInitRaw); err != nil {
		return [32]byte{}, err
	}
	return hashTranscript([]byte("flowersec-v2-handshake\x00"), fsc2Raw, lengthPrefixed(clientInitRaw)), nil
}

func ComputeHandshakeH1(h0 [32]byte, serverCoreFrame []byte) ([32]byte, error) {
	frame, err := ParseHandshakeFrame(serverCoreFrame)
	if err != nil || frame.Type != HandshakeServerFinished {
		return [32]byte{}, ErrInvalidTranscript
	}
	return hashTranscript(h0[:], lengthPrefixed(serverCoreFrame)), nil
}

func ComputeServerConfirm(handshakePRK, h1 [32]byte) ([32]byte, [32]byte, error) {
	info := append([]byte("flowersec v2 server finished"), h1[:]...)
	keyBytes, err := internalhkdf.ExpandSHA256(handshakePRK, info, 32)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	var key [32]byte
	copy(key[:], keyBytes)
	confirm := confirmHMAC(key, h1)
	return key, confirm, nil
}

func VerifyServerConfirm(handshakePRK, h1, got [32]byte) bool {
	_, want, err := ComputeServerConfirm(handshakePRK, h1)
	return err == nil && hmac.Equal(want[:], got[:])
}

func ComputeHandshakeH2(h1 [32]byte, serverFinishedRaw, clientCoreFrame []byte) ([32]byte, error) {
	serverFrame, err := ParseHandshakeFrame(serverFinishedRaw)
	if err != nil || serverFrame.Type != HandshakeServerFinished {
		return [32]byte{}, ErrInvalidTranscript
	}
	clientFrame, err := ParseHandshakeFrame(clientCoreFrame)
	if err != nil || clientFrame.Type != HandshakeClientFinished {
		return [32]byte{}, ErrInvalidTranscript
	}
	return hashTranscript(h1[:], lengthPrefixed(serverFinishedRaw), lengthPrefixed(clientCoreFrame)), nil
}

func ComputeClientConfirm(handshakePRK, h2 [32]byte) ([32]byte, [32]byte, error) {
	info := append([]byte("flowersec v2 client finished"), h2[:]...)
	keyBytes, err := internalhkdf.ExpandSHA256(handshakePRK, info, 32)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	var key [32]byte
	copy(key[:], keyBytes)
	confirm := confirmHMAC(key, h2)
	return key, confirm, nil
}

func VerifyClientConfirm(handshakePRK, h2, got [32]byte) bool {
	_, want, err := ComputeClientConfirm(handshakePRK, h2)
	return err == nil && hmac.Equal(want[:], got[:])
}

func ComputeHandshakeH3(h2 [32]byte, clientFinishedRaw []byte) ([32]byte, error) {
	if _, err := ParseClientFinished(clientFinishedRaw); err != nil {
		return [32]byte{}, err
	}
	return hashTranscript(h2[:], lengthPrefixed(clientFinishedRaw)), nil
}

func DeriveSessionPRK(h3, handshakePRK [32]byte) [32]byte {
	return internalhkdf.ExtractSHA256(h3[:], handshakePRK[:])
}

func handshakeCurve(suite Suite) (ecdh.Curve, error) {
	switch suite {
	case SuiteChaCha20Poly1305:
		return ecdh.X25519(), nil
	case SuiteAES256GCM:
		return ecdh.P256(), nil
	default:
		return nil, ErrInvalidSuite
	}
}

func lengthPrefixed(raw []byte) []byte {
	if uint64(len(raw)) > uint64(^uint32(0)) {
		return nil
	}
	out := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(out[:4], uint32(len(raw)))
	copy(out[4:], raw)
	return out
}

func hashTranscript(parts ...[]byte) [32]byte {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write(part)
	}
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

func confirmHMAC(key, transcript [32]byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(transcript[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}
