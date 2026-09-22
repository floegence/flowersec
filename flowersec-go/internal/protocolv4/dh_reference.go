package protocolv4

import (
	"crypto/ecdh"
	"crypto/subtle"
	"errors"
)

var errDHReference = errors.New(DHFailure)

// Only fixed fixture inputs are exported in this internal reference. Production
// key handles, randomness, Noise ownership and completion are not implemented.
func dhReferenceCurve(profile string) (ecdh.Curve, int, error) {
	switch profile {
	case DHProfileX25519:
		return ecdh.X25519(), DHX25519PublicBytes, nil
	case DHProfileP256:
		return ecdh.P256(), DHP256PublicBytes, nil
	default:
		return nil, 0, errDHReference
	}
}

func dhPublicReference(profile string, private []byte) ([]byte, error) {
	curve, _, err := dhReferenceCurve(profile)
	if err != nil || len(private) != DHPrivateBytes {
		return nil, errDHReference
	}
	key, err := curve.NewPrivateKey(private)
	if err != nil {
		return nil, errDHReference
	}
	return key.PublicKey().Bytes(), nil
}

func dhReference(profile string, private, remote []byte) ([]byte, error) {
	curve, publicBytes, err := dhReferenceCurve(profile)
	if err != nil || len(private) != DHPrivateBytes || len(remote) != publicBytes {
		return nil, errDHReference
	}
	// Go P256 rejects other SEC1 forms and checks canonical coordinates/on-curve.
	// X25519 import checks length only and preserves original public bytes; the
	// library applies RFC7748 masking/reduction only inside its DH computation.
	key, err := curve.NewPrivateKey(private)
	if err != nil {
		return nil, errDHReference
	}
	peer, err := curve.NewPublicKey(remote)
	if err != nil {
		return nil, errDHReference
	}
	result, err := key.ECDH(peer)
	if err != nil || len(result) != DHSecretBytes || subtle.ConstantTimeCompare(result, make([]byte, DHSecretBytes)) == 1 {
		clear(result)
		return nil, errDHReference
	}
	return result, nil
}
