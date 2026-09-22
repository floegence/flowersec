package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"filippo.io/edwards25519"
)

// VerifyEd25519 applies the v4 canonical prime-order verification predicate.
// Credential trust and permission are checked separately by the owning caller.
func VerifyEd25519(signature, message, publicKey []byte) bool {
	if len(publicKey) != StrictEd25519PublicKeyBytes || len(signature) != StrictEd25519SignatureBytes {
		return false
	}
	for _, encoded := range [][]byte{publicKey, signature[:StrictEd25519PointBytes]} {
		point, err := new(edwards25519.Point).SetBytes(encoded)
		if err != nil || !bytes.Equal(point.Bytes(), encoded) || point.Equal(edwards25519.NewIdentityPoint()) == 1 {
			return false
		}
		// Scalar negation supplies the canonical integer L-1, not L reduced to
		// zero. [(L-1)]P + P is [L]P even when P has a torsion component.
		oneBytes := make([]byte, 32)
		oneBytes[0] = 1
		one, err := new(edwards25519.Scalar).SetCanonicalBytes(oneBytes)
		if err != nil {
			return false
		}
		minusOne := new(edwards25519.Scalar).Negate(one)
		orderPoint := new(edwards25519.Point).ScalarMult(minusOne, point)
		orderPoint.Add(orderPoint, point)
		if orderPoint.Equal(edwards25519.NewIdentityPoint()) != 1 {
			return false
		}
	}
	if _, err := new(edwards25519.Scalar).SetCanonicalBytes(signature[StrictEd25519PointBytes:]); err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

var errSignatureGeneration = errors.New(StrictEd25519SigningFailure)

func strictEd25519SignReference(message, seed []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errSignatureGeneration
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	return strictEd25519SignOnce(message, func() ([]byte, []byte, error) {
		return key.Public().(ed25519.PublicKey), ed25519.Sign(key, message), nil
	})
}

// The callback is internal injection for exercising the signer output gate,
// not a public key handle or an asynchronous cancellation/ownership contract.
func strictEd25519SignOnce(message []byte, sign func() ([]byte, []byte, error)) ([]byte, error) {
	publicKey, signature, err := sign()
	if err != nil || !VerifyEd25519(signature, message, publicKey) {
		return nil, errSignatureGeneration
	}
	return signature, nil
}
