package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

const sha256Size = 32

// ExtractSHA256 performs HKDF-Extract using SHA-256.
func ExtractSHA256(salt []byte, ikm []byte) [sha256Size]byte {
	return extract(sha256.New, salt, ikm)
}

// ExpandSHA256 performs HKDF-Expand using SHA-256.
func ExpandSHA256(prk [sha256Size]byte, info []byte, outLen int) ([]byte, error) {
	if outLen < 0 {
		return nil, errInvalidLength
	}
	return expand(sha256.New, prk[:], info, outLen)
}

var errInvalidLength = &hkdfError{"invalid length"}

type hkdfError struct{ msg string }

func (e *hkdfError) Error() string { return e.msg }

func extract(hashFn func() hash.Hash, salt []byte, ikm []byte) [sha256Size]byte {
	mac := hmac.New(hashFn, salt)
	_, _ = mac.Write(ikm)
	var out [sha256Size]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func expand(hashFn func() hash.Hash, prk []byte, info []byte, outLen int) ([]byte, error) {
	if outLen == 0 {
		return []byte{}, nil
	}
	n := (outLen + sha256Size - 1) / sha256Size
	if n > 255 {
		return nil, errInvalidLength
	}

	okm := make([]byte, 0, n*sha256Size)
	var t []byte
	for i := 1; i <= n; i++ {
		mac := hmac.New(hashFn, prk)
		_, _ = mac.Write(t)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{byte(i)})
		t = mac.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:outLen], nil
}
