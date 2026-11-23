package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
)

const sha256Size = 32

// ExtractSHA256 performs HKDF-Extract using SHA-256.
func ExtractSHA256(salt []byte, ikm []byte) [sha256Size]byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	var out [sha256Size]byte
	mac.Sum(out[:0])
	return out
}

// ExpandSHA256 performs HKDF-Expand using SHA-256.
func ExpandSHA256(prk [sha256Size]byte, info []byte, outLen int) ([]byte, error) {
	if outLen < 0 {
		return nil, errInvalidLength
	}
	if outLen == 0 {
		return []byte{}, nil
	}
	blocks := (outLen + sha256Size - 1) / sha256Size
	if blocks > 255 {
		return nil, errInvalidLength
	}
	out := make([]byte, 0, blocks*sha256Size)
	mac := hmac.New(sha256.New, prk[:])
	var counter [1]byte
	for index := 0; index < blocks; index++ {
		if index != 0 {
			mac.Reset()
			mac.Write(out[len(out)-sha256Size:])
		}
		mac.Write(info)
		counter[0] = byte(index + 1)
		mac.Write(counter[:])
		out = mac.Sum(out)
	}
	return out[:outLen], nil
}

var errInvalidLength = &hkdfError{"invalid length"}

type hkdfError struct{ msg string }

func (e *hkdfError) Error() string { return e.msg }

type BlockSHA256 struct {
	Info   []byte
	Output *[sha256Size]byte
}

// ExpandBlocksSHA256 computes independent HKDF first blocks under the same PRK.
func ExpandBlocksSHA256(prk [sha256Size]byte, blocks ...BlockSHA256) {
	mac := hmac.New(sha256.New, prk[:])
	counter := []byte{1}
	for index, block := range blocks {
		if index != 0 {
			mac.Reset()
		}
		mac.Write(block.Info)
		mac.Write(counter)
		mac.Sum(block.Output[:0])
	}
}
