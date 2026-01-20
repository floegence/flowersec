package exampleutil

import (
	"crypto/rand"
	"fmt"
	"io"
)

// RandomB64u returns a base64url (raw, no padding) string of n random bytes.
//
// It is used by demos to generate channel IDs and other opaque identifiers.
func RandomB64u(n int, r io.Reader) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("n must be > 0")
	}
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return Encode(b), nil
}
