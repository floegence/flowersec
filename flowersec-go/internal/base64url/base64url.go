package base64url

import (
	"encoding/base64"
)

// Encode encodes bytes as base64url without padding.
func Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Decode decodes base64url without padding.
func Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
