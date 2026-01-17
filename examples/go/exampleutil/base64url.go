package exampleutil

import "encoding/base64"

// Raw URL-safe base64 without padding, matching the flowersec design.
//
// Notes:
//   - Many fields in the IDL are base64url-encoded (PSKs, nonces, endpoint instance ids, etc.).
//   - Prefer using the library's internal base64url helpers in real integrations; this package exists to keep examples
//     small and dependency-free.
var rawURL = base64.RawURLEncoding

func Encode(b []byte) string {
	return rawURL.EncodeToString(b)
}

func Decode(s string) ([]byte, error) {
	return rawURL.DecodeString(s)
}
