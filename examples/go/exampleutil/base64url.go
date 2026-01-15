package exampleutil

import "encoding/base64"

// Raw URL-safe base64 without padding, matching the flowersec design.
var rawURL = base64.RawURLEncoding

func Encode(b []byte) string {
	return rawURL.EncodeToString(b)
}

func Decode(s string) ([]byte, error) {
	return rawURL.DecodeString(s)
}
