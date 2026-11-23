package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestAuthorizationLookupKeyUsesCanonicalSHA256(t *testing.T) {
	seed := sha256.Sum256([]byte("tunnel marker"))
	key := []byte(base64.RawURLEncoding.EncodeToString(seed[:]))
	if !validLookupKey(string(key)) || validLookupKey(string(key[:len(key)-1])) || validLookupKey(string(key)+"=") {
		t.Fatal("invalid key length decision")
	}
	for offset := range key {
		for value := range 256 {
			changed := bytes.Clone(key)
			changed[offset] = byte(value)
			decoded, err := base64.RawURLEncoding.DecodeString(string(changed))
			want := err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == string(changed)
			if validLookupKey(string(changed)) != want {
				t.Fatalf("unexpected canonicality at byte %d, value %d", offset, value)
			}
		}
	}
}
