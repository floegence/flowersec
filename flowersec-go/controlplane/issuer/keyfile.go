package issuer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/base64url"
)

// PrivateKeyFile matches the JSON layout consumed by helper tools that mint control-plane tokens.
//
// This format is intended for local development and demos. Keep it secret.
type PrivateKeyFile struct {
	KID        string `json:"kid"`          // Key ID.
	PrivKeyB64 string `json:"privkey_b64u"` // Base64url-encoded Ed25519 private key (64 bytes).
}

// ExportPrivateKeyFile serializes the current signing key as JSON.
//
// The exported file contains the raw Ed25519 private key bytes and must be kept secret.
func (k *Keyset) ExportPrivateKeyFile() ([]byte, error) {
	if k == nil {
		return nil, errors.New("missing keyset")
	}
	k.mu.RLock()
	kid := k.activeKID
	priv := clonePrivateKey(k.activePrivate)
	k.mu.RUnlock()
	defer clear(priv)
	if kid == "" {
		return nil, errors.New("missing kid")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key")
	}
	return json.MarshalIndent(PrivateKeyFile{
		KID:        kid,
		PrivKeyB64: base64url.Encode(priv),
	}, "", "  ")
}

// LoadPrivateKeyFile loads an Ed25519 signing key from a JSON file.
func LoadPrivateKeyFile(path string) (*Keyset, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	var f PrivateKeyFile
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("private key file contains multiple JSON values")
		}
		return nil, err
	}
	if _, err := normalizeKID(f.KID); err != nil || f.PrivKeyB64 == "" {
		return nil, errors.New("invalid private key file")
	}
	priv, err := base64url.Decode(f.PrivKeyB64)
	if err != nil {
		return nil, err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key")
	}
	defer clear(priv)
	return New(f.KID, ed25519.PrivateKey(priv))
}
