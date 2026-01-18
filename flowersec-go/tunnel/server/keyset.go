package server

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
)

type IssuerKeyset struct {
	mu   sync.RWMutex                 // Guards keys map.
	keys map[string]ed25519.PublicKey // Public keys by key ID.
}

// LoadIssuerKeysetFile loads a JSON keyset exported by the issuer.
func LoadIssuerKeysetFile(path string) (*IssuerKeyset, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f issuer.TunnelKeysetFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if len(f.Keys) == 0 {
		return nil, errors.New("empty keyset file")
	}
	keys := make(map[string]ed25519.PublicKey, len(f.Keys))
	for _, k := range f.Keys {
		if k.KID == "" || k.PubKeyB64 == "" {
			return nil, errors.New("invalid key entry")
		}
		pub, err := base64url.Decode(k.PubKeyB64)
		if err != nil {
			return nil, err
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("invalid pubkey size")
		}
		keys[k.KID] = ed25519.PublicKey(pub)
	}
	return &IssuerKeyset{keys: keys}, nil
}

// Lookup returns the public key for a given kid.
func (k *IssuerKeyset) Lookup(kid string) (ed25519.PublicKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	v, ok := k.keys[kid]
	return v, ok
}

// Replace swaps the entire keyset atomically.
func (k *IssuerKeyset) Replace(newKeys map[string]ed25519.PublicKey) {
	k.mu.Lock()
	k.keys = newKeys
	k.mu.Unlock()
}
