package issuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"

	"github.com/floegence/flowersec/controlplane/token"
	"github.com/floegence/flowersec/internal/base64url"
)

type Keyset struct {
	mu   sync.RWMutex       // Guards key rotation and access.
	kid  string             // Active key ID for signing.
	priv ed25519.PrivateKey // Active private key for signing.
}

// New loads a keyset from an existing Ed25519 private key.
func New(kid string, priv ed25519.PrivateKey) (*Keyset, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key")
	}
	return &Keyset{kid: kid, priv: priv}, nil
}

// NewRandom generates a random Ed25519 keypair for signing tokens.
func NewRandom(kid string) (*Keyset, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return New(kid, priv)
}

// CurrentKID returns the active key ID for signing.
func (k *Keyset) CurrentKID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.kid
}

// PublicKeys returns a snapshot of the current public key(s).
func (k *Keyset) PublicKeys() map[string]ed25519.PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	pub := k.priv.Public().(ed25519.PublicKey)
	return map[string]ed25519.PublicKey{k.kid: pub}
}

// SignToken signs a control-plane token with the current key.
func (k *Keyset) SignToken(p token.Payload) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	p.Kid = k.kid
	return token.Sign(k.priv, p)
}

// Rotate replaces the active signing key and key ID.
func (k *Keyset) Rotate(newKid string, newPriv ed25519.PrivateKey) error {
	if len(newPriv) != ed25519.PrivateKeySize {
		return errors.New("invalid ed25519 private key")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.kid = newKid
	k.priv = newPriv
	return nil
}

// TunnelKeysetFile matches the JSON layout consumed by the tunnel server.
type TunnelKeysetFile struct {
	Keys []TunnelKey `json:"keys"` // Exported public keys for tunnel servers.
}

// TunnelKey is the exported public key entry for a tunnel server.
type TunnelKey struct {
	KID       string `json:"kid"`         // Key ID.
	PubKeyB64 string `json:"pubkey_b64u"` // Base64url-encoded Ed25519 public key.
}

// ExportTunnelKeyset serializes the public keyset for tunnel servers.
func (k *Keyset) ExportTunnelKeyset() ([]byte, error) {
	keys := make([]TunnelKey, 0, 1)
	for kid, pub := range k.PublicKeys() {
		keys = append(keys, TunnelKey{
			KID:       kid,
			PubKeyB64: base64url.Encode(pub),
		})
	}
	return json.MarshalIndent(TunnelKeysetFile{Keys: keys}, "", "  ")
}
