package issuer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
)

type Keyset struct {
	mu               sync.RWMutex                 // Guards key rotation and access.
	activeKID        string                       // Active key ID for signing.
	activePrivate    ed25519.PrivateKey           // Active private key for signing.
	verificationKeys map[string]ed25519.PublicKey // Published public keys accepted by tunnel servers.
}

// New loads a keyset from an existing Ed25519 private key.
func New(kid string, priv ed25519.PrivateKey) (*Keyset, error) {
	normalizedKID, err := normalizeKID(kid)
	if err != nil {
		return nil, err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key")
	}
	privateCopy := clonePrivateKey(priv)
	publicCopy := clonePublicKey(privateCopy.Public().(ed25519.PublicKey))
	return &Keyset{
		activeKID:        normalizedKID,
		activePrivate:    privateCopy,
		verificationKeys: map[string]ed25519.PublicKey{normalizedKID: publicCopy},
	}, nil
}

// NewRandom generates a random Ed25519 keypair for signing tokens.
func NewRandom(kid string) (*Keyset, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(priv)
	return New(kid, priv)
}

// CurrentKID returns the active key ID for signing.
func (k *Keyset) CurrentKID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.activeKID
}

// PublicKeys returns a deep-copy snapshot of all published verification keys.
func (k *Keyset) PublicKeys() map[string]ed25519.PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	keys := make(map[string]ed25519.PublicKey, len(k.verificationKeys))
	for kid, publicKey := range k.verificationKeys {
		keys[kid] = clonePublicKey(publicKey)
	}
	return keys
}

// SignToken signs a control-plane token with the current key.
func (k *Keyset) SignToken(p token.Payload) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	p.Kid = k.activeKID
	return token.Sign(k.activePrivate, p)
}

// AddVerificationKey publishes a verification key before it becomes active.
// Re-publishing the same key is idempotent; binding a different key to the same KID fails.
func (k *Keyset) AddVerificationKey(kid string, publicKey ed25519.PublicKey) error {
	normalizedKID, err := normalizeKID(kid)
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key")
	}
	publicCopy := clonePublicKey(publicKey)
	k.mu.Lock()
	defer k.mu.Unlock()
	if existing, ok := k.verificationKeys[normalizedKID]; ok {
		if !bytes.Equal(existing, publicCopy) {
			return errors.New("verification key conflicts with existing kid")
		}
		return nil
	}
	k.verificationKeys[normalizedKID] = publicCopy
	return nil
}

// Rotate activates a private key whose matching public key was already published.
func (k *Keyset) Rotate(newKID string, newPrivate ed25519.PrivateKey) error {
	normalizedKID, err := normalizeKID(newKID)
	if err != nil {
		return err
	}
	if len(newPrivate) != ed25519.PrivateKeySize {
		return errors.New("invalid ed25519 private key")
	}
	privateCopy := clonePrivateKey(newPrivate)
	publicKey := privateCopy.Public().(ed25519.PublicKey)
	k.mu.Lock()
	defer k.mu.Unlock()
	published, ok := k.verificationKeys[normalizedKID]
	if !ok {
		clear(privateCopy)
		return errors.New("verification key must be published before rotation")
	}
	if !bytes.Equal(published, publicKey) {
		clear(privateCopy)
		return errors.New("private key does not match published verification key")
	}
	oldPrivate := k.activePrivate
	k.activeKID = normalizedKID
	k.activePrivate = privateCopy
	clear(oldPrivate)
	return nil
}

// RetireVerificationKey removes a non-active verification key.
func (k *Keyset) RetireVerificationKey(kid string) error {
	normalizedKID, err := normalizeKID(kid)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if normalizedKID == k.activeKID {
		return errors.New("active verification key cannot be retired")
	}
	if _, ok := k.verificationKeys[normalizedKID]; !ok {
		return errors.New("verification key not found")
	}
	delete(k.verificationKeys, normalizedKID)
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
	publicKeys := k.PublicKeys()
	kids := make([]string, 0, len(publicKeys))
	for kid := range publicKeys {
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	keys := make([]TunnelKey, 0, len(kids))
	for _, kid := range kids {
		keys = append(keys, TunnelKey{
			KID:       kid,
			PubKeyB64: base64url.Encode(publicKeys[kid]),
		})
	}
	return json.MarshalIndent(TunnelKeysetFile{Keys: keys}, "", "  ")
}

func normalizeKID(kid string) (string, error) {
	normalized := strings.TrimSpace(kid)
	if normalized == "" {
		return "", errors.New("invalid kid")
	}
	return normalized, nil
}

func clonePrivateKey(privateKey ed25519.PrivateKey) ed25519.PrivateKey {
	return ed25519.PrivateKey(bytes.Clone(privateKey))
}

func clonePublicKey(publicKey ed25519.PublicKey) ed25519.PublicKey {
	return ed25519.PublicKey(bytes.Clone(publicKey))
}
