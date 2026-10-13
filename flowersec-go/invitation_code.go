package flowersec

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
)

var invitationEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// ErrInvalidInvitationCode is redacted; it never includes caller input.
var ErrInvalidInvitationCode = errors.New("invalid Flowersec invitation code")

// InvitationCode is an opaque 128-bit, high-entropy enrollment credential.
// Text is its intentional delivery boundary. Ordinary representations redact it.
type InvitationCode struct{ secret [16]byte }

func (InvitationCode) String() string               { return "Flowersec.InvitationCode" }
func (InvitationCode) GoString() string             { return "Flowersec.InvitationCode" }
func (InvitationCode) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// NewInvitationCode generates a fresh cryptographically random credential.
func NewInvitationCode() (InvitationCode, error) {
	var code InvitationCode
	if _, err := rand.Read(code.secret[:]); err != nil {
		return InvitationCode{}, ErrInvalidInvitationCode
	}
	return code, nil
}

// DeriveInvitationCode recovers one pseudorandom credential from a stable secret
// and a unique issuance identifier. The application owns both issuance records
// and the secret; the SDK does not persist or consume invitations.
func DeriveInvitationCode(secret []byte, identifier string) (InvitationCode, error) {
	if len(secret) < 32 || len(identifier) == 0 || len(identifier) > 256 {
		return InvitationCode{}, ErrInvalidInvitationCode
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("flowersec.invitation-code/1\x00" + identifier))
	var code InvitationCode
	copy(code.secret[:], mac.Sum(nil))
	return code, nil
}

// ParseInvitationCode accepts ASCII whitespace, display hyphens and either case.
// Ambiguous characters and non-canonical padding bits are rejected.
func ParseInvitationCode(value string) (InvitationCode, error) {
	if len(value) > 128 {
		return InvitationCode{}, ErrInvalidInvitationCode
	}
	clean := strings.ToUpper(strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, value))
	if len(clean) != 26 {
		return InvitationCode{}, ErrInvalidInvitationCode
	}
	raw, err := invitationEncoding.DecodeString(clean)
	if err != nil || len(raw) != 16 || invitationEncoding.EncodeToString(raw) != clean {
		return InvitationCode{}, ErrInvalidInvitationCode
	}
	var code InvitationCode
	copy(code.secret[:], raw)
	if !code.valid() {
		return InvitationCode{}, ErrInvalidInvitationCode
	}
	return code, nil
}

// Text intentionally exports the code for administrator delivery or user entry.
func (c InvitationCode) Text() string { return invitationEncoding.EncodeToString(c.secret[:]) }

// LookupID is a public, domain-separated locator, not an authorization proof.
func (c InvitationCode) LookupID() string {
	digest := sha256.Sum256(append([]byte("flowersec.invitation-lookup/1\x00"), c.secret[:]...))
	return hex.EncodeToString(digest[:])
}

func (c InvitationCode) valid() bool { return c.secret != [16]byte{} }

func (c InvitationCode) handshakeKey() []byte {
	digest := sha256.Sum256(append([]byte("flowersec.invitation-noise/1\x00"), c.secret[:]...))
	return digest[:]
}
