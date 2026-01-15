package token

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/flowersec/flowersec/internal/base64url"
)

const Prefix = "FST1"

type Payload struct {
	Kid       string `json:"kid"`
	Aud       string `json:"aud"`
	Iss       string `json:"iss,omitempty"`
	ChannelID string `json:"channel_id"`
	Role      uint8  `json:"role"`
	TokenID   string `json:"token_id"`
	InitExp   int64  `json:"init_exp"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
}

var (
	ErrInvalidFormat   = errors.New("token invalid format")
	ErrInvalidB64      = errors.New("token invalid base64url")
	ErrInvalidJSON     = errors.New("token invalid json")
	ErrUnknownKID      = errors.New("token unknown kid")
	ErrInvalidSig      = errors.New("token invalid signature")
	ErrInvalidAudience = errors.New("token invalid audience")
	ErrInvalidIssuer   = errors.New("token invalid issuer")
	ErrExpired         = errors.New("token expired")
	ErrIATInFuture     = errors.New("token iat in future")
	ErrInitExpired     = errors.New("token init window expired")
	ErrExpAfterInit    = errors.New("token exp > init_exp")
)

type KeyLookup interface {
	Lookup(kid string) (ed25519.PublicKey, bool)
}

type VerifyOptions struct {
	Now       time.Time
	Audience  string
	Issuer    string
	ClockSkew time.Duration
}

func Sign(priv ed25519.PrivateKey, payload Payload) (string, error) {
	if strings.TrimSpace(payload.Kid) == "" {
		return "", fmt.Errorf("missing kid: %w", ErrInvalidFormat)
	}
	if strings.TrimSpace(payload.Aud) == "" {
		return "", fmt.Errorf("missing aud: %w", ErrInvalidFormat)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64u := base64url.Encode(b)
	signed := Prefix + "." + payloadB64u
	sig := ed25519.Sign(priv, []byte(signed))
	return signed + "." + base64url.Encode(sig), nil
}

func Parse(token string) (payload Payload, signed []byte, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != Prefix {
		return Payload{}, nil, nil, ErrInvalidFormat
	}
	payloadBytes, err := base64url.Decode(parts[1])
	if err != nil {
		return Payload{}, nil, nil, ErrInvalidB64
	}
	sigBytes, err := base64url.Decode(parts[2])
	if err != nil {
		return Payload{}, nil, nil, ErrInvalidB64
	}
	var p Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return Payload{}, nil, nil, ErrInvalidJSON
	}
	signedData := []byte(Prefix + "." + parts[1])
	return p, signedData, sigBytes, nil
}

func Verify(tokenStr string, keys KeyLookup, opts VerifyOptions) (Payload, error) {
	p, signed, sig, err := Parse(tokenStr)
	if err != nil {
		return Payload{}, err
	}
	pub, ok := keys.Lookup(p.Kid)
	if !ok {
		return Payload{}, ErrUnknownKID
	}
	if !ed25519.Verify(pub, signed, sig) {
		return Payload{}, ErrInvalidSig
	}
	if opts.Audience != "" && subtle.ConstantTimeCompare([]byte(p.Aud), []byte(opts.Audience)) != 1 {
		return Payload{}, ErrInvalidAudience
	}
	if opts.Issuer != "" && subtle.ConstantTimeCompare([]byte(p.Iss), []byte(opts.Issuer)) != 1 {
		return Payload{}, ErrInvalidIssuer
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opts.ClockSkew
	if skew < 0 {
		skew = 0
	}

	iat := time.Unix(p.Iat, 0)
	exp := time.Unix(p.Exp, 0)
	initExp := time.Unix(p.InitExp, 0)

	if iat.After(now.Add(skew)) {
		return Payload{}, ErrIATInFuture
	}
	if exp.Before(now.Add(-skew)) {
		return Payload{}, ErrExpired
	}
	if initExp.Before(now.Add(-skew)) {
		return Payload{}, ErrInitExpired
	}
	if p.Exp > p.InitExp {
		return Payload{}, ErrExpAfterInit
	}

	return p, nil
}

type StaticKeyset map[string]ed25519.PublicKey

func (s StaticKeyset) Lookup(kid string) (ed25519.PublicKey, bool) {
	k, ok := s[kid]
	return k, ok
}

func EqualSignedPart(a, b string) bool {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	if len(pa) != 3 || len(pb) != 3 {
		return false
	}
	return bytes.Equal([]byte(pa[0]+"."+pa[1]), []byte(pb[0]+"."+pb[1]))
}
