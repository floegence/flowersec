package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func newKeypair() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestSignRequiresKidAndAud(t *testing.T) {
	priv := newKeypair()
	_, err := Sign(priv, Payload{Aud: "aud", IdleTimeoutSeconds: 60})
	if err == nil || !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("expected invalid format for missing kid, got %v", err)
	}
	_, err = Sign(priv, Payload{Kid: "kid", IdleTimeoutSeconds: 60})
	if err == nil || !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("expected invalid format for missing aud, got %v", err)
	}
}

func TestParseRejectsInvalidInputs(t *testing.T) {
	if _, _, _, err := Parse("bad"); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("expected invalid format, got %v", err)
	}
	if _, _, _, err := Parse("FST2.notbase64.sig"); !errors.Is(err, ErrInvalidB64) {
		t.Fatalf("expected invalid base64, got %v", err)
	}

	payload := base64.RawStdEncoding.EncodeToString([]byte("not-json"))
	if _, _, _, err := Parse("FST2." + payload + ".sig"); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("expected invalid json, got %v", err)
	}
}

func TestVerifyRejectsAudienceIssuerAndTime(t *testing.T) {
	priv := newKeypair()
	pub := priv.Public().(ed25519.PublicKey)
	base := Payload{
		Kid:                "kid",
		Aud:                "aud",
		Iss:                "iss",
		ChannelID:          "ch",
		Role:               1,
		TokenID:            "tid",
		InitExp:            100,
		IdleTimeoutSeconds: 60,
		Iat:                10,
		Exp:                50,
	}
	good, err := Sign(priv, base)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if _, err := Verify(good, StaticKeyset{"kid": pub}, VerifyOptions{Now: time.Unix(20, 0), Audience: "nope"}); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("expected invalid audience, got %v", err)
	}
	if _, err := Verify(good, StaticKeyset{"kid": pub}, VerifyOptions{Now: time.Unix(20, 0), Issuer: "nope"}); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected invalid issuer, got %v", err)
	}

	expired := base
	expired.Exp = 5
	expiredToken, _ := Sign(priv, expired)
	if _, err := Verify(expiredToken, StaticKeyset{"kid": pub}, VerifyOptions{Now: time.Unix(20, 0)}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired, got %v", err)
	}

	future := base
	future.Iat = 999
	futureToken, _ := Sign(priv, future)
	if _, err := Verify(futureToken, StaticKeyset{"kid": pub}, VerifyOptions{Now: time.Unix(20, 0)}); !errors.Is(err, ErrIATInFuture) {
		t.Fatalf("expected iat in future, got %v", err)
	}

	initExpired := base
	initExpired.InitExp = 1
	initExpiredToken, _ := Sign(priv, initExpired)
	if _, err := Verify(initExpiredToken, StaticKeyset{"kid": pub}, VerifyOptions{Now: time.Unix(20, 0)}); !errors.Is(err, ErrInitExpired) {
		t.Fatalf("expected init expired, got %v", err)
	}

	badExp := base
	badExp.Exp = 200
	badExp.InitExp = 100
	badExpToken, _ := Sign(priv, badExp)
	if _, err := Verify(badExpToken, StaticKeyset{"kid": pub}, VerifyOptions{Now: time.Unix(20, 0)}); !errors.Is(err, ErrExpAfterInit) {
		t.Fatalf("expected exp after init, got %v", err)
	}
}

func TestEqualSignedPart(t *testing.T) {
	priv := newKeypair()
	p := Payload{Kid: "kid", Aud: "aud", ChannelID: "ch", Role: 1, TokenID: "id", InitExp: 100, IdleTimeoutSeconds: 60, Iat: 10, Exp: 50}
	t1, _ := Sign(priv, p)
	t2, _ := Sign(priv, p)
	if !EqualSignedPart(t1, t2) {
		t.Fatalf("expected signed parts to match")
	}
	if EqualSignedPart("bad", t2) {
		t.Fatalf("expected invalid format to return false")
	}
}
