package token

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func FuzzParseAndVerify(f *testing.F) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	now := time.Unix(1_700_000_000, 0)
	valid, err := Sign(priv, Payload{
		Kid:                "kid_1",
		Aud:                "aud_1",
		Iss:                "iss_1",
		ChannelID:          "ch_1",
		Role:               1,
		TokenID:            "tid_1",
		InitExp:            now.Add(120 * time.Second).Unix(),
		IdleTimeoutSeconds: 60,
		Iat:                now.Unix(),
		Exp:                now.Add(60 * time.Second).Unix(),
	})
	if err != nil {
		f.Fatalf("sign seed token: %v", err)
	}

	f.Add(valid)
	f.Add("not a token")
	f.Add("FST2..")

	keys := StaticKeyset{"kid_1": pub}
	opts := VerifyOptions{Now: now, Audience: "aud_1", Issuer: "iss_1"}

	f.Fuzz(func(t *testing.T, tokenStr string) {
		_, _, _, _ = Parse(tokenStr)
		_, _ = Verify(tokenStr, keys, opts)
	})
}
