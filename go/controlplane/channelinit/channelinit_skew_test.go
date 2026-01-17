package channelinit

import (
	"testing"
	"time"

	"github.com/floegence/flowersec/controlplane/issuer"
	controlv1 "github.com/floegence/flowersec/gen/flowersec/controlplane/v1"
)

func TestReissueTokenRoundsSkewToWholeSeconds(t *testing.T) {
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("NewRandom failed: %v", err)
	}

	initExp := int64(100)
	s := &Service{
		Issuer: ks,
		Params: Params{
			TunnelURL:       "ws://127.0.0.1:8080/ws",
			TunnelAudience:  "aud",
			IssuerID:        "issuer",
			TokenExpSeconds: 60,
			ClockSkew:       1500 * time.Millisecond,
		},
	}

	grant := &controlv1.ChannelInitGrant{
		TunnelUrl:                s.Params.TunnelURL,
		ChannelId:                "ch",
		ChannelInitExpireAtUnixS: initExp,
		Role:                     controlv1.Role_client,
	}

	s.Now = func() time.Time { return time.Unix(initExp+2, 0) }
	out, err := s.ReissueToken(grant)
	if err != nil {
		t.Fatalf("ReissueToken failed: %v", err)
	}
	if out.Token == "" {
		t.Fatalf("expected token to be set")
	}

	s.Now = func() time.Time { return time.Unix(initExp+3, 0) }
	if _, err := s.ReissueToken(grant); err == nil {
		t.Fatalf("expected ErrChannelInitExpired")
	}
}
