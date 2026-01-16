package channelinit

import (
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/controlplane/issuer"
)

func TestReissueTokenRejectsExpiredGrant(t *testing.T) {
	keys, err := issuer.NewRandom("kid-1")
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	now := time.Unix(1000, 0)
	svc := &Service{
		Issuer: keys,
		Params: Params{
			TunnelURL:      "wss://example.test/ws",
			TunnelAudience: "aud",
		},
		Now: func() time.Time { return now },
	}
	grant, _, err := svc.NewChannelInit("ch_1")
	if err != nil {
		t.Fatalf("new channel init: %v", err)
	}
	grant.ChannelInitExpireAtUnixS = now.Add(-time.Second).Unix()
	_, err = svc.ReissueToken(grant)
	if !errors.Is(err, ErrChannelInitExpired) {
		t.Fatalf("expected ErrChannelInitExpired, got %v", err)
	}
}
