package channelinit

import (
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	e2eev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/e2ee/v1"
)

func TestNewChannelInitValidations(t *testing.T) {
	svc := &Service{}
	if _, _, err := svc.NewChannelInit("ch"); err == nil {
		t.Fatalf("expected missing issuer")
	}

	ks, _ := issuer.NewRandom("kid")
	svc = &Service{Issuer: ks}
	if _, _, err := svc.NewChannelInit("ch"); err == nil {
		t.Fatalf("expected missing tunnel params")
	}

	svc.Params.TunnelURL = "ws://example"
	svc.Params.TunnelAudience = "aud"
	if _, _, err := svc.NewChannelInit(""); err == nil {
		t.Fatalf("expected missing channel_id")
	}
}

func TestNewChannelInitDefaultsAndTokenExp(t *testing.T) {
	ks, _ := issuer.NewRandom("kid")
	svc := &Service{Issuer: ks}
	svc.Params.TunnelURL = "ws://example"
	svc.Params.TunnelAudience = "aud"
	svc.Params.IssuerID = "iss"
	svc.Params.TokenExpSeconds = 9999

	client, _, err := svc.NewChannelInit("ch")
	if err != nil {
		t.Fatalf("NewChannelInit failed: %v", err)
	}
	if client.DefaultSuite == 0 {
		t.Fatalf("expected default suite")
	}
	if len(client.AllowedSuites) == 0 {
		t.Fatalf("expected allowed suites")
	}

	p, _, _, err := token.Parse(client.Token)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if p.Exp > p.InitExp {
		t.Fatalf("expected exp <= init_exp")
	}
}

func TestNewChannelInitDefaultSuiteFollowsAllowedSuites(t *testing.T) {
	ks, _ := issuer.NewRandom("kid")
	svc := &Service{Issuer: ks}
	svc.Params.TunnelURL = "ws://example"
	svc.Params.TunnelAudience = "aud"
	svc.Params.AllowedSuites = []e2eev1.Suite{e2eev1.Suite_P256_HKDF_SHA256_AES_256_GCM}
	svc.Params.DefaultSuite = 0

	client, server, err := svc.NewChannelInit("ch")
	if err != nil {
		t.Fatalf("NewChannelInit failed: %v", err)
	}
	if client.DefaultSuite != controlv1.Suite_P256_HKDF_SHA256_AES_256_GCM || server.DefaultSuite != controlv1.Suite_P256_HKDF_SHA256_AES_256_GCM {
		t.Fatalf("expected default suite to follow allowed suite, got client=%v server=%v", client.DefaultSuite, server.DefaultSuite)
	}
	if len(client.AllowedSuites) != 1 || client.AllowedSuites[0] != controlv1.Suite_P256_HKDF_SHA256_AES_256_GCM {
		t.Fatalf("expected allowed suites to contain P-256 only, got %v", client.AllowedSuites)
	}
}

func TestNewChannelInitRejectsDefaultSuiteNotAllowed(t *testing.T) {
	ks, _ := issuer.NewRandom("kid")
	svc := &Service{Issuer: ks}
	svc.Params.TunnelURL = "ws://example"
	svc.Params.TunnelAudience = "aud"
	svc.Params.AllowedSuites = []e2eev1.Suite{e2eev1.Suite_X25519_HKDF_SHA256_AES_256_GCM}
	svc.Params.DefaultSuite = e2eev1.Suite_P256_HKDF_SHA256_AES_256_GCM

	if _, _, err := svc.NewChannelInit("ch"); err == nil {
		t.Fatalf("expected default suite not allowed error")
	}
}

func TestReissueToken(t *testing.T) {
	svc := &Service{}
	if _, err := svc.ReissueToken(nil); err == nil {
		t.Fatalf("expected missing grant error")
	}

	ks, _ := issuer.NewRandom("kid")
	svc = &Service{
		Issuer: ks,
		Params: Params{TunnelURL: "ws://example", TunnelAudience: "aud", IssuerID: "iss"},
		Now:    func() time.Time { return time.Unix(10, 0) },
	}
	grant, _, err := svc.NewChannelInit("ch")
	if err != nil {
		t.Fatalf("NewChannelInit failed: %v", err)
	}
	updated, err := svc.ReissueToken(grant)
	if err != nil {
		t.Fatalf("ReissueToken failed: %v", err)
	}
	if updated.Token == grant.Token {
		t.Fatalf("expected token to change")
	}
	if updated.ChannelId != grant.ChannelId {
		t.Fatalf("expected channel_id to match")
	}
}
