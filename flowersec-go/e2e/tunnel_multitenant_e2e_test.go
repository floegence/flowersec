package e2e_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
)

func TestE2E_TunnelSharedURLSupportsMultipleTenants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tenantA := newTenantIssuerFixture(t, "tenant-a", "flowersec-tunnel:tenant-a", "issuer-tenant-a", 1)
	tenantB := newTenantIssuerFixture(t, "tenant-b", "flowersec-tunnel:tenant-b", "issuer-tenant-b", 64)

	verifier, err := server.NewMultiTenantVerifier(writeTenantsFile(t, []tenantIssuerFixture{tenantA, tenantB}))
	if err != nil {
		t.Fatal(err)
	}

	fixture := newTunnelE2EFixture(t, server.Config{
		Path:            server.DefaultConfig().Path,
		Verifier:        verifier,
		AllowedOrigins:  []string{tunnelOrigin},
		CleanupInterval: 20 * time.Millisecond,
	})

	cases := []struct {
		name    string
		tenant  tenantIssuerFixture
		channel string
	}{
		{name: "tenant-a", tenant: tenantA, channel: "ch_mt_a"},
		{name: "tenant-b", tenant: tenantB, channel: "ch_mt_b"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			grantC, grantS := tc.tenant.newGrantPair(t, fixture.wsURL, tc.channel, 5)

			got := runTunnelRPCOnce(ctx, t, grantC, grantS)
			if got != `{"ok":true}` {
				t.Fatalf("unexpected rpc response payload: %s", got)
			}

			fixture.waitForChannelCount(0, 2*time.Second)
		})
	}
}

func TestE2E_TunnelSharedURLRejectsUnknownTenantScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tenantA := newTenantIssuerFixture(t, "tenant-a", "flowersec-tunnel:tenant-a", "issuer-tenant-a", 1)
	unknownTenant := newTenantIssuerFixture(t, "tenant-missing", "flowersec-tunnel:missing", "issuer-missing", 96)

	verifier, err := server.NewMultiTenantVerifier(writeTenantsFile(t, []tenantIssuerFixture{tenantA}))
	if err != nil {
		t.Fatal(err)
	}

	fixture := newTunnelE2EFixture(t, server.Config{
		Path:            server.DefaultConfig().Path,
		Verifier:        verifier,
		AllowedOrigins:  []string{tunnelOrigin},
		CleanupInterval: 20 * time.Millisecond,
	})

	grantC, _ := unknownTenant.newGrantPair(t, fixture.wsURL, "ch_mt_reject", 5)

	_, err = client.ConnectTunnel(ctx, grantC, client.WithOrigin(tunnelOrigin), client.WithKeepaliveInterval(0))
	if err == nil {
		t.Fatal("expected attach rejection for unknown tenant scope")
	}

	var fe *fserrors.Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *fserrors.Error, got %T: %v", err, err)
	}
	if fe.Path != fserrors.PathTunnel || fe.Stage != fserrors.StageAttach || fe.Code != fserrors.CodeInvalidToken {
		t.Fatalf("expected tunnel attach invalid_token, got path=%q stage=%q code=%q err=%v", fe.Path, fe.Stage, fe.Code, fe.Err)
	}

	fixture.waitForChannelCount(0, 500*time.Millisecond)
}
