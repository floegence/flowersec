package flowersec_test

import (
	"context"
	"net/netip"
	"testing"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

// These signatures remain usable without naming an internal package. Actual
// native composition, admission scope and cleanup are exercised by assemblyv4.
var (
	_ interface {
		PrepareCarrier(context.Context, fs.CarrierPreparationRequest) (*fs.PreparedCarrier, error)
		Close()
		WaitCleanup(context.Context) error
	} = (*fs.WebTransportCarrierFactory)(nil)
	_ interface {
		Accept(context.Context, fs.AcceptedEntranceConfig) (*fs.WebTransportIngress, error)
		Address() netip.AddrPort
		Close() error
		WaitCleanup(context.Context) error
	} = (*fs.WebTransportServer)(nil)
	_ interface {
		AcceptWebTransport(context.Context, *fs.WebTransportIngress, fs.WebTransportAcceptOptions) (*fs.Session, error)
	} = (*fs.ServeHandle)(nil)
)

func TestPublicWebTransportRequiresOriginalConstruction(t *testing.T) {
	limits := fs.DefaultWebTransportLimits()
	if err := limits.Validate(); err != nil {
		t.Fatal(err)
	}
	provider := fs.WebTransportProviderOptions{Limits: limits, StreamSlots: 258, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	config := fs.WebTransportFactoryConfig{Options: provider}
	if _, err := fs.WebTransportCarrierFactoryCharge(config); err == nil {
		t.Fatal("factory accepted missing original scope and route")
	}
	if result, err := fs.NewWebTransportCarrierFactory(config, fs.ResourceReference{}, fs.ResourceReference{}); result != nil || err == nil {
		t.Fatal("factory constructed without admitted owners", err)
	}
	serverConfig := fs.WebTransportServerConfig{Connection: provider}
	if result, err := fs.NewWebTransportServer(serverConfig, fs.ResourceReference{}, fs.ResourceReference{}); result != nil || err == nil {
		t.Fatal("server constructed without admitted owners", err)
	}
	server := new(fs.WebTransportServer)
	ctx := context.Background()
	if ingress, err := server.Accept(ctx, fs.AcceptedEntranceConfig{}); ingress != nil || err == nil {
		t.Fatal("detached server manufactured ingress", err)
	}
	if result, err := new(fs.ServeHandle).AcceptWebTransport(ctx, new(fs.WebTransportIngress), fs.WebTransportAcceptOptions{}); result != nil || err == nil {
		t.Fatal("detached ingress manufactured Session", err)
	}
}
