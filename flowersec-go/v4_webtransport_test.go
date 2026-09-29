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
		PrepareCarrier(context.Context, fs.V4CarrierPreparationRequest) (*fs.V4PreparedCarrier, error)
		Close()
		WaitCleanup(context.Context) error
	} = (*fs.V4WebTransportCarrierFactory)(nil)
	_ interface {
		Accept(context.Context, fs.V4AcceptedEntranceConfig) (*fs.V4WebTransportIngress, error)
		Address() netip.AddrPort
		Close() error
		WaitCleanup(context.Context) error
	} = (*fs.V4WebTransportServer)(nil)
	_ interface {
		AcceptWebTransport(context.Context, *fs.V4WebTransportIngress, fs.V4WebTransportAcceptOptions) (*fs.V4Session, error)
	} = (*fs.ServeHandle)(nil)
)

func TestV4PublicWebTransportRequiresOriginalConstruction(t *testing.T) {
	limits := fs.DefaultV4WebTransportLimits()
	if err := limits.Validate(); err != nil {
		t.Fatal(err)
	}
	provider := fs.V4WebTransportProviderOptions{Limits: limits, StreamSlots: 258, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	config := fs.V4WebTransportFactoryConfig{Options: provider}
	if _, err := fs.V4WebTransportCarrierFactoryCharge(config); err == nil {
		t.Fatal("factory accepted missing original scope and route")
	}
	if result, err := fs.NewV4WebTransportCarrierFactory(config, fs.V4ResourceReference{}, fs.V4ResourceReference{}); result != nil || err == nil {
		t.Fatal("factory constructed without admitted owners", err)
	}
	serverConfig := fs.V4WebTransportServerConfig{Connection: provider}
	if result, err := fs.NewV4WebTransportServer(serverConfig, fs.V4ResourceReference{}, fs.V4ResourceReference{}); result != nil || err == nil {
		t.Fatal("server constructed without admitted owners", err)
	}
	server := new(fs.V4WebTransportServer)
	ctx := context.Background()
	if ingress, err := server.Accept(ctx, fs.V4AcceptedEntranceConfig{}); ingress != nil || err == nil {
		t.Fatal("detached server manufactured ingress", err)
	}
	if result, err := new(fs.ServeHandle).AcceptWebTransport(ctx, new(fs.V4WebTransportIngress), fs.V4WebTransportAcceptOptions{}); result != nil || err == nil {
		t.Fatal("detached ingress manufactured Session", err)
	}
}
