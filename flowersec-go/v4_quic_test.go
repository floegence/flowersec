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
	} = (*fs.V4QUICCarrierFactory)(nil)
	_ interface {
		Accept(context.Context, fs.V4AcceptedEntranceConfig) (*fs.V4QUICIngress, error)
		Address() netip.AddrPort
		Close() error
		WaitCleanup(context.Context) error
	} = (*fs.V4QUICServer)(nil)
	_ interface {
		AcceptQUIC(context.Context, *fs.V4QUICIngress, fs.V4QUICAcceptOptions) (*fs.V4Session, error)
	} = (*fs.ServeHandle)(nil)
)

func TestV4PublicQUICRequiresOriginalConstruction(t *testing.T) {
	limits := fs.DefaultV4QUICLimits()
	if err := limits.Validate(); err != nil {
		t.Fatal(err)
	}
	provider := fs.V4QUICProviderOptions{Limits: limits, StreamSlots: 258, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	config := fs.V4QUICFactoryConfig{Options: provider}
	if _, err := fs.V4QUICCarrierFactoryCharge(config); err == nil {
		t.Fatal("factory accepted missing original scope and route")
	}
	if result, err := fs.NewV4QUICCarrierFactory(config, fs.V4ResourceReference{}, fs.V4ResourceReference{}); result != nil || err == nil {
		t.Fatal("factory constructed without admitted owners", err)
	}
	serverConfig := fs.V4QUICServerConfig{Connection: provider}
	if result, err := fs.NewV4QUICServer(serverConfig, fs.V4ResourceReference{}, fs.V4ResourceReference{}); result != nil || err == nil {
		t.Fatal("server constructed without admitted owners", err)
	}
	server := new(fs.V4QUICServer)
	ctx := context.Background()
	if ingress, err := server.Accept(ctx, fs.V4AcceptedEntranceConfig{}); ingress != nil || err == nil {
		t.Fatal("detached server manufactured ingress", err)
	}
	if result, err := new(fs.ServeHandle).AcceptQUIC(ctx, new(fs.V4QUICIngress), fs.V4QUICAcceptOptions{}); result != nil || err == nil {
		t.Fatal("detached ingress manufactured Session", err)
	}
}
