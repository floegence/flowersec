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
	} = (*fs.QUICCarrierFactory)(nil)
	_ interface {
		Accept(context.Context, fs.AcceptedEntranceConfig) (*fs.QUICIngress, error)
		Address() netip.AddrPort
		Close() error
		WaitCleanup(context.Context) error
	} = (*fs.QUICServer)(nil)
	_ interface {
		AcceptQUIC(context.Context, *fs.QUICIngress, fs.QUICAcceptOptions) (*fs.Session, error)
	} = (*fs.ServeHandle)(nil)
)

func TestPublicQUICRequiresOriginalConstruction(t *testing.T) {
	limits := fs.DefaultQUICLimits()
	if err := limits.Validate(); err != nil {
		t.Fatal(err)
	}
	provider := fs.QUICProviderOptions{Limits: limits, StreamSlots: 258, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	config := fs.QUICFactoryConfig{Options: provider}
	if _, err := fs.QUICCarrierFactoryCharge(config); err == nil {
		t.Fatal("factory accepted missing original scope and route")
	}
	if result, err := fs.NewQUICCarrierFactory(config, fs.ResourceReference{}, fs.ResourceReference{}); result != nil || err == nil {
		t.Fatal("factory constructed without admitted owners", err)
	}
	serverConfig := fs.QUICServerConfig{Connection: provider}
	if result, err := fs.NewQUICServer(serverConfig, fs.ResourceReference{}, fs.ResourceReference{}); result != nil || err == nil {
		t.Fatal("server constructed without admitted owners", err)
	}
	server := new(fs.QUICServer)
	ctx := context.Background()
	if ingress, err := server.Accept(ctx, fs.AcceptedEntranceConfig{}); ingress != nil || err == nil {
		t.Fatal("detached server manufactured ingress", err)
	}
	if result, err := new(fs.ServeHandle).AcceptQUIC(ctx, new(fs.QUICIngress), fs.QUICAcceptOptions{}); result != nil || err == nil {
		t.Fatal("detached ingress manufactured Session", err)
	}
}
