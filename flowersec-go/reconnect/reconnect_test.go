package reconnect

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

func TestOnceSourceConsumesArtifactOnce(t *testing.T) {
	source := OnceSource(&protocolio.ConnectArtifact{V: 1})
	if _, err := source.Acquire(context.Background(), AcquireContext{}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Acquire(context.Background(), AcquireContext{}); err == nil {
		t.Fatal("expected consumed source error")
	}
}

func TestManagerRetriesRefreshableSourceAndConnects(t *testing.T) {
	var attempts atomic.Int32
	manager := NewManager()
	err := manager.Connect(context.Background(), Config{
		Source: RefreshableSource(func(context.Context, AcquireContext) (*protocolio.ConnectArtifact, error) {
			return &protocolio.ConnectArtifact{V: 1}, nil
		}),
		Reconnect: Settings{
			Enabled:      true,
			MaxAttempts:  3,
			InitialDelay: time.Nanosecond,
			MaxDelay:     time.Nanosecond,
			Factor:       1,
			JitterRatio:  0,
		},
		Connector: func(context.Context, *protocolio.ConnectArtifact, ...client.ConnectOption) (client.Client, error) {
			if attempts.Add(1) < 3 {
				return nil, errors.New("dial failed")
			}
			return fakeClient{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts=%d, want 3", attempts.Load())
	}
	if manager.State().Status != StatusConnected {
		t.Fatalf("state=%s, want connected", manager.State().Status)
	}
	manager.Disconnect()
}

func TestManagerStopsOnTerminalConnectError(t *testing.T) {
	var attempts atomic.Int32
	manager := NewManager()
	err := manager.Connect(context.Background(), Config{
		Source: RefreshableSource(func(context.Context, AcquireContext) (*protocolio.ConnectArtifact, error) {
			return &protocolio.ConnectArtifact{V: 1}, nil
		}),
		Reconnect: Settings{Enabled: true, MaxAttempts: 3, Factor: 1},
		Connector: func(context.Context, *protocolio.ConnectArtifact, ...client.ConnectOption) (client.Client, error) {
			attempts.Add(1)
			return nil, fserrors.Wrap(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidPSK, errors.New("bad psk"))
		},
	})
	if err == nil {
		t.Fatal("expected terminal error")
	}
	if attempts.Load() != 1 {
		t.Fatalf("attempts=%d, want 1", attempts.Load())
	}
}

func TestSettingsPreserveExplicitZeroDelayAndJitter(t *testing.T) {
	settings, err := (Settings{
		Enabled:      true,
		MaxAttempts:  3,
		InitialDelay: 0,
		MaxDelay:     0,
		Factor:       1,
		JitterRatio:  0,
	}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	if settings.InitialDelay != 0 || settings.MaxDelay != 0 || settings.JitterRatio != 0 {
		t.Fatalf("explicit zero reconnect values were replaced: %#v", settings)
	}
}

type fakeClient struct{}

func (fakeClient) Path() client.Path          { return client.PathDirect }
func (fakeClient) EndpointInstanceID() string { return "" }
func (fakeClient) RPC() *rpc.Client           { return nil }
func (fakeClient) OpenStream(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, errors.New("not implemented")
}
func (fakeClient) Ping() error                                          { return nil }
func (fakeClient) ProbeLiveness(context.Context) (time.Duration, error) { return 0, nil }
func (fakeClient) Close() error                                         { return nil }
