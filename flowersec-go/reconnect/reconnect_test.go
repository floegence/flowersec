package reconnect

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	fsyamux "github.com/floegence/flowersec/flowersec-go/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	fsstream "github.com/floegence/flowersec/flowersec-go/stream"
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
	if err := manager.Disconnect(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerDisconnectReportsClientCloseFailure(t *testing.T) {
	closeErr := errors.New("close failed")
	manager := NewManager()
	if err := manager.Connect(context.Background(), Config{
		Source: OnceSource(&protocolio.ConnectArtifact{V: 1}),
		Connector: func(context.Context, *protocolio.ConnectArtifact, ...client.ConnectOption) (client.Client, error) {
			return fakeClient{closeErr: closeErr}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Disconnect(); !errors.Is(err, closeErr) {
		t.Fatalf("Disconnect() error = %v, want %v", err, closeErr)
	}
	state := manager.State()
	if state.Status != StatusError || !errors.Is(state.Error, closeErr) {
		t.Fatalf("state = %#v, want close failure", state)
	}
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

func TestTerminalConnectCodesMatchRegistry(t *testing.T) {
	var registry struct {
		TerminalCodes []string `json:"reconnect_terminal_codes"`
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "stability", "connect_error_code_registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	actual := make([]string, 0, len(terminalConnectCodes))
	for code := range terminalConnectCodes {
		actual = append(actual, string(code))
	}
	slices.Sort(actual)
	slices.Sort(registry.TerminalCodes)
	if !slices.Equal(actual, registry.TerminalCodes) {
		t.Fatalf("terminal codes = %v, registry = %v", actual, registry.TerminalCodes)
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

func TestManagerWaitsBeforeReconnectAfterTermination(t *testing.T) {
	var acquisitions atomic.Int32
	firstClient, terminate := newTerminatingFakeClient(t)
	manager := NewManager()
	err := manager.Connect(context.Background(), Config{
		Source: RefreshableSource(func(context.Context, AcquireContext) (*protocolio.ConnectArtifact, error) {
			acquisitions.Add(1)
			return &protocolio.ConnectArtifact{V: 1}, nil
		}),
		Reconnect: Settings{
			Enabled: true, MaxAttempts: 3, InitialDelay: 120 * time.Millisecond,
			MaxDelay: 120 * time.Millisecond, Factor: 1,
		},
		Connector: func(context.Context, *protocolio.ConnectArtifact, ...client.ConnectOption) (client.Client, error) {
			if acquisitions.Load() == 1 {
				return firstClient, nil
			}
			return fakeClient{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	terminate()
	waitForState(t, manager, StatusConnecting)
	time.Sleep(40 * time.Millisecond)
	if got := acquisitions.Load(); got != 1 {
		t.Fatalf("artifact acquired before backoff elapsed: %d", got)
	}
	deadline := time.Now().Add(time.Second)
	for acquisitions.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := acquisitions.Load(); got != 2 {
		t.Fatalf("acquisitions = %d, want 2", got)
	}
	if err := manager.Disconnect(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerDisconnectCancelsTerminationBackoff(t *testing.T) {
	var acquisitions atomic.Int32
	firstClient, terminate := newTerminatingFakeClient(t)
	manager := NewManager()
	if err := manager.Connect(context.Background(), Config{
		Source: RefreshableSource(func(context.Context, AcquireContext) (*protocolio.ConnectArtifact, error) {
			acquisitions.Add(1)
			return &protocolio.ConnectArtifact{V: 1}, nil
		}),
		Reconnect: Settings{
			Enabled: true, MaxAttempts: 3, InitialDelay: time.Second,
			MaxDelay: time.Second, Factor: 1,
		},
		Connector: func(context.Context, *protocolio.ConnectArtifact, ...client.ConnectOption) (client.Client, error) {
			return firstClient, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	terminate()
	waitForState(t, manager, StatusConnecting)
	if err := manager.Disconnect(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := acquisitions.Load(); got != 1 {
		t.Fatalf("artifact acquired after disconnect: %d", got)
	}
}

func waitForState(t *testing.T, manager *Manager, want Status) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.State().Status == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state = %s, want %s", manager.State().Status, want)
}

type fakeClient struct{ closeErr error }

func (fakeClient) Path() client.Path          { return client.PathDirect }
func (fakeClient) EndpointInstanceID() string { return "" }
func (fakeClient) RPC() *rpc.Client           { return nil }
func (fakeClient) OpenStream(context.Context, string) (fsstream.Stream, error) {
	return nil, errors.New("not implemented")
}
func (fakeClient) Ping() error                                          { return nil }
func (fakeClient) Rekey() error                                         { return nil }
func (fakeClient) ProbeLiveness(context.Context) (time.Duration, error) { return 0, nil }
func (c fakeClient) Close() error                                       { return c.closeErr }

type terminatingFakeClient struct {
	fakeClient
	mux  *fsyamux.Session
	peer net.Conn
}

func newTerminatingFakeClient(t *testing.T) (*terminatingFakeClient, func()) {
	t.Helper()
	local, peer := net.Pipe()
	mux, err := fsyamux.NewClient(local, fsyamux.YamuxLimits{}, fsyamux.LivenessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	client := &terminatingFakeClient{mux: mux, peer: peer}
	return client, func() { _ = peer.Close() }
}

func (*terminatingFakeClient) Secure() *e2ee.SecureChannel { return nil }
func (c *terminatingFakeClient) Mux() *fsyamux.Session     { return c.mux }
func (c *terminatingFakeClient) Close() error {
	return errors.Join(c.mux.Close(), c.peer.Close())
}
