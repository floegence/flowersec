package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	fsstream "github.com/floegence/flowersec/flowersec-go/stream"
)

func TestFileGrantSourceLoadsGrantClientWrapper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grant.json")
	b := mustGrantWrapperJSON(t)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write grant: %v", err)
	}

	src := fileGrantSource{path: path}
	grant, err := src.LoadGrant(context.Background())
	if err != nil {
		t.Fatalf("LoadGrant: %v", err)
	}
	if grant.Role != controlv1.Role_client {
		t.Fatalf("unexpected role: %v", grant.Role)
	}
}

func TestExecGrantSourceLoadsGrantFromCommand(t *testing.T) {
	if len(flag.Args()) > 0 && flag.Args()[0] == "helper-grant-source" {
		_, _ = io.WriteString(os.Stdout, string(mustGrantWrapperJSON(t)))
		os.Exit(0)
	}

	src := execGrantSource{
		command: []string{os.Args[0], "-test.run=TestExecGrantSourceLoadsGrantFromCommand", "--", "helper-grant-source"},
		timeout: 5 * time.Second,
	}
	grant, err := src.LoadGrant(helperContext(t))
	if err != nil {
		t.Fatalf("LoadGrant: %v", err)
	}
	if grant.Role != controlv1.Role_client {
		t.Fatalf("unexpected role: %v", grant.Role)
	}
}

func TestRouteManagerReconnectsOnRequestAfterOpenStreamFailure(t *testing.T) {
	var loads atomic.Int32
	source := grantSourceFunc(func(ctx context.Context) (*controlv1.ChannelInitGrant, error) {
		loads.Add(1)
		return &controlv1.ChannelInitGrant{Role: controlv1.Role_client}, nil
	})

	first := &fakeManagedClient{
		open: func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			return nil, errors.New("stale session")
		},
	}
	second := &fakeManagedClient{
		open: func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			return noopReadWriteCloser{}, nil
		},
	}

	var dials atomic.Int32
	mgr := newRouteManager("example.com", "https://gateway.example.com", source)
	mgr.dial = func(ctx context.Context, origin string, grant *controlv1.ChannelInitGrant) (client.Client, error) {
		switch dials.Add(1) {
		case 1:
			return first, nil
		case 2:
			return second, nil
		default:
			return nil, fmt.Errorf("unexpected extra dial")
		}
	}

	if _, err := mgr.OpenStream(helperContext(t), "flowersec-proxy/http1"); err == nil || err.Error() != "stale session" {
		t.Fatalf("expected the first request to return its stream error, got %v", err)
	}
	stream, err := mgr.OpenStream(helperContext(t), "flowersec-proxy/http1")
	if err != nil {
		t.Fatalf("second OpenStream: %v", err)
	}
	_ = stream.Close()

	if loads.Load() != 2 {
		t.Fatalf("expected 2 grant loads, got %d", loads.Load())
	}
	if dials.Load() != 2 {
		t.Fatalf("expected 2 dials, got %d", dials.Load())
	}
	if first.closed.Load() != 1 {
		t.Fatalf("expected first client to be closed once, got %d", first.closed.Load())
	}
}

func TestRouteManagerNeverRetriesWithinOneOpenStreamRequest(t *testing.T) {
	var loads atomic.Int32
	source := grantSourceFunc(func(ctx context.Context) (*controlv1.ChannelInitGrant, error) {
		loads.Add(1)
		return &controlv1.ChannelInitGrant{Role: controlv1.Role_client}, nil
	})

	first := &fakeManagedClient{
		open: func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			return nil, errors.New("stale session")
		},
	}
	second := &fakeManagedClient{
		open: func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			return nil, errors.New("fresh session failed")
		},
	}

	var dials atomic.Int32
	mgr := newRouteManager("example.com", "https://gateway.example.com", source)
	mgr.dial = func(ctx context.Context, origin string, grant *controlv1.ChannelInitGrant) (client.Client, error) {
		switch dials.Add(1) {
		case 1:
			return first, nil
		case 2:
			return second, nil
		default:
			return nil, fmt.Errorf("unexpected extra dial")
		}
	}

	_, err := mgr.OpenStream(helperContext(t), "flowersec-proxy/http1")
	if err == nil {
		t.Fatalf("expected OpenStream to fail")
	}
	if err.Error() != "stale session" {
		t.Fatalf("expected original stale-session error, got %v", err)
	}
	if loads.Load() != 1 {
		t.Fatalf("expected one grant load for one request, got %d", loads.Load())
	}
	if dials.Load() != 1 {
		t.Fatalf("expected one dial for one request, got %d", dials.Load())
	}
	if first.closed.Load() != 1 {
		t.Fatalf("expected stale client to be closed once, got %d", first.closed.Load())
	}
	if second.closed.Load() != 0 {
		t.Fatalf("expected the unused second client to remain untouched, got %d closes", second.closed.Load())
	}

	_, err = mgr.OpenStream(helperContext(t), "flowersec-proxy/http1")
	if err == nil {
		t.Fatalf("expected second OpenStream to fail")
	}
	if !strings.Contains(err.Error(), "fresh session failed") {
		t.Fatalf("expected second request's fresh-session error, got %v", err)
	}
	if dials.Load() != 2 {
		t.Fatalf("expected the next request to make one new dial, got %d dials", dials.Load())
	}
}

func TestRouteManagerLoadsFreshGrantOnlyOnNextRequest(t *testing.T) {
	var loads atomic.Int32
	source := grantSourceFunc(func(ctx context.Context) (*controlv1.ChannelInitGrant, error) {
		switch loads.Add(1) {
		case 1:
			return &controlv1.ChannelInitGrant{Role: controlv1.Role_client}, nil
		default:
			return nil, errors.New("grant source unavailable")
		}
	})

	stale := &fakeManagedClient{
		open: func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			return nil, errors.New("stale session")
		},
	}

	var dials atomic.Int32
	mgr := newRouteManager("example.com", "https://gateway.example.com", source)
	mgr.dial = func(ctx context.Context, origin string, grant *controlv1.ChannelInitGrant) (client.Client, error) {
		dials.Add(1)
		return stale, nil
	}

	_, err := mgr.OpenStream(helperContext(t), "flowersec-proxy/http1")
	if err == nil {
		t.Fatalf("expected OpenStream to fail")
	}
	if err.Error() != "stale session" {
		t.Fatalf("expected original stale-session error, got %v", err)
	}
	if loads.Load() != 1 {
		t.Fatalf("expected one initial grant load, got %d", loads.Load())
	}
	if dials.Load() != 1 {
		t.Fatalf("expected no dial after fresh grant load failure, got %d", dials.Load())
	}
	if stale.closed.Load() != 1 {
		t.Fatalf("expected stale client to be closed once, got %d", stale.closed.Load())
	}

	_, err = mgr.OpenStream(helperContext(t), "flowersec-proxy/http1")
	if err == nil || !strings.Contains(err.Error(), "grant source unavailable") {
		t.Fatalf("expected the next request to return the fresh grant error, got %v", err)
	}
	if loads.Load() != 2 {
		t.Fatalf("expected the next request to load a fresh grant, got %d loads", loads.Load())
	}
}

func TestRouteManagerCloseClosesCachedClient(t *testing.T) {
	source := grantSourceFunc(func(ctx context.Context) (*controlv1.ChannelInitGrant, error) {
		return &controlv1.ChannelInitGrant{Role: controlv1.Role_client}, nil
	})
	fake := &fakeManagedClient{
		open: func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			return noopReadWriteCloser{}, nil
		},
	}
	mgr := newRouteManager("example.com", "https://gateway.example.com", source)
	mgr.dial = func(ctx context.Context, origin string, grant *controlv1.ChannelInitGrant) (client.Client, error) {
		return fake, nil
	}
	stream, err := mgr.OpenStream(helperContext(t), "flowersec-proxy/http1")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	_ = stream.Close()
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fake.closed.Load() != 1 {
		t.Fatalf("expected cached client to be closed once, got %d", fake.closed.Load())
	}
}

type grantSourceFunc func(ctx context.Context) (*controlv1.ChannelInitGrant, error)

func (fn grantSourceFunc) LoadGrant(ctx context.Context) (*controlv1.ChannelInitGrant, error) {
	return fn(ctx)
}

func (fn grantSourceFunc) Description() string {
	return "test"
}

type fakeManagedClient struct {
	open   func(ctx context.Context, kind string) (io.ReadWriteCloser, error)
	closed atomic.Int32
}

func (c *fakeManagedClient) Path() client.Path          { return client.PathTunnel }
func (c *fakeManagedClient) EndpointInstanceID() string { return "fake" }
func (c *fakeManagedClient) RPC() *rpc.Client           { return nil }
func (c *fakeManagedClient) Ping() error                { return nil }
func (c *fakeManagedClient) Rekey() error               { return nil }
func (c *fakeManagedClient) ProbeLiveness(context.Context) (time.Duration, error) {
	return 0, nil
}
func (c *fakeManagedClient) Close() error {
	c.closed.Add(1)
	return nil
}
func (c *fakeManagedClient) OpenStream(ctx context.Context, kind string) (fsstream.Stream, error) {
	value, err := c.open(ctx, kind)
	if err != nil || value == nil {
		return nil, err
	}
	return resettableTestStream{ReadWriteCloser: value}, nil
}

type resettableTestStream struct{ io.ReadWriteCloser }

func (s resettableTestStream) Reset() error { return s.Close() }

func mustGrantWrapperJSON(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"grant_client": &controlv1.ChannelInitGrant{Role: controlv1.Role_client},
	})
	if err != nil {
		t.Fatalf("marshal grant wrapper: %v", err)
	}
	return b
}

func helperContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
