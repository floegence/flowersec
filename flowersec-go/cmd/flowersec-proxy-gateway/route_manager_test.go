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
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
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

func TestRouteManagerReconnectsAfterOpenStreamFailure(t *testing.T) {
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

	stream, err := mgr.OpenStream(helperContext(t), "flowersec-proxy/http1")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
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
func (c *fakeManagedClient) Close() error {
	c.closed.Add(1)
	return nil
}
func (c *fakeManagedClient) OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	return c.open(ctx, kind)
}

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
