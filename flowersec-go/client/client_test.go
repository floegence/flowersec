package client

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/streamhello"
	hyamux "github.com/hashicorp/yamux"
)

func newYamuxPair(t *testing.T) (client *hyamux.Session, server *hyamux.Session, closeFn func()) {
	t.Helper()
	a, b := net.Pipe()
	cfg := hyamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.LogOutput = io.Discard
	srv, err := hyamux.Server(a, cfg)
	if err != nil {
		_ = a.Close()
		_ = b.Close()
		t.Fatalf("yamux server: %v", err)
	}
	cli, err := hyamux.Client(b, cfg)
	if err != nil {
		_ = srv.Close()
		_ = a.Close()
		_ = b.Close()
		t.Fatalf("yamux client: %v", err)
	}
	return cli, srv, func() {
		_ = cli.Close()
		_ = srv.Close()
		_ = a.Close()
		_ = b.Close()
	}
}

func TestClientCloseNil(t *testing.T) {
	var c *session
	if err := c.Close(); err != nil {
		t.Fatalf("Close() on nil client should be nil, got %v", err)
	}
}

func TestClientOpenStreamValidation(t *testing.T) {
	c := &session{}
	ctx := context.Background()
	if _, err := c.OpenStream(ctx, ""); err == nil {
		t.Fatal("OpenStream(\"\") should fail")
	}
	if _, err := c.OpenStream(ctx, "echo"); err == nil {
		t.Fatal("OpenStream(\"echo\") should fail when not connected")
	}
}

func TestClientOpenStreamWritesHello(t *testing.T) {
	cli, srv, closeFn := newYamuxPair(t)
	defer closeFn()

	c := &session{path: PathDirect, mux: cli}
	st, err := c.OpenStream(context.Background(), "echo")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer st.Close()

	in, err := srv.AcceptStream()
	if err != nil {
		t.Fatalf("server AcceptStream: %v", err)
	}
	defer in.Close()

	h, err := streamhello.ReadStreamHello(in, 8*1024)
	if err != nil {
		t.Fatalf("ReadStreamHello: %v", err)
	}
	if h.Kind != "echo" {
		t.Fatalf("kind mismatch: got %q", h.Kind)
	}
}

func TestClientOpenStream_ContextCanceled_ReturnsCanceled(t *testing.T) {
	cli, _, closeFn := newYamuxPair(t)
	defer closeFn()

	c := &session{path: PathDirect, mux: cli}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.OpenStream(ctx, "echo")
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageYamux || fe.Code != CodeCanceled {
		t.Fatalf("unexpected error: %+v", fe)
	}
}
