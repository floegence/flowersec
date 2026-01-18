package endpoint

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc/frame"
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

func TestSessionAcceptStreamHello(t *testing.T) {
	cli, srv, closeFn := newYamuxPair(t)
	defer closeFn()

	go func() {
		s, err := cli.OpenStream()
		if err != nil {
			return
		}
		_ = streamhello.WriteStreamHello(s, "echo")
	}()

	sess := &session{path: PathDirect, mux: srv}
	kind, stream, err := sess.AcceptStreamHello(8 * 1024)
	if err != nil {
		t.Fatalf("AcceptStreamHello: %v", err)
	}
	defer stream.Close()
	if kind != "echo" {
		t.Fatalf("kind mismatch: got %q", kind)
	}
}

func TestSessionServeStreamsDispatches(t *testing.T) {
	cli, srv, closeFn := newYamuxPair(t)
	defer closeFn()

	sess := &session{path: PathDirect, mux: srv}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan string, 1)
	go func() {
		_ = sess.ServeStreams(ctx, 8*1024, func(kind string, stream io.ReadWriteCloser) {
			defer stream.Close()
			select {
			case got <- kind:
			default:
			}
		})
	}()

	s, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("client OpenStream: %v", err)
	}
	if err := streamhello.WriteStreamHello(s, "rpc"); err != nil {
		t.Fatalf("WriteStreamHello: %v", err)
	}

	select {
	case k := <-got:
		if k != "rpc" {
			t.Fatalf("kind mismatch: got %q", k)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler")
	}
	cancel()
}

func TestSessionServeStreamsSkipsBadStreamHello(t *testing.T) {
	cli, srv, closeFn := newYamuxPair(t)
	defer closeFn()

	sess := &session{path: PathDirect, mux: srv}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan string, 1)
	go func() {
		_ = sess.ServeStreams(ctx, 8*1024, func(kind string, stream io.ReadWriteCloser) {
			defer stream.Close()
			select {
			case got <- kind:
			default:
			}
		})
	}()

	// Stream 1: invalid StreamHello (empty kind).
	s1, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("client OpenStream: %v", err)
	}
	_ = frame.WriteJSONFrame(s1, rpcv1.StreamHello{Kind: "", V: 1})
	_ = s1.Close()

	// Stream 2: valid StreamHello.
	s2, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("client OpenStream: %v", err)
	}
	if err := streamhello.WriteStreamHello(s2, "echo"); err != nil {
		t.Fatalf("WriteStreamHello: %v", err)
	}

	select {
	case k := <-got:
		if k != "echo" {
			t.Fatalf("kind mismatch: got %q", k)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler")
	}
	cancel()
}

func TestSessionOpenStreamWritesHello(t *testing.T) {
	cli, srv, closeFn := newYamuxPair(t)
	defer closeFn()

	sess := &session{path: PathDirect, mux: srv}
	st, err := sess.OpenStream("echo")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer st.Close()

	in, err := cli.AcceptStream()
	if err != nil {
		t.Fatalf("client AcceptStream: %v", err)
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
