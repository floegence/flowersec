package endpoint

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
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
		_ = sess.ServeStreams(ctx, 8*1024, func(kind string, _ io.ReadWriteCloser) {
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
		_ = sess.ServeStreams(ctx, 8*1024, func(kind string, _ io.ReadWriteCloser) {
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
	_ = jsonframe.WriteJSONFrame(s1, rpcv1.StreamHello{Kind: "", V: 1})
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

func TestSessionServeStreams_OnErrorReportsBadStreamHello(t *testing.T) {
	cli, srv, closeFn := newYamuxPair(t)
	defer closeFn()

	sess := &session{path: PathDirect, mux: srv}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	got := make(chan string, 1)
	go func() {
		_ = sess.ServeStreams(
			ctx,
			8*1024,
			func(kind string, _ io.ReadWriteCloser) {
				select {
				case got <- kind:
				default:
				}
			},
			WithServeStreamsOnError(func(err error) {
				select {
				case errCh <- err:
				default:
				}
			}),
		)
	}()

	// Stream 1: invalid StreamHello (empty kind).
	s1, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("client OpenStream: %v", err)
	}
	_ = jsonframe.WriteJSONFrame(s1, rpcv1.StreamHello{Kind: "", V: 1})
	_ = s1.Close()

	select {
	case err := <-errCh:
		var fe *Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T", err)
		}
		if fe.Path != PathDirect || fe.Stage != StageRPC || fe.Code != CodeStreamHelloFailed {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for OnError")
	}

	// Stream 2: valid StreamHello to ensure ServeStreams continues.
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

func TestSessionServeStreamsClosesStream(t *testing.T) {
	cli, srv, closeFn := newYamuxPair(t)
	defer closeFn()

	sess := &session{path: PathDirect, mux: srv}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handled := make(chan struct{})
	go func() {
		_ = sess.ServeStreams(ctx, 8*1024, func(kind string, _ io.ReadWriteCloser) {
			if kind != "echo" {
				return
			}
			select {
			case <-handled:
			default:
				close(handled)
			}
		})
	}()

	s, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("client OpenStream: %v", err)
	}
	if err := streamhello.WriteStreamHello(s, "echo"); err != nil {
		t.Fatalf("WriteStreamHello: %v", err)
	}

	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		_ = s.Close()
		t.Fatal("timeout waiting for handler")
	}

	readDone := make(chan error, 1)
	go func() {
		var buf [1]byte
		_, err := s.Read(buf[:])
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err == nil {
			_ = s.Close()
			t.Fatal("expected stream read to fail after handler return (stream should be closed)")
		}
	case <-time.After(2 * time.Second):
		_ = s.Close()
		t.Fatal("timeout waiting for stream close")
	}
}

func TestSessionServeStreams_OnErrorReportsHandlerPanic(t *testing.T) {
	cli, srv, closeFn := newYamuxPair(t)
	defer closeFn()

	sess := &session{path: PathDirect, mux: srv}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_ = sess.ServeStreams(
			ctx,
			8*1024,
			func(kind string, _ io.ReadWriteCloser) {
				if kind == "echo" {
					panic("boom")
				}
			},
			WithServeStreamsOnError(func(err error) {
				select {
				case errCh <- err:
				default:
				}
			}),
		)
	}()

	s, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("client OpenStream: %v", err)
	}
	if err := streamhello.WriteStreamHello(s, "echo"); err != nil {
		t.Fatalf("WriteStreamHello: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected OnError error")
		}
		if !strings.Contains(err.Error(), "panic") {
			t.Fatalf("expected panic error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for OnError")
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
