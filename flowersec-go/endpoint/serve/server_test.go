package serve

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

func newServer(t *testing.T, opts Options) *Server {
	t.Helper()
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return s
}

func TestNew_NegativeMaxStreamHelloBytes_ReturnsError(t *testing.T) {
	t.Parallel()

	_, err := New(Options{MaxStreamHelloBytes: -1})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "MaxStreamHelloBytes") {
		t.Fatalf("expected error to mention MaxStreamHelloBytes, got %v", err)
	}
}

func TestNew_NegativeRPCMaxFrameBytes_ReturnsError(t *testing.T) {
	t.Parallel()

	_, err := New(Options{RPC: RPCOptions{MaxFrameBytes: -1}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "RPC.MaxFrameBytes") {
		t.Fatalf("expected error to mention RPC.MaxFrameBytes, got %v", err)
	}
}

func TestServerHandleStreamRPC(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newServer(t, Options{
		RPC: RPCOptions{
			Register: func(r *rpc.Router, _srv *rpc.Server) {
				r.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					_ = ctx
					_ = payload
					return json.RawMessage(`{"ok":true}`), nil
				})
			},
		},
	})

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleStream(ctx, "rpc", serverConn)
	}()

	c := rpc.NewClient(clientConn)
	defer c.Close()

	resp, rpcErr, err := c.Call(ctx, 1, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	if rpcErr != nil {
		t.Fatalf("unexpected rpc error: %v", rpcErr)
	}
	if string(resp) != `{"ok":true}` {
		t.Fatalf("unexpected response: %s", string(resp))
	}

	cancel()
	_ = clientConn.Close()
	<-done
}

func writeRawJSONFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func TestServerHandleStreamRPC_OnErrorReportsServeErrors(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	s := newServer(t, Options{
		RPC: RPCOptions{
			Register: func(_ *rpc.Router, _srv *rpc.Server) {},
		},
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleStream(ctx, "rpc", serverConn)
	}()

	// Send invalid JSON frames (but valid length prefixes) to force rpc.Server.Serve to fail.
	for i := 0; i < 3; i++ {
		if err := writeRawJSONFrame(clientConn, []byte("{")); err != nil {
			_ = clientConn.Close()
			t.Fatalf("write frame: %v", err)
		}
	}

	select {
	case err := <-errCh:
		var fe *fserrors.Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *fserrors.Error, got %T", err)
		}
		if fe.Path != fserrors.PathAuto || fe.Stage != fserrors.StageRPC || fe.Code != fserrors.CodeRPCFailed {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		_ = clientConn.Close()
		t.Fatal("timeout waiting for OnError")
	}

	_ = clientConn.Close()
	<-done
}

func TestServerHandleStreamUnknownCloses(t *testing.T) {
	t.Parallel()

	s := newServer(t, Options{})
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleStream(context.Background(), "unknown", serverConn)
	}()

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := clientConn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected read error")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	<-done
}

func TestServerHandle_RegisterRemoveAndHandleStreamWithNilContext(t *testing.T) {
	t.Parallel()

	s := newServer(t, Options{})
	s.Handle("", func(_ context.Context, _ io.ReadWriteCloser) {
		t.Fatal("empty kind must not be registered")
	})

	ctxCh := make(chan context.Context, 1)
	s.Handle("echo", func(ctx context.Context, _ io.ReadWriteCloser) {
		ctxCh <- ctx
	})

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleStream(nil, "echo", serverConn)
	}()

	select {
	case gotCtx := <-ctxCh:
		if gotCtx == nil {
			t.Fatal("expected non-nil context")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler")
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := clientConn.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	_ = clientConn.Close()
	<-done

	s.Handle("echo", nil)
	if got := s.lookup("echo"); got != nil {
		t.Fatal("expected handler to be removed")
	}

	serverConn2, clientConn2 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		s.HandleStream(nil, "", serverConn2)
	}()

	_ = clientConn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = clientConn2.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF for empty kind stream, got %v", err)
	}
	_ = clientConn2.Close()
	<-done2
}

func TestServerHandleStream_OnErrorReportsHandlerPanic(t *testing.T) {
	t.Parallel()

	errCh := make(chan error, 1)
	s := newServer(t, Options{
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})
	s.Handle("panic", func(_ context.Context, _ io.ReadWriteCloser) {
		panic("boom")
	})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleStream(context.Background(), "panic", serverConn)
	}()

	select {
	case err := <-errCh:
		if !strings.Contains(err.Error(), `stream handler panic (kind="panic")`) {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for OnError")
	}

	<-done
}

func TestServerHandleStreamRPC_OnErrorReportsRegisterPanics(t *testing.T) {
	t.Parallel()

	errCh := make(chan error, 1)
	s := newServer(t, Options{
		RPC: RPCOptions{
			Register: func(_ *rpc.Router, _srv *rpc.Server) {
				panic("boom")
			},
		},
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleStream(context.Background(), "rpc", serverConn)
	}()

	select {
	case err := <-errCh:
		var fe *fserrors.Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *fserrors.Error, got %T", err)
		}
		if fe.Path != fserrors.PathAuto || fe.Stage != fserrors.StageRPC || fe.Code != fserrors.CodeRPCFailed {
			t.Fatalf("unexpected error: %+v", fe)
		}
		if !strings.Contains(fe.Error(), "rpc register panic") {
			t.Fatalf("unexpected error: %v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for OnError")
	}

	<-done
}

type fakeSession struct {
	next []func() (string, io.ReadWriteCloser, error)
}

func (s *fakeSession) Path() endpoint.Path        { return endpoint.PathDirect }
func (s *fakeSession) EndpointInstanceID() string { return "" }
func (s *fakeSession) OpenStream(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, errors.New("not implemented")
}
func (s *fakeSession) ServeStreams(context.Context, int, func(string, io.ReadWriteCloser), ...endpoint.ServeStreamsOption) error {
	return errors.New("not implemented")
}
func (s *fakeSession) Ping() error  { return nil }
func (s *fakeSession) Close() error { return nil }

func (s *fakeSession) AcceptStreamHello(_ int) (string, io.ReadWriteCloser, error) {
	if len(s.next) == 0 {
		return "", nil, errors.New("unexpected call")
	}
	fn := s.next[0]
	s.next = s.next[1:]
	return fn()
}

func TestServerServeSession_ReportsBadStreamHelloAndContinues(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	gotStream := make(chan struct{}, 1)

	srv := newServer(t, Options{
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})
	srv.Handle("echo", func(_ context.Context, stream io.ReadWriteCloser) {
		defer stream.Close()
		select {
		case gotStream <- struct{}{}:
		default:
		}
	})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	sess := &fakeSession{
		next: []func() (string, io.ReadWriteCloser, error){
			func() (string, io.ReadWriteCloser, error) {
				return "", nil, &endpoint.Error{
					Path:  endpoint.PathDirect,
					Stage: endpoint.StageRPC,
					Code:  endpoint.CodeStreamHelloFailed,
					Err:   errors.New("bad stream hello"),
				}
			},
			func() (string, io.ReadWriteCloser, error) { return "echo", serverConn, nil },
			func() (string, io.ReadWriteCloser, error) { return "", nil, io.EOF },
		},
	}

	done := make(chan error, 1)
	go func() { done <- srv.ServeSession(ctx, sess) }()

	select {
	case err := <-errCh:
		var fe *endpoint.Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T", err)
		}
		if fe.Code != endpoint.CodeStreamHelloFailed {
			t.Fatalf("unexpected code: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for OnError")
	}

	select {
	case <-gotStream:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for echo handler")
	}

	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for ServeSession to finish")
	}
}
