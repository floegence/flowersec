package serve

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

func TestServerHandleStreamRPC(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := New(Options{
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

func TestServerHandleStreamUnknownCloses(t *testing.T) {
	t.Parallel()

	s := New(Options{})
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

type fakeSession struct {
	next []func() (string, io.ReadWriteCloser, error)
}

func (s *fakeSession) Path() endpoint.Path        { return endpoint.PathDirect }
func (s *fakeSession) EndpointInstanceID() string { return "" }
func (s *fakeSession) OpenStream(string) (io.ReadWriteCloser, error) {
	return nil, errors.New("not implemented")
}
func (s *fakeSession) ServeStreams(context.Context, int, func(string, io.ReadWriteCloser)) error {
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

	srv := New(Options{
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
