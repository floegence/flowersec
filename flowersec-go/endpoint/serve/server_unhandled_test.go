package serve

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
)

type nopRWC struct{}

func (nopRWC) Read(p []byte) (int, error)  { return 0, io.EOF }
func (nopRWC) Write(p []byte) (int, error) { return len(p), nil }
func (nopRWC) Close() error                { return nil }

type fakeSessionUnhandled struct {
	path   endpoint.Path
	cancel context.CancelFunc
	calls  int
}

func (s *fakeSessionUnhandled) Path() endpoint.Path { return s.path }
func (s *fakeSessionUnhandled) EndpointInstanceID() string {
	return ""
}

func (s *fakeSessionUnhandled) AcceptStreamHello(_ int) (string, io.ReadWriteCloser, error) {
	s.calls++
	if s.calls == 1 {
		if s.cancel != nil {
			s.cancel()
		}
		return "unhandled", nopRWC{}, nil
	}
	return "", nil, context.Canceled
}

func (s *fakeSessionUnhandled) ServeStreams(context.Context, int, func(string, io.ReadWriteCloser), ...endpoint.ServeStreamsOption) error {
	return errors.New("not implemented")
}

func (s *fakeSessionUnhandled) OpenStream(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, errors.New("not implemented")
}
func (s *fakeSessionUnhandled) Ping() error  { return nil }
func (s *fakeSessionUnhandled) Close() error { return nil }

func TestServer_ServeSession_OnError_UnhandledStreamKind(t *testing.T) {
	errCh := make(chan error, 1)
	srv, err := New(Options{
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sess := &fakeSessionUnhandled{path: endpoint.PathDirect, cancel: cancel}
	err = srv.ServeSession(ctx, sess)
	var fe *fserrors.Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *fserrors.Error, got %T", err)
	}
	if fe.Path != fserrors.PathDirect || fe.Stage != fserrors.StageClose || fe.Code != fserrors.CodeCanceled {
		t.Fatalf("unexpected error: %+v", fe)
	}

	select {
	case got := <-errCh:
		var fe *fserrors.Error
		if !errors.As(got, &fe) {
			t.Fatalf("expected *fserrors.Error, got %T", got)
		}
		if fe.Path != fserrors.PathDirect || fe.Stage != fserrors.StageRPC || fe.Code != fserrors.CodeMissingHandler {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for OnError")
	}
}
