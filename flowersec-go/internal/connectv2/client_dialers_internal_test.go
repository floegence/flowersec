package connectv2

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

func TestInflightConnectionGuardRestoresHandshakeRecoveryOnRelease(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	restored := make(chan struct{})
	guard := &inflightConnectionGuard{prepare: func(got net.Conn) func() {
		if got != client {
			t.Errorf("prepared connection = %T %p, want client %p", got, got, client)
		}
		return func() { close(restored) }
	}}

	if got := guard.bind(client); got != client {
		t.Fatalf("bound connection = %T %p, want client %p", got, got, client)
	}
	guard.release()
	select {
	case <-restored:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("successful WebSocket upgrade did not restore handshake-only TCP recovery")
	}
	guard.release()
}

func TestInflightConnectionGuardRestoresHandshakeRecoveryOnClose(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	restored := make(chan struct{})
	guard := &inflightConnectionGuard{prepare: func(net.Conn) func() {
		return func() { close(restored) }
	}}
	guard.bind(client)
	guard.close()

	select {
	case <-restored:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("canceled WebSocket upgrade did not restore handshake-only TCP recovery")
	}
	if _, err := client.Write([]byte("closed")); err == nil {
		t.Fatal("canceled WebSocket upgrade left its connection open")
	}
	guard.close()
}

func TestStreamAdmissionHandleReturnsAfterLocalCloseBeforeFullDrain(t *testing.T) {
	fullCloseStarted := make(chan struct{})
	releaseFullClose := make(chan struct{})
	fullCloseDone := make(chan struct{})
	session := &locallyClosableTestSession{
		localClosed:      make(chan struct{}),
		fullCloseStarted: fullCloseStarted,
		releaseFullClose: releaseFullClose,
		fullCloseDone:    fullCloseDone,
	}
	handle := &streamAdmissionHandle{session: session, stream: localCloseTestStream{}}

	closed := make(chan error, 1)
	go func() { closed <- handle.Close(context.Background()) }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		close(releaseFullClose)
		t.Fatal("admission handle waited for full carrier drain")
	}
	select {
	case <-session.localClosed:
	case <-time.After(100 * time.Millisecond):
		close(releaseFullClose)
		t.Fatal("admission handle returned before local close")
	}
	select {
	case <-fullCloseStarted:
	case <-time.After(100 * time.Millisecond):
		close(releaseFullClose)
		t.Fatal("full carrier drain did not start")
	}
	close(releaseFullClose)
	select {
	case <-fullCloseDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("full carrier drain did not finish")
	}
}

type locallyClosableTestSession struct {
	localOnce        sync.Once
	localClosed      chan struct{}
	fullCloseStarted chan struct{}
	releaseFullClose chan struct{}
	fullCloseDone    chan struct{}
}

func (session *locallyClosableTestSession) Kind() carrier.Kind         { return carrier.KindWebTransport }
func (session *locallyClosableTestSession) Path() carrier.Path         { return carrier.PathDirect }
func (session *locallyClosableTestSession) MaxIncomingStreams() uint16 { return 1 }
func (session *locallyClosableTestSession) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, errors.New("unused")
}
func (session *locallyClosableTestSession) AcceptStream(context.Context) (carrier.Stream, error) {
	return nil, errors.New("unused")
}
func (session *locallyClosableTestSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	return session.Close()
}
func (session *locallyClosableTestSession) CloseWithError(carrier.ApplicationError) error {
	return session.Close()
}
func (session *locallyClosableTestSession) Close() error {
	close(session.fullCloseStarted)
	<-session.releaseFullClose
	close(session.fullCloseDone)
	return nil
}
func (session *locallyClosableTestSession) closeLocal() error {
	session.localOnce.Do(func() { close(session.localClosed) })
	return nil
}

type localCloseTestStream struct{}

func (localCloseTestStream) Read([]byte) (int, error)          { return 0, io.EOF }
func (localCloseTestStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (localCloseTestStream) Close() error                      { return nil }
func (localCloseTestStream) CloseWrite() error                 { return nil }
func (localCloseTestStream) Reset() error                      { return nil }
func (localCloseTestStream) Context() context.Context          { return context.Background() }
