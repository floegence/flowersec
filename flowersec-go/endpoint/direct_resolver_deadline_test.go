package endpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/client"
	"github.com/floegence/flowersec/flowersec-go/v2/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/v2/endpoint"
	e2eev1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/e2ee/v1"
	"github.com/gorilla/websocket"
)

func TestDirectHandlerResolved_ResolverHonorsHardDeadline(t *testing.T) {
	origin := "http://example.com"
	channelID := "ch_resolver_timeout"
	psk := make([]byte, 32)
	initExp := time.Now().Add(2 * time.Minute).Unix()
	started := make(chan struct{})
	release := make(chan struct{})
	errCh := make(chan error, 1)

	handler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{origin},
		Handshake: endpoint.AcceptDirectResolverOptions{
			HandshakeTimeout: durationPtr(50 * time.Millisecond),
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				close(started)
				<-release
				return endpoint.DirectHandshakeSecrets{PSK: psk, InitExpireAtUnixS: initExp}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
		OnError:  func(err error) { errCh <- err },
	})
	if err != nil {
		t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	connectDone := make(chan struct{})
	go func() {
		connected, _ := client.ConnectDirect(
			context.Background(),
			directInfo("ws"+strings.TrimPrefix(srv.URL, "http"), channelID, psk, initExp),
			directClientOptions(origin)...,
		)
		if connected != nil {
			_ = connected.Close()
		}
		close(connectDone)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for resolver")
	}
	assertDirectHandlerError(t, errCh, endpoint.StageHandshake, endpoint.CodeTimeout)
	select {
	case <-connectDone:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for client close")
	}
}

func TestDirectHandlerResolved_CommitHonorsHardDeadline(t *testing.T) {
	origin := "http://example.com"
	channelID := "ch_commit_timeout"
	psk := make([]byte, 32)
	initExp := time.Now().Add(2 * time.Minute).Unix()
	started := make(chan struct{})
	release := make(chan struct{})
	errCh := make(chan error, 1)

	handler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{origin},
		Handshake: endpoint.AcceptDirectResolverOptions{
			HandshakeTimeout: durationPtr(100 * time.Millisecond),
			ResolveCredential: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeCredential, error) {
				return endpoint.DirectHandshakeCredential{
					Secrets: endpoint.DirectHandshakeSecrets{PSK: psk, InitExpireAtUnixS: initExp},
					CommitAuthenticated: func(context.Context) error {
						close(started)
						<-release
						return nil
					},
				}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
		OnError:  func(err error) { errCh <- err },
	})
	if err != nil {
		t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	connectDone := make(chan struct{})
	go func() {
		connected, _ := client.ConnectDirect(
			context.Background(),
			directInfo("ws"+strings.TrimPrefix(srv.URL, "http"), channelID, psk, initExp),
			directClientOptions(origin)...,
		)
		if connected != nil {
			_ = connected.Close()
		}
		close(connectDone)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for credential commit")
	}
	assertDirectHandlerError(t, errCh, endpoint.StageHandshake, endpoint.CodeTimeout)
	select {
	case <-connectDone:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for client close")
	}
}

func TestAcceptDirectWSResolved_ResolverCancellationIsCanceled(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	cancelAccept := make(chan struct{})
	errCh := make(chan error, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-cancelAccept
			cancel()
		}()
		handshakeTimeout := 2 * time.Second
		_, err = endpoint.AcceptDirectWSResolved(ctx, c, endpoint.AcceptDirectResolverOptions{
			HandshakeTimeout: &handshakeTimeout,
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				close(started)
				<-release
				return endpoint.DirectHandshakeSecrets{}, nil
			},
		})
		errCh <- err
	}))
	t.Cleanup(func() {
		select {
		case <-cancelAccept:
		default:
			close(cancelAccept)
		}
		close(release)
		srv.Close()
	})

	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	initPayload, err := json.Marshal(&e2eev1.E2EE_Init{
		ChannelId: "ch_resolver_canceled",
		Role:      e2eev1.Role_client,
		Version:   e2ee.ProtocolVersion,
		Suite:     e2eev1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
	})
	if err != nil {
		t.Fatalf("marshal init: %v", err)
	}
	if err := c.WriteMessage(websocket.BinaryMessage, e2ee.EncodeHandshakeFrame(e2ee.HandshakeTypeInit, initPayload)); err != nil {
		t.Fatalf("write init: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for resolver")
	}
	close(cancelAccept)

	select {
	case got := <-errCh:
		var structured *endpoint.Error
		if !errors.As(got, &structured) {
			t.Fatalf("expected *endpoint.Error, got %T: %v", got, got)
		}
		if structured.Path != endpoint.PathDirect || structured.Stage != endpoint.StageHandshake || structured.Code != endpoint.CodeCanceled {
			t.Fatalf("unexpected error: %+v", structured)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for canceled accept")
	}
}

func assertDirectHandlerError(t *testing.T, errCh <-chan error, wantStage endpoint.Stage, wantCode endpoint.Code) {
	t.Helper()
	select {
	case got := <-errCh:
		var structured *endpoint.Error
		if !errors.As(got, &structured) {
			t.Fatalf("expected *endpoint.Error, got %T: %v", got, got)
		}
		if structured.Path != endpoint.PathDirect || structured.Stage != wantStage || structured.Code != wantCode {
			t.Fatalf("unexpected error: %+v", structured)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for %s/%s error", wantStage, wantCode)
	}
}
