package endpoint

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/gorilla/websocket"
)

func TestNewDirectHandler_EnforcesWebSocketReadLimit(t *testing.T) {
	t.Parallel()

	errCh := make(chan error, 1)
	wsHandler, err := NewDirectHandler(DirectHandlerOptions{
		AllowedOrigins: []string{"example.com"},
		Handshake: AcceptDirectOptions{
			ChannelID:           "ch_1",
			PSK:                 make([]byte, 32),
			InitExpireAtUnixS:   time.Now().Add(60 * time.Second).Unix(),
			MaxHandshakePayload: 16,
			MaxRecordBytes:      64,
		},
		OnStream: func(ctx context.Context, kind string, stream io.ReadWriteCloser) {},
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandler: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsHandler(w, r)
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"http://example.com"}})
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// The server sets a 64-byte read limit; sending 65 bytes should trip websocket.ErrReadLimit
	// before any E2EE framing checks run.
	if err := c.WriteMessage(websocket.BinaryMessage, make([]byte, 65)); err != nil {
		t.Fatalf("write oversized frame: %v", err)
	}

	select {
	case got := <-errCh:
		if got == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(got, websocket.ErrReadLimit) {
			t.Fatalf("expected websocket.ErrReadLimit, got %T: %v", got, got)
		}
		var fe *fserrors.Error
		if !errors.As(got, &fe) {
			t.Fatalf("expected *fserrors.Error, got %T: %v", got, got)
		}
		if fe.Path != fserrors.PathDirect || fe.Stage != fserrors.StageHandshake || fe.Code != fserrors.CodeHandshakeFailed {
			t.Fatalf("unexpected error classification: path=%q stage=%q code=%q err=%v", fe.Path, fe.Stage, fe.Code, fe.Err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server error")
	}
}

func TestConnectTunnel_EnforcesWebSocketReadLimit(t *testing.T) {
	t.Parallel()

	// Minimal tunnel-like websocket: read attach JSON, then send an oversized binary message.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer c.Close()

		_, _, _ = c.ReadMessage() // attach JSON
		_ = c.WriteMessage(websocket.BinaryMessage, make([]byte, 65))
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	psk := make([]byte, 32)
	pskB64u := base64.RawURLEncoding.EncodeToString(psk)

	grant := &controlv1.ChannelInitGrant{
		TunnelUrl:                wsURL,
		ChannelId:                "ch_1",
		ChannelInitExpireAtUnixS: time.Now().Add(60 * time.Second).Unix(),
		IdleTimeoutSeconds:       60,
		Role:                     controlv1.Role_server,
		Token:                    "tok",
		E2eePskB64u:              pskB64u,
		AllowedSuites:            []controlv1.Suite{controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM},
		DefaultSuite:             controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
	}

	_, err := ConnectTunnel(
		context.Background(),
		grant,
		WithOrigin("http://example.com"),
		WithMaxHandshakePayload(16),
		WithMaxRecordBytes(64),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, websocket.ErrReadLimit) {
		t.Fatalf("expected websocket.ErrReadLimit, got %T: %v", err, err)
	}
}
