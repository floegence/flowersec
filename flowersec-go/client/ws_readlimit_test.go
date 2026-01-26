package client_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/gorilla/websocket"
)

func TestConnectDirect_EnforcesWebSocketReadLimit(t *testing.T) {
	t.Parallel()

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

		// Send an oversized binary message before any handshake exchange.
		_ = c.WriteMessage(websocket.BinaryMessage, make([]byte, 65))
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	psk := make([]byte, 32)
	pskB64u := base64.RawURLEncoding.EncodeToString(psk)

	info := &directv1.DirectConnectInfo{
		WsUrl:                    wsURL,
		ChannelId:                "ch_1",
		E2eePskB64u:              pskB64u,
		ChannelInitExpireAtUnixS: time.Now().Add(60 * time.Second).Unix(),
		DefaultSuite:             directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
	}

	_, err := client.ConnectDirect(
		context.Background(),
		info,
		client.WithOrigin("http://example.com"),
		client.WithMaxHandshakePayload(16),
		client.WithMaxRecordBytes(64),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, websocket.ErrReadLimit) {
		t.Fatalf("expected websocket.ErrReadLimit, got %T: %v", err, err)
	}
}
