package client_test

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/gorilla/websocket"
)

func TestConnectDirect_SendsOriginAndExtraHeadersAndUsesDialer(t *testing.T) {
	t.Parallel()

	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	var originOK atomic.Bool
	var headerOK atomic.Bool
	var dialerUsed atomic.Bool

	checkOrigin := func(r *http.Request) bool {
		if r.Header.Get("Origin") == origin {
			originOK.Store(true)
		}
		if r.Header.Get("X-Test") == "1" {
			headerOK.Store(true)
		}
		return true
	}

	mux := http.NewServeMux()
	wsHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		Upgrader: endpoint.UpgraderOptions{CheckOrigin: checkOrigin},
		Handshake: endpoint.AcceptDirectOptions{
			ChannelID:           channelID,
			PSK:                 psk,
			Suite:               endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS:   initExp,
			ClockSkew:           30 * time.Second,
			HandshakeTimeout:    2 * time.Second,
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
		},
		OnStream: func(_ context.Context, _kind string, stream io.ReadWriteCloser) {
			_ = stream.Close()
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandler() failed: %v", err)
	}
	mux.HandleFunc(
		"/ws",
		wsHandler,
	)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	info := &directv1.DirectConnectInfo{
		WsUrl:                    wsURL,
		ChannelId:                channelID,
		E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
		ChannelInitExpireAtUnixS: initExp,
		DefaultSuite:             directv1.Suite(endpoint.SuiteX25519HKDFAES256GCM),
	}

	dialer := &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialerUsed.Store(true)
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	c, err := client.ConnectDirect(
		context.Background(),
		info,
		client.WithOrigin(origin),
		client.WithHeader(http.Header{"X-Test": []string{"1"}}),
		client.WithDialer(dialer),
		client.WithConnectTimeout(2*time.Second),
		client.WithHandshakeTimeout(2*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		t.Fatalf("ConnectDirect() failed: %v", err)
	}
	_ = c.Close()

	if _, ok := c.(client.ClientInternal); !ok {
		t.Fatal("expected client to also implement ClientInternal")
	}

	if !originOK.Load() {
		t.Fatal("server did not observe Origin header")
	}
	if !headerOK.Load() {
		t.Fatal("server did not observe X-Test header")
	}
	if !dialerUsed.Load() {
		t.Fatal("custom websocket dialer was not used")
	}
}
