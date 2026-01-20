package client

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

func TestConnectDirect_DefaultKeepaliveDisabled(t *testing.T) {
	t.Parallel()

	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	mux := http.NewServeMux()
	wsHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		Upgrader: endpoint.UpgraderOptions{CheckOrigin: func(*http.Request) bool { return true }},
		Handshake: endpoint.AcceptDirectOptions{
			ChannelID:         channelID,
			PSK:               psk,
			Suite:             endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS: initExp,
		},
		OnStream: func(_ context.Context, _ string, stream io.ReadWriteCloser) {
			_ = stream.Close()
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandler() failed: %v", err)
	}
	mux.HandleFunc("/ws", wsHandler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	info := &directv1.DirectConnectInfo{
		WsUrl:                    wsURL,
		ChannelId:                channelID,
		E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
		ChannelInitExpireAtUnixS: initExp,
		DefaultSuite:             directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
	}

	c, err := ConnectDirect(context.Background(), info, WithOrigin(origin), WithConnectTimeout(2*time.Second), WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("ConnectDirect() failed: %v", err)
	}
	defer c.Close()

	sess, ok := c.(*session)
	if !ok {
		t.Fatalf("unexpected client type: %T", c)
	}
	if sess.keepaliveStop != nil {
		t.Fatalf("expected direct keepalive to be disabled by default")
	}
}

func TestConnectDirect_KeepaliveOptionStartsKeepalive(t *testing.T) {
	t.Parallel()

	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	mux := http.NewServeMux()
	wsHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		Upgrader: endpoint.UpgraderOptions{CheckOrigin: func(*http.Request) bool { return true }},
		Handshake: endpoint.AcceptDirectOptions{
			ChannelID:         channelID,
			PSK:               psk,
			Suite:             endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS: initExp,
		},
		OnStream: func(_ context.Context, _ string, stream io.ReadWriteCloser) {
			_ = stream.Close()
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandler() failed: %v", err)
	}
	mux.HandleFunc("/ws", wsHandler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	info := &directv1.DirectConnectInfo{
		WsUrl:                    wsURL,
		ChannelId:                channelID,
		E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
		ChannelInitExpireAtUnixS: initExp,
		DefaultSuite:             directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
	}

	c, err := ConnectDirect(
		context.Background(),
		info,
		WithOrigin(origin),
		WithKeepaliveInterval(10*time.Millisecond),
		WithConnectTimeout(2*time.Second),
		WithHandshakeTimeout(2*time.Second),
	)
	if err != nil {
		t.Fatalf("ConnectDirect() failed: %v", err)
	}
	defer c.Close()

	sess, ok := c.(*session)
	if !ok {
		t.Fatalf("unexpected client type: %T", c)
	}
	if sess.keepaliveStop == nil {
		t.Fatalf("expected direct keepalive to be enabled when configured")
	}
}
