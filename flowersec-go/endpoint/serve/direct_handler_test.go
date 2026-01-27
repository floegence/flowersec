package serve_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

func durationPtr(d time.Duration) *time.Duration { return &d }

func TestNewDirectHandler_MissingServer(t *testing.T) {
	t.Parallel()

	_, err := serve.NewDirectHandler(serve.DirectHandlerOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewDirectHandler_AllowsConnectDirect(t *testing.T) {
	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	srv, err := serve.New(serve.Options{})
	if err != nil {
		t.Fatalf("serve.New() failed: %v", err)
	}

	mux := http.NewServeMux()
	wsHandler, err := serve.NewDirectHandler(serve.DirectHandlerOptions{
		Server:         srv,
		AllowedOrigins: []string{origin},
		AllowNoOrigin:  false,
		Handshake: endpoint.AcceptDirectOptions{
			ChannelID:           channelID,
			PSK:                 psk,
			Suite:               endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS:   initExp,
			ClockSkew:           30 * time.Second,
			HandshakeTimeout:    durationPtr(2 * time.Second),
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandler() failed: %v", err)
	}
	mux.HandleFunc("/ws", wsHandler)

	httpSrv := httptest.NewServer(mux)
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/ws"
	info := &directv1.DirectConnectInfo{
		WsUrl:                    wsURL,
		ChannelId:                channelID,
		E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
		ChannelInitExpireAtUnixS: initExp,
		DefaultSuite:             directv1.Suite(endpoint.SuiteX25519HKDFAES256GCM),
	}

	c, err := client.ConnectDirect(
		context.Background(),
		info,
		client.WithOrigin(origin),
		client.WithConnectTimeout(2*time.Second),
		client.WithHandshakeTimeout(2*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		t.Fatalf("ConnectDirect() failed: %v", err)
	}
	_ = c.Close()
}

func TestNewDirectHandlerResolved_AllowsConnectDirect(t *testing.T) {
	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	srv, err := serve.New(serve.Options{})
	if err != nil {
		t.Fatalf("serve.New() failed: %v", err)
	}

	mux := http.NewServeMux()
	wsHandler, err := serve.NewDirectHandlerResolved(serve.DirectHandlerResolvedOptions{
		Server:         srv,
		AllowedOrigins: []string{origin},
		AllowNoOrigin:  false,
		Handshake: endpoint.AcceptDirectResolverOptions{
			ClockSkew:           30 * time.Second,
			HandshakeTimeout:    durationPtr(2 * time.Second),
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
			Resolve: func(_ context.Context, init endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				if init.ChannelID != channelID {
					return endpoint.DirectHandshakeSecrets{}, nil
				}
				return endpoint.DirectHandshakeSecrets{
					PSK:               psk,
					InitExpireAtUnixS: initExp,
				}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
	}
	mux.HandleFunc("/ws", wsHandler)

	httpSrv := httptest.NewServer(mux)
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/ws"
	info := &directv1.DirectConnectInfo{
		WsUrl:                    wsURL,
		ChannelId:                channelID,
		E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
		ChannelInitExpireAtUnixS: initExp,
		DefaultSuite:             directv1.Suite(endpoint.SuiteX25519HKDFAES256GCM),
	}

	c, err := client.ConnectDirect(
		context.Background(),
		info,
		client.WithOrigin(origin),
		client.WithConnectTimeout(2*time.Second),
		client.WithHandshakeTimeout(2*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		t.Fatalf("ConnectDirect() failed: %v", err)
	}
	_ = c.Close()
}
