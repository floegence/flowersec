package endpoint_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

func TestDirectHandler_AllowsConnectDirect(t *testing.T) {
	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	mux := http.NewServeMux()
	mux.HandleFunc(
		"/ws",
		endpoint.DirectHandler(endpoint.DirectHandlerOptions{
			AllowedOrigins: []string{origin},
			AllowNoOrigin:  false,
			Handshake: endpoint.AcceptDirectOptions{
				ChannelID:           channelID,
				PSK:                 psk,
				Suite:               e2ee.SuiteX25519HKDFAES256GCM,
				InitExpireAtUnixS:   initExp,
				ClockSkew:           30 * time.Second,
				HandshakeTimeout:    2 * time.Second,
				MaxHandshakePayload: 8 * 1024,
				MaxRecordBytes:      1 << 20,
			},
			OnStream: func(_kind string, stream io.ReadWriteCloser) {
				_ = stream.Close()
			},
		}),
	)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	info := &directv1.DirectConnectInfo{
		WsUrl:                    wsURL,
		ChannelId:                channelID,
		E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
		ChannelInitExpireAtUnixS: initExp,
		DefaultSuite:             uint32(e2ee.SuiteX25519HKDFAES256GCM),
	}
	c, err := client.ConnectDirect(
		context.Background(),
		info,
		origin,
		client.WithConnectTimeout(2*time.Second),
		client.WithHandshakeTimeout(2*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		t.Fatalf("ConnectDirect() failed: %v", err)
	}
	_ = c.Close()
}
