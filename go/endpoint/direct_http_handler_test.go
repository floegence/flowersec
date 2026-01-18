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

	"github.com/floegence/flowersec/client"
	"github.com/floegence/flowersec/crypto/e2ee"
	"github.com/floegence/flowersec/endpoint"
	directv1 "github.com/floegence/flowersec/gen/flowersec/direct/v1"
)

func TestDirectHTTPHandler_AllowsDialDirect(t *testing.T) {
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
		endpoint.DirectHTTPHandler(endpoint.DirectHTTPHandlerOptions{
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
		WsUrl:        wsURL,
		ChannelId:    channelID,
		E2eePskB64u:  base64.RawURLEncoding.EncodeToString(psk),
		DefaultSuite: uint32(e2ee.SuiteX25519HKDFAES256GCM),
	}
	c, err := client.DialDirect(context.Background(), info, client.DialDirectOptions{
		Origin:           origin,
		ConnectTimeout:   2 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		MaxRecordBytes:   1 << 20,
	})
	if err != nil {
		t.Fatalf("DialDirect() failed: %v", err)
	}
	_ = c.Close()
}
