package endpoint_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/gorilla/websocket"
)

func TestConnectTunnel_MapsAttachRejectionCloseReason(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		reason string
		want   endpoint.Code
	}{
		{"invalid_token", "invalid_token", endpoint.CodeInvalidToken},
		{"init_exp_mismatch", "init_exp_mismatch", endpoint.CodeInitExpMismatch},
		{"idle_timeout_mismatch", "idle_timeout_mismatch", endpoint.CodeIdleTimeoutMismatch},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Minimal tunnel-like websocket: reads the attach JSON, then rejects the attach via close reason token.
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

				_, _, _ = c.ReadMessage()
				_ = c.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation, tc.reason),
					time.Now().Add(2*time.Second),
				)
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

			_, err := endpoint.ConnectTunnel(
				context.Background(),
				grant,
				endpoint.WithOrigin("https://example.test"),
				endpoint.WithConnectTimeout(2*time.Second),
				endpoint.WithHandshakeTimeout(2*time.Second),
			)
			if err == nil {
				t.Fatal("expected error")
			}
			var fe *endpoint.Error
			if !errors.As(err, &fe) {
				t.Fatalf("expected *endpoint.Error, got %T: %v", err, err)
			}
			if fe.Path != endpoint.PathTunnel || fe.Stage != endpoint.StageAttach || fe.Code != tc.want {
				t.Fatalf("expected tunnel attach %s, got path=%q stage=%q code=%q err=%v", tc.reason, fe.Path, fe.Stage, fe.Code, fe.Err)
			}
		})
	}
}
