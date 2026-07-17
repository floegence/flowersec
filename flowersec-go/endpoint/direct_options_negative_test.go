package endpoint_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	e2eev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/e2ee/v1"
	"github.com/gorilla/websocket"
)

func TestAcceptDirectWS_NegativeOptions_ReturnsInvalidOption(t *testing.T) {
	t.Parallel()

	errCh := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer c.Close()

		_, err = endpoint.AcceptDirectWS(context.Background(), c, endpoint.AcceptDirectOptions{
			ChannelID:           "ch_1",
			PSK:                 make([]byte, 32),
			Suite:               endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS:   time.Now().Add(60 * time.Second).Unix(),
			ClockSkew:           -1 * time.Second,
			MaxHandshakePayload: 0,
			MaxRecordBytes:      0,
			MaxBufferedBytes:    0,
		})
		errCh <- err
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer c.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected error")
		}
		var fe *endpoint.Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T: %v", err, err)
		}
		if fe.Path != endpoint.PathDirect || fe.Stage != endpoint.StageValidate || fe.Code != endpoint.CodeInvalidOption {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for error")
	}
}

func TestAcceptDirectWSResolved_NegativeOptions_ReturnsInvalidOption(t *testing.T) {
	t.Parallel()

	errCh := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer c.Close()

		handshakeTimeout := 200 * time.Millisecond
		_, err = endpoint.AcceptDirectWSResolved(context.Background(), c, endpoint.AcceptDirectResolverOptions{
			HandshakeTimeout: &handshakeTimeout,
			ClockSkew:        -1 * time.Second,
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				return endpoint.DirectHandshakeSecrets{
					PSK:               make([]byte, 32),
					InitExpireAtUnixS: time.Now().Add(60 * time.Second).Unix(),
				}, nil
			},
		})
		errCh <- err
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer c.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected error")
		}
		var fe *endpoint.Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T: %v", err, err)
		}
		if fe.Path != endpoint.PathDirect || fe.Stage != endpoint.StageValidate || fe.Code != endpoint.CodeInvalidOption {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for error")
	}
}

func TestAcceptDirectWS_WhitespaceChannelID_ReturnsMissingChannelID(t *testing.T) {
	t.Parallel()

	errCh := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer c.Close()

		_, err = endpoint.AcceptDirectWS(context.Background(), c, endpoint.AcceptDirectOptions{
			ChannelID:           " \t\r\n",
			PSK:                 make([]byte, 32),
			Suite:               endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS:   time.Now().Add(60 * time.Second).Unix(),
			ClockSkew:           0,
			MaxHandshakePayload: 0,
			MaxRecordBytes:      0,
			MaxBufferedBytes:    0,
		})
		errCh <- err
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer c.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected error")
		}
		var fe *endpoint.Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T: %v", err, err)
		}
		if fe.Path != endpoint.PathDirect || fe.Stage != endpoint.StageValidate || fe.Code != endpoint.CodeMissingChannelID {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for error")
	}
}

func TestAcceptDirectWSResolved_WhitespaceChannelID_ReturnsMissingChannelID(t *testing.T) {
	t.Parallel()

	errCh := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer c.Close()

		handshakeTimeout := 200 * time.Millisecond
		_, err = endpoint.AcceptDirectWSResolved(context.Background(), c, endpoint.AcceptDirectResolverOptions{
			HandshakeTimeout: &handshakeTimeout,
			ClockSkew:        0,
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				return endpoint.DirectHandshakeSecrets{
					PSK:               make([]byte, 32),
					InitExpireAtUnixS: time.Now().Add(60 * time.Second).Unix(),
				}, nil
			},
		})
		errCh <- err
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer c.Close()

	initJSON, err := json.Marshal(&e2eev1.E2EE_Init{
		ChannelId: " \t\r\n",
		Role:      e2eev1.Role_client,
		Version:   e2ee.ProtocolVersion,
	})
	if err != nil {
		t.Fatalf("marshal init: %v", err)
	}
	if err := c.WriteMessage(websocket.BinaryMessage, e2ee.EncodeHandshakeFrame(e2ee.HandshakeTypeInit, initJSON)); err != nil {
		t.Fatalf("write init frame: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected error")
		}
		var fe *endpoint.Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T: %v", err, err)
		}
		if fe.Path != endpoint.PathDirect || fe.Stage != endpoint.StageValidate || fe.Code != endpoint.CodeMissingChannelID {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for error")
	}
}

func TestAcceptDirectWSResolved_InvalidInitSkipsResolver(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		mutate    func(*e2eev1.E2EE_Init)
		wantStage endpoint.Stage
		wantCode  endpoint.Code
	}{
		{
			name: "surrounding whitespace",
			mutate: func(init *e2eev1.E2EE_Init) {
				init.ChannelId = " channel-id "
			},
			wantStage: endpoint.StageValidate,
			wantCode:  endpoint.CodeInvalidInput,
		},
		{
			name: "too long channel ID",
			mutate: func(init *e2eev1.E2EE_Init) {
				init.ChannelId = strings.Repeat("x", 257)
			},
			wantStage: endpoint.StageValidate,
			wantCode:  endpoint.CodeInvalidInput,
		},
		{
			name: "invalid version",
			mutate: func(init *e2eev1.E2EE_Init) {
				init.Version = e2ee.ProtocolVersion + 1
			},
			wantStage: endpoint.StageHandshake,
			wantCode:  endpoint.CodeHandshakeFailed,
		},
		{
			name: "invalid role",
			mutate: func(init *e2eev1.E2EE_Init) {
				init.Role = e2eev1.Role_server
			},
			wantStage: endpoint.StageHandshake,
			wantCode:  endpoint.CodeHandshakeFailed,
		},
		{
			name: "invalid suite",
			mutate: func(init *e2eev1.E2EE_Init) {
				init.Suite = e2eev1.Suite(99)
			},
			wantStage: endpoint.StageHandshake,
			wantCode:  endpoint.CodeHandshakeFailed,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			errCh := make(chan error, 1)
			var resolverCalled atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
				if err != nil {
					t.Errorf("upgrade websocket: %v", err)
					return
				}
				defer c.Close()
				handshakeTimeout := 200 * time.Millisecond
				_, err = endpoint.AcceptDirectWSResolved(context.Background(), c, endpoint.AcceptDirectResolverOptions{
					HandshakeTimeout: &handshakeTimeout,
					Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
						resolverCalled.Store(true)
						return endpoint.DirectHandshakeSecrets{}, errors.New("resolver must not be called")
					},
				})
				errCh <- err
			}))
			t.Cleanup(srv.Close)

			c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
			if err != nil {
				t.Fatalf("dial websocket: %v", err)
			}
			defer c.Close()
			init := &e2eev1.E2EE_Init{
				ChannelId: "channel-id",
				Role:      e2eev1.Role_client,
				Version:   e2ee.ProtocolVersion,
				Suite:     e2eev1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
			}
			tt.mutate(init)
			initJSON, err := json.Marshal(init)
			if err != nil {
				t.Fatalf("marshal init: %v", err)
			}
			if err := c.WriteMessage(websocket.BinaryMessage, e2ee.EncodeHandshakeFrame(e2ee.HandshakeTypeInit, initJSON)); err != nil {
				t.Fatalf("write init frame: %v", err)
			}

			select {
			case got := <-errCh:
				var structured *endpoint.Error
				if !errors.As(got, &structured) {
					t.Fatalf("expected *endpoint.Error, got %T: %v", got, got)
				}
				if structured.Path != endpoint.PathDirect || structured.Stage != tt.wantStage || structured.Code != tt.wantCode {
					t.Fatalf("unexpected error: %+v", structured)
				}
				if resolverCalled.Load() {
					t.Fatal("resolver was called for an invalid handshake init")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for validation error")
			}
		})
	}
}

func TestAcceptDirectWS_ZeroClockSkewDoesNotUseDefaultAcceptanceWindow(t *testing.T) {
	t.Parallel()

	origin := "http://example.com"
	channelID := "ch_1"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(-2 * time.Second).Unix()
	errCh := make(chan error, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer c.Close()

		_, err = endpoint.AcceptDirectWS(context.Background(), c, endpoint.AcceptDirectOptions{
			ChannelID:           channelID,
			PSK:                 psk,
			Suite:               endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS:   initExp,
			ClockSkew:           0,
			HandshakeTimeout:    durationPtr(2 * time.Second),
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
		})
		errCh <- err
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	info := &directv1.DirectConnectInfo{
		WsUrl:                    wsURL,
		ChannelId:                channelID,
		E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
		ChannelInitExpireAtUnixS: initExp,
		DefaultSuite:             directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
	}

	_, err := client.ConnectDirect(
		context.Background(),
		info,
		client.WithOrigin(origin),
		client.WithConnectTimeout(2*time.Second),
		client.WithHandshakeTimeout(2*time.Second),
		client.WithMaxRecordBytes(1<<20),
		client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
	)
	if err == nil {
		t.Fatalf("expected client handshake error")
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected error")
		}
		var fe *endpoint.Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T: %v", err, err)
		}
		if fe.Path != endpoint.PathDirect || fe.Stage != endpoint.StageHandshake {
			t.Fatalf("unexpected error: %+v", fe)
		}
		switch fe.Code {
		case endpoint.CodeTimestampAfterInitExp, endpoint.CodeTimestampOutOfSkew:
		default:
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for error")
	}
}
