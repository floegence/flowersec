package endpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
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
