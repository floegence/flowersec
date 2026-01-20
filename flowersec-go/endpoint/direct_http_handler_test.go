package endpoint_test

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

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

func TestNewDirectHandler_OriginPolicy(t *testing.T) {
	t.Parallel()

	_, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{})
	if err == nil {
		t.Fatal("expected error")
	}

	if _, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowNoOrigin: true,
		OnStream:      func(context.Context, string, io.ReadWriteCloser) {},
	}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins: []string{""},
		OnStream:       func(context.Context, string, io.ReadWriteCloser) {},
	}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins: []string{"example.com"},
		OnStream:       func(context.Context, string, io.ReadWriteCloser) {},
	}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		Upgrader: endpoint.UpgraderOptions{CheckOrigin: func(*http.Request) bool { return true }},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
	}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestNewDirectHandlerResolved_OriginPolicy(t *testing.T) {
	t.Parallel()

	if _, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowNoOrigin: true,
		Handshake: endpoint.AcceptDirectResolverOptions{
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				return endpoint.DirectHandshakeSecrets{}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
	}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{""},
		Handshake: endpoint.AcceptDirectResolverOptions{
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				return endpoint.DirectHandshakeSecrets{}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
	}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{"example.com"},
		Handshake: endpoint.AcceptDirectResolverOptions{
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				return endpoint.DirectHandshakeSecrets{}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
	}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		Upgrader: endpoint.UpgraderOptions{CheckOrigin: func(*http.Request) bool { return true }},
		Handshake: endpoint.AcceptDirectResolverOptions{
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				return endpoint.DirectHandshakeSecrets{}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
	}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestNewDirectHandler_MissingOnStream(t *testing.T) {
	t.Parallel()

	_, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins: []string{"example.com"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "OnStream") {
		t.Fatalf("expected error to mention OnStream, got %v", err)
	}
}

func TestNewDirectHandlerResolved_MissingOnStream(t *testing.T) {
	t.Parallel()

	_, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{"example.com"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "OnStream") {
		t.Fatalf("expected error to mention OnStream, got %v", err)
	}
}

func TestDirectHandler_AllowsConnectDirect(t *testing.T) {
	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	mux := http.NewServeMux()
	wsHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins: []string{origin},
		AllowNoOrigin:  false,
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

func TestDirectHandler_OnError_HandlerPanic(t *testing.T) {
	t.Parallel()

	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	wsHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins: []string{origin},
		AllowNoOrigin:  false,
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
		OnStream: func(context.Context, string, io.ReadWriteCloser) {
			panic("boom")
		},
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
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
	defer c.Close()

	select {
	case got := <-errCh:
		if got == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(got.Error(), "direct stream handler panic") {
			t.Fatalf("unexpected error: %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for OnError")
	}
}

func TestDirectHandlerResolved_AllowsConnectDirect(t *testing.T) {
	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	mux := http.NewServeMux()
	wsHandler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{origin},
		AllowNoOrigin:  false,
		Handshake: endpoint.AcceptDirectResolverOptions{
			ClockSkew:           30 * time.Second,
			HandshakeTimeout:    2 * time.Second,
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
			Resolve: func(_ context.Context, init endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				if init.ChannelID != channelID {
					return endpoint.DirectHandshakeSecrets{}, errors.New("unknown channel")
				}
				return endpoint.DirectHandshakeSecrets{PSK: psk, InitExpireAtUnixS: initExp}, nil
			},
		},
		OnStream: func(_ context.Context, _kind string, stream io.ReadWriteCloser) {
			_ = stream.Close()
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
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

func TestDirectHandlerResolved_OnError_HandlerPanic(t *testing.T) {
	t.Parallel()

	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	wsHandler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{origin},
		AllowNoOrigin:  false,
		Handshake: endpoint.AcceptDirectResolverOptions{
			ClockSkew:           30 * time.Second,
			HandshakeTimeout:    2 * time.Second,
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
			Resolve: func(_ context.Context, init endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				if init.ChannelID != channelID {
					return endpoint.DirectHandshakeSecrets{}, errors.New("unknown channel")
				}
				return endpoint.DirectHandshakeSecrets{PSK: psk, InitExpireAtUnixS: initExp}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {
			panic("boom")
		},
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
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
	defer c.Close()

	select {
	case got := <-errCh:
		if got == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(got.Error(), "direct stream handler panic") {
			t.Fatalf("unexpected error: %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for OnError")
	}
}

func TestDirectHandlerResolved_OnError_ResolveFailed(t *testing.T) {
	t.Parallel()

	origin := "http://example.com"
	channelID := "ch_test"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(120 * time.Second).Unix()

	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	wsHandler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{origin},
		AllowNoOrigin:  false,
		Handshake: endpoint.AcceptDirectResolverOptions{
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				return endpoint.DirectHandshakeSecrets{}, errors.New("nope")
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
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
		DefaultSuite:             directv1.Suite(endpoint.SuiteX25519HKDFAES256GCM),
	}
	_, _ = client.ConnectDirect(
		context.Background(),
		info,
		client.WithOrigin(origin),
		client.WithConnectTimeout(2*time.Second),
		client.WithHandshakeTimeout(2*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)

	select {
	case got := <-errCh:
		var fe *endpoint.Error
		if !errors.As(got, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T", got)
		}
		if fe.Path != endpoint.PathDirect || fe.Stage != endpoint.StageValidate || fe.Code != endpoint.CodeResolveFailed {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for OnError")
	}
}

func TestDirectHandler_OnError_UpgradeFailed(t *testing.T) {
	t.Parallel()

	origin := "http://example.com"
	errCh := make(chan error, 1)
	wsHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins: []string{origin},
		OnStream:       func(context.Context, string, io.ReadWriteCloser) {},
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandler() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/ws", nil)
	rec := httptest.NewRecorder()
	wsHandler(rec, req)

	select {
	case got := <-errCh:
		var fe *endpoint.Error
		if !errors.As(got, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T", got)
		}
		if fe.Path != endpoint.PathDirect || fe.Stage != endpoint.StageConnect || fe.Code != endpoint.CodeUpgradeFailed {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for OnError")
	}
}

func TestDirectHandler_OnError_MissingOrigin(t *testing.T) {
	t.Parallel()

	origin := "http://example.com"
	errCh := make(chan error, 1)
	wsHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins: []string{origin},
		OnStream:       func(context.Context, string, io.ReadWriteCloser) {},
		OnError: func(err error) {
			select {
			case errCh <- err:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandler() failed: %v", err)
	}

	// WebSocket upgrade attempt without Origin.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	rec := httptest.NewRecorder()
	wsHandler(rec, req)

	select {
	case got := <-errCh:
		var fe *endpoint.Error
		if !errors.As(got, &fe) {
			t.Fatalf("expected *endpoint.Error, got %T", got)
		}
		if fe.Path != endpoint.PathDirect || fe.Stage != endpoint.StageValidate || fe.Code != endpoint.CodeMissingOrigin {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for OnError")
	}
}
