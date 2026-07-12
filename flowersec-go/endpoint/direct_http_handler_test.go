package endpoint_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

func durationPtr(d time.Duration) *time.Duration { return &d }

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

func TestNewDirectHandler_NegativeMaxStreamHelloBytes_ReturnsError(t *testing.T) {
	t.Parallel()

	_, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins:      []string{"example.com"},
		MaxStreamHelloBytes: -1,
		OnStream:            func(context.Context, string, io.ReadWriteCloser) {},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "MaxStreamHelloBytes") {
		t.Fatalf("expected error to mention MaxStreamHelloBytes, got %v", err)
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

func TestNewDirectHandlerResolved_NegativeMaxStreamHelloBytes_ReturnsError(t *testing.T) {
	t.Parallel()

	_, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins:      []string{"example.com"},
		MaxStreamHelloBytes: -1,
		Handshake: endpoint.AcceptDirectResolverOptions{
			Resolve: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
				return endpoint.DirectHandshakeSecrets{}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "MaxStreamHelloBytes") {
		t.Fatalf("expected error to mention MaxStreamHelloBytes, got %v", err)
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
			HandshakeTimeout:    durationPtr(2 * time.Second),
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
			HandshakeTimeout:    durationPtr(2 * time.Second),
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
			HandshakeTimeout:    durationPtr(2 * time.Second),
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

func TestDirectHandlerResolved_CommitsOnlyAfterAuthentication(t *testing.T) {
	t.Parallel()
	origin := "http://example.com"
	channelID := "ch_commit"
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 7
	}
	initExp := time.Now().Add(120 * time.Second).Unix()
	var commits atomic.Int32
	errCh := make(chan error, 2)

	handler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{origin},
		Handshake: endpoint.AcceptDirectResolverOptions{
			HandshakeTimeout: durationPtr(2 * time.Second),
			ResolveCredential: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeCredential, error) {
				return endpoint.DirectHandshakeCredential{
					Secrets: endpoint.DirectHandshakeSecrets{PSK: psk, InitExpireAtUnixS: initExp},
					CommitAuthenticated: func(context.Context) error {
						commits.Add(1)
						return nil
					},
				}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
		OnError: func(err error) {
			errCh <- err
		},
	})
	if err != nil {
		t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	wrongPSK := append([]byte(nil), psk...)
	wrongPSK[0] ^= 0xff
	wrongInfo := directInfo(wsURL, channelID, wrongPSK, initExp)
	if _, err := client.ConnectDirect(context.Background(), wrongInfo, directClientOptions(origin)...); err == nil {
		t.Fatal("expected wrong-PSK connect to fail")
	}
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server handshake failure")
	}
	if got := commits.Load(); got != 0 {
		t.Fatalf("commit count after failed authentication = %d, want 0", got)
	}

	connected, err := client.ConnectDirect(context.Background(), directInfo(wsURL, channelID, psk, initExp), directClientOptions(origin)...)
	if err != nil {
		t.Fatalf("authenticated ConnectDirect() failed: %v", err)
	}
	_ = connected.Close()
	if got := commits.Load(); got != 1 {
		t.Fatalf("commit count after authentication = %d, want 1", got)
	}
}

func TestDirectHandlerResolved_CommitFailurePreventsYamux(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		commit func(context.Context) error
	}{
		{name: "error", commit: func(context.Context) error { return errors.New("already consumed") }},
		{name: "panic", commit: func(context.Context) error { panic("boom") }},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			origin := "http://example.com"
			psk := make([]byte, 32)
			initExp := time.Now().Add(120 * time.Second).Unix()
			errCh := make(chan error, 1)
			var streams atomic.Int32
			handler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
				AllowedOrigins: []string{origin},
				Handshake: endpoint.AcceptDirectResolverOptions{
					HandshakeTimeout: durationPtr(2 * time.Second),
					ResolveCredential: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeCredential, error) {
						return endpoint.DirectHandshakeCredential{
							Secrets:             endpoint.DirectHandshakeSecrets{PSK: psk, InitExpireAtUnixS: initExp},
							CommitAuthenticated: tt.commit,
						}, nil
					},
				},
				OnStream: func(context.Context, string, io.ReadWriteCloser) { streams.Add(1) },
				OnError:  func(err error) { errCh <- err },
			})
			if err != nil {
				t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
			}
			srv := httptest.NewServer(handler)
			defer srv.Close()
			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
			if _, err := client.ConnectDirect(context.Background(), directInfo(wsURL, "ch_commit_failure", psk, initExp), directClientOptions(origin)...); err == nil {
				t.Fatal("expected connect failure")
			}
			select {
			case got := <-errCh:
				var structured *endpoint.Error
				if !errors.As(got, &structured) || structured.Stage != endpoint.StageHandshake || structured.Code != endpoint.CodeCredentialCommitFailed {
					t.Fatalf("unexpected server error: %v", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for commit failure")
			}
			if got := streams.Load(); got != 0 {
				t.Fatalf("stream count = %d, want 0", got)
			}
		})
	}
}

func TestDirectHandlerResolved_ConcurrentCommitAllowsOneSession(t *testing.T) {
	t.Parallel()
	origin := "http://example.com"
	psk := make([]byte, 32)
	initExp := time.Now().Add(120 * time.Second).Unix()
	var consumed atomic.Bool
	handler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins: []string{origin},
		Handshake: endpoint.AcceptDirectResolverOptions{
			HandshakeTimeout: durationPtr(2 * time.Second),
			ResolveCredential: func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeCredential, error) {
				return endpoint.DirectHandshakeCredential{
					Secrets: endpoint.DirectHandshakeSecrets{PSK: psk, InitExpireAtUnixS: initExp},
					CommitAuthenticated: func(context.Context) error {
						if !consumed.CompareAndSwap(false, true) {
							return errors.New("already consumed")
						}
						return nil
					},
				}, nil
			},
		},
		OnStream: func(context.Context, string, io.ReadWriteCloser) {},
	})
	if err != nil {
		t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	info := directInfo("ws"+strings.TrimPrefix(srv.URL, "http"), "ch_concurrent", psk, initExp)

	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			connected, err := client.ConnectDirect(context.Background(), info, directClientOptions(origin)...)
			if connected != nil {
				_ = connected.Close()
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful sessions = %d, want 1", successes)
	}
}

func directInfo(wsURL, channelID string, psk []byte, initExp int64) *directv1.DirectConnectInfo {
	return &directv1.DirectConnectInfo{
		WsUrl:                    wsURL,
		ChannelId:                channelID,
		E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
		ChannelInitExpireAtUnixS: initExp,
		DefaultSuite:             directv1.Suite(endpoint.SuiteX25519HKDFAES256GCM),
	}
}

func directClientOptions(origin string) []client.ConnectOption {
	return []client.ConnectOption{
		client.WithOrigin(origin),
		client.WithConnectTimeout(2 * time.Second),
		client.WithHandshakeTimeout(2 * time.Second),
		client.WithMaxRecordBytes(1 << 20),
	}
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
			HandshakeTimeout:    durationPtr(2 * time.Second),
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
