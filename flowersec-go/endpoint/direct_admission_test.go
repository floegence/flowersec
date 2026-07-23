package endpoint_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/client"
	"github.com/floegence/flowersec/flowersec-go/v2/endpoint"
	"github.com/gorilla/websocket"
)

const directAdmissionOrigin = "http://example.com"

func TestDirectHandlersRejectNegativeMaxPendingHandshakes(t *testing.T) {
	tests := []struct {
		name string
		new  func() error
	}{
		{
			name: "fixed",
			new: func() error {
				_, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
					AllowedOrigins:       []string{directAdmissionOrigin},
					MaxPendingHandshakes: -1,
					OnStream:             func(context.Context, string, io.ReadWriteCloser) {},
				})
				return err
			},
		},
		{
			name: "resolved",
			new: func() error {
				_, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
					AllowedOrigins:       []string{directAdmissionOrigin},
					MaxPendingHandshakes: -1,
					OnStream:             func(context.Context, string, io.ReadWriteCloser) {},
				})
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.new()
			if err == nil || !strings.Contains(err.Error(), "MaxPendingHandshakes") {
				t.Fatalf("error = %v, want MaxPendingHandshakes validation", err)
			}
		})
	}
}

func TestDirectHandlersRejectExcessPendingHandshakeBeforeUpgrade(t *testing.T) {
	for _, kind := range []string{"fixed", "resolved"} {
		t.Run(kind, func(t *testing.T) {
			errCh := make(chan error, 2)
			handler := newAdmissionTestHandler(t, kind, 1, 2*time.Second, nil, errCh)
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)
			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

			first := dialPendingHandshake(t, wsURL)
			second, response, err := newAdmissionTestDialer().DialContext(context.Background(), wsURL, nil)
			if second != nil {
				_ = second.Close()
			}
			if err == nil {
				t.Fatal("handshake beyond the admission limit was upgraded")
			}
			if response == nil || response.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status = %v, want 503", responseStatus(response))
			}
			if response.Body != nil {
				_ = response.Body.Close()
			}
			assertDirectHandlerError(t, errCh, endpoint.StageHandshake, endpoint.CodeResourceExhausted)

			_ = first.Close()
			waitDirectHandlerError(t, errCh)
			third := dialPendingHandshake(t, wsURL)
			_ = third.Close()
			waitDirectHandlerError(t, errCh)
		})
	}
}

func TestDirectHandlersReleaseAdmissionAfterRequestCancellation(t *testing.T) {
	for _, kind := range []string{"fixed", "resolved"} {
		t.Run(kind, func(t *testing.T) {
			errCh := make(chan error, 2)
			base := newAdmissionTestHandler(t, kind, 1, 2*time.Second, nil, errCh)
			cancelCh := make(chan context.CancelFunc, 1)
			var requestCount atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requestCount.Add(1) == 1 {
					ctx, cancel := context.WithCancel(r.Context())
					cancelCh <- cancel
					base.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				base.ServeHTTP(w, r)
			})
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)
			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

			first := dialPendingHandshake(t, wsURL)
			cancel := <-cancelCh
			cancel()
			assertDirectHandlerError(t, errCh, endpoint.StageHandshake, endpoint.CodeCanceled)
			_ = first.Close()

			second := dialPendingHandshake(t, wsURL)
			_ = second.Close()
			waitDirectHandlerError(t, errCh)
		})
	}
}

func TestDirectHandlersReleaseAdmissionAfterHandshakeTimeout(t *testing.T) {
	for _, kind := range []string{"fixed", "resolved"} {
		t.Run(kind, func(t *testing.T) {
			errCh := make(chan error, 2)
			handler := newAdmissionTestHandler(t, kind, 1, 25*time.Millisecond, nil, errCh)
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)
			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

			first := dialPendingHandshake(t, wsURL)
			assertDirectHandlerError(t, errCh, endpoint.StageHandshake, endpoint.CodeTimeout)
			_ = first.Close()
			second := dialPendingHandshake(t, wsURL)
			assertDirectHandlerError(t, errCh, endpoint.StageHandshake, endpoint.CodeTimeout)
			_ = second.Close()
		})
	}
}

func TestDirectHandlerResolvedReleasesAdmissionAfterResolverPanic(t *testing.T) {
	psk := make([]byte, 32)
	initExp := time.Now().Add(2 * time.Minute).Unix()
	errCh := make(chan error, 2)
	handler := newAdmissionTestHandler(t, "resolved", 1, 2*time.Second, func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
		panic("resolver panic")
	}, errCh)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	connected, err := client.ConnectDirect(
		context.Background(),
		directInfo(wsURL, "ch_resolver_panic", psk, initExp),
		directClientOptions(directAdmissionOrigin)...,
	)
	if connected != nil {
		_ = connected.Close()
	}
	if err == nil {
		t.Fatal("resolver panic connection unexpectedly succeeded")
	}
	var structured *endpoint.Error
	serverErr := waitDirectHandlerError(t, errCh)
	if !errors.As(serverErr, &structured) || structured.Code != endpoint.CodeResolveFailed {
		t.Fatalf("server error = %v, want resolve_failed", serverErr)
	}

	pending := dialPendingHandshake(t, wsURL)
	_ = pending.Close()
	waitDirectHandlerError(t, errCh)
}

func TestDirectHandlersReleaseAdmissionAfterSessionCreation(t *testing.T) {
	for _, kind := range []string{"fixed", "resolved"} {
		t.Run(kind, func(t *testing.T) {
			psk := make([]byte, 32)
			initExp := time.Now().Add(2 * time.Minute).Unix()
			errCh := make(chan error, 2)
			handler := newAdmissionTestHandler(t, kind, 1, 2*time.Second, nil, errCh)
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)
			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

			connected, err := client.ConnectDirect(
				context.Background(),
				directInfo(wsURL, "ch_admission", psk, initExp),
				directClientOptions(directAdmissionOrigin)...,
			)
			if err != nil {
				t.Fatalf("ConnectDirect() failed: %v", err)
			}
			defer connected.Close()

			pending := dialPendingHandshake(t, wsURL)
			_ = pending.Close()
			waitDirectHandlerError(t, errCh)
		})
	}
}

func TestDirectHandlerReleasesAdmissionDuringPanicUnwind(t *testing.T) {
	for _, kind := range []string{"fixed", "resolved"} {
		t.Run(kind, func(t *testing.T) {
			var checks atomic.Int32
			upgrader := endpoint.UpgraderOptions{CheckOrigin: func(*http.Request) bool {
				if checks.Add(1) == 1 {
					panic("origin checker panic")
				}
				return true
			}}
			onStream := func(context.Context, string, io.ReadWriteCloser) {}
			var handler http.HandlerFunc
			var err error
			if kind == "fixed" {
				handler, err = endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
					Upgrader:             upgrader,
					MaxPendingHandshakes: 1,
					OnStream:             onStream,
				})
			} else {
				handler, err = endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
					Upgrader:             upgrader,
					MaxPendingHandshakes: 1,
					OnStream:             onStream,
				})
			}
			if err != nil {
				t.Fatalf("new handler failed: %v", err)
			}

			call := func() *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/ws", nil)
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Origin", directAdmissionOrigin)
				req.Header.Set("Sec-WebSocket-Version", "13")
				req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				rec := httptest.NewRecorder()
				handler(rec, req)
				return rec
			}

			func() {
				defer func() {
					if recovered := recover(); recovered == nil {
						t.Fatal("CheckOrigin panic was not propagated")
					}
				}()
				call()
			}()

			if response := call(); response.Code == http.StatusServiceUnavailable {
				t.Fatal("admission slot was not released while unwinding the panic")
			}
		})
	}
}

func newAdmissionTestHandler(
	t *testing.T,
	kind string,
	maxPending int,
	timeout time.Duration,
	resolve func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error),
	errCh chan<- error,
) http.Handler {
	t.Helper()
	psk := make([]byte, 32)
	initExp := time.Now().Add(2 * time.Minute).Unix()
	onStream := func(context.Context, string, io.ReadWriteCloser) {}
	onError := func(err error) { errCh <- err }
	if kind == "fixed" {
		handler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
			Upgrader:             endpoint.UpgraderOptions{CheckOrigin: func(*http.Request) bool { return true }},
			MaxPendingHandshakes: maxPending,
			Handshake: endpoint.AcceptDirectOptions{
				ChannelID:         "ch_admission",
				PSK:               psk,
				InitExpireAtUnixS: initExp,
				HandshakeTimeout:  &timeout,
			},
			OnStream: onStream,
			OnError:  onError,
		})
		if err != nil {
			t.Fatalf("NewDirectHandler() failed: %v", err)
		}
		return handler
	}
	if resolve == nil {
		resolve = func(context.Context, endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
			return endpoint.DirectHandshakeSecrets{PSK: psk, InitExpireAtUnixS: initExp}, nil
		}
	}
	handler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		Upgrader:             endpoint.UpgraderOptions{CheckOrigin: func(*http.Request) bool { return true }},
		MaxPendingHandshakes: maxPending,
		Handshake: endpoint.AcceptDirectResolverOptions{
			HandshakeTimeout: &timeout,
			Resolve:          resolve,
		},
		OnStream: onStream,
		OnError:  onError,
	})
	if err != nil {
		t.Fatalf("NewDirectHandlerResolved() failed: %v", err)
	}
	return handler
}

func dialPendingHandshake(t *testing.T, wsURL string) *websocket.Conn {
	t.Helper()
	conn, response, err := newAdmissionTestDialer().DialContext(context.Background(), wsURL, nil)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("dial pending handshake: %v (status=%v)", err, responseStatus(response))
	}
	return conn
}

func newAdmissionTestDialer() *websocket.Dialer {
	return &websocket.Dialer{HandshakeTimeout: time.Second}
}

func waitDirectHandlerError(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for direct handler error")
		return nil
	}
}

func responseStatus(response *http.Response) any {
	if response == nil {
		return nil
	}
	return response.StatusCode
}
