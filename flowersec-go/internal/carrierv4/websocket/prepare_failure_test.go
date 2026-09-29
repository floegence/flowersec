package websocket

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	ws "github.com/gorilla/websocket"
)

func TestPrepareConnectionInterruptionRetainsOriginalSocketSource(t *testing.T) {
	for _, tc := range []struct {
		name, scheme, response string
		interrupted            bool
	}{
		{"http_empty", "ws", "", true},
		{"http_truncated", "ws", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n", true},
		{"http_malformed", "ws", "invalid response\r\n\r\n", false},
		{"http_refused_then_disconnect", "ws", "HTTP/1.1 403 Forbidden\r\nContent-Length: 32\r\n\r\n", false},
		{"tls_empty", "wss", "", true},
		{"tls_truncated", "wss", "\x16\x03\x03\x00\x20\x02", true},
		{"tls_plaintext", "wss", "HTTP/1.1 403 Forbidden\r\n\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			exited := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					exited <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if tc.scheme == "ws" {
					_, err = http.ReadRequest(bufio.NewReader(conn))
				} else {
					var header [5]byte
					_, err = io.ReadFull(conn, header[:])
					if err == nil {
						_, err = io.CopyN(io.Discard, conn, int64(header[3])<<8|int64(header[4]))
					}
				}
				if err == nil && tc.response != "" {
					_, err = io.WriteString(conn, tc.response)
				}
				exited <- err
			}()
			options := testOptions()
			charge, err := Charge(options)
			if err != nil {
				t.Fatal(err)
			}
			root, ref, environment := reservations(t, charge)
			before := root.Snapshot().Charged
			endpoint := listener.Addr().(*net.TCPAddr).AddrPort()
			config := DialConfig{URL: tc.scheme + "://" + endpoint.String() + "/flowersec/v4/local", RemoteAddress: endpoint, Subprotocol: SubprotocolLocal,
				CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { return nil }}
			if tc.scheme == "wss" {
				config.Subprotocol = SubprotocolDirect
				config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			}
			messages, err := Dial(context.Background(), config, options, ref, environment)
			if messages != nil || err == nil || (err == native.ErrConnectionLost) != tc.interrupted {
				t.Fatalf("interrupted=%v: %v", tc.interrupted, err)
			}
			if tc.name == "http_refused_then_disconnect" && !errors.Is(err, ws.ErrBadHandshake) {
				t.Fatal("body interruption replaced HTTP refusal", err)
			}
			if err := <-exited; err != nil {
				t.Fatal(err)
			}
			after := root.Snapshot().Charged
			for i := range before {
				if before[i]-after[i] != charge[i] {
					t.Fatalf("failed preparation retained charge dimension %d", i)
				}
			}
		})
	}
}

func TestPrepareTLSVerifierCannotSupplySocketInterruption(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	for _, failure := range []error{io.EOF, native.ErrConnectionLost, &prepareInterruption{}} {
		tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tlsConfig.VerifyConnection = func(tls.ConnectionState) error { return failure }
		options := testOptions()
		charge, _ := Charge(options)
		_, ref, environment := reservations(t, charge)
		_, err := Dial(context.Background(), DialConfig{URL: "wss" + strings.TrimPrefix(server.URL, "https"), RemoteAddress: preparedAddress(t, server.URL), Subprotocol: SubprotocolDirect,
			TLSConfig: tlsConfig, CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { return nil }}, options, ref, environment)
		if err == native.ErrConnectionLost || !errors.Is(err, ErrTLSHandshake) || !errors.Is(err, failure) {
			t.Fatal("TLS verifier failure became retry permission", err)
		}
	}
}

func TestPrepareTLSHTTPInterruption(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.(*tls.Conn).NetConn().Close()
		}
	}))
	defer server.Close()
	options := testOptions()
	charge, _ := Charge(options)
	_, ref, environment := reservations(t, charge)
	_, err := Dial(context.Background(), DialConfig{URL: "wss" + strings.TrimPrefix(server.URL, "https"), RemoteAddress: preparedAddress(t, server.URL), Subprotocol: SubprotocolDirect,
		TLSConfig: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { return nil }}, options, ref, environment)
	if err != native.ErrConnectionLost {
		t.Fatal(err)
	}
}
