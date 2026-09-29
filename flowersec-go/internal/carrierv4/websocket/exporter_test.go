package websocket

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestWSSExporterUsesOriginalHijackedTLS(t *testing.T) {
	options := testOptions()
	charge, err := Charge(options)
	if err != nil {
		t.Fatal(err)
	}
	_, clientRef, clientEnv := reservations(t, charge)
	_, serverRef, serverEnv := reservations(t, charge)
	type result struct {
		messages *Messages
		err      error
	}
	accepted := make(chan result, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, err := Upgrade(r.Context(), w, r, UpgradeConfig{Subprotocol: SubprotocolDirect, CheckPolicy: func(*http.Request) error { return nil },
			CheckAcceptedRoute: func(protocolv4.AcceptedWebSocketEndpoint, *protocolv4.SignedMap, uint64, protocolv4.HelloPolicy) error {
				return nil
			}}, options, serverRef, serverEnv)
		accepted <- result{m, err}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := Dial(context.Background(), DialConfig{URL: "wss" + strings.TrimPrefix(server.URL, "https") + "/flowersec/v4/direct",
		RemoteAddress: preparedAddress(t, server.URL), Subprotocol: SubprotocolDirect, TLSConfig: server.Client().Transport.(*http.Transport).TLSClientConfig,
		CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { return nil }}, options, clientRef, clientEnv)
	if err != nil {
		t.Fatal(err)
	}
	cleanupMessages(t, client)
	peer := <-accepted
	if peer.err != nil {
		t.Fatal(peer.err)
	}
	cleanupMessages(t, peer.messages)
	artifact := [32]byte{9, 1}
	left, err := client.ExportBinding(artifact)
	if err != nil {
		t.Fatal(err)
	}
	right, err := peer.messages.ExportBinding(artifact)
	if err != nil || left != right || left == ([32]byte{}) {
		t.Fatal("original WSS exporters differ", err)
	}
	state := client.tlsConnection.ConnectionState()
	exact, err := state.ExportKeyingMaterial("EXPORTER-flowersec-v4", artifact[:], 32)
	if err != nil || !bytes.Equal(exact, left[:]) {
		t.Fatal("WSS exporter inputs changed", err)
	}
	other, err := peer.messages.ExportBinding([32]byte{9, 2})
	if err != nil || other == left {
		t.Fatal("WSS artifact context omitted", err)
	}
	if err := peer.messages.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.messages.ExportBinding(artifact); err == nil {
		t.Fatal("closed WSS retained exporter authority")
	}
}
