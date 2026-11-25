package flowersec

import (
	"crypto/tls"
	"net"
	"slices"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
)

func TestDirectIngressChecksProfileAndLocalEndpoint(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	ingress := directIngress{local: local, authority: local.String(), mode: webSocketAdmissionHTTP}
	candidate := artifactv3.CanonicalCandidate{ID: "http-direct", Carrier: artifactv3.CarrierWebSocket,
		NormalizedURL: "wss://127.0.0.1:8080" + WebSocketDirectPath, TLS: artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}}
	decoded := &artifactv3.DecodedRequest{Request: artifactv3.Request{PathKind: artifactv3.PathDirect, ChosenCandidateID: candidate.ID, Candidates: []artifactv3.CanonicalCandidate{candidate}}}
	if _, ok := ingress.match(decoded, candidate.Carrier); !ok {
		t.Fatal("matching local HTTP profile rejected")
	}
	ingress.mode = webSocketAdmissionPrivate
	if _, ok := ingress.match(decoded, candidate.Carrier); ok {
		t.Fatal("accepted a mismatched profile")
	}
	ingress.mode = webSocketAdmissionHTTP
	ingress.local = &net.TCPAddr{IP: local.IP, Port: 8081}
	if _, ok := ingress.match(decoded, candidate.Carrier); ok {
		t.Fatal("accepted a mismatched local listener")
	}
}

func TestDirectIngressForwardedPort(t *testing.T) {
	config, _ := internalWebSocketServerTLS(t)
	const endpoint = "wss://localhost:9443" + WebSocketDirectPath
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7443}
	state := &tls.ConnectionState{Version: tls.VersionTLS13, LocalCertificate: config.Certificates[0].Certificate}
	candidate := artifactv3.CanonicalCandidate{ID: "public", Carrier: artifactv3.CarrierWebSocket, NormalizedURL: endpoint, TLS: artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}}
	decoded := &artifactv3.DecodedRequest{Request: artifactv3.Request{PathKind: artifactv3.PathDirect, ChosenCandidateID: candidate.ID, Candidates: []artifactv3.CanonicalCandidate{candidate}}}
	aliases := []string{endpoint}
	ingress := directIngress{local: local, state: state, authority: "localhost:9443", aliases: func() []string { return aliases }}
	check := func(want bool) {
		t.Helper()
		if _, ok := ingress.match(decoded, candidate.Carrier); ok != want {
			t.Fatalf("authority %q aliases %v: matched=%v, want %v", ingress.authority, aliases, ok, want)
		}
	}
	check(true)
	ingress.authority = "localhost:7443"
	check(false)
	ingress.authority = "localhost:9443"
	state.DidResume = true
	check(false)
	state.DidResume = false
	aliases = []string{"wss://localhost:9444" + WebSocketDirectPath}
	check(false)
	aliases = nil
	check(false)
	ingress.authority = "localhost:7443"
	decoded.Request.Candidates[0].NormalizedURL = "wss://localhost:7443" + WebSocketDirectPath
	check(true)
}

func TestAcceptorAdmissionReasonsAreDirectOnly(t *testing.T) {
	acceptor := &Acceptor{}
	got := make([]string, 0, len(acceptor.reasons()))
	for reason := range acceptor.reasons() {
		got = append(got, reason)
	}
	slices.Sort(got)
	want := []string{"authorization_denied", "authorization_unavailable", "expired_artifact", "permission_denied"}
	if !slices.Equal(got, want) {
		t.Fatalf("Acceptor admission reasons = %v, want direct-only reasons %v", got, want)
	}
}
