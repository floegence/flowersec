package flowersec

import (
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
