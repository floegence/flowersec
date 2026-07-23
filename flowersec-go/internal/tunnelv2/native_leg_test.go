package tunnelv2_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
)

func TestNativeStreamLegDelaysResponseAndRejectsExtraStreams(t *testing.T) {
	endpoint, tunnelSession := memorySessionPair(carrier.KindQUIC)
	admissionClient, admissionServer := memoryStreamPair()
	leg, err := tunnelv2.NewNativeStreamLeg(tunnelSession, admissionServer)
	if err != nil {
		t.Fatal(err)
	}
	raw := validTunnelFSB2(t, 1, "client", "attach-token")
	clientWriteDone := make(chan error, 1)
	go func() {
		_, writeErr := admissionClient.Write(raw)
		clientWriteDone <- errors.Join(writeErr, admissionClient.CloseWrite())
	}()
	decoded, err := leg.ReceiveAdmission(context.Background())
	if err != nil {
		t.Fatalf("ReceiveAdmission: %v", err)
	}
	if err := <-clientWriteDone; err != nil {
		t.Fatal(err)
	}
	if decoded.Request.EndpointInstanceID != "client" {
		t.Fatalf("decoded request = %+v", decoded.Request)
	}

	guardCtx, cancelGuard := context.WithCancel(context.Background())
	guardDone := make(chan error, 1)
	go func() { guardDone <- leg.RejectWaitingStreams(guardCtx) }()
	extra, err := endpoint.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := extra.Write([]byte("must-reset"))
		writeDone <- writeErr
	}()
	select {
	case writeErr := <-writeDone:
		if writeErr == nil {
			t.Fatal("waiting native stream was not reset")
		}
	case <-time.After(time.Second):
		t.Fatal("extra stream reset did not unblock writer")
	}
	cancelGuard()
	if err := <-guardDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("RejectWaitingStreams error = %v", err)
	}

	responseDone := make(chan error, 1)
	go func() {
		response, readErr := artifactv2.ReadResponse(admissionClient, tunnelv2.DefaultReasonRegistry())
		if readErr == nil && response.Status != artifactv2.AdmissionSuccess {
			readErr = errors.New("unexpected admission response")
		}
		if readErr == nil {
			var one [1]byte
			if n, eofErr := admissionClient.Read(one[:]); n != 0 || !errors.Is(eofErr, io.EOF) {
				readErr = errors.New("admission response did not end in FIN")
			}
		}
		responseDone <- readErr
	}()
	if err := leg.SendAdmission(context.Background(), artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, tunnelv2.DefaultReasonRegistry()); err != nil {
		t.Fatalf("SendAdmission: %v", err)
	}
	if err := <-responseDone; err != nil {
		t.Fatal(err)
	}
	session, err := leg.Activate(context.Background())
	if err != nil || session != tunnelSession {
		t.Fatalf("Activate = %T/%v", session, err)
	}
}

func validTunnelFSB2(t *testing.T, role uint8, endpoint, token string) []byte {
	return validTunnelFSB2ForCarrier(t, role, endpoint, token, artifactv2.CarrierRawQUIC)
}

func validTunnelFSB2ForCarrier(t *testing.T, role uint8, endpoint, token string, chosenCarrier artifactv2.Carrier) []byte {
	t.Helper()
	session := artifactv2.SessionContract{
		ChannelID: "channel", InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: 32, AllowedSuites: []uint16{1}, DefaultSuite: 1,
	}
	for index := range session.E2EEPSK {
		session.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(session)
	if err != nil {
		t.Fatal(err)
	}
	session.ContractHash = hash
	expected := "server"
	if role == 2 {
		expected = "client"
	}
	artifact := artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: session,
		Path: artifactv2.ArtifactPath{
			Kind: artifactv2.PathTunnel, RendezvousGroupID: "group", ListenerAudience: "listener",
			Role: role, LocalEndpointInstanceID: endpoint, ExpectedPeerEndpointInstanceID: expected,
			Token: token, Candidates: []artifactv2.Candidate{
				{ID: "q1", Carrier: artifactv2.CarrierRawQUIC, URL: "quic://example.test:443", WireProfile: "flowersec-tunnel/2"},
				{ID: "t1", Carrier: artifactv2.CarrierWebTransport, URL: "https://example.test/flowersec/webtransport/v2/tunnel", WireProfile: "flowersec-tunnel/2"},
				{ID: "w1", Carrier: artifactv2.CarrierWebSocket, URL: "wss://example.test/flowersec/v2/tunnel", WireProfile: "flowersec-tunnel/2"},
			},
		},
		Scoped:      []artifactv2.ScopeMetadata{},
		Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
	chosenID := map[artifactv2.Carrier]string{
		artifactv2.CarrierRawQUIC: "q1", artifactv2.CarrierWebTransport: "t1", artifactv2.CarrierWebSocket: "w1",
	}[chosenCarrier]
	request, err := artifactv2.BuildRequest(artifact, chosenID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
