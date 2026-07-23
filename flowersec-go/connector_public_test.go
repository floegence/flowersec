package flowersec_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
)

func TestConnectorPublicSurfaceIsCarrierNeutral(t *testing.T) {
	optionsType := reflect.TypeOf(flowersec.ConnectorOptions{})
	wantFields := []string{"TrustRoots", "Origin", "ConnectTimeout"}
	if optionsType.NumField() != len(wantFields) {
		t.Fatalf("ConnectorOptions has %d fields, want %d", optionsType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if got := optionsType.Field(index).Name; got != want {
			t.Fatalf("ConnectorOptions field %d = %q, want %q", index, got, want)
		}
	}

	options := flowersec.ConnectorOptions{
		TrustRoots: x509.NewCertPool(), Origin: "https://client.example",
		ConnectTimeout: time.Second,
	}
	var connector *flowersec.Connector
	var connect func(context.Context) (flowersec.Session, error)
	_ = options
	if connector != nil {
		connect = connector.Connect
	}
	_ = connect
	if got, want := fmt.Sprintf("%v %#v", connector, connector), "Flowersec.Connector flowersec.Connector"; got != want {
		t.Fatalf("connector formatting = %q, want %q", got, want)
	}
}

func TestUnreliableMessagePublicSurfaceIsOpaqueAndCarrierNeutral(t *testing.T) {
	channel := reflect.TypeOf((*flowersec.UnreliableMessageChannel)(nil)).Elem()
	if channel.NumMethod() != 3 {
		t.Fatalf("UnreliableMessageChannel methods = %d, want 3", channel.NumMethod())
	}
	for index := range channel.NumMethod() {
		signature := channel.Method(index).Type.String()
		for _, forbidden := range []string{"Artifact", "Credential", "Admission", "Handshake", "Control", "Carrier", "QUIC", "WebTransport", "Yamux"} {
			if strings.Contains(signature, forbidden) {
				t.Fatalf("public unreliable signature %q exposes %q", signature, forbidden)
			}
		}
	}
	options := reflect.TypeOf(flowersec.UnreliableSendOptions{})
	if options.NumField() != 1 || options.Field(0).Name != "ExpiresAt" || options.Field(0).Type != reflect.TypeOf(time.Time{}) {
		t.Fatalf("UnreliableSendOptions = %v", options)
	}
	wantStatuses := []flowersec.UnreliableSendStatus{
		flowersec.UnreliableAccepted,
		flowersec.UnreliableDroppedExpired,
		flowersec.UnreliableDroppedBudget,
		flowersec.UnreliableDroppedCarrier,
	}
	for _, status := range wantStatuses {
		if status == "" {
			t.Fatal("empty unreliable send status")
		}
	}
}

func TestConnectErrorPublicSnapshotContainsNoInternalDetail(t *testing.T) {
	var err *flowersec.ConnectError
	want := "<nil>"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if err.Code() != flowersec.ConnectFailed {
		t.Fatalf("nil ConnectError code = %q, want %q", err.Code(), flowersec.ConnectFailed)
	}
	var _ interface{ Is(error) bool } = err
	var _ interface{ Unwrap() error } = (*flowersec.SessionError)(nil)
}

func TestRPCErrorPublicSnapshotPreservesApplicationSemantics(t *testing.T) {
	errorType := reflect.TypeOf(flowersec.RPCError{})
	wantFields := []string{"Code", "Message"}
	if errorType.NumField() != len(wantFields) {
		t.Fatalf("RPCError has %d fields, want %d", errorType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if got := errorType.Field(index).Name; got != want {
			t.Fatalf("RPCError field %d = %q, want %q", index, got, want)
		}
	}
	pointerType := reflect.PointerTo(errorType)
	if pointerType.NumMethod() != 1 || pointerType.Method(0).Name != "Error" {
		t.Fatalf("RPCError methods = %v, want only Error", pointerType)
	}

	err := &flowersec.RPCError{Code: 404, Message: "handler not found"}
	if got, want := err.Error(), "Flowersec RPC failed (code=404)"; got != want {
		t.Fatalf("RPC Error() = %q, want %q", got, want)
	}
	if err.Code != 404 || err.Message != "handler not found" {
		t.Fatalf("RPC error = %#v, want application code/message", err)
	}
	var _ error = err
}

func TestConnectorRejectsInvalidCarrierNeutralOptions(t *testing.T) {
	artifact := parseFixtureArtifact(t)
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flowersec.NewConnector(lease, flowersec.ConnectorOptions{
		TrustRoots: x509.NewCertPool(),
	}); err != flowersec.ErrInvalidConnectorOptions {
		t.Fatalf("NewConnector error = %v, want ErrInvalidConnectorOptions", err)
	}
	for _, origin := range []string{"", "http://client.example", "https://user@client.example", "https://client.example/path"} {
		if _, err := flowersec.NewConnector(lease, flowersec.ConnectorOptions{
			TrustRoots: fixtureTrustRoots(t), Origin: origin,
		}); err != flowersec.ErrInvalidConnectorOptions {
			t.Fatalf("NewConnector origin %q error = %v, want ErrInvalidConnectorOptions", origin, err)
		}
	}
}

func fixtureTrustRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil || len(pool.Subjects()) == 0 {
		t.Skip("system trust roots unavailable")
	}
	return pool
}
