package flowersec_test

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
)

func TestConnectorPublicSurfaceIsCarrierNeutral(t *testing.T) {
	optionsType := reflect.TypeOf(flowersec.ConnectorOptions{})
	wantFields := []string{"TrustRoots", "Origin", "AdmissionReasons", "ConnectTimeout"}
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
		AdmissionReasons: flowersec.AdmissionReasonRegistry{"capacity": {}},
		ConnectTimeout:   time.Second,
	}
	var connector *flowersec.Connector
	var connect func(context.Context) (flowersec.Session, error)
	_ = options
	if connector != nil {
		connect = connector.Connect
	}
	_ = connect
}

func TestConnectErrorPublicSnapshotContainsNoInternalDetail(t *testing.T) {
	err := &flowersec.ConnectError{Path: "auto", Stage: "connect", Code: "dial_failed"}
	want := "Flowersec connection failed (path=auto stage=connect code=dial_failed)"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, flowersec.ErrConnectionFailed) {
		t.Fatal("ConnectError does not unwrap to the stable public sentinel")
	}
	for _, forbidden := range []string{"candidate", "carrier", "wss://", "quic"} {
		if strings.Contains(strings.ToLower(err.Error()), forbidden) {
			t.Fatalf("Error() leaked forbidden detail %q", forbidden)
		}
	}
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
