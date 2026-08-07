package main

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

func TestPathConfigurationUsesCanonicalWebTransportPaths(t *testing.T) {
	for _, test := range []struct {
		value       string
		connectPath string
		sessionPath session.PathKind
	}{
		{value: "direct", connectPath: carrierwt.PathDirect, sessionPath: session.PathDirect},
		{value: "tunnel", connectPath: carrierwt.PathTunnel, sessionPath: session.PathTunnel},
	} {
		t.Run(test.value, func(t *testing.T) {
			connectPath, sessionPath, err := pathConfiguration(test.value)
			if err != nil || connectPath != test.connectPath || sessionPath != test.sessionPath {
				t.Fatalf("pathConfiguration(%q) = %q, %q, %v", test.value, connectPath, sessionPath, err)
			}
		})
	}
	if _, _, err := pathConfiguration("other"); err == nil {
		t.Fatal("unsupported path was accepted")
	}
}

func TestNodeOriginPolicyAcceptsOnlyOriginlessLoopback(t *testing.T) {
	request := &http.Request{Header: make(http.Header), RemoteAddr: "127.0.0.1:44321"}
	if !allowedNodeOrigin(request) {
		t.Fatal("originless loopback Node client was rejected")
	}
	request.Header.Set("Origin", "https://client.example")
	if allowedNodeOrigin(request) {
		t.Fatal("browser Origin was accepted by the Node-only peer")
	}
	request.Header.Del("Origin")
	request.RemoteAddr = "192.0.2.1:44321"
	if allowedNodeOrigin(request) {
		t.Fatal("originless non-loopback client was accepted")
	}
}

func TestTLSConfigPublishesSHA256CertificateHash(t *testing.T) {
	config, encoded, err := testTLSConfig(time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != config.MaxVersion || len(config.Certificates) != 1 || len(config.Certificates[0].Certificate) != 1 {
		t.Fatalf("unexpected TLS config: %+v", config)
	}
	hash, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(hash) != 32 {
		t.Fatalf("certificate hash = %q, %v", encoded, err)
	}
}
