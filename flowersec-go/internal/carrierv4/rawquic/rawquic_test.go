package rawquic

import (
	"crypto/tls"
	"testing"
)

func TestRawQUICRejectsPreviousWireALPN(t *testing.T) {
	for _, alpn := range []string{"flowersec-direct/3", "flowersec-tunnel/3", "h3", ""} {
		if validALPN(alpn) {
			t.Fatal("accepted unregistered ALPN", alpn)
		}
		if _, err := prepareTLS(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}}, false); err == nil {
			t.Fatal("configured unregistered ALPN", alpn)
		}
	}
	for _, alpn := range []string{ALPNDirect, ALPNTunnel} {
		if _, err := prepareTLS(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}}, false); err != nil {
			t.Fatal(err)
		}
	}
}
