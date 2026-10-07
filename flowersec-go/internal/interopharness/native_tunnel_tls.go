package interopharness

import (
	"crypto/tls"
	"crypto/x509"
)

// The native listener uses the same root/leaf separation as every engineering
// endpoint, with the installed root kept out of the end-entity position.
func nativeTunnelTLSMaterial(host string) (tls.Certificate, *x509.CertPool, string, []byte, error) {
	return TLSMaterial(host)
}
