package interopharness

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func TestEngineeringTLSIdentitiesUseLeafCertificates(t *testing.T) {
	for name, material := range map[string]func(string) (tls.Certificate, *x509.CertPool, string, []byte, error){"direct": TLSMaterial, "native_tunnel": nativeTunnelTLSMaterial} {
		t.Run(name, func(t *testing.T) {
			serverIdentity, _, trust, _, err := material("127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			clientIdentity, clientRoots, err := engineeringControlClientTLS()
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(trust)) {
				t.Fatal("missing installed server root")
			}
			root, rest := pem.Decode([]byte(trust))
			if root == nil || len(rest) != 0 || !bytes.Equal(root.Bytes, serverIdentity.Certificate[1]) {
				t.Fatal("trust PEM does not contain exactly the independent root")
			}
			for _, identity := range []struct {
				certificate tls.Certificate
				roots       *x509.CertPool
				usage       x509.ExtKeyUsage
				other       x509.ExtKeyUsage
			}{{serverIdentity, roots, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, {clientIdentity, clientRoots, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}} {
				leaf := identity.certificate.Leaf
				if leaf == nil || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
					t.Fatal("TLS endpoint has CA signing authority")
				}
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: identity.roots, KeyUsages: []x509.ExtKeyUsage{identity.usage}}); err != nil {
					t.Fatal(err)
				}
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: identity.roots, KeyUsages: []x509.ExtKeyUsage{identity.other}}); err == nil {
					t.Fatal("endpoint certificate accepted for the opposite TLS role")
				}
				key, err := x509.MarshalPKCS8PrivateKey(identity.certificate.PrivateKey)
				if err != nil {
					t.Fatal(err)
				}
				reloaded, err := tls.X509KeyPair([]byte(engineeringCertificatePEM(identity.certificate)), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
				clear(key)
				if err != nil || len(reloaded.Certificate) != 2 || !bytes.Equal(reloaded.Certificate[0], identity.certificate.Certificate[0]) {
					t.Fatal("installation PEM lost the original leaf/key or chain", err)
				}
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			server := tls.Server(left, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverIdentity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots})
			client := tls.Client(right, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{clientIdentity}})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.HandshakeContext(ctx) }()
			clientErr := client.HandshakeContext(ctx)
			serverErr := <-serverDone
			if clientErr != nil || serverErr != nil {
				t.Fatal("mutually authenticated TLS 1.3 handshake", clientErr, serverErr)
			}
		})
	}
}
