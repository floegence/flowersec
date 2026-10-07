package interopharness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// TLSMaterial keeps the installed root separate from the endpoint identity.
// Certificate[0] is always the leaf used by the listener and certificate pins.
func TLSMaterial(host string) (tls.Certificate, *x509.CertPool, string, []byte, error) {
	certificate, roots, err := engineeringTLSIdentity(host, "Flowersec engineering peer", x509.ExtKeyUsageServerAuth)
	if err != nil {
		return tls.Certificate{}, nil, "", nil, err
	}
	policy, err := protocolv4.EncodeMap(make([]byte, 4096), "TLSPolicy", []protocolv4.Field{{Name: "mode"}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: 1}})
	return certificate, roots, engineeringTrustPEM(certificate), policy, err
}

// engineeringControlClientTLS supplies the fixed, independent client identity
// for this owner's local control listener. It is never derived from Artifact,
// Grant, activation or peer-provided trust material.
func engineeringControlClientTLS() (tls.Certificate, *x509.CertPool, error) {
	return engineeringTLSIdentity("", "Flowersec original control client", x509.ExtKeyUsageClientAuth)
}

func engineeringTLSIdentity(host, name string, usage x509.ExtKeyUsage) (tls.Certificate, *x509.CertPool, error) {
	authorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	authority := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Flowersec engineering root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true}
	authorityDER, err := x509.CreateCertificate(rand.Reader, authority, authority, &authorityKey.PublicKey, authorityKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	authority, err = x509.ParseCertificate(authorityDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, NotBefore: authority.NotBefore, NotAfter: authority.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true}
	if usage == x509.ExtKeyUsageServerAuth {
		leaf.DNSNames = []string{"localhost"}
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		if address := net.ParseIP(host); address != nil {
			if !address.Equal(leaf.IPAddresses[0]) {
				leaf.IPAddresses = append(leaf.IPAddresses, address)
			}
		} else if host != "" && host != "localhost" {
			leaf.DNSNames = append(leaf.DNSNames, host)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, authority, &leafKey.PublicKey, authorityKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	return tls.Certificate{Certificate: [][]byte{leafDER, authorityDER}, PrivateKey: leafKey, Leaf: leaf}, roots, nil
}

func engineeringCertificatePEM(certificate tls.Certificate) string {
	var encoded strings.Builder
	for _, der := range certificate.Certificate {
		encoded.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return encoded.String()
}

func engineeringTrustPEM(certificate tls.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[len(certificate.Certificate)-1]}))
}
