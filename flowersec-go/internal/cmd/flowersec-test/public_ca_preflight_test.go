package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublicCAPreflightRequiresCompleteConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, cert, key, host, want string
	}{
		{"missing", "", "", "", "requires"},
		{"partial", "cert.pem", "", "example.com", "requires"},
		{"noncanonical-host", "cert.pem", "key.pem", "Example.COM", "canonical"},
		{"bad-material", "cert.pem", "key.pem", "example.com", "material"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validatePublicCAConfiguration(test.cert, test.key, test.host, time.Now())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestPublicCAPreflightRejectsUntrustedLeaf(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, dir, "browser.example.com", 7*24*time.Hour)
	err := validatePublicCAConfiguration(certPath, keyPath, "browser.example.com", time.Now())
	if err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("error = %v, want system trust rejection", err)
	}
}

func TestPublicCAPreflightAcceptsCurrentTrustedP256Leaf(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, rootPool := writeTrustedTestCertificate(t, dir, "browser.example.com", 7*24*time.Hour)
	if err := validatePublicCAMaterial(certPath, keyPath, "browser.example.com", time.Now(), rootPool); err != nil {
		t.Fatal(err)
	}
}

func TestPublicCAPreflightRejectsIPLiteralAndLongHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", strings.Repeat("a", 254)} {
		if err := validatePublicCAConfiguration("cert.pem", "key.pem", host, time.Now()); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Fatalf("host %q error = %v, want canonical-host rejection", host, err)
		}
	}
}

func TestPublicCAPreflightRejectsLifetimeAndHostnameViolations(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, dir, "browser.example.com", 15*24*time.Hour)
	if err := validatePublicCAConfiguration(certPath, keyPath, "browser.example.com", time.Now()); err == nil || !strings.Contains(err.Error(), "14-day") {
		t.Fatalf("long-lived certificate error = %v, want lifetime rejection", err)
	}
	certPath, keyPath = writeTestCertificate(t, dir, "browser.example.com", 7*24*time.Hour)
	if err := validatePublicCAConfiguration(certPath, keyPath, "other.example.com", time.Now()); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("hostname mismatch error = %v, want hostname rejection", err)
	}
}

func writeTestCertificate(t *testing.T, dir, host string, lifetime time.Duration) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now, NotAfter: now.Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := certFile.Close(); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatal(err)
	}
	if err := keyFile.Close(); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func writeTrustedTestCertificate(t *testing.T, dir, host string, lifetime time.Duration) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Flowersec Test Root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, NotBefore: now, NotAfter: now.Add(365 * 24 * time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now, NotAfter: now.Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, template, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "trusted-cert.pem")
	keyPath := filepath.Join(dir, "trusted-key.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER}); err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: rootDER}); err != nil {
		t.Fatal(err)
	}
	if err := certFile.Close(); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatal(err)
	}
	if err := keyFile.Close(); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(root)
	return certPath, keyPath, pool
}
