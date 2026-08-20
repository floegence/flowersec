package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

var canonicalPublicCAHost = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func validatePublicCAConfigurationFromEnvironment() error {
	return validatePublicCAConfiguration(
		os.Getenv("FLOWERSEC_BROWSER_PUBLIC_CA_CERT"),
		os.Getenv("FLOWERSEC_BROWSER_PUBLIC_CA_KEY"),
		os.Getenv("FLOWERSEC_BROWSER_PUBLIC_CA_HOST"),
		time.Now(),
	)
}

func validatePublicCAConfiguration(certificatePath, privateKeyPath, host string, now time.Time) error {
	if certificatePath == "" || privateKeyPath == "" || host == "" {
		return errors.New("public-CA preflight requires FLOWERSEC_BROWSER_PUBLIC_CA_CERT, FLOWERSEC_BROWSER_PUBLIC_CA_KEY, and FLOWERSEC_BROWSER_PUBLIC_CA_HOST")
	}
	if len(host) > 253 || net.ParseIP(host) != nil || strings.ToLower(host) != host || strings.HasSuffix(host, ".") || !canonicalPublicCAHost.MatchString(host) {
		return errors.New("public-CA host must be a canonical lowercase DNS hostname")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		return errors.New("public-CA preflight cannot load the system trust store")
	}
	return validatePublicCAMaterial(certificatePath, privateKeyPath, host, now, pool)
}

func validatePublicCAMaterial(certificatePath, privateKeyPath, host string, now time.Time, roots *x509.CertPool) error {
	pair, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return errors.New("public-CA certificate/key material is invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("public-CA leaf certificate is invalid")
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("public-CA leaf certificate must use ECDSA P-256")
	}
	if leaf.IsCA {
		return errors.New("public-CA server certificate must be a leaf")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.NotAfter.Sub(leaf.NotBefore) > 14*24*time.Hour {
		return errors.New("public-CA leaf certificate is expired or exceeds the 14-day lifetime")
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return fmt.Errorf("public-CA leaf certificate does not cover %s: %w", host, err)
	}
	intermediatePool, err := intermediates(pair.Certificate[1:])
	if err != nil {
		return err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediatePool, CurrentTime: now}); err != nil {
		return fmt.Errorf("public-CA leaf is not trusted by the system public CA roots: %w", err)
	}
	return nil
}

func intermediates(certs [][]byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, raw := range certs {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("public-CA certificate chain contains an invalid intermediate")
		}
		pool.AddCert(cert)
	}
	return pool, nil
}
