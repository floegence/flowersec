package tlspolicy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func testCertificate(t *testing.T, curve elliptic.Curve, days int, serial int64, key *ecdsa.PrivateKey) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	var err error
	if key == nil {
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "unrelated.invalid"}, DNSNames: []string{"authorized.example"},
		NotBefore: time.Unix(86400, 0), NotAfter: time.Unix(int64(days+1)*86400, 0), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, parsed, key
}

func TestPinUsesCompleteDERAndFullCertificateProfile(t *testing.T) {
	now := timev4.Interval{LowerMS: 100000000, UpperMS: 100000100}
	der, certificate, key := testCertificate(t, elliptic.P256(), 14, 1, nil)
	start, end := uint64(90000000), uint64(110000000)
	pin, err := PinFromDER(der, start, end, now)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{mode: 1, count: 1, pins: [MaxPins]Pin{pin}}
	prepared, err := policy.Prepare(now)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{certificate}}
	verified, err := prepared.Verify(state, "not-the-SAN.example", nil, now)
	if err != nil || verified.Check(now) != nil {
		t.Fatal("valid self-signed DER pin required CA/SAN", err)
	}
	_, reissued, _ := testCertificate(t, elliptic.P256(), 14, 2, key)
	state.PeerCertificates[0] = reissued
	if _, err := prepared.Verify(state, "", nil, now); !errors.Is(err, ErrCertificate) {
		t.Fatal("same key new DER reused pin", err)
	}
	for _, days := range []int{15, 30} {
		long, _, _ := testCertificate(t, elliptic.P256(), days, 3, nil)
		if _, err := PinFromDER(long, start, end, now); !errors.Is(err, ErrCertificate) {
			t.Fatal("short signed window qualified long-lived DER", err)
		}
	}
	p384, _, _ := testCertificate(t, elliptic.P384(), 14, 4, nil)
	if _, err := PinFromDER(p384, start, end, now); !errors.Is(err, ErrCertificate) {
		t.Fatal("wrong key profile accepted", err)
	}
	for _, window := range [][2]uint64{{1, end}, {start, 2000000000}, {end, start}, {start, start}} {
		if _, err := PinFromDER(der, window[0], window[1], now); !errors.Is(err, ErrCertificate) {
			t.Fatal("invalid signed window accepted", window, err)
		}
	}
	if verified.Check(timev4.Interval{LowerMS: end - 1, UpperMS: end}) == nil {
		t.Fatal("upper equality extended matched pin")
	}
}

func TestPinPreparationPreservesOriginalActiveSetAndMatchedWindow(t *testing.T) {
	now := timev4.Interval{LowerMS: 100000000, UpperMS: 100000100}
	der, certificate, _ := testCertificate(t, elliptic.P256(), 14, 1, nil)
	pin, err := PinFromDER(der, 90000000, 110000000, now)
	if err != nil {
		t.Fatal(err)
	}
	future := pin
	future.notBefore, future.notAfter = 120000000, 130000000
	policy := Policy{mode: 1, count: 2, pins: [MaxPins]Pin{pin, future}}
	prepared, err := policy.Prepare(now)
	if err != nil || prepared.count != 1 {
		t.Fatal("wrong original active set", err)
	}
	state := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{certificate}}
	later := timev4.Interval{LowerMS: 120000000, UpperMS: 120000100}
	if _, err := prepared.Verify(state, "", nil, later); err == nil {
		t.Fatal("prepared connection silently changed authorized pin window")
	}
	policy = Policy{mode: 1, count: 1, pins: [MaxPins]Pin{future}}
	if _, err := policy.Prepare(now); !errors.Is(err, timev4.ErrPending) {
		t.Fatal("future window was not time pending", err)
	}
	state.Version = tls.VersionTLS12
	if _, err := prepared.Verify(state, "", nil, now); err == nil {
		t.Fatal("TLS1.2 accepted")
	}
}

func TestCARequiresSANChainAndWholeTrustedTimeInterval(t *testing.T) {
	now := timev4.Interval{LowerMS: 100000000, UpperMS: 100000100}
	_, certificate, _ := testCertificate(t, elliptic.P256(), 30, 1, nil)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	prepared, err := (Policy{}).Prepare(now)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{certificate}}
	if _, err := prepared.Verify(state, "authorized.example", roots, now); err != nil {
		t.Fatal("valid CA path rejected", err)
	}
	if _, err := prepared.Verify(state, "unrelated.invalid", roots, now); err == nil {
		t.Fatal("common name substituted for SAN")
	}
	if _, err := prepared.Verify(state, "authorized.example", x509.NewCertPool(), now); err == nil {
		t.Fatal("CA failure fell back to a pin")
	}
	if _, err := prepared.Verify(state, "authorized.example", roots, timev4.Interval{LowerMS: 86399999, UpperMS: 86400001}); err == nil {
		t.Fatal("upper-only validation ignored unproven notBefore")
	}
}
