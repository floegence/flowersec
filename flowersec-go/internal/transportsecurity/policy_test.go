package transportsecurity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
)

func TestPrivateCAPolicyCompletesRealTLSHandshake(t *testing.T) {
	now := time.Now().UTC()
	server, roots := privateCATestMaterial(t, now)
	config, err := BuildClientTLS(&tls.Config{RootCAs: roots}, "wss://localhost/flowersec/v3/direct", artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}, now)
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify || config.VerifyConnection != nil || !config.SessionTicketsDisabled {
		t.Fatalf("CA policy TLS controls = insecure:%v callback:%v tickets_disabled:%v", config.InsecureSkipVerify, config.VerifyConnection != nil, config.SessionTicketsDisabled)
	}
	if err := realTLSHandshake(server, config); err != nil {
		t.Fatalf("private CA handshake failed: %v", err)
	}

	untrusted, err := BuildClientTLS(&tls.Config{RootCAs: x509.NewCertPool()}, "wss://localhost/flowersec/v3/direct", artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := realTLSHandshake(server, untrusted); err == nil {
		t.Fatal("untrusted private CA completed a TLS handshake")
	}
}

func TestSelfSignedPinPolicyCompletesRealTLSHandshakeWithoutCADowngrade(t *testing.T) {
	now := time.Now().UTC()
	server, certificate := selfSignedPinTestMaterial(t, now)
	digest := sha256.Sum256(certificate.Raw)
	policy := artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
		Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(digest[:]),
		NotAfterUnixS: now.Add(time.Hour).Unix(),
	}}}
	config, err := BuildClientTLS(&tls.Config{RootCAs: x509.NewCertPool()}, "wss://localhost/flowersec/v3/direct", policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if !config.SessionTicketsDisabled || config.ClientSessionCache != nil {
		t.Fatalf("pin policy must disable TLS resumption: tickets_disabled=%v cache=%v", config.SessionTicketsDisabled, config.ClientSessionCache != nil)
	}
	if err := realTLSHandshake(server, config); err != nil {
		t.Fatalf("self-signed pin handshake failed: %v", err)
	}

	wrong := sha256.Sum256([]byte("wrong certificate"))
	policy.Pins[0].ValueBase64URL = base64.RawURLEncoding.EncodeToString(wrong[:])
	mismatch, err := BuildClientTLS(nil, "wss://localhost/flowersec/v3/direct", policy, now)
	if err != nil {
		t.Fatal(err)
	}
	err = realTLSHandshake(server, mismatch)
	if !IsDetail(err, FailurePinMismatch) {
		t.Fatalf("pin mismatch error = %v, want %s", err, FailurePinMismatch)
	}
}

func TestPinProviderRejectsCertificateProfileMatrixWithUnknownTLSFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, test := range []struct {
		name      string
		curve     elliptic.Curve
		notBefore time.Time
		notAfter  time.Time
	}{
		{name: "non-p256", curve: elliptic.P384(), notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)},
		{name: "overlong", curve: elliptic.P256(), notBefore: now.Add(-time.Hour), notAfter: now.Add(15 * 24 * time.Hour)},
		{name: "not-yet-valid", curve: elliptic.P256(), notBefore: now.Add(time.Hour), notAfter: now.Add(2 * time.Hour)},
		{name: "expired", curve: elliptic.P256(), notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, certificate := selfSignedPinTestMaterialWithProfile(
				t, test.curve, test.notBefore, test.notAfter,
			)
			digest := sha256.Sum256(certificate.Raw)
			policy := artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
				Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(digest[:]),
				NotAfterUnixS: now.Add(time.Hour).Unix(),
			}}}
			config, err := BuildClientTLS(nil, "wss://localhost/flowersec/v3/direct", policy, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := realTLSHandshake(server, config); !IsDetail(err, FailureUnknown) {
				t.Fatalf("profile failure = %v, want %s", err, FailureUnknown)
			}
		})
	}
}

func TestPinPolicyRejectsPrivateCATrustEvenWhenRootsAreProvided(t *testing.T) {
	now := time.Now().UTC()
	server, roots := privateCATestMaterial(t, now)
	wrong := sha256.Sum256([]byte("wrong private CA leaf pin"))
	policy := artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
		Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(wrong[:]),
		NotAfterUnixS: now.Add(time.Hour).Unix(),
	}}}
	config, err := BuildClientTLS(&tls.Config{RootCAs: roots}, "wss://localhost/flowersec/v3/direct", policy, now)
	if err != nil {
		t.Fatal(err)
	}
	err = realTLSHandshake(server, config)
	if !IsDetail(err, FailurePinMismatch) {
		t.Fatalf("private CA with wrong pin error = %v, want %s", err, FailurePinMismatch)
	}
}

func TestOverlappingPinPolicyAcceptsBothActiveCertificates(t *testing.T) {
	now := time.Now().UTC()
	oldServer, oldCertificate := selfSignedPinTestMaterial(t, now)
	newServer, newCertificate := selfSignedPinTestMaterial(t, now)
	oldDigest := sha256.Sum256(oldCertificate.Raw)
	newDigest := sha256.Sum256(newCertificate.Raw)
	oldPin := artifactv3.CertificatePin{
		Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(oldDigest[:]),
		NotAfterUnixS: now.Add(15 * time.Minute).Unix(),
	}
	newPin := artifactv3.CertificatePin{
		Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(newDigest[:]),
		NotAfterUnixS: now.Add(time.Hour).Unix(),
	}
	pins := []artifactv3.CertificatePin{oldPin, newPin}
	if pins[0].ValueBase64URL > pins[1].ValueBase64URL {
		pins[0], pins[1] = pins[1], pins[0]
	}
	policy := artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: pins}

	for name, server := range map[string]*tls.Config{"old": oldServer, "new": newServer} {
		t.Run(name, func(t *testing.T) {
			config, err := BuildClientTLS(nil, "wss://localhost/flowersec/v3/direct", policy, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := realTLSHandshake(server, config); err != nil {
				t.Fatalf("overlapping pin handshake failed: %v", err)
			}
		})
	}
}

func TestExpiredPinPolicyFailsBeforeNetworkAttempt(t *testing.T) {
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte("expired pin"))
	_, err := BuildClientTLS(nil, "wss://localhost/flowersec/v3/direct", artifactv3.TLSPolicy{
		Mode: artifactv3.TLSModePin,
		Pins: []artifactv3.CertificatePin{{
			Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(digest[:]),
			NotAfterUnixS: now.Unix(),
		}},
	}, now)
	if !IsDetail(err, FailureExpired) {
		t.Fatalf("expired policy error = %v, want %s", err, FailureExpired)
	}
}

func TestSnapshotPolicyFixesActivePinsWithoutRewritingArtifactPolicy(t *testing.T) {
	expired := sha256.Sum256([]byte("expired rotation pin"))
	active := sha256.Sum256([]byte("active rotation pin"))
	policy := artifactv3.TLSPolicy{
		Mode: artifactv3.TLSModePin,
		Pins: []artifactv3.CertificatePin{
			{Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(expired[:]), NotAfterUnixS: 100},
			{Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(active[:]), NotAfterUnixS: 200},
		},
	}
	if policy.Pins[0].ValueBase64URL > policy.Pins[1].ValueBase64URL {
		policy.Pins[0], policy.Pins[1] = policy.Pins[1], policy.Pins[0]
	}

	snapshot, err := SnapshotPolicy(policy, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Pins) != 2 {
		t.Fatalf("declared pins = %d, want 2", len(policy.Pins))
	}
	if len(snapshot.Pins) != 1 || snapshot.Pins[0].NotAfterUnixS != 200 {
		t.Fatalf("snapshot pins = %+v, want only the active pin", snapshot.Pins)
	}
	if _, err := SnapshotPolicy(policy, time.Unix(200, 0)); !IsDetail(err, FailureExpired) {
		t.Fatalf("all-expired snapshot error = %v, want %s", err, FailureExpired)
	}
}

func TestSharedActivePinSnapshotVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/artifact_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ActivePinSnapshots []struct {
			ID         string               `json:"id"`
			AttemptNow int64                `json:"attempt_now"`
			Declared   artifactv3.TLSPolicy `json:"declared"`
			Active     []string             `json:"active_value_b64u"`
			Result     string               `json:"result"`
		} `json:"active_pin_snapshots"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.ActivePinSnapshots {
		t.Run(vector.ID, func(t *testing.T) {
			snapshot, err := SnapshotPolicy(vector.Declared, time.Unix(vector.AttemptNow, 0))
			switch vector.Result {
			case "attempt":
				if err != nil {
					t.Fatal(err)
				}
				active := make([]string, 0, len(snapshot.Pins))
				for _, pin := range snapshot.Pins {
					active = append(active, pin.ValueBase64URL)
				}
				if !slices.Equal(active, vector.Active) {
					t.Fatalf("active pins = %v, want %v", active, vector.Active)
				}
			case "tls_policy_expired":
				if len(vector.Active) != 0 {
					t.Fatalf("expired vector active pins = %v, want empty", vector.Active)
				}
				if !IsDetail(err, FailureExpired) {
					t.Fatalf("snapshot error = %v, want %s", err, FailureExpired)
				}
			default:
				t.Fatalf("unknown active pin result %q", vector.Result)
			}
		})
	}
}

func TestCertificateValidityUsesHandshakeTimeWhilePinsUseAttemptSnapshot(t *testing.T) {
	attemptNow := time.Now().UTC().Truncate(time.Second)
	for _, boundary := range []struct {
		name         string
		notBefore    time.Time
		notAfter     time.Time
		handshakeNow time.Time
		wantSuccess  bool
	}{
		{
			name:      "becomes_valid_after_attempt",
			notBefore: attemptNow.Add(30 * time.Minute), notAfter: attemptNow.Add(2 * time.Hour),
			handshakeNow: attemptNow.Add(time.Hour), wantSuccess: true,
		},
		{
			name:      "expires_after_attempt",
			notBefore: attemptNow.Add(-time.Hour), notAfter: attemptNow.Add(30 * time.Minute),
			handshakeNow: attemptNow.Add(time.Hour), wantSuccess: false,
		},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			caServer, roots := privateCATestMaterialWithValidity(
				t, attemptNow, boundary.notBefore, boundary.notAfter,
			)
			pinServer, certificate := selfSignedPinTestMaterialWithValidity(
				t, boundary.notBefore, boundary.notAfter,
			)
			digest := sha256.Sum256(certificate.Raw)
			pinPolicy := artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
				Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(digest[:]),
				// This expires before the successful delayed handshake. The active
				// pin set is intentionally fixed at attemptNow.
				NotAfterUnixS: attemptNow.Add(45 * time.Minute).Unix(),
			}}}

			for name, test := range map[string]struct {
				server *tls.Config
				base   *tls.Config
				policy artifactv3.TLSPolicy
			}{
				"ca":  {server: caServer, base: &tls.Config{RootCAs: roots}, policy: artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}},
				"pin": {server: pinServer, base: &tls.Config{}, policy: pinPolicy},
			} {
				t.Run(name, func(t *testing.T) {
					handshakeNow := attemptNow
					test.base.Time = func() time.Time { return handshakeNow }
					config, err := BuildClientTLS(
						test.base, "wss://localhost/flowersec/v3/direct", test.policy, attemptNow,
					)
					if err != nil {
						t.Fatal(err)
					}
					handshakeNow = boundary.handshakeNow
					err = realTLSHandshake(test.server, config)
					if boundary.wantSuccess && err != nil {
						t.Fatalf("certificate valid at handshake time was rejected: %v", err)
					}
					if !boundary.wantSuccess && err == nil {
						t.Fatal("certificate expired at handshake time was accepted")
					}
				})
			}
		})
	}
}

func TestClassifyLocatedTLSFailureUsesPolicyMode(t *testing.T) {
	providerFailure := errors.New("provider handshake failed")
	for _, test := range []struct {
		name   string
		mode   artifactv3.TLSMode
		err    error
		detail FailureDetail
	}{
		{name: "ca-verification", mode: artifactv3.TLSModeCA, err: x509.UnknownAuthorityError{}, detail: FailureCAUntrusted},
		{name: "ca-proof", mode: artifactv3.TLSModeCA, err: providerFailure, detail: FailureUnknown},
		{name: "pin-proof", mode: artifactv3.TLSModePin, err: providerFailure, detail: FailureUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ClassifyLocatedTLSFailure(artifactv3.TLSPolicy{Mode: test.mode}, test.err)
			if !IsDetail(err, test.detail) || !errors.Is(err, test.err) {
				t.Fatalf("mode %q classified as %v", test.mode, err)
			}
		})
	}
}

func realTLSHandshake(serverConfig, clientConfig *tls.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		serverConn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer serverConn.Close()
		serverResult <- tls.Server(serverConn, serverConfig).HandshakeContext(ctx)
	}()
	clientConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return err
	}
	client := tls.Client(clientConn, clientConfig)
	clientErr := client.HandshakeContext(ctx)
	_ = client.Close()
	serverErr := <-serverResult
	if clientErr != nil {
		return clientErr
	}
	return serverErr
}

func privateCATestMaterial(t *testing.T, now time.Time) (*tls.Config, *x509.CertPool) {
	return privateCATestMaterialWithValidity(t, now, now.Add(-time.Hour), now.Add(24*time.Hour))
}

func privateCATestMaterialWithValidity(
	t *testing.T,
	now time.Time,
	leafNotBefore time.Time,
	leafNotAfter time.Time,
) (*tls.Config, *x509.CertPool) {
	t.Helper()
	caKey := testP256Key(t)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Flowersec test CA"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := testP256Key(t)
	leafTemplate := testLeafTemplateWithValidity(2, leafNotBefore, leafNotAfter)
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}, roots
}

func selfSignedPinTestMaterial(t *testing.T, now time.Time) (*tls.Config, *x509.Certificate) {
	return selfSignedPinTestMaterialWithValidity(t, now.Add(-time.Hour), now.Add(24*time.Hour))
}

func selfSignedPinTestMaterialWithValidity(
	t *testing.T,
	notBefore time.Time,
	notAfter time.Time,
) (*tls.Config, *x509.Certificate) {
	return selfSignedPinTestMaterialWithProfile(t, elliptic.P256(), notBefore, notAfter)
}

func selfSignedPinTestMaterialWithProfile(
	t *testing.T,
	curve elliptic.Curve,
	notBefore time.Time,
	notAfter time.Time,
) (*tls.Config, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := testLeafTemplateWithValidity(3, notBefore, notAfter)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, certificate
}

func testLeafTemplate(now time.Time, serial int64, lifetime time.Duration) *x509.Certificate {
	return testLeafTemplateWithValidity(serial, now.Add(-time.Hour), now.Add(lifetime))
}

func testLeafTemplateWithValidity(serial int64, notBefore time.Time, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
