package webtransport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/quicbase"
)

func TestServerUsesOnlyDraft15SettingsAndConnectProtocol(t *testing.T) {
	server, err := NewServer(draft15ServerTLS(t), quicbase.DefaultLimits(), func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	wantSettings := map[uint64]uint64{0x2c7cf000: 1}
	if got := server.inner.H3.AdditionalSettings; !reflect.DeepEqual(got, wantSettings) {
		t.Fatalf("WebTransport SETTINGS = %#v, want only %#v", got, wantSettings)
	}

	request := &http.Request{
		Method: http.MethodConnect,
		Proto:  "webtransport",
		URL:    &url.URL{Path: PathDirect},
	}
	if _, err := server.Upgrade(httptest.NewRecorder(), request); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("legacy CONNECT error = %v, want ErrInvalidURL", err)
	}
}

func draft15ServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}},
	}
}
