package candidatev3

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
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	carrierws "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/websocketv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transportsecurity"
	gorillaws "github.com/gorilla/websocket"
	quic "github.com/quic-go/quic-go"
)

func TestIsQUICTLSFailureUsesCryptoTransportCode(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "crypto-lower-bound", err: &quic.TransportError{ErrorCode: 0x100}, want: true},
		{name: "crypto-upper-bound", err: fmt.Errorf("wrapped: %w", &quic.TransportError{ErrorCode: 0x1ff}), want: true},
		{name: "transport", err: &quic.TransportError{ErrorCode: 0x0a}, want: false},
		{name: "application", err: &quic.ApplicationError{ErrorCode: 0x100}, want: false},
		{name: "text", err: errors.New("CRYPTO_ERROR 0x12a certificate verify failed"), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isQUICTLSFailure(test.err); got != test.want {
				t.Fatalf("isQUICTLSFailure(%T) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}

func TestWebSocketPinnedLeafWithInvalidTLSProofIsUnknownTLSFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	leakedDER, serverConfig := invalidProofServerTLS(t, now)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		serverResult <- tls.Server(conn, serverConfig).Handshake()
	}()

	dialer := *gorillaws.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	dial, err := NewWebSocketCarrierDial(WebSocketDialConfig{
		Dialer:    &dialer,
		Resources: carrierws.DefaultResourcePolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(leakedDER)
	candidate := artifactv3.Candidate{
		ID:          "proof",
		Carrier:     artifactv3.CarrierWebSocket,
		URL:         "wss://" + listener.Addr().String() + "/flowersec/v3/direct",
		WireProfile: "flowersec-direct/3",
		TLS: artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
			Algorithm:      "sha-256",
			ValueBase64URL: base64.RawURLEncoding.EncodeToString(digest[:]),
			NotAfterUnixS:  now.Add(time.Hour).Unix(),
		}}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ready, err := dial(ctx, candidate, artifactv3.SessionContract{MaxInboundStreams: 1}, now)
	if ready != nil {
		_ = ready.Close(context.Background())
		t.Fatal("invalid TLS proof exposed a ready carrier")
	}
	if !transportsecurity.IsDetail(err, transportsecurity.FailureUnknown) {
		t.Fatalf("dial error = %v, want located unknown TLS failure", err)
	}
	if serverErr := <-serverResult; serverErr == nil {
		t.Fatal("server with mismatched private key unexpectedly completed TLS")
	}
}

func invalidProofServerTLS(t *testing.T, now time.Time) ([]byte, *tls.Config) {
	t.Helper()
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Flowersec invalid proof"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &certificateKey.PublicKey, certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return der, &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  wrongKey,
		}},
	}
}
