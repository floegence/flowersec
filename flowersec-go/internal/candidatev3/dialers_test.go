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

	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/quicbase"
	rawquic "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/rawquicv3"
	carrierws "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/websocketv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/transportsecurity"
	gorillaws "github.com/gorilla/websocket"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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

func TestNewWebSocketCarrierDialRejectsCustomTLSCallbacks(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*gorillaws.Dialer)
	}{
		{
			name: "context callback",
			configure: func(dialer *gorillaws.Dialer) {
				dialer.NetDialTLSContext = func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("unexpected custom TLS callback")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dialer := *gorillaws.DefaultDialer
			test.configure(&dialer)
			if _, err := NewWebSocketCarrierDial(WebSocketDialConfig{
				Dialer: &dialer, Resources: carrierws.DefaultResourcePolicy(),
			}); !errors.Is(err, ErrInvalidCarrierDialConfig) {
				t.Fatalf("constructor error = %v, want ErrInvalidCarrierDialConfig", err)
			}
		})
	}
}

func TestGoNativePinProvidersRejectHashMatchedLeafWithInvalidTLSProof(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	leakedDER, serverConfig := invalidProofServerTLS(t, now)
	digest := sha256.Sum256(leakedDER)
	policy := artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
		Algorithm:      "sha-256",
		ValueBase64URL: base64.RawURLEncoding.EncodeToString(digest[:]),
		NotAfterUnixS:  now.Add(time.Hour).Unix(),
	}}}
	tlsClient := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}

	for _, test := range []struct {
		name  string
		start func(*testing.T) (string, func())
		dial  func(*testing.T) Dial
		kind  artifactv3.Carrier
	}{
		{
			name: "websocket", kind: artifactv3.CarrierWebSocket,
			start: func(t *testing.T) (string, func()) {
				address, closeServer := startInvalidProofTCPServer(t, serverConfig.Clone())
				return "wss://" + address + "/flowersec/v3/direct", closeServer
			},
			dial: func(t *testing.T) Dial {
				dialer := *gorillaws.DefaultDialer
				dialer.TLSClientConfig = tlsClient.Clone()
				dial, err := NewWebSocketCarrierDial(WebSocketDialConfig{
					Dialer: &dialer, Resources: carrierws.DefaultResourcePolicy(),
				})
				if err != nil {
					t.Fatal(err)
				}
				return dial
			},
		},
		{
			name: "raw_quic", kind: artifactv3.CarrierRawQUIC,
			start: func(t *testing.T) (string, func()) {
				config := serverConfig.Clone()
				config.NextProtos = []string{rawquic.ALPNDirect}
				address, closeServer := startInvalidProofQUICServer(t, config)
				return "quic://" + address, closeServer
			},
			dial: func(t *testing.T) Dial {
				dial, err := NewRawQUICCarrierDial(RawQUICDialConfig{
					TLSConfig: tlsClient.Clone(), Limits: quicbase.DefaultLimits(), Dial: rawquic.Dial,
				})
				if err != nil {
					t.Fatal(err)
				}
				return dial
			},
		},
		{
			name: "webtransport", kind: artifactv3.CarrierWebTransport,
			start: func(t *testing.T) (string, func()) {
				config := serverConfig.Clone()
				config.NextProtos = []string{http3.NextProtoH3}
				address, closeServer := startInvalidProofQUICServer(t, config)
				return "https://" + address + "/flowersec/webtransport/v3/direct", closeServer
			},
			dial: func(t *testing.T) Dial {
				dial, err := NewWebTransportCarrierDial(WebTransportDialConfig{
					TLSConfig: tlsClient.Clone(), Limits: quicbase.DefaultLimits(), Origin: "https://client.example",
				})
				if err != nil {
					t.Fatal(err)
				}
				return dial
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rawURL, closeServer := test.start(t)
			defer closeServer()
			candidate := artifactv3.Candidate{
				ID: "proof", Carrier: test.kind, URL: rawURL,
				WireProfile: "flowersec-direct/3", TLS: policy,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ready, err := test.dial(t)(ctx, candidate, artifactv3.SessionContract{MaxInboundStreams: 1}, now)
			if ready != nil {
				_ = ready.Close(context.Background())
				t.Fatal("invalid TLS proof exposed a ready carrier")
			}
			if !transportsecurity.IsDetail(err, transportsecurity.FailureUnknown) {
				t.Fatalf("dial error = %v, want located unknown TLS failure", err)
			}
		})
	}
}

func startInvalidProofTCPServer(t *testing.T, config *tls.Config) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_ = tls.Server(connection, config).Handshake()
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func startInvalidProofQUICServer(t *testing.T, config *tls.Config) (string, func()) {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", config, &quic.Config{HandshakeIdleTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _, _ = listener.Accept(ctx) }()
	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
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
