package transporttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/rawquicv3"
	carrieryamux "github.com/floegence/flowersec/flowersec-go/v4/internal/mux/yamux"
	gorillaws "github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"
)

const defaultMaxInboundStreams uint16 = 32

func localTLSForHost(kind carrier.Kind, listenHost string) (*tls.Config, *tls.Config, error) {
	nextProtocol := ""
	switch kind {
	case carrier.KindRawQUIC:
		nextProtocol = rawquicv3.ALPNDirect
	case carrier.KindWebTransport:
		nextProtocol = http3.NextProtoH3
	case carrier.KindWebSocket:
	default:
		return nil, nil, fmt.Errorf("unsupported carrier %q", kind)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serverName := "localhost"
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	if listenHost != "" && listenHost != "127.0.0.1" {
		address := net.ParseIP(listenHost)
		if address == nil {
			return nil, nil, errors.New("release TLS host must be an IP address")
		}
		serverName = listenHost
		ipAddresses = append(ipAddresses, address)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(20260724),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  ipAddresses,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	server := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  privateKey,
		}},
	}
	client := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: serverName,
	}
	if nextProtocol != "" {
		server.NextProtos = []string{nextProtocol}
		client.NextProtos = []string{nextProtocol}
	}
	return server, client, nil
}

type readResult struct {
	payload []byte
	err     error
}

func readAll(reader io.Reader) <-chan readResult {
	result := make(chan readResult, 1)
	go func() {
		payload, err := io.ReadAll(reader)
		result <- readResult{payload: payload, err: err}
	}()
	return result
}

// NormalizeCloseError removes only expected terminal cleanup outcomes.
func NormalizeCloseError(err error) error { return normalizeCloseError(err) }

func normalizeCloseError(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var filtered error
		for _, child := range joined.Unwrap() {
			filtered = errors.Join(filtered, normalizeCloseError(child))
		}
		return filtered
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) ||
		errors.Is(err, gorillaws.ErrCloseSent) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, carrieryamux.ErrStreamReset) {
		return nil
	}
	var websocketClose *gorillaws.CloseError
	if errors.As(err, &websocketClose) && websocketClose.Code == 4000 {
		switch websocketClose.Text {
		case "session closed", "tunnel bridge closed", "tunnel_closed":
			return nil
		}
	}
	return err
}
