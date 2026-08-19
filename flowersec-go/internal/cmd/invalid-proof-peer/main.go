package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type readyMessage struct {
	Address       string `json:"address"`
	LeafDERBase64 string `json:"leaf_der_base64"`
}

func main() {
	carrier := flag.String("carrier", "websocket", "websocket, raw_quic, or webtransport")
	flag.Parse()
	tlsConfig, leafDER, err := invalidProofTLS()
	if err != nil {
		fail(err)
	}
	switch *carrier {
	case "websocket":
		err = serveTCP(tlsConfig, leafDER)
	case "raw_quic":
		tlsConfig.NextProtos = []string{"flowersec-direct/3"}
		err = serveQUIC(tlsConfig, leafDER)
	case "webtransport":
		tlsConfig.NextProtos = []string{http3.NextProtoH3}
		err = serveQUIC(tlsConfig, leafDER)
	default:
		err = fmt.Errorf("unsupported carrier %q", *carrier)
	}
	if err != nil {
		fail(err)
	}
}

func invalidProofTLS() (*tls.Config, []byte, error) {
	now := time.Now().UTC()
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Flowersec invalid proof"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &certificateKey.PublicKey, certificateKey)
	if err != nil {
		return nil, nil, err
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  wrongKey,
		}},
	}, der, nil
}

func serveTCP(tlsConfig *tls.Config, leafDER []byte) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := announce(listener.Addr().String(), leafDER); err != nil {
		return err
	}
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tls.Server(connection, tlsConfig).Handshake(); err == nil {
		return fmt.Errorf("invalid TLS proof unexpectedly completed")
	}
	return nil
}

func serveQUIC(tlsConfig *tls.Config, leafDER []byte) error {
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       10 * time.Second,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := announce(listener.Addr().String(), leafDER); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if connection, acceptErr := listener.Accept(ctx); acceptErr == nil {
		_ = connection.CloseWithError(0, "invalid proof unexpectedly completed")
		return fmt.Errorf("invalid QUIC TLS proof unexpectedly completed")
	}
	return nil
}

func announce(address string, leafDER []byte) error {
	return json.NewEncoder(os.Stdout).Encode(readyMessage{
		Address:       address,
		LeafDERBase64: base64.StdEncoding.EncodeToString(leafDER),
	})
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
