package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

const testPrivateKeyBase64 = "d2VidHJhbnNwb3J0LWV4YW1wbGUtY2VydC1rZXktMDE="

type endpoint struct {
	URL             string `json:"url"`
	CertificateHash string `json:"certificate_hash"`
}

func main() {
	tlsConfig, certificateHash, err := testTLSConfig(time.Now())
	must(err)
	limits, err := carrierwt.BindSessionLimits(carrierwt.DefaultLimits(), 64)
	must(err)
	server, err := carrierwt.NewServer(tlsConfig, limits, allowedOrigin)
	must(err)
	result := make(chan error, 1)
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		result <- serveSession(server, writer, request)
	}))
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	must(err)
	defer packetConn.Close()
	defer server.Close()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()

	address := packetConn.LocalAddr().(*net.UDPAddr)
	must(json.NewEncoder(os.Stdout).Encode(endpoint{
		URL:             fmt.Sprintf("https://127.0.0.1:%d%s", address.Port, carrierwt.PathDirect),
		CertificateHash: certificateHash,
	}))

	select {
	case err := <-result:
		must(err)
	case err := <-serveDone:
		must(err)
	case <-time.After(20 * time.Second):
		must(errors.New("WebTransport interop peer timed out"))
	}
}

func serveSession(server *carrierwt.Server, writer http.ResponseWriter, request *http.Request) error {
	transport, err := server.Upgrade(writer, request)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admission, err := transport.AcceptStream(ctx)
	if err != nil {
		return err
	}
	decoded, err := admissionv2.Serve(ctx, admission, nil, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	})
	if err != nil {
		return err
	}
	var psk [32]byte
	for index := range psk {
		psk[index] = byte(index + 1)
	}
	established, err := session.Establish(ctx, transport, session.Config{
		Role:                  session.RoleServer,
		Path:                  session.PathDirect,
		ChannelID:             decoded.Request.ChannelID,
		SessionContractHash:   decoded.Request.SessionContractHash,
		Suite:                 protocolv2.SuiteChaCha20Poly1305,
		PSK:                   psk,
		MaxInboundStreams:     64,
		LocalAdmissionBinding: decoded.LocalAdmissionBinding,
		PeerAdmissionBinding:  decoded.LocalAdmissionBinding,
	})
	if err != nil {
		return err
	}
	defer established.Close()

	unreliable, err := established.UnreliableMessages()
	if err != nil {
		return err
	}
	message, err := unreliable.Receive(ctx)
	if err != nil {
		return err
	}
	if string(message) != "browser-datagram" {
		return fmt.Errorf("unexpected DATAGRAM payload %q", message)
	}
	status, err := unreliable.Send(ctx, []byte("go-datagram"), session.UnreliableSendOptions{
		ExpiresAt: time.Now().Add(5 * time.Second),
	})
	if err != nil || status != session.UnreliableAccepted {
		return fmt.Errorf("send DATAGRAM: status=%s err=%w", status, err)
	}

	incoming, err := established.AcceptStream(ctx)
	if err != nil {
		return err
	}
	buffer := make([]byte, 64)
	n, err := incoming.Stream.Read(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:n]) != "hello-go" {
		return fmt.Errorf("unexpected first payload %q", buffer[:n])
	}
	if _, err := incoming.Stream.Write([]byte("hello-ts")); err != nil {
		return err
	}
	if err := established.Rekey(ctx); err != nil {
		return err
	}
	if _, err := incoming.Stream.Write([]byte("go-rekey-ok")); err != nil {
		return err
	}
	n, err = incoming.Stream.Read(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:n]) != "ts-rekey-ok" {
		return fmt.Errorf("unexpected rekey payload %q", buffer[:n])
	}
	n, err = incoming.Stream.Read(buffer)
	if !errors.Is(err, io.EOF) || n != 0 {
		return fmt.Errorf("expected EOF, got n=%d err=%v", n, err)
	}
	if _, err := incoming.Stream.Write([]byte("done")); err != nil {
		return err
	}
	if err := incoming.Stream.CloseWrite(); err != nil {
		return err
	}
	select {
	case <-established.Termination():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func allowedOrigin(request *http.Request) bool {
	parsed, err := url.Parse(request.Header.Get("Origin"))
	return err == nil && parsed.Scheme == "http" && parsed.Hostname() == "127.0.0.1" && parsed.Port() != "" &&
		parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func testTLSConfig(now time.Time) (*tls.Config, string, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(testPrivateKeyBase64)
	if err != nil {
		return nil, "", err
	}
	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), privateKeyBytes)
	if err != nil {
		return nil, "", err
	}
	utc := now.UTC()
	validFrom := time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	validFrom = validFrom.AddDate(0, 0, -int((validFrom.Weekday()+6)%7))
	validUntil := validFrom.Add(13 * 24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(validFrom.Unix()),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             validFrom,
		NotAfter:              validUntil,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")},
	}
	certificateDER, err := x509.CreateCertificate(nil, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256(certificateDER)
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certificateDER},
			PrivateKey:  privateKey,
		}},
	}, base64.RawStdEncoding.EncodeToString(hash[:]), nil
}

func must(err error) {
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
