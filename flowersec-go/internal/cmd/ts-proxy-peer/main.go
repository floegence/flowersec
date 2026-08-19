package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v3"
	"github.com/floegence/flowersec/flowersec-go/v3/controlplane"
)

type endpoint struct {
	Runtime      string `json:"runtime"`
	ArtifactJSON string `json:"artifact_json"`
	Origin       string `json:"origin"`
	TrustPEM     string `json:"trust_pem"`
}

func main() {
	upstream := flag.String("upstream", "", "fixed loopback HTTP upstream origin")
	origin := flag.String("origin", "https://app.example", "exact browser and proxy external origin")
	maxBodyBytes := flag.Int64("max-body-bytes", 8, "maximum proxied HTTP body size")
	httpTimeout := flag.Duration("http-timeout", time.Second, "proxy HTTP request timeout")
	flag.Parse()
	if *upstream == "" {
		fail(errors.New("--upstream is required"))
	}
	parsedOrigin, err := url.Parse(*origin)
	if err != nil || parsedOrigin.Scheme == "" || parsedOrigin.Host == "" || parsedOrigin.String() != parsedOrigin.Scheme+"://"+parsedOrigin.Host {
		fail(errors.New("--origin must be an exact origin"))
	}
	if *maxBodyBytes < 1 {
		fail(errors.New("--max-body-bytes must be positive"))
	}
	if *httpTimeout <= 0 {
		fail(errors.New("--http-timeout must be positive"))
	}

	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{MaxConcurrentStreams: 4})
	fail(err)
	proxy, err := flowersec.NewProxyServer(flowersec.ProxyServerOptions{
		Upstream:                    *upstream,
		UpstreamOrigin:              *upstream,
		AllowedOrigins:              []string{*origin},
		MaxConcurrentStreams:        4,
		MaxJSONFrameBytes:           4096,
		MaxChunkBytes:               8,
		MaxBodyBytes:                *maxBodyBytes,
		MaxWebSocketFrameBytes:      32,
		DefaultHTTPRequestTimeout:   *httpTimeout,
		MaxHTTPRequestTimeout:       *httpTimeout,
		ExtraRequestHeaders:         []string{"cookie", "origin", "x-request-id"},
		ExtraResponseHeaders:        []string{"x-visible"},
		BlockedResponseHeaders:      []string{"location"},
		ExtraWebSocketHeaders:       []string{"x-request-id"},
		ForbiddenCookieNames:        []string{"secret"},
		ForbiddenCookieNamePrefixes: []string{"private_"},
		OnError: func(err error) {
			// Keep peer diagnostics on stderr; the endpoint JSON remains machine-readable.
			fmt.Fprintf(os.Stderr, "proxy handler error: %v\n", err)
		},
	})
	fail(err)
	defer proxy.Close()
	fail(proxy.Register(handlers))

	var record controlplane.AuthorizationRecord
	released := make(chan struct{}, 1)
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins:    []string{*origin},
		MaxInboundStreams: 8,
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "proxy-matrix-go")
		},
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return handlers, nil
		},
		Release: func(context.Context, string) {
			select {
			case released <- struct{}{}:
			default:
			}
		},
		OnSession: func(ctx context.Context, session flowersec.Session, _ string) error {
			_, err := session.WaitTermination(ctx)
			return err
		},
	})
	fail(err)
	serverTLS, trustPEM, err := peerTLS()
	fail(err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	fail(err)
	server, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{
		Handler: acceptor.Handler(), TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second,
	})
	if err != nil {
		_ = listener.Close()
	}
	fail(err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		<-serveDone
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	fail(err)

	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID: "websocket", URL: "wss://localhost:" + port + flowersec.WebSocketDirectPath,
		TLS: controlplane.CAPolicy(),
	})
	fail(err)
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session: controlplane.SessionOptions{
			ChannelID:         "browser-proxy-go",
			ExpiresAt:         time.Now().Add(time.Minute),
			MaxInboundStreams: 8,
		},
		Endpoints:         endpoints,
		RendezvousGroupID: "browser-proxy-go",
		ListenerAudience:  "browser-proxy-matrix",
		UpstreamAddress:   listener.Addr().String(),
	})
	fail(err)
	record = issued.AuthorizationRecord()
	fail(json.NewEncoder(os.Stdout).Encode(endpoint{
		Runtime: "go", ArtifactJSON: string(issued.ArtifactJSON()), Origin: *origin, TrustPEM: trustPEM,
	}))

	select {
	case <-released:
	case <-time.After(20 * time.Second):
		fail(errors.New("proxy matrix session did not release"))
	}
}

func peerTLS() (*tls.Config, string, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "Flowersec proxy peer root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, "", err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, "", err
	}
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}
	trustPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, string(trustPEM), nil
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
