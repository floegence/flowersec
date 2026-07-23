package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier/rawquic"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/v2/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/rpc"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/session"
)

const testCertDERBase64 = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw=="
const testKeyDERBase64 = "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6"

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: raw_quic_peer client <address> [direct|tunnel] | server [direct|tunnel]")
	}
	switch os.Args[1] {
	case "client":
		if len(os.Args) < 3 || len(os.Args) > 4 {
			fatalf("client requires an address and optional profile")
		}
		runClient(os.Args[2], profileArgument(3))
	case "server":
		if len(os.Args) > 3 {
			fatalf("server accepts only an optional profile")
		}
		runServer(profileArgument(2))
	case "session-server":
		if len(os.Args) > 3 {
			fatalf("session-server accepts only an optional profile")
		}
		runSessionServer(profileArgument(2))
	default:
		fatalf("unknown mode %q", os.Args[1])
	}
}

func runSessionServer(profile string) {
	limits := rawquic.DefaultLimits()
	limits.MaxInboundStreams = 6
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS(profile), limits)
	if err != nil {
		fatalf("listen: %v", err)
	}
	defer listener.Close()
	fmt.Printf("READY %s\n", listener.Addr())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	carrierSession, err := listener.Accept(ctx)
	if err != nil {
		fatalf("accept Rust client: %v", err)
	}
	defer carrierSession.Close()
	admission, err := carrierSession.AcceptStream(ctx)
	if err != nil {
		fatalf("accept admission: %v", err)
	}
	decoded, err := admissionv2.Serve(ctx, admission, nil, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	})
	if err != nil {
		fatalf("serve admission: %v", err)
	}
	path := flowersession.PathDirect
	localEndpoint, peerEndpoint := "", ""
	if profile == "tunnel" {
		path = flowersession.PathTunnel
		localEndpoint = "endpoint-server"
		peerEndpoint = decoded.Request.EndpointInstanceID
	}
	var psk [32]byte
	for index := range psk {
		psk[index] = 0x42
	}
	router := rpc.NewRouter()
	postRekey := make(chan struct{}, 1)
	doneOpen := make(chan struct{}, 1)
	router.Register(22, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		var marker map[string]any
		if json.Unmarshal(payload, &marker) == nil {
			if _, ok := marker["epoch"]; ok {
				select {
				case postRekey <- struct{}{}:
				default:
				}
			}
		}
		return append(json.RawMessage(nil), payload...), nil
	})
	router.Register(23, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		select {
		case doneOpen <- struct{}{}:
		default:
		}
		return append(json.RawMessage(nil), payload...), nil
	})
	secure, err := flowersession.Establish(ctx, carrierSession, flowersession.Config{
		Role: flowersession.RoleServer, Path: path, ChannelID: decoded.Request.ChannelID,
		SessionContractHash: decoded.Request.SessionContractHash,
		Suite:               protocolv2.SuiteChaCha20Poly1305, PSK: psk, MaxInboundStreams: 4,
		LocalAdmissionBinding: decoded.LocalAdmissionBinding, PeerAdmissionBinding: decoded.LocalAdmissionBinding,
		LocalEndpointInstanceID: localEndpoint, ExpectedPeerEndpointInstanceID: peerEndpoint,
		RPCRouter: router,
	})
	if err != nil {
		fatalf("establish SessionV2: %v", err)
	}
	defer secure.Close()
	incoming, err := secure.AcceptStream(ctx)
	if err != nil {
		fatalf("accept Rust logical stream: %v", err)
	}
	payload, err := io.ReadAll(incoming.Stream)
	if err != nil || string(payload) != "rust-app" {
		fatalf("Rust app payload=%q err=%v", payload, err)
	}
	if err := incoming.Stream.CloseWrite(); err != nil {
		fatalf("reply FIN: %v", err)
	}
	outbound, err := secure.OpenStream(ctx, "go-open", flowersession.Metadata{})
	if err != nil {
		fatalf("open Go logical stream: %v", err)
	}
	if _, err := outbound.Write([]byte("from-go")); err != nil {
		fatalf("write Go stream: %v", err)
	}
	if err := outbound.CloseWrite(); err != nil {
		fatalf("close Go stream: %v", err)
	}
	select {
	case <-postRekey:
	case <-ctx.Done():
		fatalf("wait post-rekey RPC: %v", ctx.Err())
	}
	var reverse map[string]string
	if err := secure.RPC().Call(ctx, 11, map[string]string{"from": "go"}, &reverse); err != nil {
		fatalf("Go to Rust RPC: %v", err)
	}
	if reverse["from"] != "go" {
		fatalf("Go to Rust RPC response=%v", reverse)
	}
	done, err := secure.AcceptStream(ctx)
	if err != nil {
		fatalf("accept done stream: %v", err)
	}
	if done.Kind != "done" {
		fatalf("done kind=%q", done.Kind)
	}
	select {
	case <-doneOpen:
	case <-ctx.Done():
		fatalf("wait for Rust open acknowledgement: %v", ctx.Err())
	}
	receipt, err := io.ReadAll(done.Stream)
	if err != nil {
		fatalf("read Rust RPC receipt: %v", err)
	}
	if string(receipt) != "rpc-response-observed" {
		fatalf("Rust RPC receipt=%q", receipt)
	}
	if err := done.Stream.CloseWrite(); err != nil {
		fatalf("finish Rust RPC receipt: %v", err)
	}
	fmt.Println("OK")
}

func runClient(address, profile string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := rawquic.Dial(ctx, address, clientTLS(profile), rawquic.DefaultLimits())
	if err != nil {
		fatalf("dial Rust server: %v", err)
	}
	defer session.Close()
	stream, err := session.OpenStream(ctx)
	if err != nil {
		fatalf("open admission stream: %v", err)
	}
	response, err := admissionv2.Commit(ctx, stream, admissionFixture(profile), nil)
	if err != nil {
		fatalf("commit admission: %v", err)
	}
	if response.Status != artifactv2.AdmissionSuccess {
		fatalf("unexpected admission response: %+v", response)
	}
	fmt.Println("OK")
}

func runServer(profile string) {
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS(profile), rawquic.DefaultLimits())
	if err != nil {
		fatalf("listen: %v", err)
	}
	defer listener.Close()
	fmt.Printf("READY %s\n", listener.Addr())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := listener.Accept(ctx)
	if err != nil {
		fatalf("accept Rust client: %v", err)
	}
	defer session.Close()
	stream, err := session.AcceptStream(ctx)
	if err != nil {
		fatalf("accept admission stream: %v", err)
	}
	_, err = admissionv2.Serve(ctx, stream, nil, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	})
	if err != nil {
		fatalf("serve admission: %v", err)
	}
	barrier, err := session.AcceptStream(ctx)
	if err != nil {
		fatalf("accept delivery barrier: %v", err)
	}
	barrierPayload, err := io.ReadAll(barrier)
	if err != nil {
		fatalf("read delivery barrier: %v", err)
	}
	if string(barrierPayload) != "ACK" {
		fatalf("delivery barrier = %q, want ACK", barrierPayload)
	}
	fmt.Println("OK")
}

func serverTLS(profile string) *tls.Config {
	certDER, privateKey := testIdentity()
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: privateKey}},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{profileALPN(profile)},
	}
}

func clientTLS(profile string) *tls.Config {
	certDER, _ := testIdentity()
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		fatalf("parse test certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{
		RootCAs: roots, ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{profileALPN(profile)},
	}
}

func testIdentity() ([]byte, ed25519.PrivateKey) {
	certDER, err := base64.StdEncoding.DecodeString(testCertDERBase64)
	if err != nil {
		fatalf("decode certificate: %v", err)
	}
	keyDER, err := base64.StdEncoding.DecodeString(testKeyDERBase64)
	if err != nil {
		fatalf("decode private key: %v", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		fatalf("parse private key: %v", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		fatalf("test private key is %T, want ed25519.PrivateKey", parsed)
	}
	return certDER, privateKey
}

func admissionFixture(profile string) []byte {
	raw, err := os.ReadFile("testdata/transport_v2/artifact_vectors.json")
	if err != nil {
		fatalf("read artifact vectors: %v", err)
	}
	var fixture struct {
		Positive []struct {
			PathKind string `json:"path_kind"`
			Winners  []struct {
				CandidateID string `json:"candidate_id"`
				FSB2Hex     string `json:"fsb2_hex"`
			} `json:"winners"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		fatalf("parse artifact vectors: %v", err)
	}
	for _, vector := range fixture.Positive {
		if vector.PathKind != profile {
			continue
		}
		for _, winner := range vector.Winners {
			if winner.CandidateID != "q1" {
				continue
			}
			decoded := make([]byte, len(winner.FSB2Hex)/2)
			for index := range decoded {
				if _, err := fmt.Sscanf(winner.FSB2Hex[index*2:index*2+2], "%02x", &decoded[index]); err != nil {
					fatalf("decode FSB2 fixture: %v", err)
				}
			}
			return decoded
		}
	}
	fatalf("raw QUIC %s FSB2 fixture is missing", profile)
	return nil
}

func profileArgument(index int) string {
	if len(os.Args) <= index {
		return "direct"
	}
	profile := os.Args[index]
	if profile != "direct" && profile != "tunnel" {
		fatalf("invalid profile %q", profile)
	}
	return profile
}

func profileALPN(profile string) string {
	if profile == "tunnel" {
		return rawquic.ALPNTunnel
	}
	return rawquic.ALPNDirect
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
