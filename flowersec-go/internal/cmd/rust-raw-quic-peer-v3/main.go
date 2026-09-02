package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier/rawquicv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv3"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v5/internal/rpc"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v5/internal/rpcwire"
	flowersession "github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv3"
)

const testCertDERBase64 = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw=="
const testKeyDERBase64 = "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6"

const (
	interopChannelID  = "rust-go-v3-interop"
	interopMaxStreams = uint16(4)
	peerTimeout       = 90 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: rust-raw-quic-peer-v3 client|session-client <address> [direct|tunnel] | server|session-server [direct|tunnel]")
	}
	switch os.Args[1] {
	case "client", "session-client":
		if len(os.Args) < 3 || len(os.Args) > 4 {
			fatalf("%s requires an address and optional profile", os.Args[1])
		}
		runClient(os.Args[2], profileArgument(3), os.Args[1] == "session-client")
	case "server", "session-server":
		if len(os.Args) > 3 {
			fatalf("%s accepts only an optional profile", os.Args[1])
		}
		runServer(profileArgument(2), os.Args[1] == "session-server")
	default:
		fatalf("unknown mode %q", os.Args[1])
	}
}

func runClient(address, profile string, establish bool) {
	ctx, cancel := context.WithTimeout(context.Background(), peerTimeout)
	defer cancel()
	limits := sessionLimits()
	carrierSession, err := rawquicv3.Dial(ctx, address, clientTLS(profile), limits)
	must("dial Rust server", err)
	defer carrierSession.Close()

	artifact := interopArtifact(profile, address)
	request, err := artifactv3.BuildRequest(artifact, "q-ca")
	must("build FSB3", err)
	rawFSB3, err := artifactv3.MarshalRequest(request)
	must("marshal FSB3", err)
	stream, err := rawquicv3.OpenAdmissionStream(ctx, carrierSession)
	must("open admission", err)
	_, err = admissionv3.CommitClient(ctx, stream, rawFSB3)
	must("commit admission", err)
	if !establish {
		fmt.Println("OK")
		return
	}
	established, err := flowersession.Establish(ctx, carrierSession, sessionConfig(
		profile,
		flowersession.RoleClient,
		artifactv3.AdmissionBinding(rawFSB3),
	))
	must("establish Session v3", err)
	defer established.Close()
	must("exercise Session v3", exerciseSession(ctx, established))
	fmt.Println("OK")
}

func runServer(profile string, establish bool) {
	ctx, cancel := context.WithTimeout(context.Background(), peerTimeout)
	defer cancel()
	listener, err := rawquicv3.Listen("127.0.0.1:0", serverTLS(profile), sessionLimits())
	must("listen", err)
	defer listener.Close()
	fmt.Printf("READY %s\n", listener.Addr())
	carrierSession, err := listener.Accept(ctx)
	must("accept Rust client", err)
	defer carrierSession.Close()
	stream, err := rawquicv3.AcceptAdmissionStream(ctx, carrierSession)
	must("accept admission", err)
	decoded, err := admissionv3.Serve(ctx, stream, artifactv3.ReasonRegistry{}, func(_ context.Context, request *artifactv3.DecodedRequest) (artifactv3.AdmissionResponse, error) {
		if err := validateAdmission(profile, request); err != nil {
			return artifactv3.AdmissionResponse{}, err
		}
		return artifactv3.AdmissionResponse{Status: artifactv3.AdmissionSuccess}, nil
	})
	must("serve admission", err)
	if !establish {
		barrier, acceptErr := carrierSession.AcceptStream(ctx)
		must("accept response barrier", acceptErr)
		payload, readErr := io.ReadAll(barrier)
		must("read response barrier", readErr)
		if string(payload) != "ACK" {
			fatalf("response barrier = %q, want ACK", payload)
		}
		fmt.Println("OK")
		return
	}
	established, err := flowersession.Establish(ctx, carrierSession, sessionConfig(
		profile,
		flowersession.RoleServer,
		decoded.LocalAdmissionBinding,
	))
	must("establish Session v3", err)
	defer established.Close()
	must("exercise Session v3", exerciseSession(ctx, established))
	fmt.Println("OK")
}

func exerciseSession(ctx context.Context, established flowersession.Session) error {
	var echoed map[string]string
	if err := established.RPC().Call(ctx, 110, map[string]string{"from": "go"}, &echoed); err != nil {
		return fmt.Errorf("pre-rekey RPC: %w", err)
	}
	if echoed["from"] != "go" {
		return fmt.Errorf("pre-rekey RPC response = %v", echoed)
	}
	local, err := established.OpenStream(ctx, "go-to-rust", flowersession.Metadata{"language": "go"})
	if err != nil {
		return fmt.Errorf("open Go stream: %w", err)
	}
	if _, err := local.Write([]byte("go-app")); err != nil {
		return fmt.Errorf("write Go stream: %w", err)
	}
	if err := local.CloseWrite(); err != nil {
		return fmt.Errorf("finish Go stream: %w", err)
	}
	incoming, err := established.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept Rust stream: %w", err)
	}
	if incoming.Kind != "rust-to-go" {
		return fmt.Errorf("Rust stream kind = %q", incoming.Kind)
	}
	payload, err := io.ReadAll(incoming.Stream)
	if err != nil || string(payload) != "rust-app" {
		return fmt.Errorf("Rust stream payload = %q: %w", payload, err)
	}
	if _, err := incoming.Stream.Write([]byte("go-reply")); err != nil {
		return fmt.Errorf("reply to Rust stream: %w", err)
	}
	if err := incoming.Stream.CloseWrite(); err != nil {
		return fmt.Errorf("finish Rust stream reply: %w", err)
	}
	reply, err := io.ReadAll(local)
	if err != nil || string(reply) != "rust-reply" {
		return fmt.Errorf("Rust reply = %q: %w", reply, err)
	}
	if _, err := established.ProbeLiveness(ctx); err != nil {
		return fmt.Errorf("probe liveness: %w", err)
	}
	if err := established.Rekey(ctx); err != nil {
		return fmt.Errorf("rekey: %w", err)
	}
	echoed = nil
	if err := established.RPC().Call(ctx, 110, map[string]string{"phase": "post-rekey"}, &echoed); err != nil {
		return fmt.Errorf("post-rekey RPC: %w", err)
	}
	if echoed["phase"] != "post-rekey" {
		return fmt.Errorf("post-rekey RPC response = %v", echoed)
	}
	return nil
}

func validateAdmission(profile string, decoded *artifactv3.DecodedRequest) error {
	if decoded == nil {
		return errors.New("nil FSB3 request")
	}
	want := interopContract()
	wantPath := artifactv3.PathDirect
	if profile == "tunnel" {
		wantPath = artifactv3.PathTunnel
	}
	request := decoded.Request
	if request.PathKind != wantPath || request.Profile != artifactv3.Profile ||
		request.ChannelID != want.ChannelID || request.SessionContractHash != want.ContractHash ||
		request.ChosenCandidateID != "q-ca" || len(request.Candidates) != 1 ||
		request.Candidates[0].Carrier != artifactv3.CarrierRawQUIC ||
		request.Candidates[0].TLS.Mode != artifactv3.TLSModeCA {
		return errors.New("FSB3 request does not match the v3 interop contract")
	}
	if profile == "tunnel" && (request.Role != 1 || request.EndpointInstanceID != "endpoint-client") {
		return errors.New("FSB3 tunnel endpoint identity mismatch")
	}
	return nil
}

func interopArtifact(profile, address string) artifactv3.Artifact {
	path := artifactv3.ArtifactPath{
		Kind: artifactv3.PathDirect, RendezvousGroupID: "rust-go-v3",
		ListenerAudience: "rust-go-v3-listener", RoutingToken: "rust-go-v3-routing",
	}
	wireProfile := rawquicv3.ALPNDirect
	if profile == "tunnel" {
		path = artifactv3.ArtifactPath{
			Kind: artifactv3.PathTunnel, RendezvousGroupID: "rust-go-v3",
			ListenerAudience: "rust-go-v3-listener", Role: 1,
			LocalEndpointInstanceID: "endpoint-client", ExpectedPeerEndpointInstanceID: "endpoint-server",
			Token: "rust-go-v3-attach",
		}
		wireProfile = rawquicv3.ALPNTunnel
	}
	_, port, err := net.SplitHostPort(address)
	must("parse peer address", err)
	path.Candidates = []artifactv3.Candidate{{
		ID: "q-ca", Carrier: artifactv3.CarrierRawQUIC,
		URL:         "quic://" + net.JoinHostPort("localhost", port) + "/",
		WireProfile: wireProfile, TLS: artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA},
	}}
	return artifactv3.Artifact{
		Version: 3, Profile: artifactv3.Profile, Session: interopContract(), Path: path,
		Scoped:      []artifactv3.ScopeMetadata{},
		Correlation: artifactv3.CorrelationContext{Version: 3, Tags: []artifactv3.CorrelationTag{}},
	}
}

func interopContract() artifactv3.SessionContract {
	contract := artifactv3.SessionContract{
		ChannelID: interopChannelID, InitExpireAtUnixSeconds: 2_000_000_000,
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: interopMaxStreams, AllowedSuites: []uint16{1}, DefaultSuite: 1,
	}
	for index := range contract.E2EEPSK {
		contract.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv3.ComputeSessionContractHash(contract)
	must("compute session contract hash", err)
	contract.ContractHash = hash
	return contract
}

func sessionConfig(profile string, role flowersession.SessionRole, localBinding [32]byte) flowersession.Config {
	contract := interopContract()
	path := flowersession.PathDirect
	peerBinding := localBinding
	localEndpointID := ""
	expectedPeerEndpointID := ""
	if profile == "tunnel" {
		path = flowersession.PathTunnel
		peerBinding = [32]byte{}
		if role == flowersession.RoleClient {
			localEndpointID, expectedPeerEndpointID = "endpoint-client", "endpoint-server"
		} else {
			localEndpointID, expectedPeerEndpointID = "endpoint-server", "endpoint-client"
		}
	}
	router := internalrpc.NewRouter()
	router.Register(110, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		return append(json.RawMessage(nil), payload...), nil
	})
	return flowersession.Config{
		Role: role, Path: path, ChannelID: contract.ChannelID,
		SessionContractHash: contract.ContractHash, Suite: protocolv3.SuiteChaCha20Poly1305,
		PSK: contract.E2EEPSK, MaxInboundStreams: contract.MaxInboundStreams,
		IdleTimeout:            time.Duration(contract.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:       time.Duration(contract.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:    time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second,
		LocalAdmissionBinding:  localBinding, PeerAdmissionBinding: peerBinding,
		LocalEndpointInstanceID: localEndpointID, ExpectedPeerEndpointInstanceID: expectedPeerEndpointID,
		RPCRouter: router,
	}
}

func sessionLimits() quicbase.Limits {
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), interopMaxStreams)
	must("bind raw QUIC limits", err)
	return limits
}

func serverTLS(profile string) *tls.Config {
	certDER, privateKey := testIdentity()
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: privateKey}},
		MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{profileALPN(profile)},
	}
}

func clientTLS(profile string) *tls.Config {
	certDER, _ := testIdentity()
	certificate, err := x509.ParseCertificate(certDER)
	must("parse test certificate", err)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{
		RootCAs: roots, ServerName: "localhost",
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{profileALPN(profile)},
	}
}

func testIdentity() ([]byte, ed25519.PrivateKey) {
	certDER, err := base64.StdEncoding.DecodeString(testCertDERBase64)
	must("decode certificate", err)
	keyDER, err := base64.StdEncoding.DecodeString(testKeyDERBase64)
	must("decode private key", err)
	parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
	must("parse private key", err)
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		fatalf("test private key is %T, want ed25519.PrivateKey", parsed)
	}
	return certDER, privateKey
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
		return rawquicv3.ALPNTunnel
	}
	return rawquicv3.ALPNDirect
}

func must(operation string, err error) {
	if err != nil {
		fatalf("%s: %v", operation, err)
	}
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
