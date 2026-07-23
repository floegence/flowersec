package session_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

type testByteStream struct{}

func (testByteStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (testByteStream) Write(p []byte) (int, error) { return len(p), nil }
func (testByteStream) ID() uint64                  { return 1 }
func (testByteStream) Kind() string                { return "rpc" }
func (testByteStream) TerminalError() error        { return nil }
func (testByteStream) CloseWrite() error           { return nil }
func (testByteStream) Reset() error                { return nil }
func (testByteStream) Close() error                { return nil }

type testRPCPeer struct{}

func (testRPCPeer) Call(context.Context, uint32, any, any) error { return nil }
func (testRPCPeer) Notify(context.Context, uint32, any) error    { return nil }

type testSession struct{}

func (testSession) Path() session.PathKind             { return session.PathDirect }
func (testSession) EndpointInstanceID() (string, bool) { return "", false }
func (testSession) RPC() session.RPCPeer               { return testRPCPeer{} }
func (testSession) OpenStream(context.Context, string, session.Metadata) (session.ByteStream, error) {
	return testByteStream{}, nil
}
func (testSession) AcceptStream(context.Context) (session.IncomingStream, error) {
	return session.IncomingStream{ID: 1, Kind: "rpc", Metadata: session.Metadata{}, Stream: testByteStream{}}, nil
}
func (testSession) Rekey(context.Context) error                          { return nil }
func (testSession) ProbeLiveness(context.Context) (time.Duration, error) { return 0, nil }
func (testSession) Close() error                                         { return nil }
func (testSession) Termination() <-chan struct{} {
	terminated := make(chan struct{})
	close(terminated)
	return terminated
}
func (testSession) WaitClosed(context.Context) error { return session.ErrSessionClosed }

func TestSessionV2ContractIsCarrierNeutral(t *testing.T) {
	var _ session.ByteStream = testByteStream{}
	var _ session.RPCPeer = testRPCPeer{}
	var _ session.SessionV2 = testSession{}
	contract := reflect.TypeOf((*session.SessionV2)(nil)).Elem()
	if _, exposed := contract.MethodByName("ChosenCarrier"); exposed {
		t.Fatal("SessionV2 exposes the selected carrier")
	}
}

func TestGoCapabilityDescriptorUsesExactTuples(t *testing.T) {
	descriptor := session.GoCapabilities()
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	want := []session.CapabilityTuple{
		{Carrier: carrier.KindWebSocket, NetworkMode: session.NetworkDial, SessionRole: session.RoleClient, Path: session.PathDirect},
		{Carrier: carrier.KindWebSocket, NetworkMode: session.NetworkListen, SessionRole: session.RoleServer, Path: session.PathDirect},
		{Carrier: carrier.KindWebSocket, NetworkMode: session.NetworkDial, SessionRole: session.RoleClient, Path: session.PathTunnel},
		{Carrier: carrier.KindWebSocket, NetworkMode: session.NetworkDial, SessionRole: session.RoleServer, Path: session.PathTunnel},
		{Carrier: carrier.KindQUIC, NetworkMode: session.NetworkDial, SessionRole: session.RoleClient, Path: session.PathDirect},
		{Carrier: carrier.KindQUIC, NetworkMode: session.NetworkListen, SessionRole: session.RoleServer, Path: session.PathDirect},
		{Carrier: carrier.KindQUIC, NetworkMode: session.NetworkDial, SessionRole: session.RoleClient, Path: session.PathTunnel},
		{Carrier: carrier.KindQUIC, NetworkMode: session.NetworkDial, SessionRole: session.RoleServer, Path: session.PathTunnel},
		{Carrier: carrier.KindWebTransport, NetworkMode: session.NetworkDial, SessionRole: session.RoleClient, Path: session.PathDirect},
		{Carrier: carrier.KindWebTransport, NetworkMode: session.NetworkListen, SessionRole: session.RoleServer, Path: session.PathDirect},
		{Carrier: carrier.KindWebTransport, NetworkMode: session.NetworkDial, SessionRole: session.RoleClient, Path: session.PathTunnel},
		{Carrier: carrier.KindWebTransport, NetworkMode: session.NetworkDial, SessionRole: session.RoleServer, Path: session.PathTunnel},
	}
	for _, tuple := range want {
		if !descriptor.Supports(tuple) {
			t.Errorf("missing capability tuple: %+v", tuple)
		}
	}

	invalid := descriptor
	invalid.Tuples = append(invalid.Tuples, descriptor.Tuples[0])
	if err := invalid.Validate(); !errors.Is(err, session.ErrDuplicateCapability) {
		t.Fatalf("duplicate error = %v, want ErrDuplicateCapability", err)
	}

	invalid = session.CapabilityDescriptor{
		Runtime: "invalid-cross-product",
		Tuples: []session.CapabilityTuple{{
			Carrier:     carrier.KindQUIC,
			NetworkMode: session.NetworkListen,
			SessionRole: session.RoleClient,
			Path:        session.PathDirect,
		}},
	}
	if err := invalid.Validate(); !errors.Is(err, session.ErrInvalidCapability) {
		t.Fatalf("cross-product error = %v, want ErrInvalidCapability", err)
	}
}

func TestCapabilityDescriptorMatchesSharedCanonicalVector(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Name          string `json:"name"`
			CanonicalJSON string `json:"canonical_json"`
			DigestHex     string `json:"digest_hex"`
		} `json:"vectors"`
	}
	raw, err := os.ReadFile("../../../testdata/transport_v2/capability_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Name          string
		CanonicalJSON string
		DigestHex     string
	}
	for _, candidate := range fixture.Vectors {
		if candidate.Name == "go-native" {
			vector = struct {
				Name          string
				CanonicalJSON string
				DigestHex     string
			}{candidate.Name, candidate.CanonicalJSON, candidate.DigestHex}
		}
	}
	if vector.Name == "" {
		t.Fatal("go-native capability vector is missing")
	}

	descriptor := session.GoCapabilities()
	encoded, err := session.EncodeCapabilityDescriptor(descriptor)
	if err != nil {
		t.Fatalf("EncodeCapabilityDescriptor: %v", err)
	}
	if string(encoded) != vector.CanonicalJSON {
		t.Fatalf("canonical descriptor = %s, want %s", encoded, vector.CanonicalJSON)
	}
	digest, err := session.CapabilityDescriptorDigest(descriptor)
	if err != nil {
		t.Fatalf("CapabilityDescriptorDigest: %v", err)
	}
	if hex.EncodeToString(digest[:]) != vector.DigestHex {
		t.Fatalf("digest = %x, want %s", digest, vector.DigestHex)
	}
	decoded, err := session.DecodeCapabilityDescriptor(encoded)
	if err != nil {
		t.Fatalf("DecodeCapabilityDescriptor: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("decoded Validate: %v", err)
	}
}

func TestCapabilityDescriptorDecoderRejectsUnknownAndNonCanonicalInput(t *testing.T) {
	canonical, err := session.EncodeCapabilityDescriptor(session.GoCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := append([]byte(nil), canonical[:len(canonical)-1]...)
	withUnknown = append(withUnknown, []byte(`,"extra":true}`)...)
	if _, err := session.DecodeCapabilityDescriptor(withUnknown); err == nil {
		t.Fatal("descriptor with unknown field was accepted")
	}
	withWhitespace := append([]byte(" "), canonical...)
	if _, err := session.DecodeCapabilityDescriptor(withWhitespace); err == nil {
		t.Fatal("non-canonical descriptor was accepted")
	}
}
