package e2e_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	controlplanehttp "github.com/floegence/flowersec/flowersec-go/controlplane/http"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/proxy"
	"github.com/floegence/flowersec/flowersec-go/transportsecurity"
)

type portableProtocolVectors struct {
	Version                   int             `json:"version"`
	TransportPolicy           []transportCase `json:"transport_policy"`
	YamuxHeader               yamuxHeader     `json:"yamux_header"`
	RPCEnvelope               json.RawMessage `json:"rpc_envelope"`
	ControlplaneErrorEnvelope json.RawMessage `json:"controlplane_error_envelope"`
	ProxyHTTPRequestMeta      json.RawMessage `json:"proxy_http_request_meta"`
	ProxyWSOpenMeta           json.RawMessage `json:"proxy_ws_open_meta"`
	DiagnosticEvent           json.RawMessage `json:"diagnostic_event"`
}

type transportCase struct {
	URL            string   `json:"url"`
	Policy         string   `json:"policy"`
	AllowedHosts   []string `json:"allowed_hosts"`
	RiskAcceptance string   `json:"risk_acceptance"`
	Allowed        bool     `json:"allowed"`
}

type yamuxHeader struct {
	BytesHex string `json:"bytes_hex"`
	Version  byte   `json:"version"`
	Type     byte   `json:"type"`
	Flags    uint16 `json:"flags"`
	StreamID uint32 `json:"stream_id"`
	Length   uint32 `json:"length"`
}

type codeRegistry struct {
	Codes []struct {
		Code string `json:"code"`
	} `json:"codes"`
}

func TestPortableProtocolVectors(t *testing.T) {
	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "testdata", "portable_protocol_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors portableProtocolVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != 1 {
		t.Fatalf("unexpected vector version: %d", vectors.Version)
	}

	for _, test := range vectors.TransportPolicy {
		var policy transportsecurity.Policy = transportsecurity.RequireTLS
		switch test.Policy {
		case "allow_plaintext_for_loopback":
			policy = transportsecurity.AllowPlaintextForLoopback
		case "allow_plaintext":
			policy = transportsecurity.AllowPlaintext
		case "network_plaintext":
			if test.RiskAcceptance != string(transportsecurity.PlaintextRiskAcceptPreE2ECredentialExposure) {
				t.Fatalf("invalid network plaintext risk acceptance %q", test.RiskAcceptance)
			}
			var err error
			policy, err = transportsecurity.NewNetworkPlaintextPolicy(transportsecurity.NetworkPlaintextPolicyOptions{
				AllowedHosts:   test.AllowedHosts,
				RiskAcceptance: transportsecurity.PlaintextRiskAcceptPreE2ECredentialExposure,
			})
			if err != nil {
				t.Fatalf("network plaintext policy: %v", err)
			}
		case "require_tls":
		default:
			t.Fatalf("unknown transport policy %q", test.Policy)
		}
		_, err := transportsecurity.Evaluate(
			context.Background(),
			test.URL,
			fserrors.PathDirect,
			transportsecurity.RuntimeNative,
			policy,
		)
		if (err == nil) != test.Allowed {
			t.Fatalf("transport case url=%q policy=%q allowed=%t: %v", test.URL, test.Policy, test.Allowed, err)
		}
	}

	header, err := hex.DecodeString(vectors.YamuxHeader.BytesHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(header) != 12 ||
		header[0] != vectors.YamuxHeader.Version ||
		header[1] != vectors.YamuxHeader.Type ||
		binary.BigEndian.Uint16(header[2:4]) != vectors.YamuxHeader.Flags ||
		binary.BigEndian.Uint32(header[4:8]) != vectors.YamuxHeader.StreamID ||
		binary.BigEndian.Uint32(header[8:12]) != vectors.YamuxHeader.Length {
		t.Fatalf("unexpected Yamux header: %x", header)
	}

	var rpcEnvelope rpcv1.RpcEnvelope
	if err := json.Unmarshal(vectors.RPCEnvelope, &rpcEnvelope); err != nil {
		t.Fatal(err)
	}
	var rpcPayload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rpcEnvelope.Payload, &rpcPayload); err != nil {
		t.Fatal(err)
	}
	if rpcEnvelope.TypeId != 7 || rpcEnvelope.RequestId != 42 || rpcPayload.Message != "flowersec" {
		t.Fatalf("unexpected RPC envelope: %+v", rpcEnvelope)
	}

	var controlplaneEnvelope controlplanehttp.ErrorEnvelope
	if err := json.Unmarshal(vectors.ControlplaneErrorEnvelope, &controlplaneEnvelope); err != nil {
		t.Fatal(err)
	}
	if controlplaneEnvelope.Error.Code != "artifact_not_found" {
		t.Fatalf("unexpected controlplane envelope: %+v", controlplaneEnvelope)
	}

	var httpMeta proxy.HTTPRequestMeta
	if err := json.Unmarshal(vectors.ProxyHTTPRequestMeta, &httpMeta); err != nil {
		t.Fatal(err)
	}
	if httpMeta.V != proxy.ProtocolVersion || httpMeta.Method != "POST" || httpMeta.TimeoutMS != 1500 {
		t.Fatalf("unexpected HTTP proxy metadata: %+v", httpMeta)
	}
	var wsMeta proxy.WSOpenMeta
	if err := json.Unmarshal(vectors.ProxyWSOpenMeta, &wsMeta); err != nil {
		t.Fatal(err)
	}
	if wsMeta.V != proxy.ProtocolVersion || wsMeta.ConnID != "connection-vector-1" {
		t.Fatalf("unexpected WebSocket proxy metadata: %+v", wsMeta)
	}

	var diagnostic observability.DiagnosticEvent
	if err := json.Unmarshal(vectors.DiagnosticEvent, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if diagnostic.Path != "tunnel" || diagnostic.Stage != observability.DiagnosticStageYamux || diagnostic.Code != "liveness_timeout" {
		t.Fatalf("unexpected diagnostic event: %+v", diagnostic)
	}
	assertRegistryContains(t, filepath.Join(root, "stability", "connect_error_code_registry.json"), "resource_exhausted")
	assertRegistryContains(t, filepath.Join(root, "stability", "connect_diagnostics_code_registry.json"), diagnostic.Code)
}

func assertRegistryContains(t *testing.T, path string, code string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var registry codeRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	for _, entry := range registry.Codes {
		if entry.Code == code {
			return
		}
	}
	t.Fatalf("registry %s does not contain %q", path, code)
}
