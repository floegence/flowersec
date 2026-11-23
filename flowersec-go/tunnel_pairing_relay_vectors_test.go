package flowersec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/transportsecurity"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/tunnelv3"
)

type pairingAdmission struct {
	raw       []byte
	responses chan artifactv3.AdmissionResponse
}

func (*pairingAdmission) CarrierKind() carrier.Kind { return carrier.KindWebSocket }
func (leg *pairingAdmission) ReceiveAdmission(context.Context) (*artifactv3.DecodedRequest, error) {
	return artifactv3.ParseRequest(leg.raw)
}
func (leg *pairingAdmission) SendAdmission(ctx context.Context, response artifactv3.AdmissionResponse, _ artifactv3.ReasonRegistry) error {
	select {
	case leg.responses <- response:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*pairingAdmission) Activate(ctx context.Context, _ uint8) (carrier.Session, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*pairingAdmission) CloseWithError(context.Context, carrier.ApplicationError) error { return nil }

func (leg *pairingAdmission) expect(t *testing.T, ctx context.Context, status artifactv3.AdmissionStatus, reason string) {
	t.Helper()
	select {
	case response := <-leg.responses:
		if response.Status != status || response.Reason != reason {
			t.Fatalf("admission = %v, want %v %q", response, status, reason)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestTunnelPairingRelayVectors(t *testing.T) {
	fixture := readPairingVectors(t, "../testdata/transport_v5/tunnel_pairing_vectors.json")
	records := make(map[string]controlplane.AuthorizationRecord)
	for _, leg := range fixture.Legs {
		artifact, err := ParseArtifact([]byte(leg.ArtifactJSON))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(map[string]any{"schema_version": 1, "authority_scope": "fixture-issuer", "lookup_key": artifact.LookupKey(), "artifact_base64url": base64.RawURLEncoding.EncodeToString([]byte(leg.ArtifactJSON))})
		if err != nil {
			t.Fatal(err)
		}
		record, err := controlplane.ParseAuthorizationRecord(encoded)
		if err != nil {
			t.Fatal(err)
		}
		records[record.LookupKey()] = record
	}
	var listeners []TunnelListener
	endpoints := make(map[TunnelListener]string)
	states := make(map[string]*tls.ConnectionState)
	for id, listener := range fixture.Listeners {
		endpoint, err := url.Parse(listener.URL)
		if err != nil {
			t.Fatal(err)
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{endpoint.Hostname()}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
		if err != nil {
			t.Fatal(err)
		}
		states[id] = &tls.ConnectionState{Version: tls.VersionTLS13, LocalCertificate: [][]byte{der}}
		boundary := NewWebSocketTunnelListener()
		listeners = append(listeners, boundary)
		endpoints[boundary] = listener.URL
	}
	if len(fixture.Scenarios) != 4 {
		t.Fatalf("got %d pairing scenarios", len(fixture.Scenarios))
	}
	for _, scenario := range fixture.Scenarios {
		t.Run(scenario.ID, func(t *testing.T) {
			runtime, err := NewTunnelRuntime(TunnelRuntimeOptions{Listeners: listeners, IngressEndpoints: endpoints, AllowedOrigins: []string{"https://app.example"}, Release: func(context.Context, string) {}, Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
				return controlplane.AuthorizeTunnelRuntime(request, records[request.LookupKey()], request.LookupKey())
			}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer func() {
				cancel()
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := runtime.coordinator.WaitCleanup(cleanup); err != nil {
					t.Error(err)
				}
			}()
			var waiting *pairingAdmission
			for _, step := range scenario.Steps {
				vector := fixture.Legs[step[0]]
				listener := fixture.Listeners[step[1]]
				raw, err := hex.DecodeString(vector.Frame)
				if err != nil {
					t.Fatal(err)
				}
				leg := &pairingAdmission{raw: raw, responses: make(chan artifactv3.AdmissionResponse, 1)}
				observed := context.WithValue(ctx, acceptorTransportContextKey{}, acceptorTransportContext{carrier: "websocket", remoteAddress: "127.0.0.1:443"})
				observed = transportsecurity.WithTunnelIngress(observed, artifactv3.CarrierWebSocket, listener.URL, states[step[1]])
				err = runtime.coordinator.AdmitUntil(observed, leg, time.Now().Add(3*time.Second), func(error) {})
				switch step[2] {
				case "pending":
					if err != nil {
						t.Fatal(err)
					}
					waiting = leg
					select {
					case response := <-leg.responses:
						t.Fatalf("unpaired admission: %v", response)
					default:
					}
				case "paired":
					if err != nil || waiting == nil {
						t.Fatalf("no waiting peer or registration failed: %v", err)
					}
					waiting.expect(t, ctx, artifactv3.AdmissionSuccess, "")
					leg.expect(t, ctx, artifactv3.AdmissionSuccess, "")
					waiting = nil
				case "must_not_pair":
					if !errors.Is(err, tunnelv3.ErrPairMismatch) {
						t.Fatalf("unmirrored peer: %v", err)
					}
					leg.expect(t, ctx, artifactv3.AdmissionReject, tunnelv3.ReasonPairMismatch)
				case "deny_admission":
					switch scenario.ID {
					case "replay-after-pair":
						if !errors.Is(err, tunnelv3.ErrCredentialReplay) {
							t.Fatalf("replay: %v", err)
						}
						leg.expect(t, ctx, artifactv3.AdmissionReject, tunnelv3.ReasonCredentialReplay)
					case "wrong-listener":
						if !errors.Is(err, ErrInvalidTunnelRuntime) {
							t.Fatalf("listener mismatch: %v", err)
						}
						leg.expect(t, ctx, artifactv3.AdmissionReject, tunnelv3.ReasonInvalidCredential)
					default:
						t.Fatalf("unexpected denial: %v", err)
					}
				default:
					t.Fatalf("unknown step %q", step[2])
				}
			}
		})
	}
}
