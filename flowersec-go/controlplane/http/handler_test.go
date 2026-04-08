package controlplanehttp

import (
	"bytes"
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"

	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

func makeHandlerArtifact(channelID string, transport protocolio.ConnectArtifactTransport) *protocolio.ConnectArtifact {
	switch transport {
	case protocolio.ConnectArtifactTransportDirect:
		return &protocolio.ConnectArtifact{
			V:         1,
			Transport: protocolio.ConnectArtifactTransportDirect,
			DirectInfo: &directv1.DirectConnectInfo{
				WsUrl:                    "wss://example.invalid/direct",
				ChannelId:                channelID,
				ChannelInitExpireAtUnixS: 123,
				E2eePskB64u:              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				DefaultSuite:             directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
			},
		}
	default:
		return &protocolio.ConnectArtifact{
			V:         1,
			Transport: protocolio.ConnectArtifactTransportTunnel,
			TunnelGrant: &controlv1.ChannelInitGrant{
				TunnelUrl:                "wss://example.invalid/tunnel",
				ChannelId:                channelID,
				ChannelInitExpireAtUnixS: 123,
				IdleTimeoutSeconds:       30,
				Role:                     1,
				Token:                    "tok",
				E2eePskB64u:              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				AllowedSuites:            []controlv1.Suite{controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM},
				DefaultSuite:             controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
			},
		}
	}
}

func newArtifactHTTPRequest(t *testing.T, path, body string) *stdhttp.Request {
	t.Helper()
	req := httptest.NewRequest(stdhttp.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-123")
	req.Header.Set("Origin", "https://app.example.test")
	req.Header.Set("User-Agent", "flowersec-test")
	req.RemoteAddr = "127.0.0.1:1234"
	return req
}

func TestNewArtifactHandler_PassesMetadataAndRequestToIssuer(t *testing.T) {
	var seen ArtifactIssueInput
	handler := NewArtifactHandler(ArtifactHandlerOptions{
		ExtractMetadata: func(r *stdhttp.Request) (ArtifactRequestMetadata, error) {
			meta := DefaultRequestMetadata(r)
			meta.AuthenticatedSubject = "user-1"
			meta.Attributes["tenant"] = "t-1"
			return meta, nil
		},
		IssueArtifact: func(_ context.Context, input ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
			seen = input
			return makeHandlerArtifact("chan_1", protocolio.ConnectArtifactTransportTunnel), nil
		},
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newArtifactHTTPRequest(t, "/v1/connect/artifact", `{"endpoint_id":"env_demo","payload":{"app":"demo"},"correlation":{"trace_id":"trace-0001"}}`))

	if rec.Code != stdhttp.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if seen.EndpointID != "env_demo" || seen.TraceID != "trace-0001" {
		t.Fatalf("unexpected issue input: %+v", seen)
	}
	if seen.Metadata.AuthenticatedSubject != "user-1" || seen.Metadata.Attributes["tenant"] != "t-1" {
		t.Fatalf("unexpected metadata: %+v", seen.Metadata)
	}
}

func TestNewEntryArtifactHandler_PassesBearerTicket(t *testing.T) {
	var seen ArtifactIssueInput
	handler := NewEntryArtifactHandler(ArtifactHandlerOptions{
		IssueArtifact: func(_ context.Context, input ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
			seen = input
			return makeHandlerArtifact("chan_2", protocolio.ConnectArtifactTransportDirect), nil
		},
	})

	req := newArtifactHTTPRequest(t, "/v1/connect/artifact/entry", `{"endpoint_id":"env_demo"}`)
	req.Header.Set("Authorization", "Bearer ticket-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != stdhttp.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !seen.IsEntry || seen.EntryTicket != "ticket-1" {
		t.Fatalf("unexpected issue input: %+v", seen)
	}
}

func TestNewArtifactHandler_RejectsWrongMethod(t *testing.T) {
	handler := NewArtifactHandler(ArtifactHandlerOptions{})
	req := httptest.NewRequest(stdhttp.MethodGet, "/v1/connect/artifact", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != stdhttp.StatusMethodNotAllowed {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
}

func TestNewArtifactHandler_MapsMetadataExtractFailure(t *testing.T) {
	handler := NewArtifactHandler(ArtifactHandlerOptions{
		ExtractMetadata: func(*stdhttp.Request) (ArtifactRequestMetadata, error) {
			return ArtifactRequestMetadata{}, NewRequestError(stdhttp.StatusUnauthorized, "unauthorized", "missing subject", nil)
		},
		IssueArtifact: func(_ context.Context, input ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
			t.Fatalf("unexpected IssueArtifact call: %+v", input)
			return nil, nil
		},
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newArtifactHTTPRequest(t, "/v1/connect/artifact", `{"endpoint_id":"env_demo"}`))

	if rec.Code != stdhttp.StatusUnauthorized {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNewArtifactHandler_MapsValidationAndIssuerFailures(t *testing.T) {
	t.Run("validation failure", func(t *testing.T) {
		handler := NewArtifactHandler(ArtifactHandlerOptions{
			ValidateRequest: func(_ *stdhttp.Request, _ *ArtifactRequest) error {
				return NewRequestError(stdhttp.StatusForbidden, "origin_mismatch", "origin mismatch", nil)
			},
			IssueArtifact: func(_ context.Context, input ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
				t.Fatalf("unexpected IssueArtifact call: %+v", input)
				return nil, nil
			},
		})

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newArtifactHTTPRequest(t, "/v1/connect/artifact", `{"endpoint_id":"env_demo"}`))
		if rec.Code != stdhttp.StatusForbidden {
			t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("issuer failure", func(t *testing.T) {
		handler := NewArtifactHandler(ArtifactHandlerOptions{
			IssueArtifact: func(_ context.Context, _ ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
				return nil, NewRequestError(stdhttp.StatusTooManyRequests, "replay_guard", "artifact replay blocked", nil)
			},
		})

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newArtifactHTTPRequest(t, "/v1/connect/artifact", `{"endpoint_id":"env_demo"}`))
		if rec.Code != stdhttp.StatusTooManyRequests {
			t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestNewArtifactHandler_WritesDirectAndTunnelArtifacts(t *testing.T) {
	for _, transport := range []protocolio.ConnectArtifactTransport{
		protocolio.ConnectArtifactTransportTunnel,
		protocolio.ConnectArtifactTransportDirect,
	} {
		t.Run(string(transport), func(t *testing.T) {
			handler := NewArtifactHandler(ArtifactHandlerOptions{
				IssueArtifact: func(_ context.Context, _ ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
					return makeHandlerArtifact("chan-test", transport), nil
				},
			})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, newArtifactHTTPRequest(t, "/v1/connect/artifact", `{"endpoint_id":"env_demo"}`))
			if rec.Code != stdhttp.StatusOK {
				t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			artifact := body["connect_artifact"].(map[string]any)
			if artifact["transport"] != string(transport) {
				t.Fatalf("unexpected artifact transport: %#v", artifact)
			}
		})
	}
}
