package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

func TestConnect_AutoDetectDirect(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"ws_url":""}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageValidate || fe.Code != CodeMissingWSURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_AutoDetectTunnelURL(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"role":1,"tunnel_url":""}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeMissingTunnelURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_AutoDetectGrantClientWrapper(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"grant_client":{"role":1,"tunnel_url":""}}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeMissingTunnelURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_AutoDetectGrantServerWrapper(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"grant_server":{"role":2}}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeRoleMismatch {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_RejectsHybridLegacyInput(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"ws_url":"","tunnel_url":"ws://tunnel.invalid/ws","role":1}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_RejectsRawLegacyWithArtifactFields(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"ws_url":"ws://example.invalid/ws","correlation":{"v":1,"tags":[]}}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_RejectsBareTokenHeuristic(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"token":"tok"}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_RejectsUnknownObject(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"hello":"world"}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_AcceptsTypedDirectArtifact(t *testing.T) {
	_, err := Connect(context.Background(), protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportDirect,
		DirectInfo: &directv1.DirectConnectInfo{
			WsUrl:                    "",
			ChannelId:                "chan_1",
			E2eePskB64u:              "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			ChannelInitExpireAtUnixS: 123,
			DefaultSuite:             1,
		},
	}, WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageValidate || fe.Code != CodeMissingWSURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_ArtifactCriticalScopeWithoutResolverFailsFast(t *testing.T) {
	_, err := Connect(context.Background(), protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportDirect,
		DirectInfo: &directv1.DirectConnectInfo{
			WsUrl:                    "",
			ChannelId:                "chan_1",
			E2eePskB64u:              "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			ChannelInitExpireAtUnixS: 123,
			DefaultSuite:             1,
		},
		Scoped: []protocolio.ScopeMetadataEntry{
			{Scope: "proxy.runtime", ScopeVersion: 2, Critical: true, Payload: protocolio.ScopePayload{"mode": "strict"}},
		},
	}, WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageValidate || fe.Code != CodeResolveFailed {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_ArtifactOptionalScopeWithoutResolverIsIgnored(t *testing.T) {
	_, err := Connect(context.Background(), protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportDirect,
		DirectInfo: &directv1.DirectConnectInfo{
			WsUrl:                    "",
			ChannelId:                "chan_1",
			E2eePskB64u:              "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			ChannelInitExpireAtUnixS: 123,
			DefaultSuite:             1,
		},
		Scoped: []protocolio.ScopeMetadataEntry{
			{Scope: "proxy.runtime", ScopeVersion: 2, Critical: false, Payload: protocolio.ScopePayload{"mode": "hint"}},
		},
	}, WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageValidate || fe.Code != CodeMissingWSURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_ArtifactScopeResolverReceivesScopeVersion(t *testing.T) {
	var got protocolio.ScopeMetadataEntry
	_, err := Connect(context.Background(), protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportDirect,
		DirectInfo: &directv1.DirectConnectInfo{
			WsUrl:                    "",
			ChannelId:                "chan_1",
			E2eePskB64u:              "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			ChannelInitExpireAtUnixS: 123,
			DefaultSuite:             1,
		},
		Scoped: []protocolio.ScopeMetadataEntry{
			{Scope: "proxy.runtime", ScopeVersion: 2, Critical: true, Payload: protocolio.ScopePayload{"mode": "strict"}},
		},
	}, WithOrigin("http://example.com"), WithScopeResolver("proxy.runtime", func(_ context.Context, entry protocolio.ScopeMetadataEntry) error {
		got = entry
		return nil
	}))
	if err == nil {
		t.Fatal("expected error")
	}
	if got.ScopeVersion != 2 || got.Scope != "proxy.runtime" {
		t.Fatalf("unexpected resolver entry: %#v", got)
	}
}

func TestConnect_ArtifactOptionalScopeResolverFailureFailsFastByDefault(t *testing.T) {
	_, err := Connect(context.Background(), protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportDirect,
		DirectInfo: &directv1.DirectConnectInfo{
			WsUrl:                    "",
			ChannelId:                "chan_1",
			E2eePskB64u:              "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			ChannelInitExpireAtUnixS: 123,
			DefaultSuite:             1,
		},
		Scoped: []protocolio.ScopeMetadataEntry{
			{Scope: "proxy.runtime", ScopeVersion: 2, Critical: false, Payload: protocolio.ScopePayload{"mode": "bad"}},
		},
	}, WithOrigin("http://example.com"), WithScopeResolver("proxy.runtime", func(_ context.Context, entry protocolio.ScopeMetadataEntry) error {
		return errors.New("bad payload")
	}))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageValidate || fe.Code != CodeResolveFailed {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_ArtifactOptionalScopeResolverFailureCanBeRelaxed(t *testing.T) {
	_, err := Connect(context.Background(), protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportDirect,
		DirectInfo: &directv1.DirectConnectInfo{
			WsUrl:                    "",
			ChannelId:                "chan_1",
			E2eePskB64u:              "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			ChannelInitExpireAtUnixS: 123,
			DefaultSuite:             1,
		},
		Scoped: []protocolio.ScopeMetadataEntry{
			{Scope: "proxy.runtime", ScopeVersion: 2, Critical: false, Payload: protocolio.ScopePayload{"mode": "bad"}},
		},
	}, WithOrigin("http://example.com"), WithScopeResolver("proxy.runtime", func(_ context.Context, entry protocolio.ScopeMetadataEntry) error {
		return errors.New("bad payload")
	}), WithRelaxedOptionalScopeValidation(true))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageValidate || fe.Code != CodeMissingWSURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_RejectsInvalidJSON(t *testing.T) {
	_, err := Connect(context.Background(), strings.NewReader("not json"), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_RejectsNonJSONString(t *testing.T) {
	_, err := Connect(context.Background(), "not json", WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_InvalidJSONStringPreservesCause(t *testing.T) {
	_, err := Connect(context.Background(), "{", WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
	var se *json.SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("expected *json.SyntaxError in error chain, got %T", fe.Err)
	}
}
