package endpoint

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
)

func TestConnectTunnel_RejectsMissingToken(t *testing.T) {
	grant := &controlv1.ChannelInitGrant{
		TunnelUrl: "ws://example.invalid",
		ChannelId: "ch_1",
		Role:      controlv1.Role_server,
		Token:     "",
	}
	_, err := ConnectTunnel(context.Background(), grant, WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMissingToken) {
		t.Fatalf("expected ErrMissingToken, got %v", err)
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *endpoint.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeMissingToken {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnectTunnel_TrimSpaceRejectsBlankTunnelURL(t *testing.T) {
	grant := &controlv1.ChannelInitGrant{
		TunnelUrl: " \t\r\n",
		ChannelId: "ch_1",
		Role:      controlv1.Role_server,
		Token:     "tok",
	}
	_, err := ConnectTunnel(context.Background(), grant, WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMissingTunnelURL) {
		t.Fatalf("expected ErrMissingTunnelURL, got %v", err)
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *endpoint.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeMissingTunnelURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnectTunnel_TrimSpaceRejectsBlankChannelID(t *testing.T) {
	grant := &controlv1.ChannelInitGrant{
		TunnelUrl: "ws://example.invalid",
		ChannelId: " \t\r\n",
		Role:      controlv1.Role_server,
		Token:     "tok",
	}
	_, err := ConnectTunnel(context.Background(), grant, WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMissingChannelID) {
		t.Fatalf("expected ErrMissingChannelID, got %v", err)
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *endpoint.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeMissingChannelID {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnectTunnel_TrimSpaceRejectsBlankToken(t *testing.T) {
	grant := &controlv1.ChannelInitGrant{
		TunnelUrl: "ws://example.invalid",
		ChannelId: "ch_1",
		Role:      controlv1.Role_server,
		Token:     " \t\r\n",
	}
	_, err := ConnectTunnel(context.Background(), grant, WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMissingToken) {
		t.Fatalf("expected ErrMissingToken, got %v", err)
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *endpoint.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeMissingToken {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnectTunnel_RejectsEmptyEndpointInstanceID(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	grant := &controlv1.ChannelInitGrant{
		TunnelUrl:                "ws://example.invalid",
		ChannelId:                "ch_1",
		ChannelInitExpireAtUnixS: 1,
		Role:                     controlv1.Role_server,
		Token:                    "tok",
		E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
		DefaultSuite:             1,
		AllowedSuites:            []controlv1.Suite{controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM},
		IdleTimeoutSeconds:       60,
	}
	_, err := ConnectTunnel(context.Background(), grant, WithOrigin("http://example.com"), WithEndpointInstanceID(""))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidEndpointInstanceID) {
		t.Fatalf("expected ErrInvalidEndpointInstanceID, got %v", err)
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *endpoint.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeInvalidEndpointInstanceID {
		t.Fatalf("unexpected error: %+v", fe)
	}
}
