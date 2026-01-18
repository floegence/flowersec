package client

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

func TestConnectTunnel_RejectsInvalidEndpointInstanceID(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	grant := &controlv1.ChannelInitGrant{
		TunnelUrl:          "ws://example.invalid",
		ChannelId:          "ch_1",
		Role:               controlv1.Role_client,
		Token:              "tok",
		E2eePskB64u:        base64.RawURLEncoding.EncodeToString(psk),
		DefaultSuite:       1,
		AllowedSuites:      []controlv1.Suite{controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM},
		IdleTimeoutSeconds: 60,
	}
	_, err := ConnectTunnel(context.Background(), grant, TunnelConnectOptions{
		Origin:             "http://example.com",
		EndpointInstanceID: "!!!",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidEndpointInstanceID) {
		t.Fatalf("expected ErrInvalidEndpointInstanceID, got %v", err)
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeInvalidEndpointInstanceID {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnectTunnel_RejectsInvalidPSKLength(t *testing.T) {
	psk := make([]byte, 16)
	for i := range psk {
		psk[i] = 1
	}
	grant := &controlv1.ChannelInitGrant{
		TunnelUrl:          "ws://example.invalid",
		ChannelId:          "ch_1",
		Role:               controlv1.Role_client,
		Token:              "tok",
		E2eePskB64u:        base64.RawURLEncoding.EncodeToString(psk),
		DefaultSuite:       1,
		AllowedSuites:      []controlv1.Suite{controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM},
		IdleTimeoutSeconds: 60,
	}
	_, err := ConnectTunnel(context.Background(), grant, TunnelConnectOptions{
		Origin: "http://example.com",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidPSK) {
		t.Fatalf("expected ErrInvalidPSK, got %v", err)
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeInvalidPSK {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnectDirect_RejectsInvalidSuite(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	info := &directv1.DirectConnectInfo{
		WsUrl:        "ws://example.invalid",
		ChannelId:    "ch_1",
		E2eePskB64u:  base64.RawURLEncoding.EncodeToString(psk),
		DefaultSuite: 999,
	}
	_, err := ConnectDirect(context.Background(), info, DirectConnectOptions{Origin: "http://example.com"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidSuite) {
		t.Fatalf("expected ErrInvalidSuite, got %v", err)
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageValidate || fe.Code != CodeInvalidSuite {
		t.Fatalf("unexpected error: %+v", fe)
	}
}
