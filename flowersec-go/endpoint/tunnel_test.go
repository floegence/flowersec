package endpoint

import (
	"context"
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
