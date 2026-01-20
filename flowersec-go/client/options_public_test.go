package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/client"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

var _ client.ConnectOption = client.WithConnectTimeout(0)
var _ client.ConnectOption = client.WithHandshakeTimeout(0)
var _ client.ConnectOption = client.WithHeader(nil)
var _ client.ConnectOption = client.WithDialer(nil)
var _ client.ConnectOption = client.WithOrigin("http://example.com")
var _ client.ConnectOption = client.WithEndpointInstanceID("test")
var _ client.ConnectOption = client.WithKeepaliveInterval(0)

func TestWithEndpointInstanceID_RejectsDirect(t *testing.T) {
	_, err := client.ConnectDirect(
		context.Background(),
		&directv1.DirectConnectInfo{
			WsUrl:                    "ws://example.invalid",
			ChannelId:                "ch",
			ChannelInitExpireAtUnixS: 1,
		},
		client.WithOrigin("http://example.com"),
		client.WithEndpointInstanceID("test"),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, client.ErrEndpointInstanceIDNotAllowed) {
		t.Fatalf("expected ErrEndpointInstanceIDNotAllowed, got %v", err)
	}
	var fe *client.Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != client.PathDirect || fe.Stage != client.StageValidate || fe.Code != client.CodeInvalidOption {
		t.Fatalf("unexpected error: %+v", fe)
	}
}
