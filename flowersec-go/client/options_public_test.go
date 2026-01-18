package client_test

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/client"
)

var _ client.TunnelConnectOption = client.WithConnectTimeout(0)
var _ client.DirectConnectOption = client.WithConnectTimeout(0)
var _ client.DirectConnectOption = client.WithHandshakeTimeout(0)
var _ client.DirectConnectOption = client.WithHeader(nil)
var _ client.DirectConnectOption = client.WithDialer(nil)
var _ client.TunnelConnectOption = client.WithEndpointInstanceID("test")

func TestWithEndpointInstanceID_IsTunnelOnly(t *testing.T) {
	if _, ok := client.WithEndpointInstanceID("test").(client.DirectConnectOption); ok {
		t.Fatal("expected WithEndpointInstanceID option to not implement DirectConnectOption")
	}
}
