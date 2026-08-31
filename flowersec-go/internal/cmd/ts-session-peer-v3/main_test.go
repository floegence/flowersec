package main

import (
	"encoding/base64"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/websocketv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/sessionv3"
)

func TestInteropContractMatchesSharedV3Vector(t *testing.T) {
	contract := interopContract()
	if contract.ChannelID != "channel-3" || contract.MaxInboundStreams != 64 {
		t.Fatalf("interop contract = %+v", contract)
	}
	if got := base64.RawURLEncoding.EncodeToString(contract.ContractHash[:]); got != "jY2ao2i8vNuV6mj-Gtqrw7oqBVmggMY4Yih3Uj8Wv2Y" {
		t.Fatalf("contract hash = %s", got)
	}
}

func TestPathConfigurationIsStrictV3(t *testing.T) {
	for _, test := range []struct {
		input, subprotocol, endpoint string
		path                         sessionv3.PathKind
	}{
		{"direct", websocketv3.SubprotocolDirect, "/flowersec/v3/direct", sessionv3.PathDirect},
		{"tunnel", websocketv3.SubprotocolTunnel, "/flowersec/v3/tunnel", sessionv3.PathTunnel},
	} {
		subprotocol, path, endpoint, err := pathConfiguration(test.input)
		if err != nil || subprotocol != test.subprotocol || path != test.path || endpoint != test.endpoint {
			t.Fatalf("pathConfiguration(%q) = %q %q %q %v", test.input, subprotocol, path, endpoint, err)
		}
	}
	if _, _, _, err := pathConfiguration("v2"); err == nil {
		t.Fatal("v2 path unexpectedly accepted")
	}
}
