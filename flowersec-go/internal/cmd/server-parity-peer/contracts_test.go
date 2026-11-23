package main

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

func TestParityQueryReturnsOnlyRequestedContractsInOrder(t *testing.T) {
	manifest := parityContracts{Namespace: "flowersec.parity", Contracts: map[uint32]string{echoRPC: "echo", notifyRPC: "notify"}}
	result, rpcErr := manifest.query(context.Background(), json.RawMessage(`{"namespace":"flowersec.parity","type_ids":[7002,7001]}`))
	if rpcErr != nil || !slices.Equal(result.(map[string][]string)["contracts"], []string{"notify", "echo"}) {
		t.Fatalf("unexpected query result: %v, %v", result, rpcErr)
	}
	for raw, code := range map[string]uint32{
		`{"namespace":"unknown","type_ids":[7001]}`:                       404,
		`{"namespace":"flowersec.parity","type_ids":[7001,9999]}`:         404,
		`{"namespace":"flowersec.parity","type_ids":[]}`:                  400,
		`{"namespace":"flowersec.parity","type_ids":[7001],"extra":true}`: 400,
	} {
		result, rpcErr := manifest.query(context.Background(), json.RawMessage(raw))
		if result != nil || rpcErr == nil || rpcErr.Code != code {
			t.Fatalf("%s returned %v, %v", raw, result, rpcErr)
		}
	}
}

func TestRelayRecordsExposeOnlyVerificationFields(t *testing.T) {
	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID: "parity", URL: "wss://localhost/flowersec/v5/tunnel", TLS: controlplane.CAPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := controlplane.NewIssuer().IssueTunnelPair(controlplane.TunnelIssueOptions{
		Session:   controlplane.SessionOptions{ChannelID: "parity", ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 16},
		Endpoints: endpoints, RendezvousGroupID: "parity", AuthorityScope: parityAuthorityScope,
		ListenerAudience: "parity", FirstEndpointID: "endpoint-a", SecondEndpointID: "endpoint-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	for relay, fields := range map[string][]string{
		"go":              nil,
		"node-typescript": {"authorityScope", "credentialId", "expectedPeerEndpointInstanceId", "expiresAtUnixSeconds", "requestDigests"},
		"rust":            {"authority_scope", "expected_peer_endpoint_instance_id", "expires_at_unix_s", "admission_bindings_b64u"},
	} {
		grants, records, err := tunnelAuthorizations(relay, pair.First, pair.Second)
		if err != nil || len(grants) != 2 {
			t.Fatalf("%s: %d grants, %v", relay, len(grants), err)
		}
		if relay == "go" {
			if len(records) != 0 {
				t.Fatal("Go relay received an unused record")
			}
			continue
		}
		for _, grant := range grants {
			var record map[string]json.RawMessage
			if err := json.Unmarshal([]byte(records[grant.CredentialID]), &record); err != nil || len(record) != len(fields) {
				t.Fatalf("%s: unexpected record shape", relay)
			}
			for _, field := range fields {
				if _, ok := record[field]; !ok {
					t.Fatalf("%s: missing %s", relay, field)
				}
			}
		}
	}
}
