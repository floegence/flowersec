package controlplane_test

import (
	"fmt"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
)

func ExampleIssuer_IssueTunnelPair() {
	endpoints, err := controlplane.NewEndpointSet(
		controlplane.EndpointConfig{ID: "websocket", URL: "wss://sessions.example/flowersec/v3/tunnel", TLS: controlplane.CAPolicy()},
		controlplane.EndpointConfig{ID: "raw-quic", URL: "quic://sessions.example", TLS: controlplane.CAPolicy()},
		controlplane.EndpointConfig{ID: "webtransport", URL: "https://sessions.example/flowersec/webtransport/v3/tunnel", TLS: controlplane.CAPolicy()},
	)
	if err != nil {
		panic(err)
	}
	pair, err := controlplane.NewIssuer().IssueTunnelPair(controlplane.TunnelIssueOptions{
		Session: controlplane.SessionOptions{
			ChannelID: "session-01", ExpiresAt: time.Now().Add(time.Minute),
		},
		Endpoints: endpoints, RendezvousGroupID: "rendezvous-01",
		ListenerAudience: "production", FirstEndpointID: "browser-01", SecondEndpointID: "runtime-01",
	})
	if err != nil {
		panic(err)
	}

	stored, err := pair.First.AuthorizationRecord().Encode()
	if err != nil {
		panic(err)
	}
	restored, err := controlplane.ParseAuthorizationRecord(stored)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(pair.First.ArtifactJSON()) > 0, pair.First.LookupKey() == restored.LookupKey())
	// Output: true true
}
