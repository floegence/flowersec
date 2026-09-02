package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
)

type request struct {
	Mode       string `json:"mode"`
	Endpoint   string `json:"endpoint"`
	TopologyID string `json:"topology_id"`
}

type authorization struct {
	Decision                       string `json:"decision"`
	CredentialID                   string `json:"credentialId"`
	LeaseID                        string `json:"leaseId"`
	ExpiresAtUnixSeconds           int64  `json:"expiresAtUnixSeconds"`
	ExpectedPeerEndpointInstanceID string `json:"expectedPeerEndpointInstanceId"`
	AllowReplacement               bool   `json:"allowReplacement"`
}

type response struct {
	ArtifactJSON        string            `json:"artifact_json,omitempty"`
	EndpointAArtifact   string            `json:"endpoint_a_artifact_json,omitempty"`
	EndpointBArtifact   string            `json:"endpoint_b_artifact_json,omitempty"`
	Authorizations      []authorization   `json:"authorizations,omitempty"`
	VerificationRecords map[string]string `json:"verification_records,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if os.Getenv("FLOWERSEC_SERVER_PARITY_PEER") != "1" {
		return errors.New("parity artifact issuer is test-only")
	}
	var input request
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return fmt.Errorf("decode issuer request: %w", err)
	}
	if input.Endpoint == "" {
		return errors.New("issuer endpoint is empty")
	}
	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID: "parity", URL: input.Endpoint, TLS: controlplane.CAPolicy(),
	})
	if err != nil {
		return err
	}
	switch input.Mode {
	case "direct":
		issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
			Session: controlplane.SessionOptions{
				ChannelID: "cross-language-direct-parity", ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 16,
			},
			Endpoints: endpoints, RendezvousGroupID: "cross-language-direct-parity",
			ListenerAudience: "server-parity", UpstreamAddress: "127.0.0.1:1",
		})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(response{ArtifactJSON: string(issued.ArtifactJSON())})
	case "tunnel":
		if input.TopologyID == "" {
			return errors.New("issuer topology_id is empty")
		}
		pair, err := controlplane.NewIssuer().IssueTunnelPair(controlplane.TunnelIssueOptions{
			Session: controlplane.SessionOptions{
				ChannelID: "parity-" + input.TopologyID, ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 16,
			},
			Endpoints: endpoints, RendezvousGroupID: input.TopologyID,
			ListenerAudience: "server-parity", FirstEndpointID: input.TopologyID + "-a", SecondEndpointID: input.TopologyID + "-b",
		})
		if err != nil {
			return err
		}
		authorizations, err := tunnelAuthorizations(pair.First, pair.Second)
		if err != nil {
			return err
		}
		firstJSON := string(pair.First.ArtifactJSON())
		secondJSON := string(pair.Second.ArtifactJSON())
		return json.NewEncoder(os.Stdout).Encode(response{
			EndpointAArtifact: firstJSON,
			EndpointBArtifact: secondJSON,
			Authorizations:    authorizations,
			VerificationRecords: map[string]string{
				pair.First.LookupKey():  firstJSON,
				pair.Second.LookupKey(): secondJSON,
			},
		})
	default:
		return errors.New("issuer mode must be direct or tunnel")
	}
}

func tunnelAuthorizations(items ...controlplane.IssuedArtifact) ([]authorization, error) {
	result := make([]authorization, 0, len(items))
	for index, issued := range items {
		var artifact struct {
			Session struct {
				ExpiresAt int64 `json:"init_expire_at_unix_s"`
			} `json:"session"`
			Path struct {
				ExpectedPeer string `json:"expected_peer_endpoint_instance_id"`
			} `json:"path"`
		}
		if err := json.Unmarshal(issued.ArtifactJSON(), &artifact); err != nil || artifact.Session.ExpiresAt <= time.Now().Unix() || artifact.Path.ExpectedPeer == "" {
			return nil, errors.New("issued tunnel artifact omitted relay claims")
		}
		result = append(result, authorization{
			Decision: "allow", CredentialID: issued.LookupKey(), LeaseID: fmt.Sprintf("lease-endpoint-%c", 'a'+index),
			ExpiresAtUnixSeconds: artifact.Session.ExpiresAt, ExpectedPeerEndpointInstanceID: artifact.Path.ExpectedPeer,
		})
	}
	return result, nil
}
