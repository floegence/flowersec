package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
)

func tunnelAuthorizations(relay string, endpoints ...controlplane.IssuedArtifact) ([]tunnelAuthorizationWire, map[string]string, error) {
	items := make([]tunnelAuthorizationWire, 0, len(endpoints))
	records := make(map[string]string)
	for index, issued := range endpoints {
		artifact, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(issued.ArtifactJSON()))
		if err != nil {
			return nil, nil, err
		}
		if artifact.Path.Kind != artifactv3.PathTunnel || artifact.Session.InitExpireAtUnixSeconds <= time.Now().Unix() || artifact.Path.ExpectedPeerEndpointInstanceID == "" {
			return nil, nil, fmt.Errorf("issued tunnel artifact omitted valid relay claims")
		}
		grant := tunnelAuthorizationWire{
			Decision: "allow", CredentialID: issued.LookupKey(), LeaseID: fmt.Sprintf("lease-endpoint-%c", 'a'+index),
			ExpiresAtUnixSeconds: artifact.Session.InitExpireAtUnixSeconds, ExpectedPeerEndpointInstanceID: artifact.Path.ExpectedPeerEndpointInstanceID,
		}
		items = append(items, grant)
		if relay == "go" {
			continue
		}
		digests := make(map[string]string, len(artifact.Path.Candidates))
		var record any
		switch relay {
		case "node-typescript":
			record = map[string]any{
				"authorityScope": parityAuthorityScope, "credentialId": grant.CredentialID,
				"expectedPeerEndpointInstanceId": grant.ExpectedPeerEndpointInstanceID,
				"expiresAtUnixSeconds":           grant.ExpiresAtUnixSeconds, "requestDigests": digests,
			}
		case "rust":
			record = map[string]any{
				"authority_scope": parityAuthorityScope, "expected_peer_endpoint_instance_id": grant.ExpectedPeerEndpointInstanceID,
				"expires_at_unix_s": grant.ExpiresAtUnixSeconds, "admission_bindings_b64u": digests,
			}
		default:
			return nil, nil, fmt.Errorf("unknown relay runtime %q", relay)
		}
		for _, candidate := range artifact.Path.Candidates {
			raw, err := artifactv3.MarshalArtifactRequest(*artifact, candidate.ID)
			if err != nil {
				return nil, nil, err
			}
			var digest [32]byte
			if relay == "rust" {
				digest = artifactv3.AdmissionBinding(raw)
			} else {
				digest = sha256.Sum256(raw)
			}
			digests[candidate.ID] = base64.RawURLEncoding.EncodeToString(digest[:])
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, nil, err
		}
		records[grant.CredentialID] = string(encoded)
	}
	return items, records, nil
}
