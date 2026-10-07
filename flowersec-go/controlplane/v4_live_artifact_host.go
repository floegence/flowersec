package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type ArtifactIssueRetention = protocolv4.ArtifactIssueRetention
type ArtifactRetentionSlot = protocolv4.ArtifactRetentionSlot

type LiveArtifactHost = controlv4.LiveArtifactHost
type LiveArtifactHostConfig = controlv4.LiveArtifactHostConfig
type LiveArtifactPolicy = controlv4.LiveArtifactPolicy
type LiveArtifactTunnelConfig = controlv4.LiveArtifactTunnelConfig
type LiveArtifactGrantConfig = controlv4.LiveArtifactGrantConfig
type LiveArtifactServerResolver = controlv4.LiveArtifactServerResolver
type LiveArtifactServerRegistration = controlv4.LiveArtifactServerRegistration
type LiveArtifactServerMaterial = controlv4.LiveArtifactServerMaterial

// The host charge covers all material slots. Each of MaxArtifacts plan slots
// separately requires the returned plan charge under the same Environment.
func LiveArtifactHostCharges(c LiveArtifactHostConfig) (host, plan resourcev4.Vector, err error) {
	host, plan, err = controlv4.LiveArtifactHostCharges(c)
	err = v4IssueFailure(err)
	return
}

// Use the same host as ArtifactIssuerConfig.Retention and
// LiveAuthorizationHTTPSConfig.Host. Its Policy supplies independent access
// checks; the original durable issuance authority remains separately required.
func NewLiveArtifactHost(c LiveArtifactHostConfig, reservation resourcev4.Reference, plans []resourcev4.Reference, dependencies resourcev4.Reference) (*LiveArtifactHost, error) {
	host, err := controlv4.NewLiveArtifactHost(c, reservation, plans, dependencies)
	return host, v4IssueFailure(err)
}
