package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type V4ArtifactIssueRetention = protocolv4.ArtifactIssueRetention
type V4ArtifactRetentionSlot = protocolv4.ArtifactRetentionSlot

type V4LiveArtifactHost = controlv4.LiveArtifactHost
type V4LiveArtifactHostConfig = controlv4.LiveArtifactHostConfig
type V4LiveArtifactPolicy = controlv4.LiveArtifactPolicy
type V4LiveArtifactTunnelConfig = controlv4.LiveArtifactTunnelConfig
type V4LiveArtifactGrantConfig = controlv4.LiveArtifactGrantConfig
type V4LiveArtifactServerResolver = controlv4.LiveArtifactServerResolver
type V4LiveArtifactServerRegistration = controlv4.LiveArtifactServerRegistration
type V4LiveArtifactServerMaterial = controlv4.LiveArtifactServerMaterial

// The host charge covers all material slots. Each of MaxArtifacts plan slots
// separately requires the returned plan charge under the same Environment.
func V4LiveArtifactHostCharges(c V4LiveArtifactHostConfig) (host, plan resourcev4.Vector, err error) {
	host, plan, err = controlv4.LiveArtifactHostCharges(c)
	err = v4IssueFailure(err)
	return
}

// Use the same host as ArtifactIssuerConfig.Retention and
// LiveAuthorizationHTTPSConfig.Host. Its Policy supplies independent access
// checks; the original durable issuance authority remains separately required.
func NewV4LiveArtifactHost(c V4LiveArtifactHostConfig, reservation resourcev4.Reference, plans []resourcev4.Reference, dependencies resourcev4.Reference) (*V4LiveArtifactHost, error) {
	host, err := controlv4.NewLiveArtifactHost(c, reservation, plans, dependencies)
	return host, v4IssueFailure(err)
}
