package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type ArtifactIssueAuthenticationKind = controlv4.ArtifactIssueAuthenticationKind

const (
	ArtifactIssueMutualTLS       = controlv4.ArtifactIssueMutualTLS
	ArtifactIssueLocalCredential = controlv4.ArtifactIssueLocalCredential
)

type ArtifactIssueShareConfig = controlv4.ArtifactIssueShareConfig
type ArtifactIssueHostConfig = controlv4.ArtifactIssueHostConfig
type ArtifactIssueHost = controlv4.ArtifactIssueHost

func ArtifactIssueHostCharge(config ArtifactIssueHostConfig) (resourcev4.Vector, error) {
	return controlv4.ArtifactIssueHostCharge(config)
}
func NewArtifactIssueHost(config ArtifactIssueHostConfig, reservation, dependencies resourcev4.Reference) (*ArtifactIssueHost, error) {
	return controlv4.NewArtifactIssueHost(config, reservation, dependencies)
}

// The share manifest uses the original durable authority's exact worst-case
// State allocation instead of reproducing lease/header constants locally.
func ArtifactIssueStateShareBytes(outstanding uint32) (uint64, error) {
	return ledgerv4.SQLiteDirectIssueStateShareBytes(outstanding)
}
