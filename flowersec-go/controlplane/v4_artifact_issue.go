package controlplane

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type ArtifactIssueRequest = protocolv4.ArtifactIssueRequest
type ArtifactIssueFacts = protocolv4.ArtifactIssueFacts
type ArtifactIssuePermit = protocolv4.ArtifactIssuePermit
type ArtifactIssueAuthority = protocolv4.ArtifactIssueAuthority
type ArtifactIssuerConfig = protocolv4.ArtifactIssuerConfig
type ArtifactTunnelIssueConfig = protocolv4.ArtifactTunnelIssueConfig
type ArtifactTunnelLegIssueConfig = protocolv4.ArtifactTunnelLegIssueConfig

type ArtifactIssuer struct{ inner *protocolv4.ArtifactIssuer }

func ArtifactIssuerCharge(c ArtifactIssuerConfig) (resourcev4.Vector, error) {
	charge, err := protocolv4.ArtifactIssuerCharge(c)
	if err == nil {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ArtifactIssuer{}))})
	}
	return charge, v4IssueFailure(err)
}

func NewArtifactIssuer(c ArtifactIssuerConfig, reservation, dependencies resourcev4.Reference) (*ArtifactIssuer, error) {
	charge, err := ArtifactIssuerCharge(c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, v4IssueFailure(err)
	}
	defer owned.Release()
	issuer, err := protocolv4.NewArtifactIssuer(c, owned, dependencies)
	if err != nil {
		return nil, v4IssueFailure(err)
	}
	return &ArtifactIssuer{inner: issuer}, nil
}

func (s *ArtifactIssuer) IssueArtifactBytes(ctx context.Context, request ArtifactIssueRequest, dst []byte) (int, error) {
	if s == nil || s.inner == nil {
		return 0, IssueFailure("closed")
	}
	n, err := s.inner.IssueArtifactBytes(ctx, request, dst)
	return n, v4IssueFailure(err)
}

func (s *ArtifactIssuer) NamespaceClosure() ([protocolv4.MaxArtifactIssueNamespaces]protocolv4.NamespaceReference, uint8, error) {
	if s == nil || s.inner == nil {
		return [protocolv4.MaxArtifactIssueNamespaces]protocolv4.NamespaceReference{}, 0, IssueFailure("closed")
	}
	refs, count, err := s.inner.NamespaceClosure()
	return refs, count, v4IssueFailure(err)
}
func (s *ArtifactIssuer) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
func (s *ArtifactIssuer) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return IssueFailure("closed")
	}
	return v4IssueFailure(s.inner.WaitCleanup(ctx))
}
func (*ArtifactIssuer) String() string   { return "ArtifactIssuer(<redacted>)" }
func (*ArtifactIssuer) GoString() string { return "ArtifactIssuer(<redacted>)" }

type ArtifactIssueHTTPSConfig = controlv4.DirectIssueHTTPSConfig
type ArtifactIssueHTTPSService = controlv4.DirectIssueHTTPSService

func ArtifactIssueHTTPSServiceCharge(c ArtifactIssueHTTPSConfig) (resourcev4.Vector, error) {
	charge, err := controlv4.DirectIssueHTTPSServiceCharge(c)
	return charge, v4IssueFailure(err)
}
func NewArtifactIssueHTTPSService(issuer *ArtifactIssuer, c ArtifactIssueHTTPSConfig, reservation, dependencies resourcev4.Reference) (*ArtifactIssueHTTPSService, error) {
	if issuer == nil || issuer.inner == nil {
		return nil, IssueFailure("closed")
	}
	service, err := controlv4.NewArtifactIssueHTTPSService(issuer.inner, c, reservation, dependencies)
	return service, v4IssueFailure(err)
}
func AuthenticatedArtifactIssueClient(ctx context.Context) ([32]byte, bool) {
	return controlv4.AuthenticatedDirectIssueClient(ctx)
}
