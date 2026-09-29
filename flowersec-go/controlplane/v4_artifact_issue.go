package controlplane

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type V4ArtifactIssueRequest = protocolv4.ArtifactIssueRequest
type V4ArtifactIssueFacts = protocolv4.ArtifactIssueFacts
type V4ArtifactIssuePermit = protocolv4.ArtifactIssuePermit
type V4ArtifactIssueAuthority = protocolv4.ArtifactIssueAuthority
type V4ArtifactIssuerConfig = protocolv4.ArtifactIssuerConfig
type V4ArtifactTunnelIssueConfig = protocolv4.ArtifactTunnelIssueConfig
type V4ArtifactTunnelLegIssueConfig = protocolv4.ArtifactTunnelLegIssueConfig

type V4ArtifactIssuer struct{ inner *protocolv4.ArtifactIssuer }

func V4ArtifactIssuerCharge(c V4ArtifactIssuerConfig) (resourcev4.Vector, error) {
	charge, err := protocolv4.ArtifactIssuerCharge(c)
	if err == nil {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(V4ArtifactIssuer{}))})
	}
	return charge, v4IssueFailure(err)
}

func NewV4ArtifactIssuer(c V4ArtifactIssuerConfig, reservation, dependencies resourcev4.Reference) (*V4ArtifactIssuer, error) {
	charge, err := V4ArtifactIssuerCharge(c)
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
	return &V4ArtifactIssuer{inner: issuer}, nil
}

func (s *V4ArtifactIssuer) IssueArtifactBytes(ctx context.Context, request V4ArtifactIssueRequest, dst []byte) (int, error) {
	if s == nil || s.inner == nil {
		return 0, V4IssueFailure("closed")
	}
	n, err := s.inner.IssueArtifactBytes(ctx, request, dst)
	return n, v4IssueFailure(err)
}

func (s *V4ArtifactIssuer) NamespaceClosure() ([protocolv4.MaxArtifactIssueNamespaces]protocolv4.NamespaceReference, uint8, error) {
	if s == nil || s.inner == nil {
		return [protocolv4.MaxArtifactIssueNamespaces]protocolv4.NamespaceReference{}, 0, V4IssueFailure("closed")
	}
	refs, count, err := s.inner.NamespaceClosure()
	return refs, count, v4IssueFailure(err)
}
func (s *V4ArtifactIssuer) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
func (s *V4ArtifactIssuer) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return V4IssueFailure("closed")
	}
	return v4IssueFailure(s.inner.WaitCleanup(ctx))
}
func (*V4ArtifactIssuer) String() string   { return "V4ArtifactIssuer(<redacted>)" }
func (*V4ArtifactIssuer) GoString() string { return "V4ArtifactIssuer(<redacted>)" }

type V4ArtifactIssueHTTPSConfig = controlv4.DirectIssueHTTPSConfig
type V4ArtifactIssueHTTPSService = controlv4.DirectIssueHTTPSService

func V4ArtifactIssueHTTPSServiceCharge(c V4ArtifactIssueHTTPSConfig) (resourcev4.Vector, error) {
	charge, err := controlv4.DirectIssueHTTPSServiceCharge(c)
	return charge, v4IssueFailure(err)
}
func NewV4ArtifactIssueHTTPSService(issuer *V4ArtifactIssuer, c V4ArtifactIssueHTTPSConfig, reservation, dependencies resourcev4.Reference) (*V4ArtifactIssueHTTPSService, error) {
	if issuer == nil || issuer.inner == nil {
		return nil, V4IssueFailure("closed")
	}
	service, err := controlv4.NewArtifactIssueHTTPSService(issuer.inner, c, reservation, dependencies)
	return service, v4IssueFailure(err)
}
func V4AuthenticatedArtifactIssueClient(ctx context.Context) ([32]byte, bool) {
	return controlv4.AuthenticatedDirectIssueClient(ctx)
}
