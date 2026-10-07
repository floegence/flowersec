package controlplane

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type DirectIssueHTTPSConfig = controlv4.DirectIssueHTTPSConfig
type DirectIssueHTTPSService = controlv4.DirectIssueHTTPSService

func DirectIssueHTTPSServiceCharge(c DirectIssueHTTPSConfig) (resourcev4.Vector, error) {
	v, err := controlv4.DirectIssueHTTPSServiceCharge(c)
	return v, v4IssueFailure(err)
}

func NewDirectIssueHTTPSService(issuer *DirectIssuer, c DirectIssueHTTPSConfig, reservation, dependencies resourcev4.Reference) (*DirectIssueHTTPSService, error) {
	if issuer == nil || issuer.inner == nil {
		return nil, IssueFailure("closed")
	}
	s, err := controlv4.NewDirectIssueHTTPSService(issuer.inner, c, reservation, dependencies)
	return s, v4IssueFailure(err)
}

// AuthenticatedDirectIssueClient is for the authority's host authentication
// hook. Compare this native mTLS identity with the original request envelope;
// caller-provided body bytes alone never establish an authenticated client.
func AuthenticatedDirectIssueClient(ctx context.Context) ([32]byte, bool) {
	return controlv4.AuthenticatedDirectIssueClient(ctx)
}
