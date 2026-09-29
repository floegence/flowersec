package controlplane

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type V4DirectIssueHTTPSConfig = controlv4.DirectIssueHTTPSConfig
type V4DirectIssueHTTPSService = controlv4.DirectIssueHTTPSService

func V4DirectIssueHTTPSServiceCharge(c V4DirectIssueHTTPSConfig) (resourcev4.Vector, error) {
	v, err := controlv4.DirectIssueHTTPSServiceCharge(c)
	return v, v4IssueFailure(err)
}

func NewV4DirectIssueHTTPSService(issuer *V4DirectIssuer, c V4DirectIssueHTTPSConfig, reservation, dependencies resourcev4.Reference) (*V4DirectIssueHTTPSService, error) {
	if issuer == nil || issuer.inner == nil {
		return nil, V4IssueFailure("closed")
	}
	s, err := controlv4.NewDirectIssueHTTPSService(issuer.inner, c, reservation, dependencies)
	return s, v4IssueFailure(err)
}

// V4AuthenticatedDirectIssueClient is for the authority's host authentication
// hook. Compare this native mTLS identity with the original request envelope;
// caller-provided body bytes alone never establish an authenticated client.
func V4AuthenticatedDirectIssueClient(ctx context.Context) ([32]byte, bool) {
	return controlv4.AuthenticatedDirectIssueClient(ctx)
}
