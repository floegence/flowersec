package controlplane

import (
	"slices"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/httpdirectv1"
)

const HTTPDirectProfile = httpdirectv1.Profile

type HTTPDirectIssueOptions struct {
	Session           SessionOptions
	Endpoint          string
	RendezvousGroupID string
	ListenerAudience  string
	UpstreamAddress   string
	Metadata          ArtifactMetadata
}

// IssuedHTTPDirectArtifact is an explicit HTTP profile envelope around the
// existing authenticated v3 session. The nested WSS candidate is a binding,
// never a URL to dial or a promise that the HTTP transport uses TLS.
type IssuedHTTPDirectArtifact struct {
	artifactJSON []byte
	issued       IssuedArtifact
}

func (i IssuedHTTPDirectArtifact) ArtifactJSON() []byte { return slices.Clone(i.artifactJSON) }
func (i IssuedHTTPDirectArtifact) AuthorizationRecord() AuthorizationRecord {
	return i.issued.AuthorizationRecord()
}
func (i IssuedHTTPDirectArtifact) LookupKey() string          { return i.issued.LookupKey() }
func (IssuedHTTPDirectArtifact) String() string               { return "Flowersec.IssuedHTTPDirectArtifact" }
func (IssuedHTTPDirectArtifact) GoString() string             { return "controlplane.IssuedHTTPDirectArtifact" }
func (IssuedHTTPDirectArtifact) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// IssueHTTPDirect requires an explicit HTTP endpoint and issues independent
// admission credentials. Ordinary IssueDirect remains TLS-only.
func (issuer *Issuer) IssueHTTPDirect(options HTTPDirectIssueOptions) (IssuedHTTPDirectArtifact, error) {
	endpoint, bindingURL, err := httpdirectv1.ValidateEndpoint(options.Endpoint)
	if err != nil {
		return IssuedHTTPDirectArtifact{}, ErrInvalidControlPlaneInput
	}
	endpoints, err := NewEndpointSet(EndpointConfig{ID: "http-direct", URL: bindingURL, TLS: CAPolicy()})
	if err != nil {
		return IssuedHTTPDirectArtifact{}, err
	}
	issued, err := issuer.IssueDirect(DirectIssueOptions{
		Session: options.Session, Endpoints: endpoints, RendezvousGroupID: options.RendezvousGroupID,
		ListenerAudience: options.ListenerAudience, UpstreamAddress: options.UpstreamAddress, Metadata: options.Metadata,
	})
	if err != nil {
		return IssuedHTTPDirectArtifact{}, err
	}
	artifact, err := httpdirectv1.MarshalArtifact(endpoint, issued.ArtifactJSON())
	if err != nil {
		return IssuedHTTPDirectArtifact{}, err
	}
	return IssuedHTTPDirectArtifact{artifactJSON: artifact, issued: issued}, nil
}
