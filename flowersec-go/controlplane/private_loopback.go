package controlplane

import (
	"slices"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/privateloopbackv1"
)

const PrivateLoopbackProfile = privateloopbackv1.Profile

type PrivateLoopbackIssueOptions struct {
	Session           SessionOptions
	Endpoint          string
	RendezvousGroupID string
	ListenerAudience  string
	UpstreamAddress   string
	Metadata          ArtifactMetadata
}

// IssuedPrivateLoopbackArtifact carries a private transport profile and the
// matching opaque authorization record. Its nested flowersec/3 artifact keeps
// the existing v3 wire contract unchanged and binds the same authority and
// path through an exact WSS-to-private-WS mapping.
type IssuedPrivateLoopbackArtifact struct {
	artifactJSON []byte
	issued       IssuedArtifact
}

func (issued IssuedPrivateLoopbackArtifact) ArtifactJSON() []byte {
	return slices.Clone(issued.artifactJSON)
}

func (issued IssuedPrivateLoopbackArtifact) AuthorizationRecord() AuthorizationRecord {
	return issued.issued.AuthorizationRecord()
}

func (issued IssuedPrivateLoopbackArtifact) LookupKey() string {
	return issued.issued.LookupKey()
}

func (IssuedPrivateLoopbackArtifact) String() string {
	return "Flowersec.IssuedPrivateLoopbackArtifact"
}
func (IssuedPrivateLoopbackArtifact) GoString() string {
	return "controlplane.IssuedPrivateLoopbackArtifact"
}
func (IssuedPrivateLoopbackArtifact) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

// IssuePrivateLoopbackDirect issues the isolated private-loopback/1 profile.
// It cannot create a tunnel, a remote endpoint, or a non-WebSocket carrier.
func (issuer *Issuer) IssuePrivateLoopbackDirect(options PrivateLoopbackIssueOptions) (IssuedPrivateLoopbackArtifact, error) {
	endpoint, publicCandidate, err := privateloopbackv1.ValidateEndpoint(options.Endpoint)
	if err != nil {
		return IssuedPrivateLoopbackArtifact{}, ErrInvalidControlPlaneInput
	}
	endpoints, err := NewEndpointSet(EndpointConfig{
		ID: "private-loopback", URL: publicCandidate, TLS: CAPolicy(),
	})
	if err != nil {
		return IssuedPrivateLoopbackArtifact{}, err
	}
	issued, err := issuer.IssueDirect(DirectIssueOptions{
		Session: options.Session, Endpoints: endpoints,
		RendezvousGroupID: options.RendezvousGroupID, ListenerAudience: options.ListenerAudience,
		UpstreamAddress: options.UpstreamAddress, Metadata: options.Metadata,
	})
	if err != nil {
		return IssuedPrivateLoopbackArtifact{}, err
	}
	profileArtifact, err := privateloopbackv1.MarshalArtifact(endpoint, issued.ArtifactJSON())
	if err != nil {
		return IssuedPrivateLoopbackArtifact{}, ErrInvalidControlPlaneInput
	}
	return IssuedPrivateLoopbackArtifact{artifactJSON: profileArtifact, issued: issued}, nil
}
