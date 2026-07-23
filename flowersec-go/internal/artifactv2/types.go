// Package artifactv2 implements the transport-neutral Flowersec v2 connect
// artifact and admission wire contracts. It intentionally defines no tenant,
// environment, provider, routing-policy, or other product business fields.
package artifactv2

import (
	"encoding/json"
	"errors"
)

const (
	Profile                     = "flowersec/2"
	MaxArtifactJSONBytes        = 65_536
	MaxCandidates               = 4
	MaxCanonicalCandidateBytes  = 2_304
	MaxCanonicalCandidateSet    = 12 * 1_024
	MaxCanonicalFSB2Payload     = 32_768
	FSB2HeaderSize              = 12
	FSA2HeaderSize              = 8
	MaxAdmissionReasonBytes     = 64
	MaxAdmissionCredentialBytes = 8_192
)

var (
	ErrInvalidArtifact      = errors.New("invalid Flowersec v2 artifact")
	ErrArtifactTooLarge     = errors.New("Flowersec v2 artifact too large")
	ErrInvalidCandidate     = errors.New("invalid Flowersec v2 candidate")
	ErrInvalidFSB2          = errors.New("invalid FSB2 admission request")
	ErrFSB2PayloadTooLarge  = errors.New("FSB2 canonical payload too large")
	ErrNonCanonicalFSB2     = errors.New("non-canonical FSB2 payload")
	ErrInvalidFSA2          = errors.New("invalid FSA2 admission response")
	ErrUnknownAdmissionCode = errors.New("unknown FSA2 admission reason")
)

type Carrier string

const (
	CarrierWebSocket    Carrier = "websocket"
	CarrierRawQUIC      Carrier = "raw_quic"
	CarrierWebTransport Carrier = "webtransport"
)

type PathKind string

const (
	PathDirect PathKind = "direct"
	PathTunnel PathKind = "tunnel"
)

type Candidate struct {
	ID            string
	Carrier       Carrier
	URL           string
	WireProfile   string
	NormalizedURL string
}

// CanonicalCandidate is the exact object hashed into candidate_set_hash and
// carried by FSB2. Field declaration order is RFC 8785 key order.
type CanonicalCandidate struct {
	Carrier       Carrier `json:"carrier"`
	ID            string  `json:"id"`
	NormalizedURL string  `json:"normalized_url"`
	WireProfile   string  `json:"wire_profile"`
}

type SessionContract struct {
	ChannelID                     string
	InitExpireAtUnixSeconds       int64
	IdleTimeoutSeconds            uint32
	EstablishTimeoutSeconds       uint16
	RekeyPrepareTimeoutSeconds    uint16
	RekeyCompletionTimeoutSeconds uint16
	MaxInboundStreams             uint16
	E2EEPSK                       [32]byte
	AllowedSuites                 []uint16
	DefaultSuite                  uint16
	SelectedFeatures              uint32
	ContractHash                  [32]byte
}

type ArtifactPath struct {
	Kind                           PathKind
	RendezvousGroupID              string
	ListenerAudience               string
	Role                           uint8
	LocalEndpointInstanceID        string
	ExpectedPeerEndpointInstanceID string
	Token                          string
	RoutingToken                   string
	Candidates                     []Candidate
}

type ScopeMetadata struct {
	Scope        string
	ScopeVersion uint16
	Critical     bool
	Payload      json.RawMessage
}

type CorrelationTag struct {
	Key   string
	Value string
}

type CorrelationContext struct {
	Version int
	Tags    []CorrelationTag
}

type Artifact struct {
	Version     int
	Profile     string
	Session     SessionContract
	Path        ArtifactPath
	Scoped      []ScopeMetadata
	Correlation CorrelationContext
}

type Request struct {
	PathKind            PathKind
	Profile             string
	ChannelID           string
	SessionContractHash [32]byte
	RendezvousGroupID   string
	Candidates          []CanonicalCandidate
	CandidateSetHash    [32]byte
	ChosenCandidateID   string
	ListenerAudience    string
	RoutingToken        string
	Role                uint8
	EndpointInstanceID  string
	AttachToken         string
}

type DecodedRequest struct {
	Request               Request
	Raw                   []byte
	LocalAdmissionBinding [32]byte
}

type AdmissionStatus uint8

const (
	AdmissionSuccess   AdmissionStatus = 0
	AdmissionReject    AdmissionStatus = 1
	AdmissionRetryable AdmissionStatus = 2
)

type AdmissionResponse struct {
	Status AdmissionStatus
	Reason string
}

// ReasonRegistry is supplied by the deployment-facing admission layer. The
// codec rejects reasons outside this audited registry instead of guessing.
type ReasonRegistry map[string]struct{}
