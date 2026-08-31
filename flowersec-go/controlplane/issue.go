package controlplane

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
)

const (
	defaultArtifactLifetime = time.Minute
	maxArtifactLifetime     = 5 * time.Minute
	defaultIdleTimeout      = time.Minute
	defaultMaxInbound       = 32
)

// SessionOptions contains carrier-neutral session policy. Cryptographic suites,
// keys, protocol deadlines, and contract hashes are selected internally.
type SessionOptions struct {
	ChannelID         string
	ExpiresAt         time.Time
	IdleTimeout       time.Duration
	MaxInboundStreams uint16
}

// Scope is bounded application metadata authenticated by the artifact.
type Scope struct {
	Name     string
	Version  uint16
	Critical bool
	Payload  json.RawMessage
}

// ArtifactMetadata carries bounded application scopes and diagnostic tags.
type ArtifactMetadata struct {
	Scopes          []Scope
	CorrelationTags map[string]string
}

// DirectIssueOptions issues one artifact for a Flowersec runtime listener. The
// upstream is application traffic, not a Flowersec carrier endpoint.
type DirectIssueOptions struct {
	Session           SessionOptions
	Endpoints         EndpointSet
	RendezvousGroupID string
	ListenerAudience  string
	UpstreamAddress   string
	Metadata          ArtifactMetadata
}

// TunnelIssueOptions issues the two complementary opaque artifacts for one
// rendezvous. Endpoint roles and attach credentials remain internal.
type TunnelIssueOptions struct {
	Session           SessionOptions
	Endpoints         EndpointSet
	RendezvousGroupID string
	ListenerAudience  string
	FirstEndpointID   string
	SecondEndpointID  string
	AllowReplacement  bool
	FirstMetadata     ArtifactMetadata
	SecondMetadata    ArtifactMetadata
}

// Issuer creates v3 artifacts using the system cryptographic random source.
type Issuer struct {
	random io.Reader
	now    func() time.Time
}

// NewIssuer creates a production artifact issuer.
func NewIssuer() *Issuer {
	return &Issuer{random: rand.Reader, now: time.Now}
}

func newIssuerForTest(random io.Reader, now time.Time) *Issuer {
	return &Issuer{random: random, now: func() time.Time { return now }}
}

// IssuedArtifact contains only explicit opaque serialization boundaries and a
// matching authorization record. Generic formatting never reveals secrets.
type IssuedArtifact struct {
	artifactJSON []byte
	record       AuthorizationRecord
}

// ArtifactJSON returns a defensive copy suitable for the artifact acquisition
// response body consumed by ParseArtifact.
func (issued IssuedArtifact) ArtifactJSON() []byte {
	return slices.Clone(issued.artifactJSON)
}

// AuthorizationRecord returns the opaque server-side authorization record.
func (issued IssuedArtifact) AuthorizationRecord() AuthorizationRecord {
	return issued.record
}

// LookupKey returns the non-secret credential hash used to locate the record
// when a Flowersec runtime submits an authorization request.
func (issued IssuedArtifact) LookupKey() string {
	return issued.record.LookupKey()
}

func (IssuedArtifact) String() string               { return "Flowersec.IssuedArtifact" }
func (IssuedArtifact) GoString() string             { return "controlplane.IssuedArtifact" }
func (IssuedArtifact) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// IssuedTunnelPair contains the artifacts for the two endpoint IDs supplied to
// IssueTunnelPair. Neither value exposes its role or peer binding.
type IssuedTunnelPair struct {
	First  IssuedArtifact
	Second IssuedArtifact
}

// IssueDirect creates one direct artifact and its matching opaque record.
func (issuer *Issuer) IssueDirect(options DirectIssueOptions) (IssuedArtifact, error) {
	issuanceNow, err := issuer.issuanceTime()
	if err != nil {
		return IssuedArtifact{}, err
	}
	contract, err := issuer.session(options.Session, issuanceNow)
	if err != nil {
		return IssuedArtifact{}, err
	}
	candidates, err := options.Endpoints.candidates(artifactv3.PathDirect, issuanceNow)
	if err != nil {
		return IssuedArtifact{}, err
	}
	if !validTCPAddress(options.UpstreamAddress) {
		return IssuedArtifact{}, ErrInvalidControlPlaneInput
	}
	credential, err := issuer.credential()
	if err != nil {
		return IssuedArtifact{}, err
	}
	artifact := artifactv3.Artifact{
		Version: 3, Profile: artifactv3.Profile, Session: contract,
		Path: artifactv3.ArtifactPath{
			Kind: artifactv3.PathDirect, RendezvousGroupID: options.RendezvousGroupID,
			ListenerAudience: options.ListenerAudience, RoutingToken: credential, Candidates: candidates,
		},
	}
	if err := applyMetadata(&artifact, options.Metadata); err != nil {
		return IssuedArtifact{}, err
	}
	return issuedArtifact(artifact, options.UpstreamAddress, false)
}

// IssueTunnelPair creates complementary artifacts with independent one-time
// credentials and one shared encrypted session contract.
func (issuer *Issuer) IssueTunnelPair(options TunnelIssueOptions) (IssuedTunnelPair, error) {
	issuanceNow, err := issuer.issuanceTime()
	if err != nil {
		return IssuedTunnelPair{}, err
	}
	contract, err := issuer.session(options.Session, issuanceNow)
	if err != nil {
		return IssuedTunnelPair{}, err
	}
	candidates, err := options.Endpoints.candidates(artifactv3.PathTunnel, issuanceNow)
	if err != nil {
		return IssuedTunnelPair{}, err
	}
	firstCredential, err := issuer.credential()
	if err != nil {
		return IssuedTunnelPair{}, err
	}
	secondCredential, err := issuer.credential()
	if err != nil {
		return IssuedTunnelPair{}, err
	}
	build := func(role uint8, local, peer, credential string, metadata ArtifactMetadata) (IssuedArtifact, error) {
		artifact := artifactv3.Artifact{
			Version: 3, Profile: artifactv3.Profile, Session: contract,
			Path: artifactv3.ArtifactPath{
				Kind: artifactv3.PathTunnel, RendezvousGroupID: options.RendezvousGroupID,
				ListenerAudience: options.ListenerAudience, Role: role,
				LocalEndpointInstanceID: local, ExpectedPeerEndpointInstanceID: peer,
				Token: credential, Candidates: slices.Clone(candidates),
			},
		}
		if err := applyMetadata(&artifact, metadata); err != nil {
			return IssuedArtifact{}, err
		}
		return issuedArtifact(artifact, "", options.AllowReplacement)
	}
	first, err := build(1, options.FirstEndpointID, options.SecondEndpointID, firstCredential, options.FirstMetadata)
	if err != nil {
		return IssuedTunnelPair{}, err
	}
	second, err := build(2, options.SecondEndpointID, options.FirstEndpointID, secondCredential, options.SecondMetadata)
	if err != nil {
		return IssuedTunnelPair{}, err
	}
	return IssuedTunnelPair{First: first, Second: second}, nil
}

func (issuer *Issuer) issuanceTime() (time.Time, error) {
	if issuer == nil || issuer.random == nil || issuer.now == nil {
		return time.Time{}, ErrIssuanceFailed
	}
	now := issuer.now().UTC()
	if now.IsZero() {
		return time.Time{}, ErrIssuanceFailed
	}
	return now, nil
}

func (issuer *Issuer) session(options SessionOptions, now time.Time) (artifactv3.SessionContract, error) {
	if issuer == nil || issuer.random == nil || now.IsZero() {
		return artifactv3.SessionContract{}, ErrIssuanceFailed
	}
	expiresAt := options.ExpiresAt.UTC()
	if options.ExpiresAt.IsZero() {
		expiresAt = now.Add(defaultArtifactLifetime)
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(maxArtifactLifetime)) {
		return artifactv3.SessionContract{}, ErrInvalidControlPlaneInput
	}
	// The wire contract carries whole Unix seconds. Round future sub-second
	// expiries up so issuance cannot create an immediately expired artifact.
	expiresUnix := expiresAt.Unix()
	if time.Unix(expiresUnix, 0).Before(expiresAt) {
		expiresUnix++
	}
	normalizedExpiry := time.Unix(expiresUnix, 0).UTC()
	if !normalizedExpiry.After(now) || normalizedExpiry.After(now.Add(maxArtifactLifetime)) {
		return artifactv3.SessionContract{}, ErrInvalidControlPlaneInput
	}
	idle := options.IdleTimeout
	if idle == 0 {
		idle = defaultIdleTimeout
	}
	if idle < 0 || idle%time.Second != 0 || idle/time.Second > math.MaxUint32 {
		return artifactv3.SessionContract{}, ErrInvalidControlPlaneInput
	}
	maxInbound := options.MaxInboundStreams
	if maxInbound == 0 {
		maxInbound = defaultMaxInbound
	}
	var psk [32]byte
	if _, err := io.ReadFull(issuer.random, psk[:]); err != nil {
		return artifactv3.SessionContract{}, ErrIssuanceFailed
	}
	contract := artifactv3.SessionContract{
		ChannelID: options.ChannelID, InitExpireAtUnixSeconds: expiresUnix,
		IdleTimeoutSeconds: uint32(idle / time.Second), EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: maxInbound, E2EEPSK: psk,
		AllowedSuites: []uint16{1, 2}, DefaultSuite: 1,
	}
	hash, _, err := artifactv3.ComputeSessionContractHash(contract)
	if err != nil {
		return artifactv3.SessionContract{}, ErrInvalidControlPlaneInput
	}
	contract.ContractHash = hash
	return contract, nil
}

func (issuer *Issuer) credential() (string, error) {
	var value [32]byte
	if _, err := io.ReadFull(issuer.random, value[:]); err != nil {
		return "", ErrIssuanceFailed
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func applyMetadata(artifact *artifactv3.Artifact, metadata ArtifactMetadata) error {
	artifact.Scoped = make([]artifactv3.ScopeMetadata, 0, len(metadata.Scopes))
	for _, scope := range metadata.Scopes {
		artifact.Scoped = append(artifact.Scoped, artifactv3.ScopeMetadata{
			Scope: scope.Name, ScopeVersion: scope.Version, Critical: scope.Critical,
			Payload: slices.Clone(scope.Payload),
		})
	}
	keys := make([]string, 0, len(metadata.CorrelationTags))
	for key := range metadata.CorrelationTags {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	artifact.Correlation = artifactv3.CorrelationContext{Version: 3, Tags: make([]artifactv3.CorrelationTag, 0, len(keys))}
	for _, key := range keys {
		artifact.Correlation.Tags = append(artifact.Correlation.Tags, artifactv3.CorrelationTag{Key: key, Value: metadata.CorrelationTags[key]})
	}
	if err := artifactv3.ValidateArtifact(*artifact); err != nil {
		return ErrInvalidControlPlaneInput
	}
	return nil
}

func issuedArtifact(artifact artifactv3.Artifact, directUpstream string, allowReplacement bool) (IssuedArtifact, error) {
	encoded, err := artifactv3.MarshalArtifactJSON(artifact)
	if err != nil {
		return IssuedArtifact{}, ErrInvalidControlPlaneInput
	}
	record, err := newAuthorizationRecord(&artifact, encoded, directUpstream, allowReplacement)
	if err != nil {
		return IssuedArtifact{}, err
	}
	return IssuedArtifact{artifactJSON: encoded, record: record}, nil
}

func validTCPAddress(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
		return false
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" || strings.ContainsAny(host, " \t\r\n") {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port != 0
}
