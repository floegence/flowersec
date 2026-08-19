package artifactv3

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

var (
	scopePattern          = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	correlationKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)
)

type artifactWire struct {
	Correlation json.RawMessage `json:"correlation"`
	Path        json.RawMessage `json:"path"`
	Profile     string          `json:"profile"`
	Scoped      json.RawMessage `json:"scoped"`
	Session     json.RawMessage `json:"session"`
	Version     int             `json:"v"`
}

type sessionWire struct {
	AllowedSuites                 []uint16 `json:"allowed_suites"`
	ChannelID                     string   `json:"channel_id"`
	ContractHashBase64URL         string   `json:"contract_hash_b64u"`
	DefaultSuite                  uint16   `json:"default_suite"`
	E2EEPSKBase64URL              string   `json:"e2ee_psk_b64u"`
	EstablishTimeoutSeconds       uint16   `json:"establish_timeout_seconds"`
	IdleTimeoutSeconds            uint32   `json:"idle_timeout_seconds"`
	InitExpireAtUnixSeconds       int64    `json:"init_expire_at_unix_s"`
	MaxInboundStreams             uint16   `json:"max_inbound_streams"`
	RekeyCompletionTimeoutSeconds uint16   `json:"rekey_completion_timeout_seconds"`
	RekeyPrepareTimeoutSeconds    uint16   `json:"rekey_prepare_timeout_seconds"`
	SelectedFeatures              uint32   `json:"selected_features"`
}

type candidateWire struct {
	Carrier     Carrier   `json:"carrier"`
	ID          string    `json:"id"`
	TLS         TLSPolicy `json:"tls"`
	URL         string    `json:"url"`
	WireProfile string    `json:"wire_profile"`
}

type directPathWire struct {
	Candidates        []candidateWire `json:"candidates"`
	Kind              PathKind        `json:"kind"`
	ListenerAudience  string          `json:"listener_audience"`
	RendezvousGroupID string          `json:"rendezvous_group_id"`
	RoutingToken      string          `json:"routing_token"`
}

type tunnelPathWire struct {
	Candidates                     []candidateWire `json:"candidates"`
	ExpectedPeerEndpointInstanceID string          `json:"expected_peer_endpoint_instance_id"`
	Kind                           PathKind        `json:"kind"`
	ListenerAudience               string          `json:"listener_audience"`
	LocalEndpointInstanceID        string          `json:"local_endpoint_instance_id"`
	RendezvousGroupID              string          `json:"rendezvous_group_id"`
	Role                           uint8           `json:"role"`
	Token                          string          `json:"token"`
}

type scopeWire struct {
	Critical     bool            `json:"critical"`
	Payload      json.RawMessage `json:"payload"`
	Scope        string          `json:"scope"`
	ScopeVersion uint16          `json:"scope_version"`
}

type correlationWire struct {
	Tags    []correlationTagWire `json:"tags"`
	Version int                  `json:"v"`
}

type correlationTagWire struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func DecodeArtifactJSON(reader io.Reader) (*Artifact, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxArtifactJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxArtifactJSONBytes {
		return nil, ErrArtifactTooLarge
	}
	var top artifactWire
	if err := decodeStrictJSON(raw, &top); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArtifact, err)
	}
	if top.Version != 3 || top.Profile != Profile || len(top.Session) == 0 || len(top.Path) == 0 || len(top.Scoped) == 0 || len(top.Correlation) == 0 {
		return nil, fmt.Errorf("%w: required top-level fields", ErrInvalidArtifact)
	}

	session, err := decodeSession(top.Session)
	if err != nil {
		return nil, err
	}
	path, err := decodeArtifactPath(top.Path)
	if err != nil {
		return nil, err
	}
	scoped, err := decodeScoped(top.Scoped)
	if err != nil {
		return nil, err
	}
	correlation, err := decodeCorrelation(top.Correlation)
	if err != nil {
		return nil, err
	}
	artifact := &Artifact{
		Version:     top.Version,
		Profile:     top.Profile,
		Session:     session,
		Path:        path,
		Scoped:      scoped,
		Correlation: correlation,
	}
	if err := validateArtifact(*artifact); err != nil {
		return nil, err
	}
	canonicalCandidates, _, _, err := CanonicalizeCandidates(artifact.Path.Kind, artifact.Path.Candidates)
	if err != nil {
		return nil, err
	}
	normalizedByID := make(map[string]string, len(canonicalCandidates))
	for _, candidate := range canonicalCandidates {
		normalizedByID[candidate.ID] = candidate.NormalizedURL
	}
	for i := range artifact.Path.Candidates {
		artifact.Path.Candidates[i].NormalizedURL = normalizedByID[artifact.Path.Candidates[i].ID]
	}
	canonical, err := MarshalArtifactJSON(*artifact)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, fmt.Errorf("%w: artifact is not canonical JCS", ErrInvalidArtifact)
	}
	return artifact, nil
}

func MarshalArtifactJSON(artifact Artifact) ([]byte, error) {
	if err := validateArtifact(artifact); err != nil {
		return nil, err
	}
	session := sessionToWire(artifact.Session)
	scoped := scopesToWire(artifact.Scoped)
	correlation := correlationToWire(artifact.Correlation)
	var path any
	if artifact.Path.Kind == PathDirect {
		path = directPathWire{
			Kind:              artifact.Path.Kind,
			RendezvousGroupID: artifact.Path.RendezvousGroupID,
			ListenerAudience:  artifact.Path.ListenerAudience,
			RoutingToken:      artifact.Path.RoutingToken,
			Candidates:        candidatesToWire(artifact.Path.Candidates),
		}
	} else {
		path = tunnelPathWire{
			Kind:                           artifact.Path.Kind,
			RendezvousGroupID:              artifact.Path.RendezvousGroupID,
			ListenerAudience:               artifact.Path.ListenerAudience,
			Role:                           artifact.Path.Role,
			LocalEndpointInstanceID:        artifact.Path.LocalEndpointInstanceID,
			ExpectedPeerEndpointInstanceID: artifact.Path.ExpectedPeerEndpointInstanceID,
			Token:                          artifact.Path.Token,
			Candidates:                     candidatesToWire(artifact.Path.Candidates),
		}
	}
	wire := struct {
		Correlation correlationWire `json:"correlation"`
		Path        any             `json:"path"`
		Profile     string          `json:"profile"`
		Scoped      []scopeWire     `json:"scoped"`
		Session     sessionWire     `json:"session"`
		Version     int             `json:"v"`
	}{
		Version: artifact.Version, Profile: artifact.Profile, Session: session,
		Path: path, Scoped: scoped, Correlation: correlation,
	}
	raw, err := canonicalJSON(wire)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxArtifactJSONBytes {
		return nil, ErrArtifactTooLarge
	}
	return raw, nil
}

// ValidateArtifact applies the same fail-closed checks used by artifact
// issuance and decoding, including preflighting FSB3 for every candidate.
func ValidateArtifact(artifact Artifact) error {
	return validateArtifact(artifact)
}

func validateArtifact(artifact Artifact) error {
	if artifact.Version != 3 || artifact.Profile != Profile {
		return fmt.Errorf("%w: version/profile", ErrInvalidArtifact)
	}
	hash, _, err := ComputeSessionContractHash(artifact.Session)
	if err != nil {
		return err
	}
	if hash != artifact.Session.ContractHash {
		return fmt.Errorf("%w: session contract hash", ErrInvalidArtifact)
	}
	canonicalCandidates, _, candidateHash, err := CanonicalizeCandidates(artifact.Path.Kind, artifact.Path.Candidates)
	if err != nil {
		return err
	}
	if !validRegistryID(artifact.Path.RendezvousGroupID, 128) || !validRegistryID(artifact.Path.ListenerAudience, 128) {
		return fmt.Errorf("%w: rendezvous group or listener audience", ErrInvalidArtifact)
	}
	switch artifact.Path.Kind {
	case PathDirect:
		if !validASCII(artifact.Path.RoutingToken, MaxAdmissionCredentialBytes) || artifact.Path.Role != 0 || artifact.Path.LocalEndpointInstanceID != "" || artifact.Path.ExpectedPeerEndpointInstanceID != "" || artifact.Path.Token != "" {
			return fmt.Errorf("%w: direct path variant", ErrInvalidArtifact)
		}
	case PathTunnel:
		if artifact.Path.Role != 1 && artifact.Path.Role != 2 {
			return fmt.Errorf("%w: tunnel role", ErrInvalidArtifact)
		}
		if !validRegistryID(artifact.Path.LocalEndpointInstanceID, 128) || !validRegistryID(artifact.Path.ExpectedPeerEndpointInstanceID, 128) || !validASCII(artifact.Path.Token, MaxAdmissionCredentialBytes) || artifact.Path.RoutingToken != "" {
			return fmt.Errorf("%w: tunnel path variant", ErrInvalidArtifact)
		}
		if artifact.Path.LocalEndpointInstanceID == artifact.Path.ExpectedPeerEndpointInstanceID {
			return fmt.Errorf("%w: tunnel endpoint identity pair", ErrInvalidArtifact)
		}
	default:
		return fmt.Errorf("%w: path kind", ErrInvalidArtifact)
	}
	if err := validateScopes(artifact.Scoped); err != nil {
		return err
	}
	if err := validateCorrelation(artifact.Correlation); err != nil {
		return err
	}
	for _, candidate := range canonicalCandidates {
		request := requestFromValidatedArtifact(artifact, canonicalCandidates, candidateHash, candidate.ID)
		payload, err := marshalRequestPayload(request)
		if err != nil {
			return err
		}
		if len(payload) > MaxCanonicalFSB3Payload {
			return ErrFSB3PayloadTooLarge
		}
	}
	return nil
}

func decodeSession(raw []byte) (SessionContract, error) {
	if err := requireJSONObjectFields(raw,
		"channel_id", "init_expire_at_unix_s", "idle_timeout_seconds",
		"establish_timeout_seconds", "rekey_prepare_timeout_seconds", "rekey_completion_timeout_seconds",
		"max_inbound_streams", "e2ee_psk_b64u", "allowed_suites", "default_suite",
		"selected_features", "contract_hash_b64u",
	); err != nil {
		return SessionContract{}, fmt.Errorf("%w: session: %v", ErrInvalidArtifact, err)
	}
	var wire sessionWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return SessionContract{}, fmt.Errorf("%w: session: %v", ErrInvalidArtifact, err)
	}
	psk, err := decode32(wire.E2EEPSKBase64URL)
	if err != nil {
		return SessionContract{}, fmt.Errorf("%w: e2ee_psk_b64u", ErrInvalidArtifact)
	}
	hash, err := decode32(wire.ContractHashBase64URL)
	if err != nil {
		return SessionContract{}, fmt.Errorf("%w: contract_hash_b64u", ErrInvalidArtifact)
	}
	return SessionContract{
		ChannelID:                     wire.ChannelID,
		InitExpireAtUnixSeconds:       wire.InitExpireAtUnixSeconds,
		IdleTimeoutSeconds:            wire.IdleTimeoutSeconds,
		EstablishTimeoutSeconds:       wire.EstablishTimeoutSeconds,
		RekeyPrepareTimeoutSeconds:    wire.RekeyPrepareTimeoutSeconds,
		RekeyCompletionTimeoutSeconds: wire.RekeyCompletionTimeoutSeconds,
		MaxInboundStreams:             wire.MaxInboundStreams,
		E2EEPSK:                       psk,
		AllowedSuites:                 wire.AllowedSuites,
		DefaultSuite:                  wire.DefaultSuite,
		SelectedFeatures:              wire.SelectedFeatures,
		ContractHash:                  hash,
	}, nil
}

func decodeArtifactPath(raw []byte) (ArtifactPath, error) {
	var discriminator struct {
		Kind PathKind `json:"kind"`
	}
	if err := json.Unmarshal(raw, &discriminator); err != nil {
		return ArtifactPath{}, fmt.Errorf("%w: path discriminator", ErrInvalidArtifact)
	}
	switch discriminator.Kind {
	case PathDirect:
		var wire directPathWire
		if err := decodeStrictJSON(raw, &wire); err != nil {
			return ArtifactPath{}, fmt.Errorf("%w: direct path: %v", ErrInvalidArtifact, err)
		}
		return ArtifactPath{
			Kind: wire.Kind, RendezvousGroupID: wire.RendezvousGroupID,
			ListenerAudience: wire.ListenerAudience, RoutingToken: wire.RoutingToken,
			Candidates: candidatesFromWire(wire.Candidates),
		}, nil
	case PathTunnel:
		var wire tunnelPathWire
		if err := decodeStrictJSON(raw, &wire); err != nil {
			return ArtifactPath{}, fmt.Errorf("%w: tunnel path: %v", ErrInvalidArtifact, err)
		}
		return ArtifactPath{
			Kind: wire.Kind, RendezvousGroupID: wire.RendezvousGroupID,
			ListenerAudience: wire.ListenerAudience, Role: wire.Role,
			LocalEndpointInstanceID:        wire.LocalEndpointInstanceID,
			ExpectedPeerEndpointInstanceID: wire.ExpectedPeerEndpointInstanceID,
			Token:                          wire.Token, Candidates: candidatesFromWire(wire.Candidates),
		}, nil
	default:
		return ArtifactPath{}, fmt.Errorf("%w: path kind", ErrInvalidArtifact)
	}
}

func decodeScoped(raw []byte) ([]ScopeMetadata, error) {
	var entries []json.RawMessage
	if err := decodeStrictJSON(raw, &entries); err != nil {
		return nil, fmt.Errorf("%w: scoped: %v", ErrInvalidArtifact, err)
	}
	if entries == nil {
		return nil, fmt.Errorf("%w: scoped must be an array", ErrInvalidArtifact)
	}
	out := make([]ScopeMetadata, 0, len(entries))
	for _, rawEntry := range entries {
		if err := requireJSONObjectFields(rawEntry, "scope", "scope_version", "critical", "payload"); err != nil {
			return nil, fmt.Errorf("%w: scoped entry: %v", ErrInvalidArtifact, err)
		}
		var item scopeWire
		if err := decodeStrictJSON(rawEntry, &item); err != nil {
			return nil, fmt.Errorf("%w: scoped entry: %v", ErrInvalidArtifact, err)
		}
		out = append(out, ScopeMetadata{Scope: item.Scope, ScopeVersion: item.ScopeVersion, Critical: item.Critical, Payload: item.Payload})
	}
	return out, nil
}

func decodeCorrelation(raw []byte) (CorrelationContext, error) {
	var wire correlationWire
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || decodeStrictJSON(raw, &wire) != nil {
		return CorrelationContext{}, fmt.Errorf("%w: correlation", ErrInvalidArtifact)
	}
	if wire.Tags == nil {
		return CorrelationContext{}, fmt.Errorf("%w: correlation tags", ErrInvalidArtifact)
	}
	out := CorrelationContext{Version: wire.Version, Tags: make([]CorrelationTag, 0, len(wire.Tags))}
	for _, tag := range wire.Tags {
		out.Tags = append(out.Tags, CorrelationTag{Key: tag.Key, Value: tag.Value})
	}
	return out, nil
}

func validateScopes(scopes []ScopeMetadata) error {
	if scopes == nil || len(scopes) > 8 {
		return fmt.Errorf("%w: scoped", ErrInvalidArtifact)
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if !scopePattern.MatchString(scope.Scope) || scope.ScopeVersion == 0 {
			return fmt.Errorf("%w: scope metadata", ErrInvalidArtifact)
		}
		if _, duplicate := seen[scope.Scope]; duplicate {
			return fmt.Errorf("%w: duplicate scope", ErrInvalidArtifact)
		}
		seen[scope.Scope] = struct{}{}
		payload := bytes.TrimSpace(scope.Payload)
		if !bytes.Equal(payload, scope.Payload) || validateCanonicalScopedPayload(payload) != nil {
			return fmt.Errorf("%w: scope payload", ErrInvalidArtifact)
		}
	}
	return nil
}

func validateCorrelation(correlation CorrelationContext) error {
	if correlation.Version != 3 || correlation.Tags == nil || len(correlation.Tags) > 8 {
		return fmt.Errorf("%w: correlation", ErrInvalidArtifact)
	}
	seen := make(map[string]struct{}, len(correlation.Tags))
	for _, tag := range correlation.Tags {
		if !correlationKeyPattern.MatchString(tag.Key) || !validASCII(tag.Value, 128) {
			return fmt.Errorf("%w: correlation tag", ErrInvalidArtifact)
		}
		if _, duplicate := seen[tag.Key]; duplicate {
			return fmt.Errorf("%w: duplicate correlation tag", ErrInvalidArtifact)
		}
		seen[tag.Key] = struct{}{}
	}
	return nil
}

func sessionToWire(session SessionContract) sessionWire {
	return sessionWire{
		ChannelID: session.ChannelID, InitExpireAtUnixSeconds: session.InitExpireAtUnixSeconds,
		IdleTimeoutSeconds: session.IdleTimeoutSeconds, EstablishTimeoutSeconds: session.EstablishTimeoutSeconds,
		RekeyPrepareTimeoutSeconds: session.RekeyPrepareTimeoutSeconds, RekeyCompletionTimeoutSeconds: session.RekeyCompletionTimeoutSeconds,
		MaxInboundStreams: session.MaxInboundStreams, E2EEPSKBase64URL: encode32(session.E2EEPSK),
		AllowedSuites: session.AllowedSuites, DefaultSuite: session.DefaultSuite,
		SelectedFeatures: session.SelectedFeatures, ContractHashBase64URL: encode32(session.ContractHash),
	}
}

func candidatesToWire(candidates []Candidate) []candidateWire {
	out := make([]candidateWire, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidateWire{ID: candidate.ID, Carrier: candidate.Carrier, TLS: CloneTLSPolicy(candidate.TLS), URL: candidate.URL, WireProfile: candidate.WireProfile})
	}
	return out
}

func candidatesFromWire(candidates []candidateWire) []Candidate {
	out := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, Candidate{ID: candidate.ID, Carrier: candidate.Carrier, TLS: CloneTLSPolicy(candidate.TLS), URL: candidate.URL, WireProfile: candidate.WireProfile})
	}
	return out
}

func scopesToWire(scopes []ScopeMetadata) []scopeWire {
	out := make([]scopeWire, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, scopeWire{Scope: scope.Scope, ScopeVersion: scope.ScopeVersion, Critical: scope.Critical, Payload: scope.Payload})
	}
	return out
}

func correlationToWire(correlation CorrelationContext) correlationWire {
	tags := make([]correlationTagWire, 0, len(correlation.Tags))
	for _, tag := range correlation.Tags {
		tags = append(tags, correlationTagWire{Key: tag.Key, Value: tag.Value})
	}
	return correlationWire{Version: correlation.Version, Tags: tags}
}

func encode32(value [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func decode32(value string) ([32]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value {
		return [32]byte{}, fmt.Errorf("invalid canonical base64url")
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}
