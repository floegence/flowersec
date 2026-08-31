package controlplane

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
)

const maxAuthorizationRecordBytes = 96 * 1024

var leaseIDPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

// AuthorizationRecord is the opaque, secret server-side counterpart of one
// issued artifact. Its explicit Encode method is the only persistence boundary.
type AuthorizationRecord struct {
	artifact         *artifactv3.Artifact
	artifactJSON     []byte
	lookupKey        string
	directUpstream   string
	allowReplacement bool
}

type authorizationRecordWire struct {
	SchemaVersion     int    `json:"schema_version"`
	ArtifactBase64URL string `json:"artifact_base64url"`
	LookupKey         string `json:"lookup_key"`
	DirectUpstream    string `json:"direct_upstream,omitempty"`
	AllowReplacement  bool   `json:"allow_replacement"`
}

func newAuthorizationRecord(artifact *artifactv3.Artifact, encoded []byte, directUpstream string, allowReplacement bool) (AuthorizationRecord, error) {
	if artifact == nil || len(encoded) == 0 {
		return AuthorizationRecord{}, ErrInvalidControlPlaneInput
	}
	credential := artifactCredential(artifact)
	if credential == "" {
		return AuthorizationRecord{}, ErrInvalidControlPlaneInput
	}
	if artifact.Path.Kind == artifactv3.PathDirect {
		if directUpstream == "" || allowReplacement {
			return AuthorizationRecord{}, ErrInvalidControlPlaneInput
		}
	} else if directUpstream != "" {
		return AuthorizationRecord{}, ErrInvalidControlPlaneInput
	}
	return AuthorizationRecord{
		artifact: artifact, artifactJSON: slices.Clone(encoded), lookupKey: credentialLookupKey(credential),
		directUpstream: directUpstream, allowReplacement: allowReplacement,
	}, nil
}

// LookupKey returns a non-secret SHA-256 identifier suitable for a database key.
func (record AuthorizationRecord) LookupKey() string { return record.lookupKey }

// Encode serializes the opaque secret record for application-owned durable
// storage. Callers must protect the returned bytes as credentials.
func (record AuthorizationRecord) Encode() ([]byte, error) {
	if err := record.validate(); err != nil {
		return nil, err
	}
	wire := authorizationRecordWire{
		SchemaVersion: 1, ArtifactBase64URL: base64.RawURLEncoding.EncodeToString(record.artifactJSON),
		LookupKey: record.lookupKey, DirectUpstream: record.directUpstream,
		AllowReplacement: record.allowReplacement,
	}
	return json.Marshal(wire)
}

// ParseAuthorizationRecord restores a record produced by Encode and rejects
// unknown fields, malformed artifacts, and mismatched lookup keys.
func ParseAuthorizationRecord(encoded []byte) (AuthorizationRecord, error) {
	if len(encoded) == 0 || len(encoded) > maxAuthorizationRecordBytes {
		return AuthorizationRecord{}, ErrInvalidControlPlaneInput
	}
	var wire authorizationRecordWire
	if err := decodeStrict(encoded, &wire); err != nil || wire.SchemaVersion != 1 {
		return AuthorizationRecord{}, ErrInvalidControlPlaneInput
	}
	artifactJSON, err := base64.RawURLEncoding.DecodeString(wire.ArtifactBase64URL)
	if err != nil {
		return AuthorizationRecord{}, ErrInvalidControlPlaneInput
	}
	artifact, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(artifactJSON))
	if err != nil {
		return AuthorizationRecord{}, ErrInvalidControlPlaneInput
	}
	record, err := newAuthorizationRecord(artifact, artifactJSON, wire.DirectUpstream, wire.AllowReplacement)
	if err != nil || subtle.ConstantTimeCompare([]byte(record.lookupKey), []byte(wire.LookupKey)) != 1 {
		return AuthorizationRecord{}, ErrInvalidControlPlaneInput
	}
	return record, nil
}

func (record AuthorizationRecord) validate() error {
	if record.artifact == nil || len(record.artifactJSON) == 0 || record.lookupKey == "" {
		return ErrInvalidControlPlaneInput
	}
	parsed, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(record.artifactJSON))
	if err != nil || credentialLookupKey(artifactCredential(parsed)) != record.lookupKey {
		return ErrInvalidControlPlaneInput
	}
	if record.artifact.Path.Kind == artifactv3.PathDirect {
		if record.directUpstream == "" || record.allowReplacement {
			return ErrInvalidControlPlaneInput
		}
	} else if record.directUpstream != "" {
		return ErrInvalidControlPlaneInput
	}
	return nil
}

func (AuthorizationRecord) String() string               { return "Flowersec.AuthorizationRecord" }
func (AuthorizationRecord) GoString() string             { return "controlplane.AuthorizationRecord" }
func (AuthorizationRecord) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// RuntimeAuthorizationRequest is a validated opaque request received from the
// flowersec-runtime HTTP authorizer callback.
type RuntimeAuthorizationRequest struct {
	decoded   *artifactv3.DecodedRequest
	lookupKey string
	carrier   artifactv3.Carrier
}

type runtimeAuthorizationRequestWire struct {
	FSB3Base64URL string `json:"fsb3_base64url"`
	Carrier       string `json:"carrier"`
	RemoteAddress string `json:"remote_address"`
}

// ParseRuntimeAuthorizationRequest validates the strict runtime request and
// ensures its separately observed carrier matches the selected FSB3 candidate.
func ParseRuntimeAuthorizationRequest(encoded []byte) (RuntimeAuthorizationRequest, error) {
	if len(encoded) == 0 || len(encoded) > 64*1024 {
		return RuntimeAuthorizationRequest{}, ErrInvalidControlPlaneInput
	}
	var wire runtimeAuthorizationRequestWire
	if err := decodeStrict(encoded, &wire); err != nil || !validObservedText(wire.RemoteAddress, 512) {
		return RuntimeAuthorizationRequest{}, ErrInvalidControlPlaneInput
	}
	raw, err := base64.RawURLEncoding.DecodeString(wire.FSB3Base64URL)
	if err != nil {
		return RuntimeAuthorizationRequest{}, ErrInvalidControlPlaneInput
	}
	decoded, err := artifactv3.ParseRequest(raw)
	if err != nil {
		return RuntimeAuthorizationRequest{}, ErrInvalidControlPlaneInput
	}
	carrier := artifactv3.Carrier(wire.Carrier)
	matchedCarrier := false
	for _, candidate := range decoded.Request.Candidates {
		if candidate.ID == decoded.Request.ChosenCandidateID && candidate.Carrier == carrier {
			matchedCarrier = true
		}
	}
	if !matchedCarrier {
		return RuntimeAuthorizationRequest{}, ErrInvalidControlPlaneInput
	}
	credential := decoded.Request.RoutingToken
	if decoded.Request.PathKind == artifactv3.PathTunnel {
		credential = decoded.Request.AttachToken
	}
	if credential == "" {
		return RuntimeAuthorizationRequest{}, ErrInvalidControlPlaneInput
	}
	return RuntimeAuthorizationRequest{decoded: decoded, lookupKey: credentialLookupKey(credential), carrier: carrier}, nil
}

// LookupKey is the non-secret key used to retrieve the matching record before
// calling AuthorizeRuntime.
func (request RuntimeAuthorizationRequest) LookupKey() string { return request.lookupKey }

func (RuntimeAuthorizationRequest) String() string { return "Flowersec.RuntimeAuthorizationRequest" }
func (RuntimeAuthorizationRequest) GoString() string {
	return "controlplane.RuntimeAuthorizationRequest"
}
func (RuntimeAuthorizationRequest) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// AuthorizationResponse is the opaque JSON response accepted by
// flowersec-runtime. JSON returns a defensive copy through the explicit method.
type AuthorizationResponse struct {
	encoded []byte
}

// JSON returns the strict runtime response body.
func (response AuthorizationResponse) JSON() []byte { return slices.Clone(response.encoded) }

func (AuthorizationResponse) String() string               { return "Flowersec.AuthorizationResponse" }
func (AuthorizationResponse) GoString() string             { return "controlplane.AuthorizationResponse" }
func (AuthorizationResponse) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// TunnelAuthorizationResponse is the secret-free authorization response used
// by an untrusted tunnel runtime. It contains pairing claims and lease state,
// never an application Session contract or E2EE key.
type TunnelAuthorizationResponse struct {
	encoded []byte
}

func (response TunnelAuthorizationResponse) JSON() []byte { return slices.Clone(response.encoded) }
func (TunnelAuthorizationResponse) String() string        { return "Flowersec.TunnelAuthorizationResponse" }
func (TunnelAuthorizationResponse) GoString() string {
	return "controlplane.TunnelAuthorizationResponse"
}
func (TunnelAuthorizationResponse) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type authorizedSessionWire struct {
	ChannelID                     string   `json:"channel_id"`
	InitExpireAtUnixSeconds       int64    `json:"init_expire_at_unix_seconds"`
	IdleTimeoutSeconds            uint32   `json:"idle_timeout_seconds"`
	EstablishTimeoutSeconds       uint16   `json:"establish_timeout_seconds"`
	RekeyPrepareTimeoutSeconds    uint16   `json:"rekey_prepare_timeout_seconds"`
	RekeyCompletionTimeoutSeconds uint16   `json:"rekey_completion_timeout_seconds"`
	MaxInboundStreams             uint16   `json:"max_inbound_streams"`
	E2EEPSKBase64URL              string   `json:"e2ee_psk_base64url"`
	AllowedSuites                 []uint16 `json:"allowed_suites"`
	DefaultSuite                  uint16   `json:"default_suite"`
	SelectedFeatures              uint32   `json:"selected_features"`
}

type directAuthorizationWire struct {
	Session  authorizedSessionWire `json:"session"`
	Upstream struct {
		Network string `json:"network"`
		Address string `json:"address"`
	} `json:"upstream"`
}

type runtimeAuthorizationResponseWire struct {
	Decision     string                   `json:"decision"`
	Reason       string                   `json:"reason"`
	CredentialID string                   `json:"credential_id"`
	LeaseID      string                   `json:"lease_id"`
	ExpiresAt    time.Time                `json:"expires_at"`
	Direct       *directAuthorizationWire `json:"direct"`
}

type tunnelRuntimeAuthorizationResponseWire struct {
	Decision                       string    `json:"decision"`
	Reason                         string    `json:"reason,omitempty"`
	CredentialID                   string    `json:"credential_id"`
	LeaseID                        string    `json:"lease_id"`
	ExpiresAt                      time.Time `json:"expires_at"`
	ExpectedPeerEndpointInstanceID string    `json:"expected_peer_endpoint_instance_id"`
	AllowReplacement               bool      `json:"allow_replacement"`
}

// AuthorizeRuntime verifies the complete FSB3 bytes against the stored
// artifact before producing an allow response. The caller must atomically
// reserve the one-time record and provide its durable lease ID first.
func AuthorizeRuntime(request RuntimeAuthorizationRequest, record AuthorizationRecord, leaseID string) (AuthorizationResponse, error) {
	return authorizeRuntimeAt(request, record, leaseID, time.Now())
}

func authorizeRuntimeAt(request RuntimeAuthorizationRequest, record AuthorizationRecord, leaseID string, now time.Time) (AuthorizationResponse, error) {
	if request.decoded == nil || request.decoded.Request.PathKind != artifactv3.PathDirect ||
		request.lookupKey == "" || !leaseIDPattern.MatchString(leaseID) || record.validate() != nil ||
		record.artifact.Path.Kind != artifactv3.PathDirect ||
		subtle.ConstantTimeCompare([]byte(request.lookupKey), []byte(record.lookupKey)) != 1 {
		return AuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	artifact := record.artifact
	expected, err := artifactv3.BuildRequest(*artifact, request.decoded.Request.ChosenCandidateID)
	if err != nil {
		return AuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	expectedRaw, err := artifactv3.MarshalRequest(expected)
	if err != nil || subtle.ConstantTimeCompare(expectedRaw, request.decoded.Raw) != 1 {
		return AuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	if now.Unix() >= artifact.Session.InitExpireAtUnixSeconds {
		return RejectRuntime(artifactv3.ReasonExpiredArtifact, true)
	}
	wire := runtimeAuthorizationResponseWire{
		Decision: "allow", CredentialID: record.lookupKey, LeaseID: leaseID,
		ExpiresAt: time.Unix(artifact.Session.InitExpireAtUnixSeconds, 0).UTC(),
	}
	direct := &directAuthorizationWire{Session: sessionWire(artifact.Session)}
	direct.Upstream.Network = "tcp"
	direct.Upstream.Address = record.directUpstream
	wire.Direct = direct
	encoded, err := json.Marshal(wire)
	if err != nil {
		return AuthorizationResponse{}, fmt.Errorf("encode Flowersec authorization: %w", err)
	}
	return AuthorizationResponse{encoded: encoded}, nil
}

// AuthorizeTunnelRuntime verifies one tunnel admission and returns only the
// claims required to pair and forward opaque carrier streams.
func AuthorizeTunnelRuntime(request RuntimeAuthorizationRequest, record AuthorizationRecord, leaseID string) (TunnelAuthorizationResponse, error) {
	return authorizeTunnelRuntimeAt(request, record, leaseID, time.Now())
}

func authorizeTunnelRuntimeAt(request RuntimeAuthorizationRequest, record AuthorizationRecord, leaseID string, now time.Time) (TunnelAuthorizationResponse, error) {
	if request.decoded == nil || request.decoded.Request.PathKind != artifactv3.PathTunnel ||
		request.lookupKey == "" || !leaseIDPattern.MatchString(leaseID) || record.validate() != nil ||
		record.artifact.Path.Kind != artifactv3.PathTunnel ||
		subtle.ConstantTimeCompare([]byte(request.lookupKey), []byte(record.lookupKey)) != 1 {
		return TunnelAuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	artifact := record.artifact
	expected, err := artifactv3.BuildRequest(*artifact, request.decoded.Request.ChosenCandidateID)
	if err != nil {
		return TunnelAuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	expectedRaw, err := artifactv3.MarshalRequest(expected)
	if err != nil || subtle.ConstantTimeCompare(expectedRaw, request.decoded.Raw) != 1 {
		return TunnelAuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	if now.Unix() >= artifact.Session.InitExpireAtUnixSeconds {
		return RejectTunnelRuntime(artifactv3.ReasonExpiredArtifact, true)
	}
	return AllowTunnelRuntime(
		request,
		leaseID,
		time.Unix(artifact.Session.InitExpireAtUnixSeconds, 0),
		artifact.Path.ExpectedPeerEndpointInstanceID,
		record.allowReplacement,
	)
}

// AllowTunnelRuntime constructs the secret-free allow response returned by an
// application-owned authorizer after it has verified a tunnel admission. This
// boundary lets an untrusted relay consume only pairing and lease claims; it
// never requires an Artifact, AuthorizationRecord, Session contract, or PSK.
func AllowTunnelRuntime(request RuntimeAuthorizationRequest, leaseID string, expiresAt time.Time, expectedPeerEndpointInstanceID string, allowReplacement bool) (TunnelAuthorizationResponse, error) {
	if request.decoded == nil || request.decoded.Request.PathKind != artifactv3.PathTunnel ||
		request.lookupKey == "" || !leaseIDPattern.MatchString(leaseID) ||
		!leaseIDPattern.MatchString(expectedPeerEndpointInstanceID) ||
		expectedPeerEndpointInstanceID == request.decoded.Request.EndpointInstanceID ||
		!expiresAt.After(time.Now()) {
		return TunnelAuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	wire := tunnelRuntimeAuthorizationResponseWire{
		Decision: "allow", CredentialID: request.lookupKey, LeaseID: leaseID,
		ExpiresAt:                      expiresAt.UTC(),
		ExpectedPeerEndpointInstanceID: expectedPeerEndpointInstanceID,
		AllowReplacement:               allowReplacement,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return TunnelAuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	return TunnelAuthorizationResponse{encoded: encoded}, nil
}

// RejectTunnelRuntime creates a bounded tunnel rejection without exposing a
// direct-runtime response type at the relay boundary.
func RejectTunnelRuntime(reason string, retryable bool) (TunnelAuthorizationResponse, error) {
	status := artifactv3.AdmissionReject
	decision := "reject"
	if retryable {
		status = artifactv3.AdmissionRetryable
		decision = "retry"
	}
	if _, err := artifactv3.MarshalResponse(
		artifactv3.AdmissionResponse{Status: status, Reason: reason},
		artifactv3.ReasonRegistry{reason: {}},
	); err != nil {
		return TunnelAuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	encoded, err := json.Marshal(tunnelRuntimeAuthorizationResponseWire{Decision: decision, Reason: reason})
	if err != nil {
		return TunnelAuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	return TunnelAuthorizationResponse{encoded: encoded}, nil
}

// RejectRuntime creates a bounded reject or retry response for a reason token
// that is also configured in flowersec-runtime's rejection reason registry.
func RejectRuntime(reason string, retryable bool) (AuthorizationResponse, error) {
	status := artifactv3.AdmissionReject
	decision := "reject"
	if retryable {
		status = artifactv3.AdmissionRetryable
		decision = "retry"
	}
	if _, err := artifactv3.MarshalResponse(
		artifactv3.AdmissionResponse{Status: status, Reason: reason},
		artifactv3.ReasonRegistry{reason: {}},
	); err != nil {
		return AuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	encoded, err := json.Marshal(runtimeAuthorizationResponseWire{Decision: decision, Reason: reason})
	if err != nil {
		return AuthorizationResponse{}, ErrInvalidControlPlaneInput
	}
	return AuthorizationResponse{encoded: encoded}, nil
}

func sessionWire(session artifactv3.SessionContract) authorizedSessionWire {
	return authorizedSessionWire{
		ChannelID: session.ChannelID, InitExpireAtUnixSeconds: session.InitExpireAtUnixSeconds,
		IdleTimeoutSeconds: session.IdleTimeoutSeconds, EstablishTimeoutSeconds: session.EstablishTimeoutSeconds,
		RekeyPrepareTimeoutSeconds:    session.RekeyPrepareTimeoutSeconds,
		RekeyCompletionTimeoutSeconds: session.RekeyCompletionTimeoutSeconds,
		MaxInboundStreams:             session.MaxInboundStreams,
		E2EEPSKBase64URL:              base64.RawURLEncoding.EncodeToString(session.E2EEPSK[:]),
		AllowedSuites:                 slices.Clone(session.AllowedSuites), DefaultSuite: session.DefaultSuite,
		SelectedFeatures: session.SelectedFeatures,
	}
}

func artifactCredential(artifact *artifactv3.Artifact) string {
	if artifact == nil {
		return ""
	}
	if artifact.Path.Kind == artifactv3.PathDirect {
		return artifact.Path.RoutingToken
	}
	if artifact.Path.Kind == artifactv3.PathTunnel {
		return artifact.Path.Token
	}
	return ""
}

func credentialLookupKey(credential string) string {
	digest := sha256.Sum256([]byte(credential))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func decodeStrict(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func validObservedText(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}
