// Package controlplane provides the opaque server-side Flowersec v3 artifact
// issuance and runtime authorization boundary.
package controlplane

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
)

var (
	ErrInvalidControlPlaneInput = errors.New("flowersec control-plane input is invalid")
	ErrIssuanceFailed           = errors.New("flowersec artifact issuance failed")
)

type ControlPlaneErrorCode string

const (
	InvalidEndpointCount ControlPlaneErrorCode = "invalid_endpoint_count"
	InvalidEndpointID    ControlPlaneErrorCode = "invalid_endpoint_id"
	InvalidEndpointURL   ControlPlaneErrorCode = "invalid_endpoint_url"
	DuplicateEndpoint    ControlPlaneErrorCode = "duplicate_endpoint"
	InvalidTLSPolicy     ControlPlaneErrorCode = "invalid_tls_policy"
	InvalidPin           ControlPlaneErrorCode = "invalid_pin"
)

type ControlPlaneError struct {
	code      ControlPlaneErrorCode
	fieldPath string
}

func (*ControlPlaneError) Error() string { return ErrInvalidControlPlaneInput.Error() }

func (err *ControlPlaneError) Code() ControlPlaneErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func (err *ControlPlaneError) FieldPath() string {
	if err == nil {
		return ""
	}
	return err.fieldPath
}

func (*ControlPlaneError) Unwrap() error { return ErrInvalidControlPlaneInput }

func controlPlaneError(code ControlPlaneErrorCode, fieldPath string) error {
	return &ControlPlaneError{code: code, fieldPath: fieldPath}
}

type tlsPolicyTag uint8

const (
	tlsPolicyCA tlsPolicyTag = iota + 1
	tlsPolicyPin
)

// CertificatePin is a deployment-provided SHA-256 hash of the exact leaf DER.
type CertificatePin struct {
	SHA256   [32]byte
	NotAfter time.Time
}

// TLSPolicy is constructible only through CAPolicy or PinPolicy. Its zero value
// is intentionally invalid and never means CA trust.
type TLSPolicy struct {
	tag  tlsPolicyTag
	pins []CertificatePin
}

func CAPolicy() TLSPolicy { return TLSPolicy{tag: tlsPolicyCA} }

func PinPolicy(pins ...CertificatePin) (TLSPolicy, error) {
	if len(pins) < 1 || len(pins) > 4 {
		return TLSPolicy{}, controlPlaneError(InvalidPin, "pins")
	}
	copyPins := slices.Clone(pins)
	seen := make(map[[32]byte]struct{}, len(copyPins))
	for index, pin := range copyPins {
		if _, duplicate := seen[pin.SHA256]; duplicate {
			return TLSPolicy{}, controlPlaneError(InvalidPin, fmt.Sprintf("pins[%d].sha256", index))
		}
		seen[pin.SHA256] = struct{}{}
		if !validPinTime(pin.NotAfter) {
			return TLSPolicy{}, controlPlaneError(InvalidPin, fmt.Sprintf("pins[%d].not_after", index))
		}
		copyPins[index].NotAfter = pin.NotAfter.UTC()
	}
	slices.SortFunc(copyPins, func(left, right CertificatePin) int {
		return strings.Compare(base64.RawURLEncoding.EncodeToString(left.SHA256[:]), base64.RawURLEncoding.EncodeToString(right.SHA256[:]))
	})
	return TLSPolicy{tag: tlsPolicyPin, pins: copyPins}, nil
}

func validPinTime(value time.Time) bool {
	if value.IsZero() || value.Nanosecond() != 0 {
		return false
	}
	seconds := value.Unix()
	return seconds >= 1 && seconds <= 9_007_199_254_740_991
}

func (TLSPolicy) String() string   { return "Flowersec.TLSPolicy" }
func (TLSPolicy) GoString() string { return "controlplane.TLSPolicy" }

func (CertificatePin) String() string   { return "Flowersec.CertificatePin" }
func (CertificatePin) GoString() string { return "controlplane.CertificatePin" }

type EndpointConfig struct {
	ID  string
	URL string
	TLS TLSPolicy
}

type endpoint struct {
	id      string
	carrier artifactv3.Carrier
	url     string
	tls     TLSPolicy
}

type EndpointSet struct {
	endpoints []endpoint
}

func NewEndpointSet(configs ...EndpointConfig) (EndpointSet, error) {
	if len(configs) < 1 || len(configs) > artifactv3.MaxCandidates {
		return EndpointSet{}, controlPlaneError(InvalidEndpointCount, "endpoints")
	}
	endpoints := make([]endpoint, 0, len(configs))
	seenIDs := make(map[string]struct{}, len(configs))
	for index, config := range configs {
		prefix := fmt.Sprintf("endpoints[%d]", index)
		if !validCandidateID(config.ID) {
			return EndpointSet{}, controlPlaneError(InvalidEndpointID, prefix+".id")
		}
		if _, duplicate := seenIDs[config.ID]; duplicate {
			return EndpointSet{}, controlPlaneError(InvalidEndpointID, prefix+".id")
		}
		seenIDs[config.ID] = struct{}{}
		carrier, ok := endpointCarrier(config.URL)
		if !ok {
			return EndpointSet{}, controlPlaneError(InvalidEndpointURL, prefix+".url")
		}
		if err := validatePublicTLSPolicy(config.TLS); err != nil {
			return EndpointSet{}, controlPlaneError(InvalidTLSPolicy, prefix+".tls")
		}
		endpoints = append(endpoints, endpoint{
			id: config.ID, carrier: carrier, url: config.URL,
			tls: TLSPolicy{tag: config.TLS.tag, pins: slices.Clone(config.TLS.pins)},
		})
	}
	return EndpointSet{endpoints: endpoints}, nil
}

func (set EndpointSet) candidates(kind artifactv3.PathKind, issuanceNow time.Time) ([]artifactv3.Candidate, error) {
	if len(set.endpoints) < 1 || len(set.endpoints) > artifactv3.MaxCandidates {
		return nil, controlPlaneError(InvalidEndpointCount, "endpoints")
	}
	candidates := make([]artifactv3.Candidate, 0, len(set.endpoints))
	endpointKeys := make(map[string]struct{}, len(set.endpoints))
	for index, item := range set.endpoints {
		prefix := fmt.Sprintf("endpoints[%d]", index)
		if !validCandidateID(item.id) {
			return nil, controlPlaneError(InvalidEndpointID, prefix+".id")
		}
		if err := validatePublicTLSPolicy(item.tls); err != nil {
			return nil, controlPlaneError(InvalidTLSPolicy, prefix+".tls")
		}
		policy := toArtifactTLSPolicy(item.tls)
		if policy.Mode == artifactv3.TLSModePin {
			active, err := artifactv3.ActivePinHashes(policy, issuanceNow.UTC().Unix())
			if err != nil || len(active) == 0 {
				return nil, controlPlaneError(InvalidTLSPolicy, prefix+".tls")
			}
		}
		candidate := artifactv3.Candidate{
			ID: item.id, Carrier: item.carrier, URL: item.url, TLS: policy,
			WireProfile: "flowersec-" + string(kind) + "/3",
		}
		canonical, _, _, err := artifactv3.CanonicalizeCandidates(kind, []artifactv3.Candidate{candidate})
		if err != nil {
			return nil, controlPlaneError(InvalidEndpointURL, prefix+".url")
		}
		key := string(item.carrier) + "\x00" + string(kind) + "\x00" + canonical[0].NormalizedURL
		if _, duplicate := endpointKeys[key]; duplicate {
			return nil, controlPlaneError(DuplicateEndpoint, prefix)
		}
		endpointKeys[key] = struct{}{}
		candidates = append(candidates, candidate)
	}
	if _, _, _, err := artifactv3.CanonicalizeCandidates(kind, candidates); err != nil {
		return nil, ErrInvalidControlPlaneInput
	}
	return candidates, nil
}

func validatePublicTLSPolicy(policy TLSPolicy) error {
	switch policy.tag {
	case tlsPolicyCA:
		if policy.pins != nil {
			return ErrInvalidControlPlaneInput
		}
	case tlsPolicyPin:
		if len(policy.pins) < 1 || len(policy.pins) > 4 {
			return ErrInvalidControlPlaneInput
		}
		previous := ""
		for index, pin := range policy.pins {
			if !validPinTime(pin.NotAfter) {
				return ErrInvalidControlPlaneInput
			}
			encoded := base64.RawURLEncoding.EncodeToString(pin.SHA256[:])
			if index > 0 && previous >= encoded {
				return ErrInvalidControlPlaneInput
			}
			previous = encoded
		}
	default:
		return ErrInvalidControlPlaneInput
	}
	return nil
}

func toArtifactTLSPolicy(policy TLSPolicy) artifactv3.TLSPolicy {
	if policy.tag == tlsPolicyCA {
		return artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}
	}
	pins := make([]artifactv3.CertificatePin, 0, len(policy.pins))
	for _, pin := range policy.pins {
		pins = append(pins, artifactv3.CertificatePin{
			Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(pin.SHA256[:]),
			NotAfterUnixS: pin.NotAfter.Unix(),
		})
	}
	return artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: pins}
}

func endpointCarrier(raw string) (artifactv3.Carrier, bool) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return "", false
	}
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return "", false
	}
	switch strings.ToLower(scheme) {
	case "wss":
		return artifactv3.CarrierWebSocket, true
	case "quic":
		return artifactv3.CarrierRawQUIC, true
	case "https":
		return artifactv3.CarrierWebTransport, true
	default:
		return "", false
	}
}

func validCandidateID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func (EndpointSet) String() string   { return "Flowersec.EndpointSet" }
func (EndpointSet) GoString() string { return "controlplane.EndpointSet" }
