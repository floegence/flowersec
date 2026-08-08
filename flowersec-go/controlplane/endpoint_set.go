// Package controlplane provides the opaque server-side Flowersec v2 artifact
// issuance and runtime authorization boundary.
package controlplane

import (
	"errors"
	"strconv"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
)

// ErrInvalidControlPlaneInput reports a rejected issuance or authorization
// input without retaining credential-bearing details.
var ErrInvalidControlPlaneInput = errors.New("invalid Flowersec control-plane input")

// ErrIssuanceFailed reports an unavailable cryptographic random source without
// exposing the underlying provider error.
var ErrIssuanceFailed = errors.New("Flowersec artifact issuance failed")

type endpoint struct {
	carrier artifactv2.Carrier
	url     string
}

// EndpointSet is an opaque ordered set of production listener URLs. Carrier
// kinds and candidate identifiers remain Flowersec implementation details.
type EndpointSet struct {
	endpoints []endpoint
}

// NewEndpointSet validates the carrier schemes without exposing carrier
// objects to the caller. Path-specific validation happens during issuance.
func NewEndpointSet(urls ...string) (EndpointSet, error) {
	if len(urls) == 0 || len(urls) > artifactv2.MaxCandidates {
		return EndpointSet{}, ErrInvalidControlPlaneInput
	}
	endpoints := make([]endpoint, 0, len(urls))
	for _, raw := range urls {
		if raw == "" || raw != strings.TrimSpace(raw) {
			return EndpointSet{}, ErrInvalidControlPlaneInput
		}
		scheme, _, ok := strings.Cut(raw, "://")
		if !ok {
			return EndpointSet{}, ErrInvalidControlPlaneInput
		}
		var carrier artifactv2.Carrier
		switch strings.ToLower(scheme) {
		case "ws", "wss":
			carrier = artifactv2.CarrierWebSocket
		case "quic":
			carrier = artifactv2.CarrierRawQUIC
		case "https":
			carrier = artifactv2.CarrierWebTransport
		default:
			return EndpointSet{}, ErrInvalidControlPlaneInput
		}
		endpoints = append(endpoints, endpoint{carrier: carrier, url: raw})
	}
	return EndpointSet{endpoints: endpoints}, nil
}

func (set EndpointSet) candidates(kind artifactv2.PathKind) ([]artifactv2.Candidate, error) {
	if len(set.endpoints) == 0 || len(set.endpoints) > artifactv2.MaxCandidates {
		return nil, ErrInvalidControlPlaneInput
	}
	counts := make(map[artifactv2.Carrier]int, len(set.endpoints))
	candidates := make([]artifactv2.Candidate, 0, len(set.endpoints))
	for _, item := range set.endpoints {
		counts[item.carrier]++
		id := candidateID(item.carrier)
		if counts[item.carrier] > 1 {
			id += "-" + strconv.Itoa(counts[item.carrier])
		}
		candidates = append(candidates, artifactv2.Candidate{
			ID: id, Carrier: item.carrier, URL: item.url,
			WireProfile: "flowersec-" + string(kind) + "/2",
		})
	}
	if _, _, _, err := artifactv2.CanonicalizeCandidates(kind, candidates); err != nil {
		return nil, ErrInvalidControlPlaneInput
	}
	return candidates, nil
}

func candidateID(carrier artifactv2.Carrier) string {
	switch carrier {
	case artifactv2.CarrierWebSocket:
		return "websocket"
	case artifactv2.CarrierRawQUIC:
		return "raw-quic"
	case artifactv2.CarrierWebTransport:
		return "webtransport"
	default:
		return "invalid"
	}
}

// String deliberately reveals no listener URLs.
func (EndpointSet) String() string { return "Flowersec.EndpointSet" }

// GoString deliberately reveals no listener URLs.
func (EndpointSet) GoString() string { return "controlplane.EndpointSet" }
