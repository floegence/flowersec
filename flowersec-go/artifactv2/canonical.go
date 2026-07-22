package artifactv2

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/internal/idna15"
)

var (
	candidateIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	registryIDPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

type sessionContractCanonical struct {
	AllowedSuites                 []uint16 `json:"allowed_suites"`
	ChannelID                     string   `json:"channel_id"`
	DefaultSuite                  uint16   `json:"default_suite"`
	EstablishTimeoutSeconds       uint16   `json:"establish_timeout_seconds"`
	IdleTimeoutSeconds            uint32   `json:"idle_timeout_seconds"`
	MaxInboundStreams             uint16   `json:"max_inbound_streams"`
	Profile                       string   `json:"profile"`
	RekeyCompletionTimeoutSeconds uint16   `json:"rekey_completion_timeout_seconds"`
	RekeyPrepareTimeoutSeconds    uint16   `json:"rekey_prepare_timeout_seconds"`
	SelectedFeatures              uint32   `json:"selected_features"`
}

func ComputeSessionContractHash(session SessionContract) ([32]byte, []byte, error) {
	if err := validateSessionFields(session); err != nil {
		return [32]byte{}, nil, err
	}
	canonical, err := canonicalJSON(sessionContractCanonical{
		AllowedSuites:                 session.AllowedSuites,
		ChannelID:                     session.ChannelID,
		DefaultSuite:                  session.DefaultSuite,
		EstablishTimeoutSeconds:       session.EstablishTimeoutSeconds,
		IdleTimeoutSeconds:            session.IdleTimeoutSeconds,
		MaxInboundStreams:             session.MaxInboundStreams,
		Profile:                       Profile,
		RekeyCompletionTimeoutSeconds: session.RekeyCompletionTimeoutSeconds,
		RekeyPrepareTimeoutSeconds:    session.RekeyPrepareTimeoutSeconds,
		SelectedFeatures:              session.SelectedFeatures,
	})
	if err != nil {
		return [32]byte{}, nil, err
	}
	return hashCanonical("flowersec-v2-session-contract\x00", canonical), canonical, nil
}

func validateSessionFields(session SessionContract) error {
	if !validRegistryID(session.ChannelID, 128) {
		return fmt.Errorf("%w: channel_id", ErrInvalidArtifact)
	}
	if session.InitExpireAtUnixSeconds <= 0 {
		return fmt.Errorf("%w: init expiry", ErrInvalidArtifact)
	}
	if session.EstablishTimeoutSeconds != 30 || session.RekeyPrepareTimeoutSeconds != 10 || session.RekeyCompletionTimeoutSeconds != 30 {
		return fmt.Errorf("%w: fixed session timing", ErrInvalidArtifact)
	}
	if session.MaxInboundStreams < 1 || session.MaxInboundStreams > 128 {
		return fmt.Errorf("%w: max_inbound_streams", ErrInvalidArtifact)
	}
	if session.SelectedFeatures != 0 {
		return fmt.Errorf("%w: selected_features", ErrInvalidArtifact)
	}
	if len(session.AllowedSuites) == 0 || !slices.IsSorted(session.AllowedSuites) {
		return fmt.Errorf("%w: allowed_suites must be sorted and nonempty", ErrInvalidArtifact)
	}
	seen := make(map[uint16]struct{}, len(session.AllowedSuites))
	for _, suite := range session.AllowedSuites {
		if suite != 1 && suite != 2 {
			return fmt.Errorf("%w: unknown suite %d", ErrInvalidArtifact, suite)
		}
		if _, duplicate := seen[suite]; duplicate {
			return fmt.Errorf("%w: duplicate suite %d", ErrInvalidArtifact, suite)
		}
		seen[suite] = struct{}{}
	}
	if _, ok := seen[session.DefaultSuite]; !ok {
		return fmt.Errorf("%w: default_suite", ErrInvalidArtifact)
	}
	return nil
}

func CanonicalizeCandidates(kind PathKind, candidates []Candidate) ([]CanonicalCandidate, []byte, [32]byte, error) {
	if kind != PathDirect && kind != PathTunnel {
		return nil, nil, [32]byte{}, fmt.Errorf("%w: path kind", ErrInvalidCandidate)
	}
	if len(candidates) < 1 || len(candidates) > MaxCandidates {
		return nil, nil, [32]byte{}, fmt.Errorf("%w: candidate count", ErrInvalidCandidate)
	}
	ids := make(map[string]struct{}, len(candidates))
	tuples := make(map[string]struct{}, len(candidates))
	canonicalCandidates := make([]CanonicalCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if len(candidate.ID) < 1 || len(candidate.ID) > 64 || !candidateIDPattern.MatchString(candidate.ID) {
			return nil, nil, [32]byte{}, fmt.Errorf("%w: candidate id %q", ErrInvalidCandidate, candidate.ID)
		}
		if _, duplicate := ids[candidate.ID]; duplicate {
			return nil, nil, [32]byte{}, fmt.Errorf("%w: duplicate candidate id %q", ErrInvalidCandidate, candidate.ID)
		}
		ids[candidate.ID] = struct{}{}
		if len(candidate.URL) < 1 || len(candidate.URL) > 2_048 {
			return nil, nil, [32]byte{}, fmt.Errorf("%w: candidate URL length", ErrInvalidCandidate)
		}
		normalized, err := normalizeCandidateURL(kind, candidate.Carrier, candidate.URL)
		if err != nil {
			return nil, nil, [32]byte{}, err
		}
		if len(normalized) > 2_048 {
			return nil, nil, [32]byte{}, fmt.Errorf("%w: normalized URL length", ErrInvalidCandidate)
		}
		if candidate.NormalizedURL != "" && candidate.NormalizedURL != normalized {
			return nil, nil, [32]byte{}, fmt.Errorf("%w: normalized URL mismatch", ErrInvalidCandidate)
		}
		wireProfile := "flowersec-" + string(kind) + "/2"
		if candidate.WireProfile != wireProfile {
			return nil, nil, [32]byte{}, fmt.Errorf("%w: wire profile", ErrInvalidCandidate)
		}
		tuple := string(candidate.Carrier) + "\x00" + normalized + "\x00" + candidate.WireProfile
		if _, duplicate := tuples[tuple]; duplicate {
			return nil, nil, [32]byte{}, fmt.Errorf("%w: duplicate normalized tuple", ErrInvalidCandidate)
		}
		tuples[tuple] = struct{}{}
		item := CanonicalCandidate{
			Carrier:       candidate.Carrier,
			ID:            candidate.ID,
			NormalizedURL: normalized,
			WireProfile:   candidate.WireProfile,
		}
		encoded, err := canonicalJSON(item)
		if err != nil {
			return nil, nil, [32]byte{}, err
		}
		if len(encoded) > MaxCanonicalCandidateBytes {
			return nil, nil, [32]byte{}, fmt.Errorf("%w: canonical candidate too large", ErrInvalidCandidate)
		}
		canonicalCandidates = append(canonicalCandidates, item)
	}
	slices.SortFunc(canonicalCandidates, func(a, b CanonicalCandidate) int {
		return strings.Compare(a.ID, b.ID)
	})
	canonical, err := canonicalJSON(canonicalCandidates)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	if len(canonical) > MaxCanonicalCandidateSet {
		return nil, nil, [32]byte{}, fmt.Errorf("%w: canonical candidate set too large", ErrInvalidCandidate)
	}
	return canonicalCandidates, canonical, hashCanonical("flowersec-v2-candidates\x00", canonical), nil
}

func normalizeCandidateURL(kind PathKind, carrier Carrier, raw string) (string, error) {
	if strings.ContainsAny(raw, "\\?#%") {
		return "", fmt.Errorf("%w: forbidden URL component", ErrInvalidCandidate)
	}
	separator := strings.Index(raw, "://")
	if separator <= 0 {
		return "", fmt.Errorf("%w: URL must be absolute", ErrInvalidCandidate)
	}
	scheme := strings.ToLower(raw[:separator])
	remainder := raw[separator+3:]
	pathAt := strings.IndexByte(remainder, '/')
	authority := remainder
	path := ""
	if pathAt >= 0 {
		authority = remainder[:pathAt]
		path = remainder[pathAt:]
	}
	if authority == "" || strings.Contains(authority, "@") {
		return "", fmt.Errorf("%w: URL authority", ErrInvalidCandidate)
	}
	host, port, err := normalizeAuthority(authority)
	if err != nil {
		return "", err
	}
	wantScheme := ""
	wantPath := ""
	switch carrier {
	case CarrierWebSocket:
		wantScheme = "wss"
		wantPath = "/flowersec/v2/" + string(kind)
	case CarrierRawQUIC:
		wantScheme = "quic"
		if path != "" && path != "/" {
			return "", fmt.Errorf("%w: raw QUIC path", ErrInvalidCandidate)
		}
		path = ""
	case CarrierWebTransport:
		wantScheme = "https"
		wantPath = "/flowersec/webtransport/v2/" + string(kind)
	default:
		return "", fmt.Errorf("%w: carrier %q", ErrInvalidCandidate, carrier)
	}
	if scheme != wantScheme {
		return "", fmt.Errorf("%w: carrier scheme", ErrInvalidCandidate)
	}
	if carrier != CarrierRawQUIC && path != wantPath {
		return "", fmt.Errorf("%w: carrier URL path", ErrInvalidCandidate)
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host + path, nil
}

func normalizeAuthority(authority string) (string, string, error) {
	host := authority
	portText := ""
	if strings.HasPrefix(authority, "[") {
		closing := strings.IndexByte(authority, ']')
		if closing < 0 {
			return "", "", fmt.Errorf("%w: IPv6 authority", ErrInvalidCandidate)
		}
		host = authority[1:closing]
		tail := authority[closing+1:]
		if tail != "" {
			if !strings.HasPrefix(tail, ":") || len(tail) == 1 {
				return "", "", fmt.Errorf("%w: IPv6 port", ErrInvalidCandidate)
			}
			portText = tail[1:]
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() || address.Zone() != "" {
			return "", "", fmt.Errorf("%w: IPv6 host", ErrInvalidCandidate)
		}
		host = "[" + address.String() + "]"
	} else {
		if strings.Count(authority, ":") > 1 {
			return "", "", fmt.Errorf("%w: unbracketed IPv6", ErrInvalidCandidate)
		}
		if colon := strings.LastIndexByte(authority, ':'); colon >= 0 {
			host = authority[:colon]
			portText = authority[colon+1:]
			if portText == "" {
				return "", "", fmt.Errorf("%w: empty port", ErrInvalidCandidate)
			}
		}
		var err error
		host, err = normalizeDNSOrIPv4(host)
		if err != nil {
			return "", "", err
		}
	}
	if portText == "" {
		return host, "", nil
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", "", fmt.Errorf("%w: port", ErrInvalidCandidate)
	}
	if port == 443 {
		return host, "", nil
	}
	return host, strconv.FormatUint(port, 10), nil
}

func normalizeDNSOrIPv4(host string) (string, error) {
	if host == "" || strings.HasSuffix(host, ".") {
		return "", fmt.Errorf("%w: DNS host", ErrInvalidCandidate)
	}
	lower := strings.ToLower(host)
	if onlyDigitsAndDots(lower) {
		address, err := netip.ParseAddr(lower)
		if err != nil || !address.Is4() {
			return "", fmt.Errorf("%w: IPv4 host", ErrInvalidCandidate)
		}
		return address.String(), nil
	}
	canonical, err := idna15.LookupASCII(host)
	if err != nil {
		return "", fmt.Errorf("%w: DNS label", ErrInvalidCandidate)
	}
	return canonical, nil
}

func onlyDigitsAndDots(value string) bool {
	for i := 0; i < len(value); i++ {
		if (value[i] < '0' || value[i] > '9') && value[i] != '.' {
			return false
		}
	}
	return true
}

func hashCanonical(label string, canonical []byte) [32]byte {
	preimage := make([]byte, 0, len(label)+4+len(canonical))
	preimage = append(preimage, label...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(canonical)))
	preimage = append(preimage, size[:]...)
	preimage = append(preimage, canonical...)
	return sha256.Sum256(preimage)
}

func validRegistryID(value string, max int) bool {
	return len(value) >= 1 && len(value) <= max && registryIDPattern.MatchString(value)
}

func validASCII(value string, max int) bool {
	if len(value) < 1 || len(value) > max {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}
