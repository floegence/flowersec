// Package endpointsetv2 defines the business-neutral registration contract for
// a Flowersec Transport v2 custom tunnel endpoint set.
package endpointsetv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/carrier"
	"github.com/floegence/flowersec/flowersec-go/session"
)

const (
	Profile           = "flowersec-tunnel-endpoint-set/2"
	TunnelWireProfile = "flowersec-tunnel/2"
	MaxJSONBytes      = 64 * 1024
	MaxListeners      = 32
	// MaxFreshnessAgeSeconds bounds how long a readiness observation remains
	// usable even when its absolute expiry is farther in the future.
	MaxFreshnessAgeSeconds = 300
)

var (
	ErrInvalidEndpointSet   = errors.New("invalid Flowersec v2 endpoint set")
	ErrEndpointSetTooLarge  = errors.New("Flowersec v2 endpoint set too large")
	ErrNoCompatibleListener = errors.New("no compatible Flowersec v2 endpoint listener")
	registryID              = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
)

type ListenerTuple struct {
	Carrier     carrier.Kind        `json:"carrier"`
	NetworkMode session.NetworkMode `json:"network_mode"`
	Path        carrier.Path        `json:"path"`
	// SessionRole is the endpoint role accepted from the dialing peer. It is
	// independent of NetworkMode: one physical listener may publish separate
	// tuples for client-role and server-role tunnel peers.
	SessionRole   session.SessionRole `json:"session_role"`
	URL           string              `json:"url"`
	AdvertisedURL string              `json:"advertised_url"`
	BindEndpoint  string              `json:"bind_endpoint"`
	WireProfile   string              `json:"wire_profile"`
}

type CertificateReadiness struct {
	Ready               bool     `json:"ready"`
	NotAfterUnixSeconds int64    `json:"not_after_unix_s"`
	VerifiedServerNames []string `json:"verified_server_names"`
}

type AudienceReadiness struct {
	Ready            bool   `json:"ready"`
	ListenerAudience string `json:"listener_audience"`
}

type Freshness struct {
	IssuedAtUnixSeconds  int64 `json:"issued_at_unix_s"`
	ExpiresAtUnixSeconds int64 `json:"expires_at_unix_s"`
}

type EndpointSet struct {
	Version            int                  `json:"v"`
	Profile            string               `json:"profile"`
	RendezvousGroupID  string               `json:"rendezvous_group_id"`
	EndpointInstanceID string               `json:"endpoint_instance_id"`
	Listeners          []ListenerTuple      `json:"listeners"`
	Certificate        CertificateReadiness `json:"certificate"`
	Audience           AudienceReadiness    `json:"audience"`
	Freshness          Freshness            `json:"freshness"`
}

func Validate(set EndpointSet, now time.Time) error {
	if set.Version != 2 || set.Profile != Profile ||
		!registryID.MatchString(set.RendezvousGroupID) || !registryID.MatchString(set.EndpointInstanceID) ||
		len(set.Listeners) == 0 || len(set.Listeners) > MaxListeners {
		return invalid("version, profile, identity, or listener count")
	}
	if now.IsZero() || now.Unix() < set.Freshness.IssuedAtUnixSeconds ||
		now.Unix()-set.Freshness.IssuedAtUnixSeconds > MaxFreshnessAgeSeconds ||
		set.Freshness.IssuedAtUnixSeconds >= set.Freshness.ExpiresAtUnixSeconds ||
		now.Unix() >= set.Freshness.ExpiresAtUnixSeconds {
		return invalid("freshness")
	}
	if !set.Certificate.Ready || set.Certificate.NotAfterUnixSeconds < set.Freshness.ExpiresAtUnixSeconds ||
		len(set.Certificate.VerifiedServerNames) == 0 || !set.Audience.Ready ||
		!registryID.MatchString(set.Audience.ListenerAudience) {
		return invalid("certificate or audience readiness")
	}
	verifiedNames := make(map[string]struct{}, len(set.Certificate.VerifiedServerNames))
	for index, name := range set.Certificate.VerifiedServerNames {
		canonical, err := canonicalServerName(name)
		if err != nil || canonical != name {
			return invalid("verified server name")
		}
		if _, duplicate := verifiedNames[name]; duplicate || (index > 0 && set.Certificate.VerifiedServerNames[index-1] >= name) {
			return invalid("duplicate or unsorted verified server names")
		}
		verifiedNames[name] = struct{}{}
	}

	seen := make(map[ListenerTuple]struct{}, len(set.Listeners))
	for index, tuple := range set.Listeners {
		serverName, err := validateTuple(tuple)
		if err != nil {
			return err
		}
		if serverName != "" {
			if _, ok := verifiedNames[serverName]; !ok {
				return invalid("dial URL is not certificate-ready")
			}
		}
		if _, duplicate := seen[tuple]; duplicate {
			return invalid("duplicate listener tuple")
		}
		if index > 0 && !tupleLess(set.Listeners[index-1], tuple) {
			return invalid("listener tuples are not canonical")
		}
		seen[tuple] = struct{}{}
	}
	return nil
}

// CompatibleListeners returns the canonical listeners usable by a requester.
// A listen tuple is matched against the requester's dial tuple while preserving
// the accepted endpoint session role; dial tuples are matched exactly. Empty
// intersections fail closed with ErrNoCompatibleListener.
func CompatibleListeners(set EndpointSet, now time.Time, requester session.CapabilityDescriptor) ([]ListenerTuple, error) {
	if err := Validate(set, now); err != nil {
		return nil, err
	}
	if err := requester.Validate(); err != nil {
		return nil, err
	}
	compatible := make([]ListenerTuple, 0, len(set.Listeners))
	for _, listener := range set.Listeners {
		want := session.CapabilityTuple{
			Carrier:     carrier.Kind(listener.Carrier),
			NetworkMode: session.NetworkMode(listener.NetworkMode),
			Path:        session.PathKind(listener.Path),
			SessionRole: session.SessionRole(listener.SessionRole),
		}
		if listener.NetworkMode == session.NetworkListen {
			want.NetworkMode = session.NetworkDial
		}
		if requester.Supports(want) {
			compatible = append(compatible, listener)
		}
	}
	if len(compatible) == 0 {
		return nil, ErrNoCompatibleListener
	}
	return compatible, nil
}

func MarshalJSON(set EndpointSet, now time.Time) ([]byte, error) {
	if err := Validate(set, now); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxJSONBytes {
		return nil, ErrEndpointSetTooLarge
	}
	return raw, nil
}

func DecodeJSON(reader io.Reader, now time.Time) (*EndpointSet, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxJSONBytes {
		return nil, ErrEndpointSetTooLarge
	}
	if err := rejectDuplicateFields(raw); err != nil {
		return nil, invalid(err.Error())
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var set EndpointSet
	if err := decoder.Decode(&set); err != nil {
		return nil, invalid(err.Error())
	}
	if err := requireEOF(decoder); err != nil {
		return nil, invalid(err.Error())
	}
	if err := Validate(set, now); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(set)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, invalid("JSON is not canonical")
	}
	return &set, nil
}

func validateTuple(tuple ListenerTuple) (string, error) {
	if err := tuple.Carrier.Validate(); err != nil || tuple.Path != carrier.PathTunnel || tuple.WireProfile != TunnelWireProfile {
		return "", invalid("carrier, path, or wire profile")
	}
	if tuple.SessionRole != session.RoleClient && tuple.SessionRole != session.RoleServer {
		return "", invalid("session role")
	}
	switch tuple.NetworkMode {
	case session.NetworkDial:
		if tuple.URL == "" || tuple.AdvertisedURL != "" || tuple.BindEndpoint != "" {
			return "", invalid("dial tuple endpoint")
		}
		return validateAdvertisedURL(tuple, tuple.URL)
	case session.NetworkListen:
		if tuple.URL != "" || tuple.AdvertisedURL == "" || tuple.BindEndpoint == "" {
			return "", invalid("listen tuple endpoint or role")
		}
		if err := validateBindEndpoint(tuple.Carrier, tuple.BindEndpoint); err != nil {
			return "", err
		}
		return validateAdvertisedURL(tuple, tuple.AdvertisedURL)
	default:
		return "", invalid("network mode")
	}
}

func validateAdvertisedURL(tuple ListenerTuple, raw string) (string, error) {
	canonical, _, _, err := artifactv2.CanonicalizeCandidates(artifactv2.PathTunnel, []artifactv2.Candidate{{
		ID: "listener", Carrier: artifactv2.Carrier(tuple.Carrier), URL: raw, WireProfile: tuple.WireProfile,
	}})
	if err != nil || len(canonical) != 1 || canonical[0].NormalizedURL != raw {
		return "", invalid("advertised URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", invalid("advertised URL")
	}
	return canonicalServerName(parsed.Hostname())
}

func validateBindEndpoint(kind carrier.Kind, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return invalid("bind endpoint")
	}
	wantScheme := "tcp"
	if kind == carrier.KindQUIC || kind == carrier.KindWebTransport {
		wantScheme = "udp"
	}
	if parsed.Scheme != wantScheme {
		return invalid("bind endpoint scheme")
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil || net.ParseIP(host) == nil {
		return invalid("bind endpoint address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return invalid("bind endpoint port")
	}
	canonical := wantScheme + "://" + net.JoinHostPort(net.ParseIP(host).String(), strconv.Itoa(port))
	if canonical != raw {
		return invalid("non-canonical bind endpoint")
	}
	return nil
}

func canonicalServerName(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\\/%?#@") {
		return "", invalid("server name")
	}
	if ip := net.ParseIP(name); ip != nil {
		return ip.String(), nil
	}
	canonical, _, _, err := artifactv2.CanonicalizeCandidates(artifactv2.PathTunnel, []artifactv2.Candidate{{
		ID: "server", Carrier: artifactv2.CarrierWebSocket,
		URL: "wss://" + name + "/flowersec/v2/tunnel", WireProfile: TunnelWireProfile,
	}})
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(canonical[0].NormalizedURL)
	if err != nil {
		return "", err
	}
	return parsed.Hostname(), nil
}

func tupleLess(left, right ListenerTuple) bool {
	return slices.Compare([]string{
		string(left.Carrier), string(left.NetworkMode), string(left.Path), string(left.SessionRole), left.URL, left.AdvertisedURL, left.BindEndpoint, left.WireProfile,
	}, []string{
		string(right.Carrier), string(right.NetworkMode), string(right.Path), string(right.SessionRole), right.URL, right.AdvertisedURL, right.BindEndpoint, right.WireProfile,
	}) < 0
}

func invalid(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidEndpointSet, detail)
}

func rejectDuplicateFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
