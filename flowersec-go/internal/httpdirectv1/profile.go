// Package httpdirectv1 defines the explicitly selected HTTP direct profile.
// It shares v3 session admission but does not claim TLS transport security.
package httpdirectv1

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const Profile = "flowersec-http-direct/1"
const DirectPath = "/flowersec/v3/direct"

var ErrInvalidProfile = errors.New("invalid Flowersec HTTP direct profile")

func ValidateEndpoint(raw string) (string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "ws" || parsed.User != nil || parsed.Path != DirectPath ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" ||
		strings.ContainsAny(raw, "\\?#%") || raw != strings.TrimSpace(raw) {
		return "", "", ErrInvalidProfile
	}
	host := parsed.Hostname()
	if host != "localhost" {
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.Is4In6() || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() ||
			addr.IsLinkLocalUnicast() || host == "255.255.255.255" || addr.String() != host {
			return "", "", ErrInvalidProfile
		}
	}
	portText := parsed.Port()
	if portText == "" {
		portText = "80"
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		return "", "", ErrInvalidProfile
	}
	authority := net.JoinHostPort(host, portText)
	if port == 80 {
		authority = host
		if strings.Contains(host, ":") {
			authority = "[" + host + "]"
		}
	}
	canonical := (&url.URL{Scheme: "ws", Host: authority, Path: DirectPath}).String()
	if canonical != raw {
		return "", "", ErrInvalidProfile
	}
	bindingAuthority := net.JoinHostPort(host, portText)
	if port == 443 {
		bindingAuthority = host
		if strings.Contains(host, ":") {
			bindingAuthority = "[" + host + "]"
		}
	}
	return canonical, (&url.URL{Scheme: "wss", Host: bindingAuthority, Path: DirectPath}).String(), nil
}

func MarshalArtifact(endpoint string, inner []byte) ([]byte, error) {
	canonical, _, err := ValidateEndpoint(endpoint)
	if err != nil || len(inner) == 0 || len(inner) > 65_536 {
		return nil, ErrInvalidProfile
	}
	return json.Marshal(struct {
		Artifact string `json:"artifact_b64u"`
		Endpoint string `json:"endpoint"`
		Profile  string `json:"profile"`
		Version  uint8  `json:"v"`
	}{base64.RawURLEncoding.EncodeToString(inner), canonical, Profile, 1})
}

func RequestAllowed(r *http.Request) bool {
	if r == nil || r.URL == nil || r.TLS != nil || r.Method != http.MethodGet ||
		r.URL.Path != DirectPath || r.URL.RawPath != "" || r.URL.RawQuery != "" ||
		r.URL.Scheme != "" || r.URL.Host != "" || r.RequestURI != DirectPath {
		return false
	}
	if _, _, err := ValidateEndpoint("ws://" + r.Host + DirectPath); err != nil {
		return false
	}
	origins := r.Header.Values("Origin")
	return len(origins) == 1 && origins[0] == "http://"+r.Host
}
