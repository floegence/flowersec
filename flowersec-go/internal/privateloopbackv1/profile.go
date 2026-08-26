package privateloopbackv1

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	Profile    = "flowersec-private-loopback/1"
	DirectPath = "/flowersec/v3/direct"
)

var ErrInvalidProfile = errors.New("invalid Flowersec private loopback profile")

type artifactWire struct {
	ArtifactBase64URL string `json:"artifact_b64u"`
	Endpoint          string `json:"endpoint"`
	Profile           string `json:"profile"`
	Version           uint8  `json:"v"`
}

func MarshalArtifact(endpoint string, innerArtifact []byte) ([]byte, error) {
	if len(innerArtifact) == 0 || len(innerArtifact) > 65_536 {
		return nil, ErrInvalidProfile
	}
	canonical, _, err := ValidateEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(artifactWire{
		ArtifactBase64URL: base64.RawURLEncoding.EncodeToString(innerArtifact),
		Endpoint:          canonical,
		Profile:           Profile,
		Version:           1,
	})
	if err != nil || len(encoded) > 100_000 {
		return nil, ErrInvalidProfile
	}
	return encoded, nil
}

// ValidateEndpoint accepts only a canonical numeric-loopback WebSocket URL
// on the fixed direct path. The second result is the exact WSS candidate URL
// bound into the unchanged flowersec/3 artifact carried by this profile.
func ValidateEndpoint(raw string) (string, string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\\?#%") {
		return "", "", ErrInvalidProfile
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "ws" || parsed.User != nil || parsed.Path != DirectPath ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", "", ErrInvalidProfile
	}
	host := parsed.Hostname()
	portText := parsed.Port()
	if host == "" || portText == "" || !canonicalLoopbackIP(host) {
		return "", "", ErrInvalidProfile
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		return "", "", ErrInvalidProfile
	}
	authority := net.JoinHostPort(host, portText)
	canonical := (&url.URL{Scheme: "ws", Host: authority, Path: DirectPath}).String()
	if canonical != raw {
		return "", "", ErrInvalidProfile
	}
	return canonical, (&url.URL{Scheme: "wss", Host: authority, Path: DirectPath}).String(), nil
}

func RequestAllowed(request *http.Request) bool {
	if request == nil || request.URL == nil || request.Method != http.MethodGet ||
		request.URL.Path != DirectPath || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.Scheme != "" || request.URL.Host != "" || request.RequestURI != DirectPath {
		return false
	}
	endpoint := (&url.URL{Scheme: "ws", Host: request.Host, Path: request.URL.Path}).String()
	if _, _, err := ValidateEndpoint(endpoint); err != nil {
		return false
	}
	remoteHost, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || !canonicalLoopbackIP(remoteHost) {
		return false
	}
	origin, err := url.Parse(request.Header.Get("Origin"))
	return err == nil && origin.String() == "http://"+request.Host && origin.Scheme == "http" &&
		origin.Host == request.Host && origin.Path == "" && origin.RawQuery == "" &&
		origin.Fragment == "" && origin.User == nil
}

func canonicalLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return net.IP(ipv4).String() == host
	}
	return ip.String() == strings.ToLower(host)
}
