package transportsecurity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
)

type Runtime string

const RuntimeNative Runtime = "native"

type Input struct {
	Path    fserrors.Path
	Scheme  string
	Host    string
	Runtime Runtime
}

// Policy decides whether a high-level client may dial a WebSocket URL.
// It is evaluated before any network activity. Low-level transports remain scheme-neutral.
type Policy func(context.Context, Input) error

type PlaintextRiskAcceptance string

const PlaintextRiskAcceptPreE2ECredentialExposure PlaintextRiskAcceptance = "accept_pre_e2ee_credential_exposure"

type NetworkPlaintextPolicyOptions struct {
	AllowedHosts   []string
	RiskAcceptance PlaintextRiskAcceptance
}

var ErrDenied = errors.New("transport security policy denied websocket URL")

func RequireTLS(_ context.Context, input Input) error {
	if input.Scheme != "wss" {
		return ErrDenied
	}
	return nil
}

func AllowPlaintextForLoopback(_ context.Context, input Input) error {
	switch input.Scheme {
	case "wss":
		return nil
	case "ws":
		if isLiteralLoopbackHost(input.Host) {
			return nil
		}
	}
	return ErrDenied
}

func NewNetworkPlaintextPolicy(options NetworkPlaintextPolicyOptions) (Policy, error) {
	if options.RiskAcceptance != PlaintextRiskAcceptPreE2ECredentialExposure {
		return nil, fmt.Errorf("network plaintext policy requires explicit pre-E2EE credential exposure acceptance")
	}
	hosts, err := canonicalNetworkPlaintextHosts(options.AllowedHosts)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		allowed[host] = struct{}{}
	}
	return func(_ context.Context, input Input) error {
		switch input.Scheme {
		case "wss":
			return nil
		case "ws":
			if _, ok := allowed[input.Host]; ok {
				return nil
			}
		}
		return ErrDenied
	}, nil
}

func canonicalNetworkPlaintextHosts(rawHosts []string) ([]string, error) {
	if len(rawHosts) == 0 {
		return nil, fmt.Errorf("network plaintext policy requires at least one allowed host")
	}
	hosts := make([]string, 0, len(rawHosts))
	seen := make(map[string]struct{}, len(rawHosts))
	for _, rawHost := range rawHosts {
		host, err := canonicalNetworkPlaintextHost(rawHost)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, nil
}

func canonicalNetworkPlaintextHost(rawHost string) (string, error) {
	host := strings.TrimSpace(rawHost)
	if host == "" || host != strings.ToLower(host) || strings.ContainsAny(host, "@/?#%[]") {
		return "", fmt.Errorf("invalid network plaintext allowed host %q", rawHost)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" || addr.Is4In6() || addr.String() != host {
		return "", fmt.Errorf("network plaintext allowed host must be a canonical IP literal: %q", rawHost)
	}
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return "", fmt.Errorf("network plaintext allowed host must be a non-loopback unicast IP literal: %q", rawHost)
	}
	return host, nil
}

// Evaluate parses and sanitizes a WebSocket target, then applies policy.
// A nil policy is equivalent to RequireTLS.
func Evaluate(ctx context.Context, rawURL string, path fserrors.Path, runtime Runtime, policy Policy) (Input, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return Input{}, ErrDenied
	}
	input := Input{
		Path:    path,
		Scheme:  strings.ToLower(parsed.Scheme),
		Host:    strings.ToLower(parsed.Hostname()),
		Runtime: runtime,
	}
	if input.Scheme != "ws" && input.Scheme != "wss" {
		return Input{}, ErrDenied
	}
	if policy == nil {
		policy = RequireTLS
	}
	if err := safeEvaluate(ctx, policy, input); err != nil {
		return Input{}, err
	}
	return input, nil
}

func safeEvaluate(ctx context.Context, policy Policy, input Input) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrDenied
		}
	}()
	return policy(ctx, input)
}

func isLiteralLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" || host == "::1" {
		return true
	}
	if !isCanonicalIPv4Literal(host) {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isCanonicalIPv4Literal(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}
