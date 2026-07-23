package origin

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/idna15"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrInvalidPolicyV2       = errors.New("invalid Origin policy v2")
	ErrDuplicatePolicyV2Rule = errors.New("duplicate Origin policy v2 rule")
)

const maxPolicyV2Rules = 256

type PolicyV2Options struct {
	Rules                        []string
	AllowMissingForNativeClients bool
}

type wildcardRuleV2 struct {
	suffix string
	port   string
}

// PolicyV2 is an immutable exact and single-label wildcard HTTPS Origin
// policy shared by WebSocket and WebTransport listeners.
type PolicyV2 struct {
	exact        map[string]struct{}
	wildcards    []wildcardRuleV2
	allowMissing bool
}

func NewPolicyV2(options PolicyV2Options) (*PolicyV2, error) {
	if len(options.Rules) == 0 || len(options.Rules) > maxPolicyV2Rules {
		return nil, ErrInvalidPolicyV2
	}
	policy := &PolicyV2{
		exact:        make(map[string]struct{}, len(options.Rules)),
		allowMissing: options.AllowMissingForNativeClients,
	}
	seen := make(map[string]struct{}, len(options.Rules))
	for _, rule := range options.Rules {
		normalized, wildcard, err := normalizePolicyV2Origin(rule, true)
		if err != nil {
			return nil, ErrInvalidPolicyV2
		}
		if _, exists := seen[normalized.canonical]; exists {
			return nil, ErrDuplicatePolicyV2Rule
		}
		seen[normalized.canonical] = struct{}{}
		if wildcard {
			if _, err := publicsuffix.EffectiveTLDPlusOne(normalized.host); err != nil {
				return nil, ErrInvalidPolicyV2
			}
			policy.wildcards = append(policy.wildcards, wildcardRuleV2{suffix: normalized.host, port: normalized.port})
		} else {
			policy.exact[normalized.canonical] = struct{}{}
		}
	}
	return policy, nil
}

func (policy *PolicyV2) Allows(origin string) bool {
	if policy == nil {
		return false
	}
	if origin == "" {
		return policy.allowMissing
	}
	normalized, wildcard, err := normalizePolicyV2Origin(origin, false)
	if err != nil || wildcard {
		return false
	}
	if _, allowed := policy.exact[normalized.canonical]; allowed {
		return true
	}
	for _, rule := range policy.wildcards {
		if normalized.port != rule.port || !strings.HasSuffix(normalized.host, "."+rule.suffix) {
			continue
		}
		label := strings.TrimSuffix(normalized.host, "."+rule.suffix)
		if label != "" && !strings.Contains(label, ".") {
			return true
		}
	}
	return false
}

func (policy *PolicyV2) CheckRequest(request *http.Request) bool {
	if request == nil {
		return false
	}
	values := request.Header.Values("Origin")
	if len(values) == 0 {
		return policy.Allows("")
	}
	return len(values) == 1 && !strings.Contains(values[0], ",") && policy.Allows(values[0])
}

type normalizedPolicyV2Origin struct {
	canonical string
	host      string
	port      string
}

func normalizePolicyV2Origin(value string, allowWildcard bool) (normalizedPolicyV2Origin, bool, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\\%") {
		return normalizedPolicyV2Origin{}, false, ErrInvalidPolicyV2
	}
	parsed, err := url.Parse(value)
	if err != nil || strings.ToLower(parsed.Scheme) != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" {
		return normalizedPolicyV2Origin{}, false, ErrInvalidPolicyV2
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || strings.HasSuffix(host, ".") {
		return normalizedPolicyV2Origin{}, false, ErrInvalidPolicyV2
	}
	wildcard := strings.HasPrefix(host, "*.")
	if wildcard {
		if !allowWildcard || strings.Count(host, "*") != 1 {
			return normalizedPolicyV2Origin{}, false, ErrInvalidPolicyV2
		}
		host = strings.TrimPrefix(host, "*.")
	} else if strings.Contains(host, "*") {
		return normalizedPolicyV2Origin{}, false, ErrInvalidPolicyV2
	}

	canonicalHost, err := normalizePolicyV2Host(host, wildcard)
	if err != nil {
		return normalizedPolicyV2Origin{}, false, err
	}
	port := parsed.Port()
	if port != "" {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || value == 0 {
			return normalizedPolicyV2Origin{}, false, ErrInvalidPolicyV2
		}
		port = strconv.FormatUint(value, 10)
		if port == "443" {
			port = ""
		}
	}
	displayHost := canonicalHost
	if address, parseErr := netip.ParseAddr(canonicalHost); parseErr == nil && address.Is6() {
		displayHost = "[" + canonicalHost + "]"
	}
	if wildcard {
		displayHost = "*." + displayHost
	}
	canonicalAuthority := displayHost
	if port != "" {
		portHost := canonicalHost
		if wildcard {
			portHost = "*." + portHost
		}
		canonicalAuthority = net.JoinHostPort(portHost, port)
	}
	canonical := "https://" + canonicalAuthority
	return normalizedPolicyV2Origin{canonical: canonical, host: canonicalHost, port: port}, wildcard, nil
}

func normalizePolicyV2Host(host string, wildcard bool) (string, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if wildcard {
			return "", ErrInvalidPolicyV2
		}
		return address.String(), nil
	}
	canonical, err := idna15.LookupASCII(host)
	if err != nil {
		return "", ErrInvalidPolicyV2
	}
	labels := strings.Split(canonical, ".")
	if len(labels) < 2 {
		return "", ErrInvalidPolicyV2
	}
	return canonical, nil
}
