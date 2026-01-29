package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
)

// ProtocolVersion is the current flowersec-proxy meta version (see docs/PROXY.md).
const ProtocolVersion = 1

const (
	// DefaultMaxChunkBytes caps a single body chunk for KindHTTP1.
	DefaultMaxChunkBytes = 256 << 10 // 256 KiB
	// DefaultMaxBodyBytes caps total body bytes per direction for KindHTTP1.
	DefaultMaxBodyBytes = 64 << 20 // 64 MiB

	// DefaultMaxWSFrameBytes caps a single WS frame payload for KindWS.
	DefaultMaxWSFrameBytes = 1 << 20 // 1 MiB

	// DefaultDefaultTimeout is used when HTTPRequestMeta.timeout_ms is missing/0.
	DefaultDefaultTimeout = 30 * time.Second
	// DefaultMaxTimeout caps HTTPRequestMeta.timeout_ms when provided.
	DefaultMaxTimeout = 5 * time.Minute
)

// Options configures the server endpoint handlers registered by Register.
//
// All limits are enforced on untrusted client inputs.
type Options struct {
	// Upstream is the fixed upstream base URL to proxy to (required).
	// Example: "http://127.0.0.1:8080".
	//
	// The server endpoint MUST NOT allow the client to pick an arbitrary upstream host/port.
	Upstream string

	// UpstreamOrigin is the explicit Origin header value used for upstream WebSocket dials.
	// It must be a valid http(s) origin (scheme + host[:port]) without a path.
	UpstreamOrigin string

	// AllowedUpstreamHosts is an explicit allow-list for Upstream host validation.
	// If empty, only "127.0.0.1" is allowed.
	AllowedUpstreamHosts []string

	// MaxJSONFrameBytes caps incoming JSON meta frame size.
	// If == 0, jsonframe.DefaultMaxJSONFrameBytes is used.
	// If < 0, Register returns an error.
	MaxJSONFrameBytes int

	// MaxChunkBytes caps a single body chunk length for KindHTTP1.
	// If == 0, DefaultMaxChunkBytes is used.
	// If < 0, Register returns an error.
	MaxChunkBytes int

	// MaxBodyBytes caps the total body bytes per direction for KindHTTP1.
	// If == 0, DefaultMaxBodyBytes is used.
	// If < 0, Register returns an error.
	MaxBodyBytes int64

	// MaxWSFrameBytes caps a single WS frame payload length for KindWS.
	// If == 0, DefaultMaxWSFrameBytes is used.
	// If < 0, Register returns an error.
	MaxWSFrameBytes int

	// DefaultTimeout is used when HTTPRequestMeta.timeout_ms is missing/0.
	// nil uses DefaultDefaultTimeout; 0 disables timeouts.
	DefaultTimeout *time.Duration
	// MaxTimeout caps HTTPRequestMeta.timeout_ms when provided.
	// nil uses DefaultMaxTimeout; 0 disables the cap.
	MaxTimeout *time.Duration

	// ExtraRequestHeaders extends the request header allow-list (see docs/PROXY.md).
	ExtraRequestHeaders []string
	// ExtraResponseHeaders extends the response header allow-list (see docs/PROXY.md).
	ExtraResponseHeaders []string
	// ExtraWSHeaders extends the WS open header allow-list (see docs/PROXY.md).
	ExtraWSHeaders []string

	// ForbiddenCookieNames strips matching cookie name/value pairs from the forwarded Cookie header.
	// Matching is case-insensitive on cookie name.
	ForbiddenCookieNames []string
	// ForbiddenCookieNamePrefixes strips cookies whose names start with one of the configured prefixes.
	// Matching is case-insensitive on cookie name.
	ForbiddenCookieNamePrefixes []string
}

type compiledOptions struct {
	upstream       *url.URL
	upstreamHost   string // host:port
	upstreamOrigin string

	maxJSONFrameBytes int
	maxChunkBytes     int
	maxBodyBytes      int64
	maxWSFrameBytes   int

	defaultTimeout time.Duration
	maxTimeout     time.Duration

	extraReqHeaders  map[string]struct{}
	extraRespHeaders map[string]struct{}
	extraWSHeaders   map[string]struct{}

	forbiddenCookieNames        map[string]struct{}
	forbiddenCookieNamePrefixes []string
}

func compileOptions(opts Options) (*compiledOptions, error) {
	upstreamStr := strings.TrimSpace(opts.Upstream)
	if upstreamStr == "" {
		return nil, errors.New("missing Upstream")
	}
	upstreamURL, err := url.Parse(upstreamStr)
	if err != nil || upstreamURL == nil {
		if err == nil {
			err = errors.New("invalid url")
		}
		return nil, fmt.Errorf("invalid Upstream: %w", err)
	}
	switch upstreamURL.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("invalid Upstream scheme (expected http/https): %q", upstreamURL.Scheme)
	}
	if upstreamURL.Host == "" {
		return nil, errors.New("invalid Upstream: missing host")
	}
	if upstreamURL.Path != "" && upstreamURL.Path != "/" {
		return nil, errors.New("invalid Upstream: path must be empty (or /)")
	}
	if upstreamURL.RawQuery != "" || upstreamURL.Fragment != "" {
		return nil, errors.New("invalid Upstream: query/fragment not allowed")
	}
	host, portStr, err := net.SplitHostPort(upstreamURL.Host)
	if err != nil {
		return nil, errors.New("invalid Upstream: host must include an explicit port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid Upstream port: %q", portStr)
	}
	hostNorm := strings.ToLower(strings.TrimSpace(host))
	if hostNorm == "" {
		return nil, errors.New("invalid Upstream host")
	}
	allowedHosts := opts.AllowedUpstreamHosts
	if len(allowedHosts) == 0 {
		allowedHosts = []string{"127.0.0.1"}
	}
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, h := range allowedHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return nil, errors.New("invalid AllowedUpstreamHosts: empty entry")
		}
		allowed[h] = struct{}{}
	}
	if _, ok := allowed[hostNorm]; !ok {
		return nil, fmt.Errorf("upstream host %q is not allowed", hostNorm)
	}

	upstreamOrigin := strings.TrimSpace(opts.UpstreamOrigin)
	if upstreamOrigin == "" {
		return nil, errors.New("missing UpstreamOrigin")
	}
	originURL, err := url.Parse(upstreamOrigin)
	if err != nil || originURL == nil {
		if err == nil {
			err = errors.New("invalid url")
		}
		return nil, fmt.Errorf("invalid UpstreamOrigin: %w", err)
	}
	switch originURL.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("invalid UpstreamOrigin scheme (expected http/https): %q", originURL.Scheme)
	}
	if originURL.Host == "" {
		return nil, errors.New("invalid UpstreamOrigin: missing host")
	}
	if originURL.Path != "" && originURL.Path != "/" {
		return nil, errors.New("invalid UpstreamOrigin: path must be empty")
	}
	if originURL.RawQuery != "" || originURL.Fragment != "" {
		return nil, errors.New("invalid UpstreamOrigin: query/fragment not allowed")
	}
	// Normalize to scheme://host[:port].
	originURL.Path = ""
	upstreamOrigin = originURL.String()

	maxJSON := opts.MaxJSONFrameBytes
	if maxJSON < 0 {
		return nil, errors.New("invalid MaxJSONFrameBytes (must be >= 0)")
	}
	if maxJSON == 0 {
		maxJSON = jsonframe.DefaultMaxJSONFrameBytes
	}

	maxChunk := opts.MaxChunkBytes
	if maxChunk < 0 {
		return nil, errors.New("invalid MaxChunkBytes (must be >= 0)")
	}
	if maxChunk == 0 {
		maxChunk = DefaultMaxChunkBytes
	}

	maxBody := opts.MaxBodyBytes
	if maxBody < 0 {
		return nil, errors.New("invalid MaxBodyBytes (must be >= 0)")
	}
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}

	maxWSFrame := opts.MaxWSFrameBytes
	if maxWSFrame < 0 {
		return nil, errors.New("invalid MaxWSFrameBytes (must be >= 0)")
	}
	if maxWSFrame == 0 {
		maxWSFrame = DefaultMaxWSFrameBytes
	}

	defaultTimeout := DefaultDefaultTimeout
	if opts.DefaultTimeout != nil {
		if *opts.DefaultTimeout < 0 {
			return nil, errors.New("invalid DefaultTimeout (must be >= 0)")
		}
		defaultTimeout = *opts.DefaultTimeout
	}
	maxTimeout := DefaultMaxTimeout
	if opts.MaxTimeout != nil {
		if *opts.MaxTimeout < 0 {
			return nil, errors.New("invalid MaxTimeout (must be >= 0)")
		}
		maxTimeout = *opts.MaxTimeout
	}

	extraReq, err := normalizeHeaderNameSet(opts.ExtraRequestHeaders)
	if err != nil {
		return nil, fmt.Errorf("invalid ExtraRequestHeaders: %w", err)
	}
	extraResp, err := normalizeHeaderNameSet(opts.ExtraResponseHeaders)
	if err != nil {
		return nil, fmt.Errorf("invalid ExtraResponseHeaders: %w", err)
	}
	extraWS, err := normalizeHeaderNameSet(opts.ExtraWSHeaders)
	if err != nil {
		return nil, fmt.Errorf("invalid ExtraWSHeaders: %w", err)
	}

	forbiddenCookieNames := make(map[string]struct{}, len(opts.ForbiddenCookieNames))
	for _, n := range opts.ForbiddenCookieNames {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			return nil, errors.New("invalid ForbiddenCookieNames: empty entry")
		}
		forbiddenCookieNames[n] = struct{}{}
	}
	var forbiddenCookiePrefixes []string
	for _, p := range opts.ForbiddenCookieNamePrefixes {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			return nil, errors.New("invalid ForbiddenCookieNamePrefixes: empty entry")
		}
		forbiddenCookiePrefixes = append(forbiddenCookiePrefixes, p)
	}

	return &compiledOptions{
		upstream:       upstreamURL,
		upstreamHost:   net.JoinHostPort(hostNorm, strconv.Itoa(port)),
		upstreamOrigin: upstreamOrigin,

		maxJSONFrameBytes: maxJSON,
		maxChunkBytes:     maxChunk,
		maxBodyBytes:      maxBody,
		maxWSFrameBytes:   maxWSFrame,

		defaultTimeout: defaultTimeout,
		maxTimeout:     maxTimeout,

		extraReqHeaders:  extraReq,
		extraRespHeaders: extraResp,
		extraWSHeaders:   extraWS,

		forbiddenCookieNames:        forbiddenCookieNames,
		forbiddenCookieNamePrefixes: forbiddenCookiePrefixes,
	}, nil
}
