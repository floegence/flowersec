package flowersec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/gorilla/websocket"
)

const (
	proxyHTTPStreamKind = "flowersec-proxy/http1"
	proxyWSStreamKind   = "flowersec-proxy/ws"
	proxyWireVersion    = 2
)

var ErrInvalidProxyServer = errors.New("invalid Flowersec proxy server")

// ProxyServerOptions configures Flowersec's server-side browser proxy
// application. The upstream is fixed by the application and can never be
// selected by an untrusted session peer.
type ProxyServerOptions struct {
	Credentials          *ProxyCredentialPolicy
	Upstream             string
	UpstreamOrigin       string
	AllowedUpstreamHosts []string
	// AllowedUpstreamAddresses fixes the numeric addresses or CIDRs for a named
	// upstream. Numeric upstreams are always pinned to their exact address.
	AllowedUpstreamAddresses    []string
	AllowedOrigins              []string
	MaxConcurrentStreams        int
	MaxConcurrentHTTPStreams    int
	MaxConcurrentEventStreams   int
	EventStreamIdleTimeout      time.Duration
	MaxMetadataBytes            int
	MaxChunkBytes               int
	MaxBodyBytes                int64
	MaxWebSocketFrameBytes      int
	DefaultHTTPRequestTimeout   time.Duration
	MaxHTTPRequestTimeout       time.Duration
	ExtraRequestHeaders         []string
	ExtraResponseHeaders        []string
	BlockedResponseHeaders      []string
	ExtraWebSocketHeaders       []string
	ForbiddenCookieNames        []string
	ForbiddenCookieNamePrefixes []string
	OnError                     func(error)
}

// ProxyServer owns the proxy application protocol and its upstream clients.
// Carrier, session, stream framing, and proxy wire values remain private.
type ProxyServer struct {
	config       proxyServerConfig
	permits      chan struct{}
	httpPermits  chan struct{}
	eventPermits chan struct{}
	httpClient   *http.Client
	wsDialer     *websocket.Dialer
	closeOnce    sync.Once
	stateMu      sync.Mutex
	closed       bool
	closeCtx     context.Context
	closeCancel  context.CancelFunc
	active       sync.WaitGroup
	cookieOwners map[string]*proxyCookieOwner
	cookieBytes  uint64
}

type proxyStream interface {
	io.ReadWriter
	Reset() error
}

type proxyServerConfig struct {
	credentials       *ProxyCredentialPolicy
	upstream          *url.URL
	network           *proxyNetworkPolicy
	upstreamOrigin    string
	allowedOrigins    map[string]struct{}
	maxMetadata       int
	maxChunk          int
	maxBody           int64
	maxWSFrame        int
	defaultTimeout    time.Duration
	maxTimeout        time.Duration
	eventIdleTimeout  time.Duration
	maxHTTP           int
	maxEvents         int
	requestHeaders    map[string]struct{}
	responseHeaders   map[string]struct{}
	blockedResponses  map[string]struct{}
	webSocketHeaders  map[string]struct{}
	forbiddenCookies  map[string]struct{}
	forbiddenPrefixes []string
	onError           func(error)
}

// NewProxyServer creates one bounded server-side proxy application.
func NewProxyServer(options ProxyServerOptions) (*ProxyServer, error) {
	config, concurrent, err := compileProxyServerOptions(options)
	if err != nil {
		return nil, err
	}
	credentials, err := compileProxyCredentials(options.Credentials)
	if err != nil {
		return nil, err
	}
	config.credentials = credentials
	transport := newProxyHTTPTransport(config)
	closeCtx, closeCancel := context.WithCancel(context.Background())
	return &ProxyServer{
		config:       config,
		cookieOwners: make(map[string]*proxyCookieOwner),
		permits:      make(chan struct{}, concurrent),
		httpPermits:  make(chan struct{}, config.maxHTTP),
		eventPermits: make(chan struct{}, config.maxEvents),
		closeCtx:     closeCtx,
		closeCancel:  closeCancel,
		httpClient: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		wsDialer: &websocket.Dialer{Proxy: nil, NetDialContext: config.network.dialContext, HandshakeTimeout: 10 * time.Second, EnableCompression: false},
	}, nil
}

// Close cancels active upstream operations, waits for their handlers to
// finish, and rejects any future dispatch through the registered handlers.
func (server *ProxyServer) Close() error {
	if server == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		server.stateMu.Lock()
		server.closed = true
		server.closeCancel()
		owners := make([]*proxyCookieOwner, 0, len(server.cookieOwners))
		for _, owner := range server.cookieOwners {
			owners = append(owners, owner)
		}
		server.stateMu.Unlock()
		for _, owner := range owners {
			_ = owner.clear()
		}
		for _, owner := range owners {
			<-owner.done
		}
		if transport, ok := server.httpClient.Transport.(*proxyHTTPTransport); ok {
			transport.Close()
		}
		server.active.Wait()
	})
	return nil
}

func (server *ProxyServer) runLimited(ctx context.Context, stream proxyStream, handler func(context.Context) error) error {
	server.stateMu.Lock()
	if server.closed {
		server.stateMu.Unlock()
		if stream != nil {
			_ = stream.Reset()
		}
		server.report(ErrInvalidProxyServer)
		return nil
	}
	server.active.Add(1)
	server.stateMu.Unlock()
	defer server.active.Done()

	select {
	case server.permits <- struct{}{}:
		defer func() { <-server.permits }()
		operationCtx, cancel := context.WithCancel(ctx)
		stopped := make(chan struct{})
		stop := context.AfterFunc(server.closeCtx, func() { defer close(stopped); cancel() })
		defer func() {
			if !stop() {
				<-stopped
			}
			cancel()
		}()
		return handler(operationCtx)
	default:
		if stream != nil {
			_ = stream.Reset()
		}
		server.report(ErrInvalidProxyServer)
		return nil
	}
}

func (server *ProxyServer) report(err error) {
	if err != nil && server != nil && server.config.onError != nil {
		server.config.onError(err)
	}
}

func compileProxyServerOptions(options ProxyServerOptions) (proxyServerConfig, int, error) {
	fail := func() (proxyServerConfig, int, error) { return proxyServerConfig{}, 0, ErrInvalidProxyServer }
	upstream, err := url.Parse(strings.TrimSpace(options.Upstream))
	if err != nil || upstream == nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" ||
		(upstream.Path != "" && upstream.Path != "/") || upstream.RawQuery != "" || upstream.Fragment != "" || upstream.User != nil {
		return fail()
	}
	host, portText, err := net.SplitHostPort(upstream.Host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 {
		return fail()
	}
	host = strings.ToLower(strings.TrimSpace(host))
	portText = strconv.Itoa(port)
	upstream.Host = net.JoinHostPort(host, portText)
	network, err := compileProxyNetworkPolicy(host, portText, options.AllowedUpstreamAddresses)
	if err != nil {
		return fail()
	}
	allowedHosts := options.AllowedUpstreamHosts
	if len(allowedHosts) == 0 {
		allowedHosts = []string{"127.0.0.1"}
	}
	allowed := false
	for _, candidate := range allowedHosts {
		if strings.ToLower(strings.TrimSpace(candidate)) == host && candidate != "" {
			allowed = true
		}
	}
	if !allowed {
		return fail()
	}
	origin, validOrigin := canonicalProxyOrigin(options.UpstreamOrigin)
	if !validOrigin {
		return fail()
	}
	allowedOriginValues := options.AllowedOrigins
	if len(allowedOriginValues) == 0 {
		allowedOriginValues = []string{origin}
	}
	allowedOrigins := make(map[string]struct{}, len(allowedOriginValues))
	for _, raw := range allowedOriginValues {
		allowed, valid := canonicalProxyOrigin(raw)
		if !valid {
			return fail()
		}
		allowedOrigins[allowed] = struct{}{}
	}
	maxConcurrent := positiveProxyLimit(options.MaxConcurrentStreams, defaults.ProxyMaxConcurrentStreams)
	maxHTTP := positiveProxyLimit(options.MaxConcurrentHTTPStreams, min(24, maxConcurrent))
	maxEvents := positiveProxyLimit(options.MaxConcurrentEventStreams, max(1, min(16, maxHTTP*2/3)))
	eventIdleTimeout := options.EventStreamIdleTimeout
	if eventIdleTimeout == 0 {
		eventIdleTimeout = 45 * time.Second
	}
	if maxHTTP < 1 || maxHTTP > maxConcurrent || maxEvents < 1 || maxEvents > maxHTTP || eventIdleTimeout < 0 {
		return fail()
	}
	maxMetadata := positiveProxyLimit(options.MaxMetadataBytes, protocolv4.ProxyMetadataLimit())
	maxChunk := positiveProxyLimit(options.MaxChunkBytes, defaults.ProxyMaxChunkBytes)
	maxWS := positiveProxyLimit(options.MaxWebSocketFrameBytes, defaults.ProxyMaxWSFrameBytes)
	maxBody := options.MaxBodyBytes
	if maxBody == 0 {
		maxBody = defaults.ProxyMaxBodyBytes
	}
	if maxConcurrent < 1 || maxMetadata < 1 || maxChunk < 1 || maxWS < 1 || maxBody < 1 || options.DefaultHTTPRequestTimeout < 0 || options.MaxHTTPRequestTimeout < 0 {
		return fail()
	}
	defaultTimeout := options.DefaultHTTPRequestTimeout
	if defaultTimeout == 0 {
		defaultTimeout = defaults.ProxyDefaultTimeout
	}
	maxTimeout := options.MaxHTTPRequestTimeout
	if maxTimeout == 0 {
		maxTimeout = defaults.ProxyMaxTimeout
	}
	if defaultTimeout > maxTimeout {
		return fail()
	}
	requestHeaders, err := normalizeProxyHeaderSet(options.ExtraRequestHeaders)
	if err != nil {
		return fail()
	}
	responseHeaders, err := normalizeProxyHeaderSet(options.ExtraResponseHeaders, true)
	if err != nil {
		return fail()
	}
	blockedResponses, err := normalizeProxyHeaderSet(options.BlockedResponseHeaders)
	if _, stripsCoding := blockedResponses["content-encoding"]; stripsCoding {
		return fail()
	}
	if err != nil {
		return fail()
	}
	webSocketHeaders, err := normalizeProxyHeaderSet(options.ExtraWebSocketHeaders)
	if err != nil {
		return fail()
	}
	forbiddenCookies := make(map[string]struct{}, len(options.ForbiddenCookieNames))
	for _, raw := range options.ForbiddenCookieNames {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			return fail()
		}
		forbiddenCookies[name] = struct{}{}
	}
	forbiddenPrefixes := make([]string, 0, len(options.ForbiddenCookieNamePrefixes))
	for _, raw := range options.ForbiddenCookieNamePrefixes {
		prefix := strings.ToLower(strings.TrimSpace(raw))
		if prefix == "" {
			return fail()
		}
		forbiddenPrefixes = append(forbiddenPrefixes, prefix)
	}
	return proxyServerConfig{
		upstream: upstream, network: network, upstreamOrigin: origin, allowedOrigins: allowedOrigins, maxMetadata: maxMetadata, maxChunk: maxChunk,
		maxHTTP: maxHTTP, maxEvents: maxEvents, eventIdleTimeout: eventIdleTimeout,
		maxBody: maxBody, maxWSFrame: maxWS, defaultTimeout: defaultTimeout, maxTimeout: maxTimeout,
		requestHeaders: requestHeaders, responseHeaders: responseHeaders, blockedResponses: blockedResponses,
		webSocketHeaders: webSocketHeaders, forbiddenCookies: forbiddenCookies, forbiddenPrefixes: forbiddenPrefixes,
		onError: options.OnError,
	}, maxConcurrent, nil
}

func canonicalProxyOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	canonical := parsed.Scheme + "://" + parsed.Host
	return canonical, raw == canonical
}

func positiveProxyLimit(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func validOrigin(value string) bool {
	if value == "" {
		return true
	}
	origin, err := url.Parse(value)
	return err == nil && (origin.Scheme == "https" || origin.Scheme == "http") && origin.Host != "" && origin.User == nil && origin.Hostname() != "" && origin.Path == "" && origin.RawPath == "" && origin.Opaque == "" && origin.RawQuery == "" && !origin.ForceQuery && origin.Fragment == "" && origin.RawFragment == ""
}
