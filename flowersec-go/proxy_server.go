package flowersec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/defaults"
	internaljsonframe "github.com/floegence/flowersec/flowersec-go/v5/internal/framing/jsonframe"
	"github.com/gorilla/websocket"
)

const (
	proxyHTTPStreamKind = "flowersec-proxy/http1"
	proxyWSStreamKind   = "flowersec-proxy/ws"
	proxyWireVersion    = 1
)

var ErrInvalidProxyServer = errors.New("invalid Flowersec proxy server")

// ProxyServerOptions configures Flowersec's server-side browser proxy
// application. The upstream is fixed by the application and can never be
// selected by an untrusted session peer.
type ProxyServerOptions struct {
	Upstream                    string
	UpstreamOrigin              string
	AllowedUpstreamHosts        []string
	AllowedOrigins              []string
	MaxConcurrentStreams        int
	MaxJSONFrameBytes           int
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
	config      proxyServerConfig
	permits     chan struct{}
	httpClient  *http.Client
	wsDialer    *websocket.Dialer
	closeOnce   sync.Once
	stateMu     sync.Mutex
	closed      bool
	closeCtx    context.Context
	closeCancel context.CancelFunc
	active      sync.WaitGroup
}

type proxyServerConfig struct {
	upstream          *url.URL
	upstreamOrigin    string
	allowedOrigins    map[string]struct{}
	maxJSONFrame      int
	maxChunk          int
	maxBody           int64
	maxWSFrame        int
	defaultTimeout    time.Duration
	maxTimeout        time.Duration
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
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 8,
	}
	closeCtx, closeCancel := context.WithCancel(context.Background())
	return &ProxyServer{
		config:      config,
		permits:     make(chan struct{}, concurrent),
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
		httpClient: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		wsDialer: &websocket.Dialer{Proxy: nil, HandshakeTimeout: 10 * time.Second, EnableCompression: false},
	}, nil
}

// RegisterStreamHandlers installs the HTTP and WebSocket proxy handlers on a
// carrier-neutral stream registry. A handler registry can contain at most one
// ProxyServer.
func (server *ProxyServer) RegisterStreamHandlers(handlers StreamHandlerRegistrar) error {
	return server.register(handlers)
}

func (server *ProxyServer) register(handlers StreamHandlerRegistrar) error {
	if server == nil || server.httpClient == nil || server.wsDialer == nil || handlers == nil {
		return ErrInvalidProxyServer
	}
	server.stateMu.Lock()
	defer server.stateMu.Unlock()
	if server.closed {
		return ErrInvalidProxyServer
	}
	err := handlers.registerStreams(map[string]StreamHandler{
		proxyHTTPStreamKind: server.limit(func(ctx context.Context, incoming IncomingStream) error {
			server.serveHTTP(ctx, incoming)
			return nil
		}),
		proxyWSStreamKind: server.limit(func(ctx context.Context, incoming IncomingStream) error {
			return server.serveWebSocket(ctx, incoming)
		}),
	})
	if err != nil {
		return fmt.Errorf("%w: handler registration rejected", ErrInvalidProxyServer)
	}
	return nil
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
		server.stateMu.Unlock()
		if transport, ok := server.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		server.active.Wait()
	})
	return nil
}

func (server *ProxyServer) limit(handler StreamHandler) StreamHandler {
	return func(ctx context.Context, incoming IncomingStream) error {
		server.stateMu.Lock()
		if server.closed {
			server.stateMu.Unlock()
			if incoming.Stream != nil {
				_ = incoming.Stream.Reset()
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
			stop := context.AfterFunc(server.closeCtx, cancel)
			defer func() {
				stop()
				cancel()
			}()
			return handler(operationCtx, incoming)
		default:
			if incoming.Stream != nil {
				_ = incoming.Stream.Reset()
			}
			server.report(ErrInvalidProxyServer)
			return nil
		}
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
	maxJSON := positiveProxyLimit(options.MaxJSONFrameBytes, internaljsonframe.DefaultMaxJSONFrameBytes)
	maxChunk := positiveProxyLimit(options.MaxChunkBytes, defaults.ProxyMaxChunkBytes)
	maxWS := positiveProxyLimit(options.MaxWebSocketFrameBytes, defaults.ProxyMaxWSFrameBytes)
	maxBody := options.MaxBodyBytes
	if maxBody == 0 {
		maxBody = defaults.ProxyMaxBodyBytes
	}
	if maxConcurrent < 1 || maxJSON < 1 || maxChunk < 1 || maxWS < 1 || maxBody < 1 || options.DefaultHTTPRequestTimeout < 0 || options.MaxHTTPRequestTimeout < 0 {
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
	requestHeaders, err := normalizeProxyHeaderSet(options.ExtraRequestHeaders)
	if err != nil {
		return fail()
	}
	responseHeaders, err := normalizeProxyHeaderSet(options.ExtraResponseHeaders)
	if err != nil {
		return fail()
	}
	blockedResponses, err := normalizeProxyHeaderSet(options.BlockedResponseHeaders)
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
		upstream: upstream, upstreamOrigin: origin, allowedOrigins: allowedOrigins, maxJSONFrame: maxJSON, maxChunk: maxChunk,
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
