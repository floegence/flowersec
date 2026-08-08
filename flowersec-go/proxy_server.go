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

	"github.com/floegence/flowersec/flowersec-go/v2/internal/defaults"
	internaljsonframe "github.com/floegence/flowersec/flowersec-go/v2/internal/framing/jsonframe"
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
	config     proxyServerConfig
	permits    chan struct{}
	httpClient *http.Client
	wsDialer   *websocket.Dialer
	closeOnce  sync.Once
}

type proxyServerConfig struct {
	upstream          *url.URL
	upstreamOrigin    string
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
	return &ProxyServer{
		config:  config,
		permits: make(chan struct{}, concurrent),
		httpClient: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		wsDialer: &websocket.Dialer{Proxy: nil, HandshakeTimeout: 10 * time.Second, EnableCompression: false},
	}, nil
}

// Register installs the HTTP and WebSocket proxy handlers atomically. A
// handler registry can contain at most one ProxyServer.
func (server *ProxyServer) Register(handlers *SessionHandlers) error {
	if server == nil || server.httpClient == nil || server.wsDialer == nil || handlers == nil {
		return ErrInvalidProxyServer
	}
	err := handlers.handleStreams(map[string]StreamHandler{
		proxyHTTPStreamKind: server.limit(server.serveHTTP),
		proxyWSStreamKind:   server.limit(server.serveWebSocket),
	})
	if err != nil {
		return fmt.Errorf("%w: handler registration rejected", ErrInvalidProxyServer)
	}
	return nil
}

// Close releases idle upstream connections. Active session streams continue
// to follow their contexts and are not detached from SessionHandlers.
func (server *ProxyServer) Close() error {
	if server == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		if transport, ok := server.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	})
	return nil
}

func (server *ProxyServer) limit(handler StreamHandler) StreamHandler {
	return func(ctx context.Context, incoming IncomingStream) {
		select {
		case server.permits <- struct{}{}:
			defer func() { <-server.permits }()
			handler(ctx, incoming)
		default:
			if incoming.Stream != nil {
				_ = incoming.Stream.Reset()
			}
			server.report(ErrInvalidProxyServer)
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
	origin, err := url.Parse(strings.TrimSpace(options.UpstreamOrigin))
	if err != nil || origin == nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" ||
		(origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil {
		return fail()
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
		upstream: upstream, upstreamOrigin: origin.String(), maxJSONFrame: maxJSON, maxChunk: maxChunk,
		maxBody: maxBody, maxWSFrame: maxWS, defaultTimeout: defaultTimeout, maxTimeout: maxTimeout,
		requestHeaders: requestHeaders, responseHeaders: responseHeaders, blockedResponses: blockedResponses,
		webSocketHeaders: webSocketHeaders, forbiddenCookies: forbiddenCookies, forbiddenPrefixes: forbiddenPrefixes,
		onError: options.OnError,
	}, maxConcurrent, nil
}

func positiveProxyLimit(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}
