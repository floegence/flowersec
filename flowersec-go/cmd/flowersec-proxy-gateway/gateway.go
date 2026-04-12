package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	fsproxy "github.com/floegence/flowersec/flowersec-go/proxy"
	realtimews "github.com/floegence/flowersec/flowersec-go/realtime/ws"
	"github.com/gorilla/websocket"
)

type browserPolicy struct {
	allowedOrigins []string
	allowNoOrigin  bool
}

func (p browserPolicy) checkOrigin(r *http.Request) bool {
	return realtimews.IsOriginAllowed(r, p.allowedOrigins, p.allowNoOrigin)
}

func (p browserPolicy) allowHTTPRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Origin")) != "" {
		return p.checkOrigin(r)
	}
	if !httpRequestNeedsBrowserBoundary(r) {
		return true
	}
	switch browserFetchSite(r) {
	case "same-origin", "none":
		return true
	case "same-site", "cross-site":
		return false
	default:
		if sameOriginReferer(r) {
			return true
		}
		return p.allowNoOrigin
	}
}

func httpRequestNeedsBrowserBoundary(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !isSafeHTTPMethod(r.Method) {
		return true
	}
	return strings.TrimSpace(r.Header.Get("Cookie")) != ""
}

func isSafeHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func browserFetchSite(r *http.Request) string {
	if r == nil {
		return ""
	}
	switch v := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); v {
	case "same-origin", "same-site", "cross-site", "none":
		return v
	default:
		return ""
	}
}

func sameOriginReferer(r *http.Request) bool {
	if r == nil {
		return false
	}
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" {
		return false
	}
	refURL, err := url.Parse(ref)
	if err != nil || refURL == nil || refURL.Host == "" {
		return false
	}
	refHost, err := canonicalHostKey(refURL.Host)
	if err != nil {
		return false
	}
	reqHost, err := canonicalHostKey(r.Host)
	if err != nil {
		return false
	}
	return refHost == reqHost
}

type gateway struct {
	routes  map[string]streamOpener
	bridge  *fsproxy.Bridge
	browser browserPolicy
	logger  *log.Logger
}

func newGateway(routes map[string]streamOpener, bridge *fsproxy.Bridge, browser browserPolicy, logger *log.Logger) *gateway {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	if bridge == nil {
		bridge, _ = fsproxy.NewBridge(fsproxy.BridgeOptions{})
	}
	return &gateway{routes: routes, bridge: bridge, browser: browser, logger: logger}
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/_flowersec/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
		return
	}

	host, err := canonicalHostKey(r.Host)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	route := g.routes[host]
	if route == nil {
		http.NotFound(w, r)
		return
	}
	if websocket.IsWebSocketUpgrade(r) {
		g.serveWS(w, r, route)
		return
	}
	g.serveHTTP(w, r, route)
}

func (g *gateway) serveHTTP(w http.ResponseWriter, r *http.Request, route streamOpener) {
	if !g.browser.allowHTTPRequest(r) {
		http.Error(w, "request origin not allowed", http.StatusForbidden)
		return
	}
	if err := g.bridge.ProxyHTTP(w, r, route); err != nil {
		g.logProxyError(r, err)
	}
}

func (g *gateway) serveWS(w http.ResponseWriter, r *http.Request, route streamOpener) {
	upgrader := websocket.Upgrader{CheckOrigin: g.browser.checkOrigin}
	if err := g.bridge.ProxyWS(w, r, route, upgrader); err != nil {
		g.logProxyError(r, err)
	}
}

func (g *gateway) logProxyError(r *http.Request, err error) {
	if err == nil {
		return
	}
	var bridgeErr *fsproxy.BridgeError
	if errors.As(err, &bridgeErr) && bridgeErr.Status > 0 && bridgeErr.Status < 500 {
		return
	}
	g.logger.Printf("proxy gateway request failed method=%s host=%s path=%s err=%v", r.Method, strings.TrimSpace(r.Host), r.URL.RequestURI(), err)
}
