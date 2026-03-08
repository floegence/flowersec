package main

import (
	"errors"
	"io"
	"log"
	"net/http"
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
