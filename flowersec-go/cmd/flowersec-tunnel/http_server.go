package main

import (
	"net/http"
	"time"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 10 * time.Second
	httpWriteTimeout      = 10 * time.Second
	httpIdleTimeout       = 60 * time.Second
	httpMaxHeaderBytes    = 32 << 10
)

// newHTTPServer configures conservative HTTP timeouts for the pre-upgrade phase.
// WebSocket connections are hijacked by the upgrader, so these settings mainly
// protect the HTTP handshake and plain HTTP endpoints.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}
