package endpoint

import "net/http"

// UpgraderOptions exposes a small set of WebSocket upgrader controls.
//
// It mirrors the subset used by Flowersec and keeps the endpoint API self-contained
// (so users do not need to import lower-level websocket helpers).
type UpgraderOptions struct {
	ReadBufferSize  int                        // Read buffer size for upgrader.
	WriteBufferSize int                        // Write buffer size for upgrader.
	CheckOrigin     func(r *http.Request) bool // Optional origin check.
}
