package endpoint

import "github.com/floegence/flowersec/flowersec-go/crypto/e2ee"

// HandshakeCache caches server-side handshake state to support init retries.
//
// This is an advanced option. Most servers can rely on the default internal cache.
type HandshakeCache = e2ee.ServerHandshakeCache

// NewHandshakeCache returns a cache with conservative defaults.
func NewHandshakeCache() *HandshakeCache { return e2ee.NewServerHandshakeCache() }
