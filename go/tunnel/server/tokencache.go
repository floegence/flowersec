package server

import (
	"sync"
	"time"
)

// TokenUseCache provides in-memory single-use enforcement for token_id values.
//
// # Security Model
//
// This cache is memory-based and will be cleared on tunnel server restart.
// However, token replay protection is primarily a defense-in-depth measure,
// NOT a critical security barrier. Here's why:
//
//   - Token ≠ E2EE secret: The token only authorizes tunnel attachment; it is
//     NOT used for E2EE key derivation. The actual encryption uses e2ee_psk,
//     which is never visible to the tunnel.
//
//   - Without e2ee_psk, an attacker cannot: complete the E2EE handshake
//     (auth_tag requires PSK), derive session keys, or decrypt any traffic.
//
//   - Primary risks of token replay (if cache is lost):
//     1. DoS: Replaying triggers replacement semantics, closing BOTH sides
//     2. Resource consumption: Attacker can occupy tunnel connections
//     3. Probing: Attacker can detect if a channel_id is active
//
//   - Token replay CANNOT cause: data theft, data tampering, or impersonation
//     (assuming TLS and E2EE are intact).
//
// # Deployment Considerations
//
//   - Single-instance assumption: This implementation assumes a single tunnel
//     server instance. For multi-instance deployments, use shared storage
//     (e.g., Redis) to maintain replay protection consistency.
//
//   - Short token expiry: Keep token exp short (e.g., 60s) to minimize the
//     replay window after restart.
type TokenUseCache struct {
	mu   sync.Mutex       // Guards the used map.
	used map[string]int64 // key: tokenID, value: expUnix
}

func NewTokenUseCache() *TokenUseCache {
	return &TokenUseCache{used: make(map[string]int64)}
}

func (c *TokenUseCache) TryUse(tokenID string, expUnix int64, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tokenID == "" {
		return false
	}
	if prev, ok := c.used[tokenID]; ok && prev >= now.Unix() {
		return false
	}
	c.used[tokenID] = expUnix
	return true
}

func (c *TokenUseCache) Cleanup(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	nowUnix := now.Unix()
	for k, exp := range c.used {
		if exp < nowUnix {
			delete(c.used, k)
		}
	}
}
