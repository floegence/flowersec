package server

import (
	"sync"
	"time"
)

type TokenUseCache struct {
	mu   sync.Mutex
	used map[string]int64
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
