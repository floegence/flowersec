package flowersec

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestProxyCookieClearReplacementFailureKeepsOldInvalidation(t *testing.T) {
	f := newPublicReferenceFixture(t)
	account, err := f.root.Account(ResourceAccountKey{Kind: EnvironmentAccount, ID: [16]byte{1}}, ResourceVector{SDKBytes: 1 << 28, Items: 1024})
	if err != nil {
		t.Fatal(err)
	}
	policy := &ProxyCredentialPolicy{Mode: ProxyCredentialsCookieSession, Clock: f.clock, Root: f.root, Owner: f.owner(), Accounts: []ResourceAccount{account}, MaxOwners: 1, CookieBytes: 8 << 20, RuntimeBytesPerOwner: 4096, RuntimeBytesPerRequest: 4096, Authorize: func(context.Context, any, ProxyCredentialScope) error { return nil }}
	server, err := NewProxyServer(ProxyServerOptions{Upstream: "http://127.0.0.1:8080", UpstreamOrigin: "http://127.0.0.1:8080", Credentials: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	scope := ProxyCredentialScope{Tenant: "tenant", Principal: "principal", PolicyRevision: "policy", SurfaceOwner: [16]byte{1}, ContentOrigin: "https://content.example", ScopeNotAfterMS: 5000, IdleMS: 1000, DelegatedFirstParty: true}
	session, err := server.NewCookieSession(context.Background(), nil, scope)
	if err != nil {
		t.Fatal(err)
	}
	old := session.owner
	// A retained original request forbids physical cleanup and keeps MaxOwners
	// occupied. Fresh replacement cannot borrow its old owner's capacity.
	old.mu.Lock()
	old.active++
	old.mu.Unlock()
	result, err := session.ClearUpstreamCredentials()
	if err == nil || result.ServerInvalidation != "confirmed" || result.CredentialContext != "" {
		t.Fatal("fresh replacement failure erased confirmed server invalidation", result, err)
	}
	if _, err = session.Attachment(); !errors.Is(err, ErrProxyCredentialScope) {
		t.Fatal("Clear failure reopened the old attachment", err)
	}
	old.mu.Lock()
	closed := old.closed
	old.active--
	old.cleanupLocked()
	old.mu.Unlock()
	if !closed {
		t.Fatal("Clear left the original context usable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = session.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestProxyCookieTransportCleanupWaitsForActualNativeBodyExit(t *testing.T) {
	config := proxyServerConfig{maxHTTP: 1}
	transport := &proxyHTTPTransport{slots: make([]proxyHTTPSlot, config.maxHTTP), native: &http.Transport{}, done: make(chan struct{})}
	transport.slots[0].busy = true
	exchange := &proxyHTTPExchange{transport: transport, slot: &transport.slots[0], returned: true, requestClosed: true, responseClosed: true, methods: 1}
	transport.Close()
	select {
	case <-transport.done:
		t.Fatal("logical Close refunded an active native method")
	default:
	}
	transport.mu.Lock()
	exchange.methods--
	exchange.releaseLocked()
	transport.mu.Unlock()
	select {
	case <-transport.done:
	default:
		t.Fatal("actual method exit failed to release transport tail")
	}
}
