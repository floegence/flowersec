package flowersec

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
	"golang.org/x/net/publicsuffix"
)

type ProxyCredentialMode string

const (
	ProxyCredentialsNone          ProxyCredentialMode = "none"
	ProxyCredentialsExternal      ProxyCredentialMode = "external"
	ProxyCredentialsCookieSession ProxyCredentialMode = "upstream_cookie_session"
)

var (
	ErrProxyCredentialScope  = errors.New("proxy credential scope unavailable")
	ErrProxyCredentialUpdate = errors.New("credential_update_failed")
)

// ProxyCredentialPolicy is trusted host configuration. Its accounts belong to
// the original complete ProxyServer budget; CookieBytes is a usage sublimit,
// never another allowance. Managed cookies require explicit delegated
// first-party authorization and are never created by a content request.
type ProxyCredentialPolicy struct {
	Mode                   ProxyCredentialMode
	Clock                  *Clock
	Root                   *ResourceRoot
	Owner                  ResourceOwnerKey
	Accounts               []ResourceAccount
	MaxOwners              uint32
	CookieBytes            uint64
	RuntimeBytesPerOwner   uint64
	RuntimeBytesPerRequest uint64
	// ResolveScope uses the original authenticated Stream and trusted registration.
	// Request-provided origins and owner IDs never establish scope authority.
	ResolveScope   func(context.Context, any, [16]byte) (ProxyCredentialScope, error)
	AllowWebSocket bool
	// Authorize checks the actual authenticated Stream binding against the
	// originally registered tenant, principal, policy and Surface owner.
	Authorize func(context.Context, any, ProxyCredentialScope) error
	// External returns only credentials from an explicitly authorized source.
	// Content-provided Cookie/Authorization are not a substitute for it.
	External func(context.Context, any, *url.URL) (http.Header, error)
}

type ProxyCredentialScope struct {
	Tenant, Principal, PolicyRevision string
	SurfaceOwner                      [16]byte
	ContentOrigin                     string
	ScopeNotAfterMS                   uint64
	IdleMS                            uint64
	DelegatedFirstParty               bool
}

// ProxyCookieSession owns one volatile credential incarnation. Attachment is
// given only to the trusted narrow proxy dispatcher, never to content code.
// Clear closes the old association permanently; a fresh trusted attachment
// requires a new registration, with the original scope deadline unchanged.
type ProxyCookieSession struct {
	mu     sync.Mutex
	owner  *proxyCookieOwner
	closed bool
}

// ProxyCredentialClearResult reports only this server's invalidation facts.
// Host and Service Worker delivery fences are confirmed by their own owners.
type ProxyCredentialClearResult struct {
	ServerInvalidation string
	CredentialContext  string
	Cleanup            CleanupStatus
}

func (*ProxyCookieSession) String() string               { return "Flowersec.ProxyCookieSession" }
func (*ProxyCookieSession) GoString() string             { return "flowersec.ProxyCookieSession" }
func (*ProxyCookieSession) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
func (s *ProxyCookieSession) Attachment() (string, error) {
	if s == nil {
		return "", ErrProxyCredentialScope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner == nil || s.closed {
		return "", ErrProxyCredentialScope
	}
	o := s.owner
	sample, err := o.server.config.credentials.Clock.Sample()
	if err != nil {
		_ = o.clear()
		return "", err
	}
	o.mu.Lock()
	err = o.checkLockedAt(sample)
	private := o.binding
	o.mu.Unlock()
	if err != nil {
		_ = o.clear()
		return "", err
	}
	return private, nil
}
func (s *ProxyCookieSession) ClearUpstreamCredentials() (ProxyCredentialClearResult, error) {
	result := ProxyCredentialClearResult{ServerInvalidation: "not_attempted"}
	if s == nil {
		return result, ErrProxyCredentialScope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.owner
	if s.closed {
		return result, ErrProxyCredentialScope
	}
	if previous == nil {
		return result, ErrProxyCredentialScope
	}
	sample, err := previous.server.config.credentials.Clock.Sample()
	if err != nil {
		return result, err
	}
	previous.mu.Lock()
	err = previous.checkLockedAt(sample)
	if err == nil && previous.clearClaimed {
		err = ErrProxyCredentialScope
	}
	if err == nil {
		previous.clearClaimed = true
	}
	if err != nil {
		previous.mu.Unlock()
		return result, err
	}
	// The old association is permanently invalid before replacement admission.
	// A capacity/provider failure cannot undo this independently confirmed fact.
	previous.closed = true
	previous.transportClosing = true
	if previous.incarnation < math.MaxUint64 {
		previous.incarnation++
	}
	previous.cancel()
	client := previous.client
	scope := previous.scope
	previous.mu.Unlock()
	client.Transport.(*proxyHTTPTransport).Close()
	previous.mu.Lock()
	previous.transportClosing = false
	previous.cleanupLocked()
	previous.mu.Unlock()
	result.ServerInvalidation = "confirmed"
	result.Cleanup = previous.cleanupStatus()
	s.closed = true
	next, err := previous.server.newCookieSession(scope)
	if err != nil {
		return result, err
	}
	s.owner = next.owner
	s.closed = false
	result.CredentialContext = next.owner.binding
	return result, nil
}
func (s *ProxyCookieSession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	o := s.owner
	s.mu.Unlock()
	if o == nil {
		return nil
	}
	return o.clear()
}
func (s *ProxyCookieSession) CleanupStatus() CleanupStatus {
	if s == nil {
		return CleanupStatus{}
	}
	s.mu.Lock()
	o := s.owner
	s.mu.Unlock()
	if o == nil {
		return CleanupStatus{}
	}
	return o.cleanupStatus()
}
func (s *ProxyCookieSession) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrProxyCredentialScope
	}
	s.mu.Lock()
	o := s.owner
	s.mu.Unlock()
	if o == nil {
		return ErrProxyCredentialScope
	}
	select {
	case <-o.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type proxyCookie struct {
	cookie       http.Cookie
	domain, path string
	hostOnly     bool
	deadline     *timev4.Deadline
	serial       uint64
	notAfterMS   uint64
}
type proxyCookieOwner struct {
	mu                                                               sync.Mutex
	server                                                           *ProxyServer
	scope                                                            ProxyCredentialScope
	binding                                                          string
	incarnation                                                      uint64
	reservation, state                                               resourcev4.Reference
	stateBytes, baseBytes                                            uint64
	cookies                                                          []proxyCookie
	serial                                                           uint64
	deadline                                                         *timev4.Deadline
	idle                                                             *timev4.Idle
	ctx                                                              context.Context
	cancel                                                           context.CancelFunc
	client                                                           *http.Client
	active                                                           uint32
	closed, cleaned, lifetimeRunning, transportClosing, clearClaimed bool
	done                                                             chan struct{}
	invalidCookies                                                   [8]uint64
}

func (server *ProxyServer) NewCookieSession(ctx context.Context, binding any, scope ProxyCredentialScope) (*ProxyCookieSession, error) {
	if server == nil || ctx == nil {
		return nil, ErrProxyCredentialScope
	}
	p := server.config.credentials
	if p == nil || p.Mode != ProxyCredentialsCookieSession {
		return nil, ErrProxyCredentialScope
	}
	if err := p.Authorize(ctx, binding, scope); err != nil {
		return nil, err
	}
	return server.newCookieSession(scope)
}

func (server *ProxyServer) reserveCookieBytes(bytes, items uint64) (resourcev4.Reference, error) {
	p := server.config.credentials
	var identity [32]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return resourcev4.Reference{}, err
	}
	key := p.Owner
	copy(key.Instance[:], identity[:16])
	copy(key.Backing[:], identity[16:])
	server.stateMu.Lock()
	defer server.stateMu.Unlock()
	if server.closed || server.cookieBytes > p.CookieBytes || bytes > p.CookieBytes-server.cookieBytes {
		return resourcev4.Reference{}, ErrProxyCredentialUpdate
	}
	ref, err := p.Root.Reserve(key, resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: items}, p.Accounts...)
	if err != nil {
		return resourcev4.Reference{}, ErrProxyCredentialUpdate
	}
	server.cookieBytes += bytes
	return ref, nil
}
func (server *ProxyServer) releaseCookieBytes(ref resourcev4.Reference, bytes uint64) {
	ref.Release()
	server.stateMu.Lock()
	server.cookieBytes -= bytes
	server.stateMu.Unlock()
}
func (server *ProxyServer) newCookieSession(scope ProxyCredentialScope) (*ProxyCookieSession, error) {
	p := server.config.credentials
	if !scope.DelegatedFirstParty || scope.Tenant == "" || len(scope.Tenant) > 128 || scope.Principal == "" || len(scope.Principal) > 128 || scope.PolicyRevision == "" || len(scope.PolicyRevision) > 128 || scope.SurfaceOwner == ([16]byte{}) || !validOrigin(scope.ContentOrigin) || scope.ContentOrigin == "" || scope.IdleMS == 0 {
		return nil, ErrProxyCredentialScope
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, err
	}
	cost := uint64(unsafe.Sizeof(proxyCookieOwner{})) + uint64(unsafe.Sizeof(ProxyCookieSession{})) + p.RuntimeBytesPerOwner + uint64(server.config.maxHTTP)*uint64(unsafe.Sizeof(proxyHTTPSlot{})) + uint64(43+len(scope.Tenant)+len(scope.Principal)+len(scope.PolicyRevision)+len(scope.ContentOrigin))
	ref, err := server.reserveCookieBytes(cost, 1)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			server.releaseCookieBytes(ref, cost)
		}
	}()
	deadline, err := timev4.NewDeadline(p.Clock, scope.ScopeNotAfterMS)
	if err != nil {
		return nil, err
	}
	idle, err := timev4.NewIdle(p.Clock, scope.IdleMS, 0)
	if err != nil {
		return nil, err
	}
	if err = idle.Start(); err != nil {
		return nil, err
	}
	private := base64.RawURLEncoding.EncodeToString(secret[:])
	scope.Tenant = strings.Clone(scope.Tenant)
	scope.Principal = strings.Clone(scope.Principal)
	scope.PolicyRevision = strings.Clone(scope.PolicyRevision)
	scope.ContentOrigin = strings.Clone(scope.ContentOrigin)
	ownerCtx, cancel := context.WithCancel(server.closeCtx)
	o := &proxyCookieOwner{server: server, scope: scope, binding: private, incarnation: 1, reservation: ref, baseBytes: cost, deadline: deadline, idle: idle, ctx: ownerCtx, cancel: cancel, done: make(chan struct{}), lifetimeRunning: true}
	o.client = &http.Client{Transport: newProxyHTTPTransport(server.config), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	server.stateMu.Lock()
	if server.closed || uint32(len(server.cookieOwners)) >= p.MaxOwners {
		server.stateMu.Unlock()
		cancel()
		o.client.Transport.(*proxyHTTPTransport).Close()
		return nil, ErrProxyCredentialScope
	}
	server.cookieOwners[private] = o
	server.stateMu.Unlock()
	owned = true
	go o.runLifetime()
	return &ProxyCookieSession{owner: o}, nil
}
func (o *proxyCookieOwner) checkLockedAt(sample timev4.Sample) error {
	if o.closed {
		return ErrProxyCredentialScope
	}
	if err := o.reservation.Check(); err != nil {
		return err
	}
	if err := o.deadline.CheckUsingSample(sample); err != nil {
		return err
	}
	return o.idle.CheckAt(sample)
}
func (o *proxyCookieOwner) runLifetime() {
	defer func() {
		o.mu.Lock()
		transport := o.client.Transport.(*proxyHTTPTransport)
		o.mu.Unlock()
		// Transport.Close is a cancellation request. Its original busy/body slots
		// pin this owner until all native methods have actually relinquished them.
		<-transport.done
		o.mu.Lock()
		o.lifetimeRunning = false
		o.cleanupLocked()
		o.mu.Unlock()
	}()
	for {
		sample, err := o.server.config.credentials.Clock.Sample()
		o.mu.Lock()
		if err == nil {
			err = o.checkLockedAt(sample)
		}
		remaining := uint64(0)
		if err == nil {
			remaining, err = o.deadline.RemainingMSAt(sample)
			idle, _, idleErr := o.idle.RemainingMSAt(sample)
			if err == nil {
				err = idleErr
				remaining = min(remaining, idle)
			}
		}
		closed := o.closed
		o.mu.Unlock()
		if err != nil || closed {
			_ = o.clear()
			return
		}
		// Host timers are wakeup hints. Every wake checks the original Clock; the
		// chunk bounds conversion without extending either authorization deadline.
		timer := time.NewTimer(time.Duration(min(remaining, uint64(60000))) * time.Millisecond)
		select {
		case <-o.ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}
func (o *proxyCookieOwner) clear() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	o.transportClosing = true
	if o.incarnation < math.MaxUint64 {
		o.incarnation++
	}
	o.cancel()
	client := o.client
	o.mu.Unlock()
	client.Transport.(*proxyHTTPTransport).Close()
	o.mu.Lock()
	o.transportClosing = false
	o.cleanupLocked()
	o.mu.Unlock()
	return nil
}
func (o *proxyCookieOwner) cleanupStatus() CleanupStatus {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cleaned {
		return CleanupStatus{Complete: true, Status: protocolv4.V4CleanupStateComplete, CoreCleanup: protocolv4.V4CoreCleanupComplete}
	}
	pending := uint64(o.active)
	if o.lifetimeRunning {
		pending++
	}
	if o.transportClosing {
		pending++
	}
	return CleanupStatus{PendingCallbacks: pending, Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
}
func (o *proxyCookieOwner) cleanupLocked() {
	if !o.closed || o.cleaned || o.active != 0 || o.lifetimeRunning || o.transportClosing {
		return
	}
	o.cleaned = true
	o.server.stateMu.Lock()
	delete(o.server.cookieOwners, o.binding)
	o.server.stateMu.Unlock()
	o.cookies = nil
	o.client = nil
	o.binding = ""
	o.server.releaseCookieBytes(o.state, o.stateBytes)
	o.server.releaseCookieBytes(o.reservation, o.baseBytes)
	o.state, o.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	close(o.done)
}

type proxyCredentialRequest struct {
	owner        *proxyCookieOwner
	incarnation  uint64
	ctx          context.Context
	cancel       context.CancelFunc
	stop         func() bool
	stopDone     chan struct{}
	once         sync.Once
	headerBytes  uint64
	validUntil   *timev4.Deadline
	headerRef    resourcev4.Reference
	cookieHeader string
	allow        bool
}

func (server *ProxyServer) captureCredentials(ctx context.Context, stream proxyStream, target *url.URL, private, selection, requestOrigin string, raw []proxyHeader, headers http.Header) (*proxyCredentialRequest, error) {
	p := server.config.credentials
	if p == nil || p.Mode == ProxyCredentialsNone {
		headers.Del("Cookie")
		headers.Del("Authorization")
		if private != "" {
			return nil, ErrProxyCredentialScope
		}
		return nil, nil
	}
	original, ok := stream.(interface{ credentialApplicationBinding() any })
	if !ok {
		return nil, ErrProxyCredentialScope
	}
	binding := original.credentialApplicationBinding()
	if p.Mode == ProxyCredentialsExternal {
		headers.Del("Cookie")
		headers.Del("Authorization")
		if private != "" {
			return nil, ErrProxyCredentialScope
		}
		if selection == "omit" {
			return nil, nil
		}
		external, err := p.External(ctx, binding, target)
		if err != nil {
			return nil, err
		}
		for _, name := range []string{"Cookie", "Authorization"} {
			for _, value := range external.Values(name) {
				if !protocolCredentialOctets(value) {
					return nil, ErrProxyCredentialScope
				}
				headers.Add(name, value)
			}
		}
		return nil, nil
	}
	if selection != "omit" && selection != "same-origin" && selection != "include" || !validOrigin(requestOrigin) || requestOrigin == "" {
		return nil, ErrProxyCredentialScope
	}
	if len(private) != 43 {
		return nil, ErrProxyCredentialScope
	}
	for _, h := range raw {
		if strings.EqualFold(h.Name, "cookie") || strings.EqualFold(h.Name, "authorization") {
			return nil, ErrProxyCredentialScope
		}
	}
	server.stateMu.Lock()
	o := server.cookieOwners[private]
	server.stateMu.Unlock()
	if o == nil {
		return nil, ErrProxyCredentialScope
	}
	if err := p.Authorize(ctx, binding, o.scope); err != nil {
		return nil, err
	}
	if target.Host != server.config.upstream.Host {
		return nil, ErrProxyCredentialScope
	}
	websocket := target.Scheme == "ws" || target.Scheme == "wss"
	if websocket && !p.AllowWebSocket {
		return nil, ErrProxyCredentialScope
	}
	expected := server.config.upstream.Scheme
	if websocket {
		if expected == "https" {
			expected = "wss"
		} else {
			expected = "ws"
		}
	}
	if target.Scheme != expected {
		return nil, ErrProxyCredentialScope
	}
	sample, err := p.Clock.Sample()
	if err != nil {
		_ = o.clear()
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err = o.checkLockedAt(sample); err != nil {
		return nil, err
	}
	if o.active == math.MaxUint32 {
		return nil, ErrProxyCredentialScope
	}
	allow := selection == "include" || selection == "same-origin" && requestOrigin == o.scope.ContentOrigin
	selectedCount, headerLength := 0, 0
	until := o.scope.ScopeNotAfterMS
	if allow {
		for _, entry := range o.cookies {
			if entry.deadline.CheckUsingSample(sample) != nil || entry.cookie.Secure && server.config.upstream.Scheme != "https" || !proxyCookiePathMatches(target.EscapedPath(), entry.path) {
				continue
			}
			selectedCount++
			headerLength += len(entry.cookie.Name) + 1 + len(entry.cookie.Value)
			until = min(until, entry.notAfterMS)
		}
	}
	if selectedCount > 0 {
		headerLength += 2 * (selectedCount - 1)
	}
	// Reserve before allocating even the omit request, callback/context, sort
	// workspace and both header backings. The snapshot has no borrowed jar bytes.
	charge := uint64(unsafe.Sizeof(proxyCredentialRequest{})) + p.RuntimeBytesPerRequest + uint64(selectedCount)*uint64(unsafe.Sizeof(proxyCookie{})) + 2*uint64(headerLength) + uint64(unsafe.Sizeof(timev4.Deadline{}))
	ref, err := server.reserveCookieBytes(charge, 1)
	if err != nil {
		return nil, err
	}
	requestCtx, cancel := context.WithCancel(ctx)
	r := &proxyCredentialRequest{owner: o, incarnation: o.incarnation, ctx: requestCtx, cancel: cancel, allow: allow, headerRef: ref, headerBytes: charge, stopDone: make(chan struct{})}
	failed := true
	defer func() {
		if failed {
			cancel()
			server.releaseCookieBytes(ref, charge)
		}
	}()
	r.validUntil, err = timev4.NewDeadlineAt(p.Clock, sample, until)
	if err != nil {
		return nil, err
	}
	if allow {
		selected := make([]proxyCookie, 0, selectedCount)
		for _, entry := range o.cookies {
			if entry.deadline.CheckUsingSample(sample) != nil || entry.cookie.Secure && server.config.upstream.Scheme != "https" || !proxyCookiePathMatches(target.EscapedPath(), entry.path) {
				continue
			}
			selected = append(selected, entry)
		}
		sort.SliceStable(selected, func(i, j int) bool {
			if len(selected[i].path) != len(selected[j].path) {
				return len(selected[i].path) > len(selected[j].path)
			}
			return selected[i].serial < selected[j].serial
		})
		var header strings.Builder
		header.Grow(headerLength)
		for i, e := range selected {
			if i > 0 {
				header.WriteString("; ")
			}
			header.WriteString(e.cookie.Name)
			header.WriteByte('=')
			header.WriteString(e.cookie.Value)
		}
		r.cookieHeader = strings.Clone(header.String())
		if r.cookieHeader != "" {
			headers.Set("Cookie", r.cookieHeader)
		}
	}
	if err = o.idle.RefreshAt(sample); err != nil {
		return nil, err
	}
	o.active++
	r.stop = context.AfterFunc(o.ctx, func() { defer close(r.stopDone); cancel() })
	failed = false
	return r, nil
}
func protocolCredentialOctets(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 32 && b != '\t' || b == 127 {
			return false
		}
	}
	return true
}
func proxyCookiePathMatches(path, cookiePath string) bool {
	if path == "" {
		path = "/"
	}
	return path == cookiePath || strings.HasPrefix(path, cookiePath) && (strings.HasSuffix(cookiePath, "/") || len(path) > len(cookiePath) && path[len(cookiePath)] == '/')
}
func (r *proxyCredentialRequest) check() error {
	if r == nil {
		return nil
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	o := r.owner
	sample, err := o.server.config.credentials.Clock.Sample()
	if err != nil {
		_ = o.clear()
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if r.incarnation != o.incarnation {
		return ErrProxyCredentialScope
	}
	if err = o.checkLockedAt(sample); err != nil {
		return err
	}
	return r.validUntil.CheckUsingSample(sample)
}
func (r *proxyCredentialRequest) finish() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		if r.stop != nil && !r.stop() {
			<-r.stopDone
		}
		r.cancel()
		r.cookieHeader = ""
		r.owner.server.releaseCookieBytes(r.headerRef, r.headerBytes)
		o := r.owner
		o.mu.Lock()
		o.active--
		o.cleanupLocked()
		o.mu.Unlock()
	})
}

func proxyCookieStateBytes(entries []proxyCookie) uint64 {
	bytes := uint64(len(entries)) * uint64(unsafe.Sizeof(proxyCookie{}))
	for _, entry := range entries {
		bytes += uint64(len(entry.cookie.Name)+len(entry.cookie.Value)+len(entry.domain)+len(entry.path)) + uint64(unsafe.Sizeof(timev4.Deadline{}))
	}
	return bytes
}
func (o *proxyCookieOwner) rejectCookie(reason int) {
	if o.invalidCookies[reason] < math.MaxUint64 {
		o.invalidCookies[reason]++
	}
}
func (r *proxyCredentialRequest) update(target *url.URL, headers http.Header) error {
	if r == nil {
		return nil
	}
	// Preserve and validate the complete original header facts before any
	// stripping or credential update. Connection-named fields are hop-by-hop.
	facts, err := inspectProxyHeaders(proxyNativeHeaders(headers))
	if err != nil {
		return err
	}
	lines := headers.Values("Set-Cookie")
	if _, hop := facts.connection["set-cookie"]; hop {
		lines = nil
	}
	headers.Del("Set-Cookie")
	if !r.allow || len(lines) == 0 {
		return nil
	}
	o := r.owner
	p := o.server.config.credentials
	sample, err := p.Clock.Sample()
	if err != nil {
		return err
	}
	// Response fields already belong to the finite HTTP parser. Reserve a full
	// bounded candidate and maintained-parser work before creating new backing.
	rawBytes := uint64(0)
	for _, line := range lines {
		if len(line) <= 4096 {
			rawBytes += uint64(len(line))
		}
	}
	if rawBytes > uint64(o.server.config.maxMetadata) {
		return ErrProxyCredentialUpdate
	}
	workBytes := uint64(512<<10) + 4*rawBytes + uint64(64)*uint64(unsafe.Sizeof(proxyCookie{})) + uint64(64)*uint64(unsafe.Sizeof(timev4.Deadline{}))
	work, err := o.server.reserveCookieBytes(workBytes, 65)
	if err != nil {
		return ErrProxyCredentialUpdate
	}
	defer o.server.releaseCookieBytes(work, workBytes)
	o.mu.Lock()
	defer o.mu.Unlock()
	if r.incarnation != o.incarnation {
		return ErrProxyCredentialScope
	}
	if err = o.checkLockedAt(sample); err != nil {
		return err
	}
	candidate := make([]proxyCookie, 0, 64)
	for _, entry := range o.cookies {
		if entry.deadline.CheckUsingSample(sample) == nil {
			candidate = append(candidate, entry)
		}
	}
	serial := o.serial
	for _, line := range lines {
		if len(line) > 4096 {
			o.rejectCookie(0)
			continue
		}
		cookie, e := http.ParseSetCookie(line)
		if e != nil {
			o.rejectCookie(1)
			continue
		}
		if cookie.Partitioned {
			o.rejectCookie(2)
			continue
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure || cookie.Secure && o.server.config.upstream.Scheme != "https" {
			o.rejectCookie(3)
			continue
		}
		host := strings.ToLower(o.server.config.upstream.Hostname())
		domain := strings.ToLower(strings.TrimPrefix(cookie.Domain, "."))
		hostOnly := domain == ""
		if hostOnly {
			domain = host
		} else {
			if net.ParseIP(host) != nil {
				if domain != host {
					o.rejectCookie(4)
					continue
				}
				hostOnly = true
			} else {
				suffix, _ := publicsuffix.PublicSuffix(domain)
				if domain == suffix || host != domain && !strings.HasSuffix(host, "."+domain) {
					o.rejectCookie(4)
					continue
				}
			}
		}
		if strings.HasPrefix(cookie.Name, "__Secure-") && !cookie.Secure || strings.HasPrefix(cookie.Name, "__Host-") && (!cookie.Secure || !hostOnly || cookie.Path != "/") {
			o.rejectCookie(5)
			continue
		}
		path := cookie.Path
		if path == "" || path[0] != '/' {
			path = target.EscapedPath()
			at := strings.LastIndex(path, "/")
			if at <= 0 {
				path = "/"
			} else {
				path = path[:at]
			}
		}
		until := o.scope.ScopeNotAfterMS
		if cookie.MaxAge > 0 {
			age := uint64(cookie.MaxAge)
			if age > math.MaxUint64/1000 || sample.LowerMS > math.MaxUint64-age*1000 {
				return ErrProxyCredentialUpdate
			}
			until = min(until, sample.LowerMS+age*1000)
		} else if !cookie.Expires.IsZero() {
			if cookie.Expires.UnixMilli() <= 0 {
				until = 0
			} else {
				until = min(until, uint64(cookie.Expires.UnixMilli()))
			}
		}
		index := -1
		for i, entry := range candidate {
			if entry.cookie.Name == cookie.Name && entry.domain == domain && entry.path == path {
				index = i
				break
			}
		}
		if cookie.MaxAge < 0 || until <= sample.UpperMS {
			if index >= 0 {
				candidate = append(candidate[:index], candidate[index+1:]...)
			}
			continue
		}
		deadline, e := timev4.NewDeadlineAt(p.Clock, sample, until)
		if e != nil {
			return ErrProxyCredentialUpdate
		}
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 {
			cookie.SameSite = http.SameSiteLaxMode
		}
		// Preserve only the fields the frozen profile uses. Parser diagnostics and
		// raw Set-Cookie aliases never become persistent credential state.
		cookie.Raw = ""
		cookie.RawExpires = ""
		cookie.Domain = ""
		cookie.Path = ""
		cookie.Unparsed = nil
		entry := proxyCookie{cookie: *cookie, domain: domain, path: path, hostOnly: hostOnly, deadline: deadline, notAfterMS: until}
		if index < 0 {
			if len(candidate) == 64 {
				return ErrProxyCredentialUpdate
			}
			if serial == math.MaxUint64 {
				return ErrProxyCredentialUpdate
			}
			serial++
			entry.serial = serial
			candidate = append(candidate, entry)
		} else {
			entry.serial = candidate[index].serial
			candidate[index] = entry
		}
	}
	stateBytes := proxyCookieStateBytes(candidate)
	if stateBytes > 512<<10 {
		return ErrProxyCredentialUpdate
	}
	// Old state, parsing work and the complete final allocation coexist and are
	// charged until each backing loses its last actual reference.
	state, err := o.server.reserveCookieBytes(stateBytes, uint64(len(candidate))+1)
	if err != nil {
		return ErrProxyCredentialUpdate
	}
	installed := make([]proxyCookie, len(candidate))
	for i, entry := range candidate {
		entry.cookie.Name = strings.Clone(entry.cookie.Name)
		entry.cookie.Value = strings.Clone(entry.cookie.Value)
		entry.domain = strings.Clone(entry.domain)
		entry.path = strings.Clone(entry.path)
		installed[i] = entry
	}
	current, err := p.Clock.RefreshSample(sample)
	if err == nil {
		err = o.checkLockedAt(current)
	}
	if err != nil || r.incarnation != o.incarnation {
		o.server.releaseCookieBytes(state, stateBytes)
		if err != nil {
			return err
		}
		return ErrProxyCredentialScope
	}
	old, oldBytes := o.state, o.stateBytes
	o.cookies, o.state, o.stateBytes, o.serial = installed, state, stateBytes, serial
	o.server.releaseCookieBytes(old, oldBytes)
	return nil
}

// Request ownership is captured before dispatch and survives HTTP/2's strictly
// unprocessed retry. Every actual retry checks the same binding/incarnation.
type proxyCredentialRequestKey struct{}

func checkProxyRequestCredentials(ctx context.Context) error {
	if r, ok := ctx.Value(proxyCredentialRequestKey{}).(*proxyCredentialRequest); ok {
		return r.check()
	}
	return nil
}

func compileProxyCredentials(p *ProxyCredentialPolicy) (*ProxyCredentialPolicy, error) {
	if p == nil {
		return nil, nil
	}
	copy := *p
	copy.Accounts = append([]ResourceAccount(nil), p.Accounts...)
	switch copy.Mode {
	case ProxyCredentialsNone:
		return &copy, nil
	case ProxyCredentialsExternal:
		if copy.External == nil {
			return nil, ErrProxyCredentialScope
		}
		return &copy, nil
	case ProxyCredentialsCookieSession:
		if copy.Clock == nil || copy.Root == nil || copy.Authorize == nil || copy.RuntimeBytesPerOwner == 0 || copy.RuntimeBytesPerOwner > 8<<20 || copy.RuntimeBytesPerRequest == 0 || copy.RuntimeBytesPerRequest > 8<<20 || copy.MaxOwners == 0 || copy.MaxOwners > 64 || copy.CookieBytes == 0 || copy.CookieBytes > 8<<20 || len(copy.Accounts) == 0 || len(copy.Accounts) > resourcev4.MaxAccountsPerCharge {
			return nil, ErrProxyCredentialScope
		}
		return &copy, nil
	default:
		return nil, ErrProxyCredentialScope
	}
}
