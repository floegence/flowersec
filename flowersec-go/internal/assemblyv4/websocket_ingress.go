package assemblyv4

import (
	"bufio"
	"context"
	"crypto/sha256"
	"net"
	"net/http"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// WebSocketIngressConfig binds one original HTTP callback to its fixed listener
// policy and preauth accounts. The host separately admits HTTP parsing and TLS.
// Upgrade policy is bounded trusted deployment code, never application policy;
// application authorization belongs to the later authenticated Session plan.
type WebSocketIngressConfig struct {
	Root                      *resourcev4.Root
	Owner                     resourcev4.OwnerKey
	Environment, Dependencies resourcev4.Reference
	Accounts                  []resourcev4.Account
	Entrance                  sessionv4.AcceptedEntranceConfig
	Server                    *WebSocketServer
	Upgrade                   websocket.UpgradeConfig
	Options                   websocket.Options
	RuntimeBytes              uint64
}

// WebSocketIngress retains the HTTP request/writer until FinishHTTP returns.
// Cancellation of Accept cannot return those borrowed objects while the
// original upgrade is still using them. Returned providers additionally retain
// policy backing until their original physical cleanup and retirement.
type WebSocketIngress struct {
	mu                              sync.Mutex
	c                               WebSocketIngressConfig
	writer                          http.ResponseWriter
	request                         *http.Request
	reservation, shared             resourcev4.Reference
	serverShared                    resourcev4.Reference
	providerCharge                  resourcev4.Vector
	accounts                        [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	started, finished, httpFinished bool
	provider, upgraded, cleaned     bool
	done                            chan struct{}
}

func WebSocketIngressCharge(c WebSocketIngressConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.RuntimeBytes == 0 || len(c.Accounts) == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge ||
		c.Entrance.Initial.Limits.MaxFrame < 1 || uint64(c.Options.MaxMessageBytes) < uint64(c.Entrance.Initial.Limits.MaxFrame)+protocolv4.EnvelopePrefixSize {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if c.Server == nil {
		if c.Upgrade.Subprotocol != websocket.SubprotocolDirect && c.Upgrade.Subprotocol != websocket.SubprotocolLocal ||
			c.Upgrade.CheckPolicy == nil || c.Upgrade.CheckAcceptedRoute == nil || len(c.Upgrade.ResponseHeader) != 0 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	} else if c.Upgrade.Subprotocol != "" || c.Upgrade.CheckPolicy != nil || c.Upgrade.CheckAcceptedRoute != nil || len(c.Upgrade.ResponseHeader) != 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := websocket.Charge(c.Options); err != nil {
		return resourcev4.Vector{}, err
	}
	if c.Server != nil && c.Server.tunnel {
		if c.Entrance.Initial.Deadline == nil || c.Entrance.Initial.Role != c.Server.c.Side || !c.Entrance.Initial.Deadline.BelongsTo(c.Server.c.Clock) {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		if _, err := sessionv4.InitialCharge(c.Entrance.Initial.Limits); err != nil {
			return resourcev4.Vector{}, err
		}
	} else if _, err := sessionv4.AcceptedEntranceRequirements(c.Entrance); err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(WebSocketIngress{})) + uint64(unsafe.Sizeof(ingressWebSocket{})) + uint64(unsafe.Sizeof(ingressHTTPWriter{})), resourcev4.Items: 2, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewWebSocketIngress(w http.ResponseWriter, r *http.Request, c WebSocketIngressConfig, reservation resourcev4.Reference) (*WebSocketIngress, error) {
	if w == nil || r == nil {
		return nil, resourcev4.ErrConfiguration
	}
	charge, err := WebSocketIngressCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(c.Environment); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(c.Dependencies); err != nil {
		return nil, err
	}
	shared, err := c.Dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	var serverShared resourcev4.Reference
	if c.Server != nil {
		serverShared, err = c.Server.borrowPolicy(c.Environment)
		if err != nil {
			shared.Release()
			return nil, err
		}
		c.Upgrade = c.Server.UpgradePolicy()
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		serverShared.Release()
		if c.Server != nil {
			c.Server.releasePolicy()
		}
		return nil, err
	}
	f := &WebSocketIngress{c: c, writer: w, request: r, reservation: owned, shared: shared, serverShared: serverShared, done: make(chan struct{})}
	copy(f.accounts[:], c.Accounts)
	f.c.Accounts = f.accounts[:len(c.Accounts):len(c.Accounts)]
	f.c.Upgrade.ResponseHeader = nil
	f.providerCharge, _ = websocket.Charge(c.Options)
	return f, nil
}

func (f *WebSocketIngress) PrepareAccepted(ctx context.Context, deadline *timev4.Deadline) (*sessionv4.AcceptedEntrance, error) {
	return prepareWebSocketIngress(f, ctx, deadline, false, func(provider *ingressWebSocket) (*sessionv4.AcceptedEntrance, error) {
		return sessionv4.NewAcceptedMessages(ctx, f.c.Entrance, provider, f.c.Root, ingressResourceOwner(f.c.Owner, 2), f.c.Environment, f.c.Accounts...)
	})
}

func prepareWebSocketIngress[T any](f *WebSocketIngress, ctx context.Context, deadline *timev4.Deadline, tunnel bool, finish func(*ingressWebSocket) (*T, error)) (*T, error) {
	if f == nil || ctx == nil || deadline == nil {
		return nil, resourcev4.ErrConfiguration
	}
	f.mu.Lock()
	if f.started || f.httpFinished || deadline != f.c.Entrance.Initial.Deadline || tunnel != (f.c.Server != nil && f.c.Server.tunnel) {
		f.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	f.started = true
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.finished = true
		f.writer, f.request = nil, nil
		close(f.done)
		f.cleanupLocked()
		f.mu.Unlock()
	}()
	if err := f.shared.Check(); err != nil {
		return nil, err
	}
	remaining, err := deadline.RemainingMS()
	if err != nil {
		return nil, err
	}
	options := f.c.Options
	if remaining < uint64(options.HandshakeTimeout/time.Millisecond) {
		options.HandshakeTimeout = time.Duration(remaining) * time.Millisecond
	}
	reservation, err := f.c.Root.Reserve(ingressResourceOwner(f.c.Owner, 1), f.providerCharge, f.c.Accounts...)
	if err != nil {
		return nil, err
	}
	defer reservation.Release()
	messages, err := websocket.Upgrade(ctx, &ingressHTTPWriter{ResponseWriter: f.writer, ingress: f}, f.request, f.c.Upgrade, options, reservation, f.c.Environment)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.provider = true
	f.mu.Unlock()
	provider := &ingressWebSocket{Messages: messages, ingress: f, server: f.c.Server}
	transferred := false
	defer func() {
		if !transferred {
			_ = provider.Close()
			_ = provider.WaitCleanup(context.Background())
			_ = provider.Retire()
		}
	}()
	entrance, err := finish(provider)
	transferred = entrance != nil
	return entrance, err
}

// FinishHTTP is called by the original HTTP handler on every path, including
// errors before Environment adoption. It fences an unstarted factory or joins
// the actual writer/request borrow. It never waits for an established Session.
func (f *WebSocketIngress) FinishHTTP() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.httpFinished = true
	started := f.started
	if !started {
		f.writer, f.request = nil, nil
	}
	f.cleanupLocked()
	f.mu.Unlock()
	if started {
		<-f.done
	}
}

// Hijacked reports whether the actual HTTP socket ownership moved, including
// failures after hijack. A caller must never write another HTTP response then.
func (f *WebSocketIngress) Hijacked() bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.upgraded
}

func (f *WebSocketIngress) cleanupLocked() {
	if f.cleaned || !f.httpFinished || f.started && !f.finished || f.provider {
		return
	}
	f.cleaned = true
	server := f.c.Server
	f.c = WebSocketIngressConfig{}
	f.shared.Release()
	f.serverShared.Release()
	if server != nil {
		server.releasePolicy()
	}
	f.reservation.Release()
}

func ingressResourceOwner(owner resourcev4.OwnerKey, tag byte) resourcev4.OwnerKey {
	var identity [40]byte
	copy(identity[:23], "flowersec/v4/ws-ingress\x00")
	copy(identity[23:39], owner.Backing[:])
	identity[39] = tag
	digest := sha256.Sum256(identity[:])
	copy(owner.Backing[:], digest[:16])
	return owner
}

type ingressHTTPWriter struct {
	http.ResponseWriter
	ingress *WebSocketIngress
}

func (w *ingressHTTPWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	connection, buffered, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.ingress.mu.Lock()
		w.ingress.upgraded = true
		w.ingress.mu.Unlock()
	}
	return connection, buffered, err
}

type ingressWebSocket struct {
	*websocket.Messages
	ingress *WebSocketIngress
	server  *WebSocketServer
	once    sync.Once
}

func (p *ingressWebSocket) Retire() error {
	if err := p.Messages.Retire(); err != nil {
		return err
	}
	p.once.Do(func() {
		p.ingress.mu.Lock()
		p.ingress.provider = false
		p.ingress.cleanupLocked()
		p.ingress.mu.Unlock()
	})
	return nil
}

var _ sessionv4.AcceptedIngressFactory = (*WebSocketIngress)(nil)

// ConnectionGuarantees checks the actual upgrade before applying the exact
// independently provisioned route binding. The ingress pins the server policy
// until this provider's real retirement, including after FinishHTTP.
func (p *ingressWebSocket) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	actual, err := p.Messages.ConnectionGuarantees()
	if err != nil {
		return protocolv4.V4ConnectionGuarantees{}, err
	}
	s := p.server
	if s == nil {
		return actual, nil
	}
	if err := s.checkCertificate(); err != nil {
		return protocolv4.V4ConnectionGuarantees{}, err
	}
	return s.routeBinding.Check(actual)
}
