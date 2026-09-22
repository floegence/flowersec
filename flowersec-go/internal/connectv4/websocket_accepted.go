package connectv4

import (
	"context"
	"net/http"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// WebSocketAcceptedConfig is captured before the original HTTP callback starts
// preparation. Request and ResponseWriter remain borrowed until WaitCleanup;
// immutable deployment callbacks remain borrowed through provider retirement.
type WebSocketAcceptedConfig struct {
	Upgrade       websocket.UpgradeConfig
	DefaultPolicy *WebSocketAcceptedPolicy
	Options       websocket.Options
	Entrance      sessionv4.AcceptedEntranceConfig
	Root          *resourcev4.Root
	Owner         resourcev4.OwnerKey
	Environment   resourcev4.Reference
	Accounts      [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	AccountCount  uint8
	RuntimeBytes  uint64
}

type WebSocketAcceptedFactory struct {
	mu                                        sync.Mutex
	config                                    WebSocketAcceptedConfig
	writer                                    http.ResponseWriter
	request                                   *http.Request
	reservation, shared                       resourcev4.Reference
	started, active, closed, cleaned, retired bool
	done                                      chan struct{}
}

func WebSocketAcceptedCharge(c WebSocketAcceptedConfig) (resourcev4.Vector, error) {
	if c.RuntimeBytes == 0 || c.Root == nil || int(c.AccountCount) > len(c.Accounts) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if c.DefaultPolicy == nil {
		if c.Upgrade.CheckAcceptedRoute == nil || c.Upgrade.CheckPolicy == nil {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
	} else if c.DefaultPolicy.validate() != nil || c.Upgrade.CheckAcceptedRoute != nil || c.Upgrade.Subprotocol != websocket.SubprotocolDirect {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if _, err := websocket.Charge(c.Options); err != nil {
		return resourcev4.Vector{}, err
	}
	if _, err := sessionv4.AcceptedEntranceRequirements(c.Entrance); err != nil {
		return resourcev4.Vector{}, err
	}
	// The bounded response-header copy includes map entries, slice headers,
	// pointers and string backing even for a set of single-byte headers.
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(WebSocketAcceptedFactory{})) + uint64(unsafe.Sizeof(upgradeResponse{})) + 128*uint64(c.Options.HandshakeBytes) + 16384, resourcev4.Items: 2, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewWebSocketAcceptedFactory(w http.ResponseWriter, r *http.Request, c WebSocketAcceptedConfig, reservation resourcev4.Reference) (*WebSocketAcceptedFactory, error) {
	if w == nil || r == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := WebSocketAcceptedCharge(c)
	if err != nil {
		return nil, err
	}
	var size uint64
	for key, values := range c.Upgrade.ResponseHeader {
		size += uint64(len(key)) + 1
		for _, value := range values {
			size += uint64(len(value)) + 1
		}
		if size > uint64(c.Options.HandshakeBytes) {
			return nil, websocket.ErrHeaderLimit
		}
	}
	if err = reservation.CheckSameEnvironment(c.Environment); err != nil {
		return nil, err
	}
	shared, err := c.Environment.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	c.Upgrade.ResponseHeader = c.Upgrade.ResponseHeader.Clone()
	if c.DefaultPolicy != nil {
		c.DefaultPolicy = captureAcceptedPolicy(*c.DefaultPolicy)
	}
	return &WebSocketAcceptedFactory{config: c, writer: w, request: r, reservation: owned, shared: shared, done: make(chan struct{})}, nil
}

func (f *WebSocketAcceptedFactory) PrepareAccepted(ctx context.Context, deadline *timev4.Deadline) (_ *sessionv4.AcceptedEntrance, err error) {
	if f == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	f.mu.Lock()
	if f.closed || f.started {
		f.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	c, w, request := f.config, f.writer, f.request
	if deadline != c.Entrance.Initial.Deadline {
		f.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	if err = f.reservation.Check(); err == nil {
		err = f.shared.Check()
	}
	if err != nil {
		f.mu.Unlock()
		return nil, err
	}
	f.started, f.active = true, true
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.active = false
		f.writer, f.request = nil, nil
		f.completeLocked()
		f.mu.Unlock()
	}()
	if err = deadline.Check(); err != nil {
		return nil, err
	}
	charge, err := websocket.Charge(c.Options)
	if err != nil {
		return nil, err
	}
	if c.DefaultPolicy != nil {
		if !deadline.BelongsTo(c.DefaultPolicy.Clock) {
			return nil, cryptov4.ErrConfiguration
		}
		charge, err = charge.Add(acceptedWebSocketPolicyCharge())
		if err != nil {
			return nil, err
		}
	}
	provider, err := c.Root.Reserve(c.Owner, charge, c.Accounts[:c.AccountCount]...)
	if err != nil {
		return nil, err
	}
	defer provider.Release()
	var policy *acceptedPolicyMessages
	var policyBacking resourcev4.Reference
	adopted := false
	defer func() {
		if !adopted {
			policyBacking.Release()
		}
	}()
	if c.DefaultPolicy != nil {
		policyBacking, err = provider.Borrow()
		if err != nil {
			return nil, err
		}
		c.Upgrade, policy, err = c.DefaultPolicy.upgrade(request, c.Upgrade, policyBacking)
		if err != nil {
			return nil, err
		}
	}
	messages, err := websocket.Upgrade(ctx, w, request, c.Upgrade, c.Options, provider, c.Environment)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			_ = messages.Close()
			_ = messages.WaitCleanup(context.Background())
			_ = messages.Retire()
		}
	}()
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	var entrance *sessionv4.AcceptedEntrance
	if policy != nil {
		policy.Messages = messages
		entrance, err = sessionv4.NewAcceptedMessages(ctx, c.Entrance, policy, c.Root, c.Owner, c.Environment, c.Accounts[:c.AccountCount]...)
	} else {
		entrance, err = sessionv4.NewAcceptedMessages(ctx, c.Entrance, messages, c.Root, c.Owner, c.Environment, c.Accounts[:c.AccountCount]...)
	}
	adopted = err == nil
	return entrance, err
}

func (f *WebSocketAcceptedFactory) completeLocked() {
	if !f.active && (f.started || f.closed) && !f.cleaned {
		f.cleaned = true
		f.writer, f.request = nil, nil
		close(f.done)
	}
}

// Close seals future entry. It does not close a successfully transferred
// entrance, and cannot assert that a currently borrowed HTTP writer is free.
func (f *WebSocketAcceptedFactory) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.closed = true
	f.completeLocked()
	f.mu.Unlock()
}

func (f *WebSocketAcceptedFactory) WaitCleanup(ctx context.Context) error {
	if f == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-f.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *WebSocketAcceptedFactory) Retire() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.cleaned {
		return cryptov4.ErrCapacity
	}
	if !f.retired {
		f.retired = true
		f.closed = true
		f.config = WebSocketAcceptedConfig{}
		f.reservation.Release()
		f.shared.Release()
	}
	return nil
}

// AcceptWebSocket retains the actual HTTP callback until all factory accesses
// to its borrowed request/writer have returned, including canceled late work.
// Intake's original Environment position separately owns the returned carrier.
func AcceptWebSocket(ctx context.Context, environment *sessionv4.Environment, w http.ResponseWriter, r *http.Request, c WebSocketAcceptedConfig, reservation resourcev4.Reference, ingress sessionv4.AcceptedIngressConfig) (*sessionv4.EnvironmentSession, error) {
	factory, err := NewWebSocketAcceptedFactory(w, r, c, reservation)
	if err != nil {
		return nil, err
	}
	defer func() {
		factory.Close()
		_ = factory.WaitCleanup(context.Background())
		_ = factory.Retire()
	}()
	ingress.Factory = factory
	return environment.AcceptIngress(ctx, ingress)
}
