package connectv4

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv4"
)

// WebSocketIngressPlan is produced by trusted local assembly under the
// original bounded HTTP responsibility. Build performs only finite local
// configuration/reservation, never provider I/O, authorization or user work.
// Its returned reservations transfer to Accept; failed local admission must
// leave no detached allocations. Release handles all unadopted references.
type WebSocketIngressPlan struct {
	Provider WebSocketAcceptedConfig
	Factory  resourcev4.Reference
	Ingress  sessionv4.AcceptedIngressConfig
}

func (p WebSocketIngressPlan) Release() {
	p.Factory.Release()
	p.Ingress.Reservation.Release()
	c := p.Ingress.Intake
	c.Reservation.Release()
	c.Establishment.Release()
	c.Subscriptions.Release()
	c.Input.Buffers.Release()
	c.Input.Invocation.Release()
}

// WebSocketRoute is the actual single-owner HTTP dispatch capability. Bind it
// once to a host route; Serve claims this instance exclusively. Closing its
// Serve seals only this route's upgrades, never the borrowed HTTP server or
// other routes. Configuration/deployment closures are immutable and held by
// the same preadmitted shared dependencies as the group.
type WebSocketRoute struct {
	reservation, shared resourcev4.Reference
	retired             bool
	mu                  sync.Mutex
	group               *sessionv4.ServeGroup
	claimed             bool
	build               func() (WebSocketIngressPlan, error)
	onSession           func(*sessionv4.EnvironmentSession)
}

func WebSocketRouteCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(WebSocketRoute{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func NewWebSocketRoute(build func() (WebSocketIngressPlan, error), onSession func(*sessionv4.EnvironmentSession), runtimeBytes uint64, reservation, dependencies resourcev4.Reference) (*WebSocketRoute, error) {
	if build == nil || onSession == nil || reservation == dependencies {
		return nil, cryptov4.ErrConfiguration
	}
	cost, err := WebSocketRouteCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		shared.Release()
		return nil, err
	}
	return &WebSocketRoute{build: build, onSession: onSession, reservation: owned, shared: shared}, nil
}

func (r *WebSocketRoute) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.claimed = true
	g := r.group
	r.mu.Unlock()
	if g != nil {
		g.Close()
	}
}

func (r *WebSocketRoute) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	g, claimed := r.group, r.claimed
	r.mu.Unlock()
	if g != nil {
		return g.WaitCleanup(ctx)
	}
	if !claimed {
		return cryptov4.ErrTransition
	}
	return nil
}

func (r *WebSocketRoute) Retire() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.claimed {
		return cryptov4.ErrTransition
	}
	if r.group != nil {
		if err := r.group.Retire(); err != nil {
			return err
		}
	}
	if !r.retired {
		r.retired = true
		r.group, r.build, r.onSession = nil, nil, nil
		r.reservation.Release()
		r.shared.Release()
	}
	return nil
}

func (r *WebSocketRoute) Serve(ctx context.Context, e *sessionv4.Environment, c sessionv4.ServeConfig, reservation resourcev4.Reference) (*sessionv4.ServeGroup, error) {
	if r == nil {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claimed {
		return nil, cryptov4.ErrTransition
	}
	if err := r.reservation.CheckSameEnvironment(reservation); err != nil {
		return nil, err
	}
	if err := r.shared.Check(); err != nil {
		return nil, err
	}
	g, err := e.NewServeGroup(ctx, c, reservation)
	if err != nil {
		return nil, err
	}
	r.group, r.claimed = g, true
	return g, nil
}

func (r *WebSocketRoute) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	r.mu.Lock()
	g, build, onSession := r.group, r.build, r.onSession
	r.mu.Unlock()
	if g == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	child, err := g.BeginIngress()
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer child.Release()
	plan, err := build()
	defer func() { plan.Release() }()
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	writer := &upgradeResponse{ResponseWriter: w}
	factory, err := NewWebSocketAcceptedFactory(writer, request, plan.Provider, plan.Factory)
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	// Even a canceled accept cannot release the host's ResponseWriter while
	// its actual factory call is still using it. This is the original callback,
	// not a new cleanup waiter or a task started at shutdown.
	defer func() {
		factory.Close()
		_ = factory.WaitCleanup(context.Background())
		_ = factory.Retire()
	}()
	plan.Ingress.Factory = factory
	session, owned, err := child.AcceptOwned(request.Context(), plan.Ingress)
	if owned {
		plan.Ingress = sessionv4.AcceptedIngressConfig{}
	}
	factory.Close()
	_ = factory.WaitCleanup(context.Background())
	if err != nil {
		if !writer.committed {
			http.Error(writer, "service unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	returned := false
	defer func() {
		if !returned {
			session.Close()
		}
	}()
	onSession(session)
	returned = true
}

// Access is confined to the original factory and then its joined HTTP caller.
// A hijack attempt consumes HTTP response ownership even if the host fails it.
type upgradeResponse struct {
	http.ResponseWriter
	committed bool
}

func (w *upgradeResponse) WriteHeader(code int) {
	w.committed = true
	w.ResponseWriter.WriteHeader(code)
}
func (w *upgradeResponse) Write(p []byte) (int, error) {
	w.committed = true
	return w.ResponseWriter.Write(p)
}
func (w *upgradeResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.committed = true
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, cryptov4.ErrConfiguration
	}
	return h.Hijack()
}
