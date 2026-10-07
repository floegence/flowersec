package sessionv4

import (
	"context"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

var (
	ErrHTTPHandlerExit = errors.New("sessionv4: HTTP handler exited without returning")
	ErrHTTPServe       = errors.New("sessionv4: HTTP service failed")
)

// HTTPStreamOptions describes one explicitly delegated native HTTP/1 service.
// ExternalRuntime is the trusted deployment's complete admitted native HTTP,
// handler, upgrade and associated work envelope, not an application claim of
// an enforced RSS limit. Its independently qualified external owner is borrowed
// until the actual HTTP callbacks and native service stop. No ordinary executor
// permit is silently released or reacquired as a long handler waits.
type HTTPStreamOptions struct {
	Connection                     StreamConnOptions
	ReadHeaderTimeout, IdleTimeout time.Duration
	MaxHeaderBytes                 int
	RuntimeBytes                   uint64
	ExternalRuntime                resourcev4.Vector
}

func normalizeHTTPStreamOptions(o HTTPStreamOptions) (HTTPStreamOptions, error) {
	if o.ReadHeaderTimeout < 0 || o.IdleTimeout < 0 || o.MaxHeaderBytes < 0 || o.MaxHeaderBytes > math.MaxInt-4096 || o.RuntimeBytes == 0 {
		return o, cryptov4.ErrConfiguration
	}
	if o.ReadHeaderTimeout == 0 {
		o.ReadHeaderTimeout = 15 * time.Second
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 60 * time.Second
	}
	if o.MaxHeaderBytes == 0 {
		o.MaxHeaderBytes = 64 * 1024
	}
	// At least the parser's selected input bound and the actual native
	// connection/background-read tasks must be declared before ownership.
	// This minimum is not a qualification of arbitrary handler allocations.
	if o.ExternalRuntime[resourcev4.ProviderBytes] < uint64(o.MaxHeaderBytes)+4096 || o.ExternalRuntime[resourcev4.Tasks] < 2 || o.ExternalRuntime[resourcev4.WorkSlots] == 0 {
		return o, cryptov4.ErrConfiguration
	}
	if _, err := StreamConnCharge(o.Connection); err != nil {
		return o, err
	}
	return o, nil
}

func HTTPStreamCharge(options HTTPStreamOptions) (resourcev4.Vector, error) {
	o, err := normalizeHTTPStreamOptions(options)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	fixed := uint64(unsafe.Sizeof(HTTPStream{})) + uint64(unsafe.Sizeof(http.Server{})) + uint64(unsafe.Sizeof(httpStreamListener{})) + uint64(unsafe.Sizeof(connExternalCleanup{})) + uint64(unsafe.Sizeof(controlledHTTPExecution{})) + uint64(unsafe.Sizeof(controlledHTTPResponse{})) + uint64(unsafe.Sizeof(http.Request{})) + applicationContextBytes()
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: fixed, resourcev4.Items: 4, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: o.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(o.ExternalRuntime)
}

// HTTPStream owns one native server, a single accepted connection, all handler
// entry and the upgrade endpoint's original cancellation responsibility. Its
// cleanup is a child of the same StreamConn close owner, not another close
// state machine. The original Stream supplies its only connection.
type HTTPStream struct {
	controlled                *controlledHTTPExecution
	response                  *controlledHTTPResponse
	upgrade                   *controlledHTTPUpgrade
	mu                        sync.Mutex
	conn                      *StreamConn
	server                    *http.Server
	listener                  *httpStreamListener
	handler                   http.Handler
	reservation, dependencies resourcev4.Reference
	external                  *connExternalCleanup
	accepted, terminal        bool
	callback                  bool
	workers                   uint8
	wake, serveDone           chan struct{}
}

// StartHTTPStream is the delegated native HTTP composition entry. Trusted
// registration must have admitted the full service slot, external execution
// envelope and handler backing before calling this after acceptance. It starts
// no application callback until both direction ownership and every charge have
// transferred. Normal HTTP and upgrades use the original lifetime; the default
// Connection.TimeoutMS=0 adds no duration bound to keep-alive or a response.
func StartHTTPStream(ctx context.Context, owner *StreamOwnership, handler http.Handler, options HTTPStreamOptions, reservation, connectionReservation, dependencies resourcev4.Reference) (*HTTPStream, error) {
	return startHTTPStream(ctx, owner, handler, options, reservation, connectionReservation, dependencies, nil)
}

func startHTTPStream(ctx context.Context, owner *StreamOwnership, handler http.Handler, options HTTPStreamOptions, reservation, connectionReservation, dependencies resourcev4.Reference, controlled *controlledHTTPExecution) (*HTTPStream, error) {
	if ctx == nil || owner == nil || handler == nil || reservation == connectionReservation || reservation == dependencies || connectionReservation == dependencies {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o, err := normalizeHTTPStreamOptions(options)
	if err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(connectionReservation); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	var upgrade *ControlledHTTPUpgradeConfig
	if controlled != nil {
		upgrade = controlled.upgrade
	}
	charge, err := controlledHTTPStreamCharge(o, upgrade)
	if err != nil {
		return nil, err
	}
	owned, shared, external, err := prepareConnExternal(reservation, dependencies, charge)
	if err != nil {
		return nil, err
	}
	h := &HTTPStream{controlled: controlled, handler: handler, reservation: owned, dependencies: shared, external: external, workers: 2, wake: make(chan struct{}, 1), serveDone: make(chan struct{})}
	if upgrade != nil {
		h.upgrade = &controlledHTTPUpgrade{head: make([]byte, upgrade.MaxHeadBytes), ready: make(chan struct{})}
	}
	h.listener = &httpStreamListener{owner: h}
	h.server = &http.Server{Handler: h, ReadHeaderTimeout: o.ReadHeaderTimeout, IdleTimeout: o.IdleTimeout, MaxHeaderBytes: o.MaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context { return ctx }, ConnState: h.connState, ErrorLog: log.New(io.Discard, "", 0)}
	// Explicitly select HTTP/1. HTTP/2 would introduce multiplexed handlers and
	// a different native budget and upgrade contract on this one byte Stream.
	h.server.Protocols = new(http.Protocols)
	h.server.Protocols.SetHTTP1(true)
	h.conn, err = owner.asConn(ctx, o.Connection, connectionReservation, external)
	if err != nil {
		external.backing.Release()
		external.dependencies.Release()
		owned.Release()
		shared.Release()
		return nil, err
	}
	go h.serve()
	go h.interrupt()
	return h, nil
}

// ServeHTTPStream waits for real sending Finish and compound cleanup. Context
// cancellation also owns the original service cancellation; a canceled wait
// does not pretend that a blocked handler has physically exited. Callers that
// need later cleanup observation retain the handle returned by StartHTTPStream.
func ServeHTTPStream(ctx context.Context, owner *StreamOwnership, handler http.Handler, options HTTPStreamOptions, reservation, connectionReservation, dependencies resourcev4.Reference) (protocolv4.V4CloseResult, error) {
	h, err := StartHTTPStream(ctx, owner, handler, options, reservation, connectionReservation, dependencies)
	if err != nil {
		return protocolv4.V4CloseResult{}, err
	}
	return h.WaitCleanup(ctx)
}

func (h *HTTPStream) Abort() { h.fail(ErrAbandoned) }

func (h *HTTPStream) fail(err error) {
	c := h.conn
	c.mu.Lock()
	c.closeLocked(err)
	c.mu.Unlock()
}

func (h *HTTPStream) WaitCleanup(ctx context.Context) (protocolv4.V4CloseResult, error) {
	r, err := h.conn.WaitCleanup(ctx)
	if err == nil && (!r.SendDrained || r.CleanupStatus.Status != protocolv4.V4CleanupStateComplete) {
		err = ErrHTTPServe
	}
	return r, err
}

func (h *HTTPStream) Result() (protocolv4.V4CloseResult, uint64, error) { return h.conn.Result() }
func (h *HTTPStream) CleanupStatus() protocolv4.V4CleanupStatus         { return h.conn.CleanupStatus() }

func (h *HTTPStream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	c := h.conn
	c.mu.Lock()
	err := h.reservation.Check()
	if err == nil {
		err = h.dependencies.Check()
	}
	if err == nil && (h.callback || h.terminal || c.closed) {
		err = net.ErrClosed
	}
	if err == nil {
		err = c.owner.enterCallback()
	}
	handler := h.handler
	if err == nil {
		h.callback = true
		h.external.callbacks.Store(1)
	}
	c.mu.Unlock()
	h.mu.Unlock()
	if err != nil {
		h.fail(err)
		return
	}
	returned := false
	defer func() {
		// Never format, retain or publish an arbitrary application panic value.
		// Goexit also leaves returned=false and follows the same abort owner.
		_ = recover()
		if !returned {
			h.fail(ErrHTTPHandlerExit)
		}
		h.mu.Lock()
		h.callback = false
		h.external.callbacks.Store(0)
		connNotify(h.wake)
		h.mu.Unlock()
	}()
	if h.controlled == nil {
		handler.ServeHTTP(w, r)
	} else if err := h.controlled.serve(h, handler, w, r); err != nil {
		h.fail(err)
	}
	returned = true
}

func (h *HTTPStream) connState(_ net.Conn, state http.ConnState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch state {
	case http.StateHijacked:
		h.terminal = true
	case http.StateClosed:
		h.terminal = true
	}
	connNotify(h.wake)
}

func (h *HTTPStream) serve() {
	defer h.exitWorker()
	err := h.server.Serve(h.listener)
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		h.fail(ErrHTTPServe)
	}
	h.mu.Lock()
	if !h.accepted {
		h.terminal = true
	}
	h.mu.Unlock()
	for {
		h.mu.Lock()
		exited := h.terminal && !h.callback && (h.upgrade == nil || h.upgrade.running == 0)
		h.mu.Unlock()
		if exited {
			break
		}
		<-h.wake
	}
	close(h.serveDone)
}

func (h *HTTPStream) interrupt() {
	defer h.exitWorker()
	defer func() {
		if recover() != nil {
			h.fail(ErrHTTPUpgrade)
		}
	}()
	select {
	case <-h.conn.aborting:
		// The original abort gate has already won. A subsequent parameterless
		// net.Conn.Close from net/http cannot turn this into normal completion.
		_ = h.server.Close()
	case <-h.serveDone:
	}
	if u := h.upgrade; u != nil {
		// A transfer racing cancellation is joined before looking up the peer.
		// No separate abort task or unowned Close callback is introduced.
		select {
		case <-u.ready:
		case <-h.serveDone:
		}
		h.mu.Lock()
		peer := u.peer
		h.mu.Unlock()
		if peer != nil {
			_ = peer.Close()
		}
	}
}

func (h *HTTPStream) exitWorker() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.workers--
	if h.workers != 0 {
		return
	}
	// StateClosed follows finalFlush and native pending-read interruption;
	// StateHijacked is terminal for the parser, and the handler must actually
	// return. Upgraded I/O remains joined separately by the original conn.
	h.handler, h.server, h.listener = nil, nil, nil
	h.controlled, h.response, h.upgrade = nil, nil, nil
	h.reservation.Release()
	h.dependencies.Release()
	h.reservation, h.dependencies = resourcev4.Reference{}, resourcev4.Reference{}
	close(h.external.done)
}

type httpStreamListener struct{ owner *HTTPStream }

func (l *httpStreamListener) Accept() (net.Conn, error) {
	h := l.owner
	h.mu.Lock()
	if !h.accepted {
		h.conn.mu.Lock()
		closed := h.conn.closed
		h.conn.mu.Unlock()
		if !closed {
			h.accepted = true
			h.mu.Unlock()
			return h.conn, nil
		}
	}
	h.mu.Unlock()
	<-h.conn.closeStart
	return nil, net.ErrClosed
}
func (l *httpStreamListener) Close() error { return l.owner.conn.Close() }
func (*httpStreamListener) Addr() net.Addr { return streamConnAddress{} }
