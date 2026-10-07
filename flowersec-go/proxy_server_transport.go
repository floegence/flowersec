package flowersec

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// The standard Transport.RoundTrip may replay requests on a reused connection.
// This private HTTP/1 pool uses exactly one ClientConn.RoundTrip per request.
// Its slots include preparation and both body owners, not just response headers.
type proxyHTTPTransport struct {
	mu        sync.Mutex
	closed    bool
	closing   bool
	done      chan struct{}
	cleaned   bool
	scheme    string
	authority string
	native    *http.Transport
	slots     []proxyHTTPSlot
}

type proxyHTTPSlot struct {
	connection *http.ClientConn
	response   *proxyResponseConn
	busy       bool
}

func newProxyHTTPTransport(config proxyServerConfig) *proxyHTTPTransport {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport := &proxyHTTPTransport{
		scheme: config.upstream.Scheme, authority: config.upstream.Host, done: make(chan struct{}),
		slots: make([]proxyHTTPSlot, config.maxHTTP),
		native: &http.Transport{
			Proxy: nil, DisableCompression: true, DialContext: config.network.dialContext,
			Protocols: protocols, MaxResponseHeaderBytes: int64(config.maxMetadata),
		},
	}
	wrap := func(ctx context.Context, connection net.Conn) (net.Conn, error) {
		slot, ok := ctx.Value(proxyResponseSlotKey{}).(*proxyHTTPSlot)
		if !ok || slot == nil {
			_ = connection.Close()
			return nil, ErrInvalidProxyServer
		}
		response := &proxyResponseConn{Conn: connection, maximum: config.maxMetadata}
		transport.mu.Lock()
		slot.response = response
		transport.mu.Unlock()
		if secure, ok := connection.(*tls.Conn); ok {
			return &proxyResponseTLSConn{response, secure}, nil
		}
		return response, nil
	}
	transport.native.DialContext = func(ctx context.Context, network, authority string) (net.Conn, error) {
		connection, err := config.network.dialContext(ctx, network, authority)
		if err != nil {
			return nil, err
		}
		return wrap(ctx, connection)
	}
	transport.native.DialTLSContext = func(ctx context.Context, network, authority string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		connection, err := config.network.dialContext(ctx, network, authority)
		if err != nil {
			return nil, err
		}
		configuration := transport.native.TLSClientConfig
		if configuration == nil {
			configuration = &tls.Config{}
		} else {
			configuration = configuration.Clone()
		}
		configuration.ServerName, configuration.NextProtos = config.network.host, []string{"http/1.1"}
		secure := tls.Client(connection, configuration)
		if err := secure.HandshakeContext(ctx); err != nil {
			_ = secure.Close()
			return nil, err
		}
		return wrap(ctx, secure)
	}
	return transport
}

type proxyResponseSlotKey struct{}

func (transport *proxyHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, ErrInvalidProxyServer
	}
	if request.URL.Scheme != transport.scheme || request.URL.Host != transport.authority ||
		request.URL.User != nil || request.Host != "" && request.Host != transport.authority {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, ErrInvalidProxyServer
	}
	if err := checkProxyRequestCredentials(request.Context()); err != nil {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, err
	}
	transport.mu.Lock()
	var slot *proxyHTTPSlot
	if !transport.closed {
		for index := range transport.slots {
			if !transport.slots[index].busy {
				slot = &transport.slots[index]
				slot.busy = true
				break
			}
		}
	}
	transport.mu.Unlock()
	if slot == nil {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, ErrInvalidProxyServer
	}
	exchange := &proxyHTTPExchange{transport: transport, slot: slot, requestClosed: request.Body == nil || request.Body == http.NoBody}
	outgoing := new(http.Request)
	*outgoing = *request
	if !exchange.requestClosed {
		outgoing.Body = &proxyHTTPBody{body: request.Body, exchange: exchange, request: true}
	}
	connection, err := transport.prepare(request.Context(), slot)
	if err == nil {
		// Reserve has one consumer: RoundTrip, or Release on pre-publication
		// refusal. No deferred Release may refund a consumed reservation.
		err = connection.Reserve()
	}
	if err == nil {
		transport.mu.Lock()
		closed := transport.closed
		transport.mu.Unlock()
		if closed || request.Context().Err() != nil {
			connection.Release()
			err = request.Context().Err()
			if err == nil {
				err = ErrInvalidProxyServer
			}
		}
	}
	if err != nil {
		if outgoing.Body != nil {
			_ = outgoing.Body.Close()
		}
		exchange.finish(false)
		return nil, err
	}
	transport.mu.Lock()
	original := slot.response
	transport.mu.Unlock()
	if original == nil {
		err = ErrInvalidProxyServer
	} else {
		err = original.arm()
	}
	if err != nil {
		connection.Release()
		_ = connection.Close()
		if outgoing.Body != nil {
			_ = outgoing.Body.Close()
		}
		exchange.finish(false)
		return nil, err
	}
	if err := checkProxyRequestCredentials(outgoing.Context()); err != nil {
		connection.Release()
		_ = connection.Close()
		if outgoing.Body != nil {
			_ = outgoing.Body.Close()
		}
		exchange.finish(false)
		return nil, err
	}
	response, err := connection.RoundTrip(outgoing)
	if err == nil {
		var headers http.Header
		headers, err = original.take()
		if err == nil {
			response.Header = headers
		} else {
			_ = response.Body.Close()
		}
	}
	if err != nil {
		// There is no method/idempotency-key/GetBody retry branch. A failure
		// after this call begins leaves upstream processing unknown.
		_ = connection.Close()
		if outgoing.Body != nil {
			_ = outgoing.Body.Close()
		}
		exchange.finish(false)
		return nil, err
	}
	response.Body = &proxyHTTPBody{body: response.Body, exchange: exchange}
	exchange.finish(true)
	return response, nil
}

func (transport *proxyHTTPTransport) prepare(ctx context.Context, slot *proxyHTTPSlot) (*http.ClientConn, error) {
	transport.mu.Lock()
	connection, closed := slot.connection, transport.closed
	transport.mu.Unlock()
	if closed {
		return nil, ErrInvalidProxyServer
	}
	if connection != nil && connection.Err() == nil && connection.Available() > 0 {
		return connection, nil
	}
	if connection != nil {
		_ = connection.Close()
	}
	connection, err := transport.native.NewClientConn(context.WithValue(ctx, proxyResponseSlotKey{}, slot), transport.scheme, transport.authority)
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	closed = transport.closed
	slot.connection = connection
	transport.mu.Unlock()
	if closed || ctx.Err() != nil {
		_ = connection.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrInvalidProxyServer
	}
	return connection, nil
}

func (transport *proxyHTTPTransport) Close() {
	transport.mu.Lock()
	if transport.closed {
		transport.mu.Unlock()
		return
	}
	transport.closed = true
	transport.closing = true
	transport.mu.Unlock()
	for index := range transport.slots {
		transport.mu.Lock()
		connection := transport.slots[index].connection
		transport.mu.Unlock()
		if connection != nil {
			_ = connection.Close()
		}
	}
	transport.mu.Lock()
	transport.closing = false
	transport.cleanupLocked()
	transport.mu.Unlock()
}

// The transport owns native body/preparation methods until their real exits.
// Logical connection closure never refunds these slots or their jar backing.
func (transport *proxyHTTPTransport) cleanupLocked() {
	if !transport.closed || transport.closing || transport.cleaned {
		return
	}
	for _, slot := range transport.slots {
		if slot.busy {
			return
		}
	}
	transport.cleaned = true
	close(transport.done)
}

type proxyHTTPExchange struct {
	transport      *proxyHTTPTransport
	slot           *proxyHTTPSlot
	returned       bool
	requestClosed  bool
	responseClosed bool
	methods        int
}

func (exchange *proxyHTTPExchange) finish(response bool) {
	exchange.transport.mu.Lock()
	defer exchange.transport.mu.Unlock()
	exchange.returned = true
	exchange.responseClosed = !response
	exchange.releaseLocked()
}

func (exchange *proxyHTTPExchange) releaseLocked() {
	if exchange.returned && exchange.requestClosed && exchange.responseClosed && exchange.methods == 0 {
		exchange.slot.busy = false
		exchange.transport.cleanupLocked()
	}
}

type proxyHTTPBody struct {
	body     io.ReadCloser
	exchange *proxyHTTPExchange
	request  bool
	once     sync.Once
	closeErr error
}

func (body *proxyHTTPBody) Read(dst []byte) (int, error) {
	exchange := body.exchange
	exchange.transport.mu.Lock()
	closed := exchange.responseClosed
	if body.request {
		closed = exchange.requestClosed
	}
	if closed {
		exchange.transport.mu.Unlock()
		return 0, http.ErrBodyReadAfterClose
	}
	exchange.methods++
	exchange.transport.mu.Unlock()
	defer func() {
		exchange.transport.mu.Lock()
		exchange.methods--
		exchange.releaseLocked()
		exchange.transport.mu.Unlock()
	}()
	return body.body.Read(dst)
}

func (body *proxyHTTPBody) Close() error {
	body.once.Do(func() {
		exchange := body.exchange
		exchange.transport.mu.Lock()
		exchange.methods++
		if body.request {
			exchange.requestClosed = true
		} else {
			exchange.responseClosed = true
		}
		exchange.transport.mu.Unlock()
		body.closeErr = body.body.Close()
		exchange.transport.mu.Lock()
		exchange.methods--
		exchange.releaseLocked()
		exchange.transport.mu.Unlock()
	})
	return body.closeErr
}
