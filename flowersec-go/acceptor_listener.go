package flowersec

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/quicbase"
	rawquic "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/rawquicv3"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/webtransportv3"
)

type listenerLifecycle interface {
	Address() string
	Close() error
	acceptorListener()
}

// DirectListener is a listener that terminates an application Session at an
// Acceptor. It cannot be registered with a TunnelRuntime.
type DirectListener interface {
	listenerLifecycle
	directListener()
}

// TunnelListener is a listener that admits one opaque relay leg. It cannot be
// registered with an application Acceptor.
type TunnelListener interface {
	listenerLifecycle
	tunnelListener()
}

type directListener struct{ registeredAcceptorListener }

func (*directListener) directListener() {}

type tunnelListener struct{ registeredAcceptorListener }

func (*tunnelListener) tunnelListener() {}

func NewWebSocketDirectListener() DirectListener {
	return &directListener{registeredAcceptorListener: &websocketAcceptorListener{path: carrier.PathDirect}}
}

func NewWebSocketTunnelListener() TunnelListener {
	return &tunnelListener{registeredAcceptorListener: &websocketAcceptorListener{path: carrier.PathTunnel}}
}

type registeredAcceptorListener interface {
	listenerLifecycle
	acceptorCarrier() carrier.Kind
	acceptorPath() carrier.Path
	serve(context.Context, func(context.Context, carrier.Session) error) error
}

type websocketAcceptorListener struct{ path carrier.Path }

func (*websocketAcceptorListener) acceptorListener() {}
func (*websocketAcceptorListener) Address() string   { return "" }
func (*websocketAcceptorListener) Close() error      { return nil }
func (listener *websocketAcceptorListener) acceptorCarrier() carrier.Kind {
	return carrier.KindWebSocket
}
func (listener *websocketAcceptorListener) acceptorPath() carrier.Path { return listener.path }
func (*websocketAcceptorListener) serve(context.Context, func(context.Context, carrier.Session) error) error {
	return errors.New("WebSocket listener is served by Acceptor.Handler")
}

type rawQUICAcceptorListener struct {
	listener *rawquic.Listener
	path     carrier.Path
	mu       sync.Mutex
	closed   bool
}

func (*rawQUICAcceptorListener) acceptorListener() {}
func (listener *rawQUICAcceptorListener) Address() string {
	if listener == nil || listener.listener == nil || listener.listener.Addr() == nil {
		return ""
	}
	return listener.listener.Addr().String()
}
func (*rawQUICAcceptorListener) acceptorCarrier() carrier.Kind       { return carrier.KindRawQUIC }
func (listener *rawQUICAcceptorListener) acceptorPath() carrier.Path { return listener.path }
func (listener *rawQUICAcceptorListener) serve(ctx context.Context, accept func(context.Context, carrier.Session) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		native, err := listener.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		_ = accept(ctx, native)
	}
}
func (listener *rawQUICAcceptorListener) Close() error {
	listener.mu.Lock()
	if listener.closed {
		listener.mu.Unlock()
		return nil
	}
	listener.closed = true
	listener.mu.Unlock()
	return listener.listener.Close()
}

// RawQUICListenerOptions configures one native raw QUIC listener.
type RawQUICListenerOptions struct {
	Address           string
	TLSConfig         *tls.Config
	MaxInboundStreams uint16
}

func NewRawQUICDirectListener(options RawQUICListenerOptions) (DirectListener, error) {
	listener, err := newRawQUICListener(options, carrier.PathDirect)
	if err != nil {
		return nil, err
	}
	return &directListener{registeredAcceptorListener: listener}, nil
}

func NewRawQUICTunnelListener(options RawQUICListenerOptions) (TunnelListener, error) {
	listener, err := newRawQUICListener(options, carrier.PathTunnel)
	if err != nil {
		return nil, err
	}
	return &tunnelListener{registeredAcceptorListener: listener}, nil
}

func newRawQUICListener(options RawQUICListenerOptions, path carrier.Path) (registeredAcceptorListener, error) {
	if options.TLSConfig == nil || options.Address == "" {
		return nil, ErrInvalidAcceptor
	}
	maxLogical := options.MaxInboundStreams
	if maxLogical == 0 {
		maxLogical = carrier.MaxLogicalIncomingStreams
	}
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), maxLogical)
	if err != nil {
		return nil, ErrInvalidAcceptor
	}
	tlsConfig := options.TLSConfig.Clone()
	if path == carrier.PathDirect {
		tlsConfig.NextProtos = []string{rawquic.ALPNDirect}
	} else {
		tlsConfig.NextProtos = []string{rawquic.ALPNTunnel}
	}
	listener, err := rawquic.Listen(options.Address, tlsConfig, limits)
	if err != nil {
		return nil, ErrInvalidAcceptor
	}
	return &rawQUICAcceptorListener{listener: listener, path: path}, nil
}

type webTransportAcceptorListener struct {
	server      *carrierwt.Server
	path        carrier.Path
	checkOrigin func(*http.Request) bool
	packet      net.PacketConn
	mu          sync.Mutex
	closed      bool
}

func (*webTransportAcceptorListener) acceptorListener() {}
func (listener *webTransportAcceptorListener) Address() string {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.packet == nil || listener.packet.LocalAddr() == nil {
		return ""
	}
	return listener.packet.LocalAddr().String()
}
func (*webTransportAcceptorListener) acceptorCarrier() carrier.Kind       { return carrier.KindWebTransport }
func (listener *webTransportAcceptorListener) acceptorPath() carrier.Path { return listener.path }
func (listener *webTransportAcceptorListener) serve(ctx context.Context, accept func(context.Context, carrier.Session) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	listener.mu.Lock()
	if listener.closed || listener.packet == nil {
		listener.mu.Unlock()
		return ErrInvalidAcceptor
	}
	packet := listener.packet
	listener.mu.Unlock()
	listener.server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.URL.Path != pathForAcceptorWebTransport(listener.path) || !listener.checkOrigin(request) {
			http.Error(writer, "request rejected", http.StatusForbidden)
			return
		}
		native, upgradeErr := listener.server.Upgrade(writer, request)
		if upgradeErr != nil {
			return
		}
		_ = accept(ctx, native)
	}))
	result := make(chan error, 1)
	go func() { result <- listener.server.Serve(packet) }()
	select {
	case <-ctx.Done():
		_ = listener.Close()
		<-result
		return ctx.Err()
	case err := <-result:
		return err
	}
}
func (listener *webTransportAcceptorListener) Close() error {
	listener.mu.Lock()
	if listener.closed {
		listener.mu.Unlock()
		return nil
	}
	listener.closed = true
	packet := listener.packet
	listener.packet = nil
	listener.mu.Unlock()
	serverErr := listener.server.Close()
	if packet != nil {
		serverErr = errors.Join(serverErr, packet.Close())
	}
	return serverErr
}

// WebTransportListenerOptions configures one native WebTransport listener.
type WebTransportListenerOptions struct {
	Address           string
	TLSConfig         *tls.Config
	MaxInboundStreams uint16
	CheckOrigin       func(*http.Request) bool
}

func NewWebTransportDirectListener(options WebTransportListenerOptions) (DirectListener, error) {
	listener, err := newWebTransportListener(options, carrier.PathDirect)
	if err != nil {
		return nil, err
	}
	return &directListener{registeredAcceptorListener: listener}, nil
}

func NewWebTransportTunnelListener(options WebTransportListenerOptions) (TunnelListener, error) {
	listener, err := newWebTransportListener(options, carrier.PathTunnel)
	if err != nil {
		return nil, err
	}
	return &tunnelListener{registeredAcceptorListener: listener}, nil
}

func newWebTransportListener(options WebTransportListenerOptions, path carrier.Path) (registeredAcceptorListener, error) {
	if options.TLSConfig == nil || options.Address == "" || options.CheckOrigin == nil {
		return nil, ErrInvalidAcceptor
	}
	maxLogical := options.MaxInboundStreams
	if maxLogical == 0 {
		maxLogical = carrier.MaxLogicalIncomingStreams
	}
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), maxLogical)
	if err != nil {
		return nil, ErrInvalidAcceptor
	}
	server, err := carrierwt.NewServer(options.TLSConfig, limits, options.CheckOrigin)
	if err != nil {
		return nil, ErrInvalidAcceptor
	}
	packet, err := net.ListenPacket("udp", options.Address)
	if err != nil {
		_ = server.Close()
		return nil, ErrInvalidAcceptor
	}
	return &webTransportAcceptorListener{server: server, packet: packet, path: path, checkOrigin: options.CheckOrigin}, nil
}

func pathForAcceptorWebTransport(path carrier.Path) string {
	if path == carrier.PathTunnel {
		return carrierwt.PathTunnel
	}
	return carrierwt.PathDirect
}
