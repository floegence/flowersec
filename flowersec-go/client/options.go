package client

import (
	"fmt"
	"net/http"
	"time"

	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	"github.com/gorilla/websocket"
)

// TunnelConnectOption configures dialing, timeouts, and limits for tunnel connects.
type TunnelConnectOption interface {
	applyTunnel(*tunnelConnectOptions) error
}

// DirectConnectOption configures dialing, timeouts, and limits for direct connects.
type DirectConnectOption interface {
	applyDirect(*directConnectOptions) error
}

// ConnectOption configures options common to both tunnel and direct connects.
//
// Users construct ConnectOption values via helper functions like WithConnectTimeout(...).
type ConnectOption struct {
	apply func(*connectOptions) error
}

func (o ConnectOption) applyTunnel(cfg *tunnelConnectOptions) error {
	if o.apply == nil {
		return nil
	}
	return o.apply(&cfg.connectOptions)
}

func (o ConnectOption) applyDirect(cfg *directConnectOptions) error {
	if o.apply == nil {
		return nil
	}
	return o.apply(&cfg.connectOptions)
}

type tunnelOnlyOption struct {
	apply func(*tunnelConnectOptions) error
}

func (o tunnelOnlyOption) applyTunnel(cfg *tunnelConnectOptions) error {
	if o.apply == nil {
		return nil
	}
	return o.apply(cfg)
}

type connectOptions struct {
	header http.Header
	dialer *websocket.Dialer

	connectTimeout   time.Duration
	handshakeTimeout time.Duration

	maxHandshakePayload int
	maxRecordBytes      int
	maxBufferedBytes    int

	clientFeatures uint32
}

type tunnelConnectOptions struct {
	connectOptions

	// endpointInstanceID is used only for tunnel attaches; it must be base64url(16..32 bytes).
	endpointInstanceID string
}

type directConnectOptions struct {
	connectOptions
}

func defaultConnectOptions() connectOptions {
	return connectOptions{
		connectTimeout:   defaults.ConnectTimeout,
		handshakeTimeout: defaults.HandshakeTimeout,
	}
}

func defaultTunnelConnectOptions() tunnelConnectOptions {
	return tunnelConnectOptions{connectOptions: defaultConnectOptions()}
}

func defaultDirectConnectOptions() directConnectOptions {
	return directConnectOptions{connectOptions: defaultConnectOptions()}
}

func applyTunnelConnectOptions(opts []TunnelConnectOption) (tunnelConnectOptions, error) {
	cfg := defaultTunnelConnectOptions()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt.applyTunnel(&cfg); err != nil {
			return tunnelConnectOptions{}, err
		}
	}
	return cfg, nil
}

func applyDirectConnectOptions(opts []DirectConnectOption) (directConnectOptions, error) {
	cfg := defaultDirectConnectOptions()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt.applyDirect(&cfg); err != nil {
			return directConnectOptions{}, err
		}
	}
	return cfg, nil
}

// WithHeader adds extra HTTP headers for the WebSocket handshake.
func WithHeader(h http.Header) ConnectOption {
	return ConnectOption{apply: func(cfg *connectOptions) error {
		cfg.header = h
		return nil
	}}
}

// WithDialer sets a custom gorilla/websocket dialer (proxy/TLS/etc).
func WithDialer(d *websocket.Dialer) ConnectOption {
	return ConnectOption{apply: func(cfg *connectOptions) error {
		cfg.dialer = d
		return nil
	}}
}

// WithConnectTimeout sets the WebSocket connect timeout; 0 disables the timeout.
func WithConnectTimeout(d time.Duration) ConnectOption {
	return ConnectOption{apply: func(cfg *connectOptions) error {
		if d < 0 {
			return fmt.Errorf("connect timeout must be >= 0")
		}
		cfg.connectTimeout = d
		return nil
	}}
}

// WithHandshakeTimeout sets the total E2EE handshake timeout; 0 disables the timeout.
func WithHandshakeTimeout(d time.Duration) ConnectOption {
	return ConnectOption{apply: func(cfg *connectOptions) error {
		if d < 0 {
			return fmt.Errorf("handshake timeout must be >= 0")
		}
		cfg.handshakeTimeout = d
		return nil
	}}
}

// WithMaxHandshakePayload sets the maximum handshake JSON payload size.
func WithMaxHandshakePayload(n int) ConnectOption {
	return ConnectOption{apply: func(cfg *connectOptions) error {
		if n <= 0 {
			return fmt.Errorf("max handshake payload must be > 0")
		}
		cfg.maxHandshakePayload = n
		return nil
	}}
}

// WithMaxRecordBytes sets the maximum encrypted record size on the wire.
func WithMaxRecordBytes(n int) ConnectOption {
	return ConnectOption{apply: func(cfg *connectOptions) error {
		if n <= 0 {
			return fmt.Errorf("max record bytes must be > 0")
		}
		cfg.maxRecordBytes = n
		return nil
	}}
}

// WithMaxBufferedBytes sets the maximum buffered plaintext bytes in the secure channel.
func WithMaxBufferedBytes(n int) ConnectOption {
	return ConnectOption{apply: func(cfg *connectOptions) error {
		if n <= 0 {
			return fmt.Errorf("max buffered bytes must be > 0")
		}
		cfg.maxBufferedBytes = n
		return nil
	}}
}

// WithClientFeatures sets the feature bitset advertised during the E2EE handshake.
func WithClientFeatures(features uint32) ConnectOption {
	return ConnectOption{apply: func(cfg *connectOptions) error {
		cfg.clientFeatures = features
		return nil
	}}
}

// WithEndpointInstanceID sets the endpoint instance ID for tunnel attaches (base64url 16..32 bytes).
func WithEndpointInstanceID(id string) TunnelConnectOption {
	return tunnelOnlyOption{apply: func(cfg *tunnelConnectOptions) error {
		cfg.endpointInstanceID = id
		return nil
	}}
}
