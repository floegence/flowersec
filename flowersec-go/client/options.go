package client

import (
	"fmt"
	"net/http"
	"time"

	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	"github.com/gorilla/websocket"
)

// ConnectOption configures dialing, timeouts, and limits for connects.
//
// Omit an option to use the library default. For timeouts, a value of 0 disables the timeout.
type ConnectOption func(*connectOptions) error

type connectOptions struct {
	header http.Header
	dialer *websocket.Dialer

	connectTimeout   time.Duration
	handshakeTimeout time.Duration

	maxHandshakePayload int
	maxRecordBytes      int
	maxBufferedBytes    int

	clientFeatures uint32

	// endpointInstanceID is used only for tunnel attaches; it must be base64url(16..32 bytes).
	endpointInstanceID string

	keepaliveInterval time.Duration
	keepaliveSet      bool
}

func defaultConnectOptions() connectOptions {
	return connectOptions{
		connectTimeout:   defaults.ConnectTimeout,
		handshakeTimeout: defaults.HandshakeTimeout,
	}
}

func applyConnectOptions(opts []ConnectOption) (connectOptions, error) {
	cfg := defaultConnectOptions()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return connectOptions{}, err
		}
	}
	return cfg, nil
}

// WithHeader adds extra HTTP headers for the WebSocket handshake.
func WithHeader(h http.Header) ConnectOption {
	return func(cfg *connectOptions) error {
		cfg.header = h
		return nil
	}
}

// WithDialer sets a custom gorilla/websocket dialer (proxy/TLS/etc).
func WithDialer(d *websocket.Dialer) ConnectOption {
	return func(cfg *connectOptions) error {
		cfg.dialer = d
		return nil
	}
}

// WithConnectTimeout sets the WebSocket connect timeout; 0 disables the timeout.
func WithConnectTimeout(d time.Duration) ConnectOption {
	return func(cfg *connectOptions) error {
		if d < 0 {
			return fmt.Errorf("connect timeout must be >= 0")
		}
		cfg.connectTimeout = d
		return nil
	}
}

// WithHandshakeTimeout sets the total E2EE handshake timeout; 0 disables the timeout.
func WithHandshakeTimeout(d time.Duration) ConnectOption {
	return func(cfg *connectOptions) error {
		if d < 0 {
			return fmt.Errorf("handshake timeout must be >= 0")
		}
		cfg.handshakeTimeout = d
		return nil
	}
}

// WithMaxHandshakePayload sets the maximum handshake JSON payload size.
func WithMaxHandshakePayload(n int) ConnectOption {
	return func(cfg *connectOptions) error {
		if n <= 0 {
			return fmt.Errorf("max handshake payload must be > 0")
		}
		cfg.maxHandshakePayload = n
		return nil
	}
}

// WithMaxRecordBytes sets the maximum encrypted record size on the wire.
func WithMaxRecordBytes(n int) ConnectOption {
	return func(cfg *connectOptions) error {
		if n <= 0 {
			return fmt.Errorf("max record bytes must be > 0")
		}
		cfg.maxRecordBytes = n
		return nil
	}
}

// WithMaxBufferedBytes sets the maximum buffered plaintext bytes in the secure channel.
func WithMaxBufferedBytes(n int) ConnectOption {
	return func(cfg *connectOptions) error {
		if n <= 0 {
			return fmt.Errorf("max buffered bytes must be > 0")
		}
		cfg.maxBufferedBytes = n
		return nil
	}
}

// WithClientFeatures sets the feature bitset advertised during the E2EE handshake.
func WithClientFeatures(features uint32) ConnectOption {
	return func(cfg *connectOptions) error {
		cfg.clientFeatures = features
		return nil
	}
}

// WithEndpointInstanceID sets the endpoint instance ID for tunnel attaches (base64url 16..32 bytes).
func WithEndpointInstanceID(id string) ConnectOption {
	return func(cfg *connectOptions) error {
		cfg.endpointInstanceID = id
		return nil
	}
}

// WithKeepaliveInterval sets the encrypted keepalive ping interval (0 disables).
func WithKeepaliveInterval(d time.Duration) ConnectOption {
	return func(cfg *connectOptions) error {
		if d < 0 {
			return fmt.Errorf("keepalive interval must be >= 0")
		}
		cfg.keepaliveInterval = d
		cfg.keepaliveSet = true
		return nil
	}
}
