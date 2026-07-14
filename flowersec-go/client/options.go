package client

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	fsyamux "github.com/floegence/flowersec/flowersec-go/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/session/internalnormalize"
	"github.com/gorilla/websocket"
)

// ConnectOption configures dialing, timeouts, and limits for connects.
//
// Omit an option to use the library default. For timeouts, a value of 0 disables the timeout.
type ConnectOption func(*connectOptions) error

type connectOptions struct {
	header http.Header
	dialer *websocket.Dialer

	origin string

	connectTimeout   time.Duration
	handshakeTimeout time.Duration

	maxHandshakePayload      int
	maxRecordBytes           int
	maxBufferedBytes         int
	outboundRecordChunkBytes int
	yamuxLimits              YamuxLimits

	clientFeatures uint32

	// endpointInstanceID is used only for tunnel attaches; it must be base64url(16..32 bytes).
	endpointInstanceID    string
	endpointInstanceIDSet bool

	liveness                LivenessOptions
	livenessSet             bool
	livenessDisabled        bool
	observer                observability.ClientObserver
	transportSecurityPolicy TransportSecurityPolicy

	scopeResolvers                 map[string]internalnormalize.ScopeResolver
	relaxedOptionalScopeValidation bool
}

func defaultConnectOptions() connectOptions {
	return connectOptions{
		connectTimeout:           defaults.ConnectTimeout,
		handshakeTimeout:         defaults.HandshakeTimeout,
		outboundRecordChunkBytes: e2eeDefaultOutboundRecordChunkBytes,
		yamuxLimits:              YamuxLimits(fsyamux.DefaultLimits()),
		transportSecurityPolicy:  RequireTLS,
	}
}

const e2eeDefaultOutboundRecordChunkBytes = 64 * 1024

// LivenessOptions configures ACK-based session liveness probes.
type LivenessOptions = fsyamux.LivenessOptions

// YamuxLimits bounds high-level multiplexing concurrency, frames, and receive memory.
type YamuxLimits = fsyamux.YamuxLimits

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

// WithOrigin sets the explicit Origin header value used for the WebSocket handshake.
//
// If unset, Connect* falls back to cfg.header.Get("Origin") if present.
func WithOrigin(origin string) ConnectOption {
	return func(cfg *connectOptions) error {
		cfg.origin = origin
		return nil
	}
}

// WithHeader merges extra HTTP headers for the WebSocket handshake.
//
// Header keys set by later WithHeader calls override earlier ones.
func WithHeader(h http.Header) ConnectOption {
	return func(cfg *connectOptions) error {
		if h == nil {
			return nil
		}
		if cfg.header == nil {
			cfg.header = make(http.Header, len(h))
		}
		for k, vv := range h {
			cp := make([]string, len(vv))
			copy(cp, vv)
			cfg.header[http.CanonicalHeaderKey(k)] = cp
		}
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

// WithOutboundRecordChunkBytes sets the preferred plaintext bytes per encrypted record.
func WithOutboundRecordChunkBytes(n int) ConnectOption {
	return func(cfg *connectOptions) error {
		if n <= 0 {
			return fmt.Errorf("outbound record chunk bytes must be > 0")
		}
		cfg.outboundRecordChunkBytes = n
		return nil
	}
}

// WithYamuxLimits overrides the hardened high-level multiplexing limits.
func WithYamuxLimits(limits YamuxLimits) ConnectOption {
	return func(cfg *connectOptions) error {
		if _, err := fsyamux.ValidateLimits(limits); err != nil {
			return err
		}
		cfg.yamuxLimits = limits
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
		cfg.endpointInstanceIDSet = true
		return nil
	}
}

// WithLiveness enables periodic ACK-based session liveness probes.
func WithLiveness(options LivenessOptions) ConnectOption {
	return func(cfg *connectOptions) error {
		if options.Interval <= 0 || options.Timeout <= 0 {
			return fmt.Errorf("liveness interval and timeout must be > 0")
		}
		cfg.liveness = options
		cfg.livenessSet = true
		cfg.livenessDisabled = false
		return nil
	}
}

// WithLivenessDisabled disables automatic session probes.
func WithLivenessDisabled() ConnectOption {
	return func(cfg *connectOptions) error {
		cfg.liveness = LivenessOptions{}
		cfg.livenessSet = true
		cfg.livenessDisabled = true
		return nil
	}
}

func WithObserver(observer observability.ClientObserver) ConnectOption {
	return func(cfg *connectOptions) error {
		cfg.observer = observer
		return nil
	}
}

// WithTransportSecurityPolicy sets the policy evaluated before a high-level WebSocket dial.
// RequireTLS is the default when this option is omitted.
func WithTransportSecurityPolicy(policy TransportSecurityPolicy) ConnectOption {
	return func(cfg *connectOptions) error {
		if policy == nil {
			return fmt.Errorf("transport security policy must be non-nil")
		}
		cfg.transportSecurityPolicy = policy
		return nil
	}
}

type ScopeResolver = internalnormalize.ScopeResolver

func WithScopeResolver(scope string, resolver ScopeResolver) ConnectOption {
	return func(cfg *connectOptions) error {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return fmt.Errorf("scope name must be non-empty")
		}
		if resolver == nil {
			return fmt.Errorf("scope resolver must be non-nil")
		}
		if cfg.scopeResolvers == nil {
			cfg.scopeResolvers = make(map[string]internalnormalize.ScopeResolver, 1)
		}
		cfg.scopeResolvers[scope] = internalnormalize.ScopeResolver(resolver)
		return nil
	}
}

func WithRelaxedOptionalScopeValidation(enabled bool) ConnectOption {
	return func(cfg *connectOptions) error {
		cfg.relaxedOptionalScopeValidation = enabled
		return nil
	}
}
