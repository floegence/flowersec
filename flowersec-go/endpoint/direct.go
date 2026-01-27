package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	e2eev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/e2ee/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/contextutil"
	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/internal/wsutil"
	"github.com/floegence/flowersec/flowersec-go/realtime/ws"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

func hasNonEmptyAllowedOrigins(allowed []string) bool {
	for _, o := range allowed {
		if strings.TrimSpace(o) != "" {
			return true
		}
	}
	return false
}

// AcceptDirectOptions configures AcceptDirectWS for direct (no-tunnel) server endpoints.
type AcceptDirectOptions struct {
	ChannelID string
	PSK       []byte
	Suite     Suite

	InitExpireAtUnixS int64
	ClockSkew         time.Duration

	HandshakeTimeout *time.Duration // Total E2EE handshake timeout (nil uses default; 0 disables).

	ServerFeatures uint32

	MaxHandshakePayload int
	MaxRecordBytes      int
	MaxBufferedBytes    int

	HandshakeCache *HandshakeCache
	YamuxConfig    *hyamux.Config
}

// AcceptDirectWS performs the server-side E2EE handshake on an upgraded websocket connection
// and returns a multiplexed endpoint session.
func AcceptDirectWS(ctx context.Context, c *websocket.Conn, opts AcceptDirectOptions) (Session, error) {
	if c == nil {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingConn, ErrMissingConn)
	}
	if opts.ChannelID == "" {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingChannelID, ErrMissingChannelID)
	}
	if opts.InitExpireAtUnixS <= 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingInitExp, ErrMissingInitExp)
	}
	if len(opts.PSK) != 32 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidPSK, ErrInvalidPSK)
	}
	suite := opts.Suite
	if suite == 0 {
		suite = SuiteX25519HKDFAES256GCM
	}
	switch suite {
	case SuiteX25519HKDFAES256GCM, SuiteP256HKDFAES256GCM:
	default:
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidSuite, ErrInvalidSuite)
	}

	handshakeTimeout := defaults.HandshakeTimeout
	if opts.HandshakeTimeout != nil {
		handshakeTimeout = *opts.HandshakeTimeout
	}
	if handshakeTimeout < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("handshake timeout must be >= 0"))
	}
	if opts.ClockSkew < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("clock skew must be >= 0"))
	}
	if opts.MaxHandshakePayload < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("max handshake payload must be >= 0"))
	}
	if opts.MaxRecordBytes < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("max record bytes must be >= 0"))
	}
	if opts.MaxBufferedBytes < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("max buffered bytes must be >= 0"))
	}
	handshakeCtx, handshakeCancel := contextutil.WithTimeout(ctx, handshakeTimeout)
	defer handshakeCancel()

	// Guard against a single oversized websocket message causing an OOM before E2EE framing checks run.
	c.SetReadLimit(wsutil.ReadLimit(opts.MaxHandshakePayload, opts.MaxRecordBytes))

	bt := e2ee.NewWebSocketBinaryTransport(c)
	secure, err := e2ee.ServerHandshake(handshakeCtx, bt, opts.HandshakeCache, e2ee.ServerHandshakeOptions{
		PSK:                 opts.PSK,
		Suite:               e2ee.Suite(suite),
		ChannelID:           opts.ChannelID,
		InitExpireAtUnixS:   opts.InitExpireAtUnixS,
		ClockSkew:           opts.ClockSkew,
		ServerFeatures:      opts.ServerFeatures,
		MaxHandshakePayload: opts.MaxHandshakePayload,
		MaxRecordBytes:      opts.MaxRecordBytes,
		MaxBufferedBytes:    opts.MaxBufferedBytes,
	})
	if err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.ClassifyHandshakeCode(err), err)
	}

	ycfg := opts.YamuxConfig
	if ycfg == nil {
		ycfg = hyamux.DefaultConfig()
		ycfg.EnableKeepAlive = false
		ycfg.LogOutput = io.Discard
	}
	mux, err := hyamux.Server(secure, ycfg)
	if err != nil {
		_ = secure.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageYamux, fserrors.CodeMuxFailed, err)
	}

	return &session{
		path:   fserrors.PathDirect,
		secure: secure,
		mux:    mux,
	}, nil
}

// DirectHandshakeInit contains stable, security-relevant fields from the client handshake init.
type DirectHandshakeInit struct {
	ChannelID      string
	Version        uint8
	Suite          Suite
	ClientFeatures uint32
}

// DirectHandshakeSecrets are the per-channel secrets required to accept a direct handshake.
type DirectHandshakeSecrets struct {
	PSK               []byte
	InitExpireAtUnixS int64
}

// AcceptDirectResolverOptions configures a direct handshake where per-channel secrets are resolved
// at runtime based on the client handshake init.
type AcceptDirectResolverOptions struct {
	HandshakeTimeout *time.Duration // Total E2EE handshake timeout (nil uses default; 0 disables).

	ClockSkew time.Duration

	ServerFeatures uint32

	MaxHandshakePayload int
	MaxRecordBytes      int
	MaxBufferedBytes    int

	HandshakeCache *HandshakeCache
	YamuxConfig    *hyamux.Config

	// Resolve returns the PSK and init_exp for the given client init. It must not panic.
	Resolve func(ctx context.Context, init DirectHandshakeInit) (DirectHandshakeSecrets, error)
}

type replayBinaryTransport struct {
	first     []byte
	firstUsed bool
	t         e2ee.BinaryTransport
}

func (r *replayBinaryTransport) ReadBinary(ctx context.Context) ([]byte, error) {
	if !r.firstUsed {
		r.firstUsed = true
		return r.first, nil
	}
	return r.t.ReadBinary(ctx)
}

func (r *replayBinaryTransport) WriteBinary(ctx context.Context, b []byte) error {
	return r.t.WriteBinary(ctx, b)
}

func (r *replayBinaryTransport) Close() error { return r.t.Close() }

// AcceptDirectWSResolved performs the server-side E2EE handshake on an upgraded websocket connection
// but resolves per-channel secrets (PSK + init_exp) dynamically based on the client init frame.
func AcceptDirectWSResolved(ctx context.Context, c *websocket.Conn, opts AcceptDirectResolverOptions) (Session, error) {
	if c == nil {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingConn, ErrMissingConn)
	}
	if opts.Resolve == nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, ErrMissingResolver)
	}

	handshakeTimeout := defaults.HandshakeTimeout
	if opts.HandshakeTimeout != nil {
		handshakeTimeout = *opts.HandshakeTimeout
	}
	if handshakeTimeout < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("handshake timeout must be >= 0"))
	}
	if opts.ClockSkew < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("clock skew must be >= 0"))
	}
	if opts.MaxHandshakePayload < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("max handshake payload must be >= 0"))
	}
	if opts.MaxRecordBytes < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("max record bytes must be >= 0"))
	}
	if opts.MaxBufferedBytes < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("max buffered bytes must be >= 0"))
	}
	handshakeCtx, handshakeCancel := contextutil.WithTimeout(ctx, handshakeTimeout)
	defer handshakeCancel()

	maxHello := opts.MaxHandshakePayload
	if maxHello <= 0 {
		maxHello = 8 * 1024
	}

	// Guard against a single oversized websocket message causing an OOM before E2EE framing checks run.
	c.SetReadLimit(wsutil.ReadLimit(opts.MaxHandshakePayload, opts.MaxRecordBytes))

	bt := e2ee.NewWebSocketBinaryTransport(c)
	firstFrame, err := bt.ReadBinary(handshakeCtx)
	if err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.ClassifyHandshakeCode(err), err)
	}
	ht, payload, err := e2ee.DecodeHandshakeFrame(firstFrame, maxHello)
	if err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.ClassifyHandshakeCode(err), err)
	}
	if ht != e2ee.HandshakeTypeInit {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeHandshakeFailed, errors.New("unexpected handshake type"))
	}
	var initMsg e2eev1.E2EE_Init
	if err := json.Unmarshal(payload, &initMsg); err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeHandshakeFailed, err)
	}
	if initMsg.ChannelId == "" {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingChannelID, ErrMissingChannelID)
	}
	if initMsg.Version != e2ee.ProtocolVersion {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeInvalidVersion, e2ee.ErrInvalidVersion)
	}
	if initMsg.Role != e2eev1.Role_client {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeHandshakeFailed, errors.New("unexpected role in init"))
	}

	resolveInput := DirectHandshakeInit{
		ChannelID:      initMsg.ChannelId,
		Version:        initMsg.Version,
		Suite:          Suite(initMsg.Suite),
		ClientFeatures: initMsg.ClientFeatures,
	}
	secrets, err := safeResolve(handshakeCtx, opts.Resolve, resolveInput)
	if err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeResolveFailed, err)
	}
	if secrets.InitExpireAtUnixS <= 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingInitExp, ErrMissingInitExp)
	}
	if len(secrets.PSK) != 32 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidPSK, ErrInvalidPSK)
	}

	ycfg := opts.YamuxConfig
	if ycfg == nil {
		ycfg = hyamux.DefaultConfig()
		ycfg.EnableKeepAlive = false
		ycfg.LogOutput = io.Discard
	}

	secure, err := e2ee.ServerHandshake(handshakeCtx, &replayBinaryTransport{first: firstFrame, t: bt}, opts.HandshakeCache, e2ee.ServerHandshakeOptions{
		PSK:                 secrets.PSK,
		Suite:               e2ee.Suite(initMsg.Suite),
		ChannelID:           initMsg.ChannelId,
		InitExpireAtUnixS:   secrets.InitExpireAtUnixS,
		ClockSkew:           opts.ClockSkew,
		ServerFeatures:      opts.ServerFeatures,
		MaxHandshakePayload: opts.MaxHandshakePayload,
		MaxRecordBytes:      opts.MaxRecordBytes,
		MaxBufferedBytes:    opts.MaxBufferedBytes,
	})
	if err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.ClassifyHandshakeCode(err), err)
	}

	mux, err := hyamux.Server(secure, ycfg)
	if err != nil {
		_ = secure.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageYamux, fserrors.CodeMuxFailed, err)
	}

	return &session{
		path:   fserrors.PathDirect,
		secure: secure,
		mux:    mux,
	}, nil
}

type DirectHandlerOptions struct {
	AllowedOrigins []string
	AllowNoOrigin  bool

	Upgrader UpgraderOptions

	Handshake AcceptDirectOptions

	MaxStreamHelloBytes int

	// OnStream is required and is invoked in its own goroutine for each accepted stream.
	//
	// The stream is closed after OnStream returns.
	OnStream func(ctx context.Context, kind string, stream io.ReadWriteCloser)

	// OnError is called on upgrade/handshake/serve failures. It must not panic.
	OnError func(err error)
}

// NewDirectHandler returns an http.HandlerFunc that upgrades to WebSocket, runs the server handshake,
// and then dispatches yamux streams by StreamHello(kind).
func NewDirectHandler(opts DirectHandlerOptions) (http.HandlerFunc, error) {
	if opts.OnStream == nil {
		return nil, errors.New("missing OnStream (set DirectHandlerOptions.OnStream)")
	}
	checkOrigin := opts.Upgrader.CheckOrigin
	hasCustomOriginCheck := checkOrigin != nil
	if checkOrigin == nil {
		if !hasNonEmptyAllowedOrigins(opts.AllowedOrigins) {
			// Keep the default origin policy explicit and safe. AllowNoOrigin is an additive capability
			// (for non-browser clients that omit Origin) and does not replace the allow-list.
			return nil, errors.New("missing AllowedOrigins (set AllowedOrigins or set Upgrader.CheckOrigin)")
		}
		checkOrigin = ws.NewOriginChecker(opts.AllowedOrigins, opts.AllowNoOrigin)
	}
	maxHello := opts.MaxStreamHelloBytes
	if maxHello < 0 {
		return nil, errors.New("invalid MaxStreamHelloBytes (must be >= 0)")
	}
	if maxHello == 0 {
		maxHello = DefaultMaxStreamHelloBytes
	}
	upgrader := ws.UpgraderOptions{
		ReadBufferSize:  opts.Upgrader.ReadBufferSize,
		WriteBufferSize: opts.Upgrader.WriteBufferSize,
		CheckOrigin:     checkOrigin,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		onErr := func(err error) {
			if opts.OnError == nil || err == nil {
				return
			}
			defer func() {
				_ = recover()
			}()
			opts.OnError(err)
		}

		c, err := ws.Upgrade(w, r, upgrader)
		if err != nil {
			if !hasCustomOriginCheck && websocket.IsWebSocketUpgrade(r) && r.Header.Get("Origin") == "" && !opts.AllowNoOrigin {
				onErr(wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingOrigin, ErrMissingOrigin))
				return
			}
			onErr(wrapErr(fserrors.PathDirect, fserrors.StageConnect, fserrors.CodeUpgradeFailed, err))
			return
		}
		defer c.Close()
		sess, err := AcceptDirectWS(r.Context(), c.Underlying(), opts.Handshake)
		if err != nil {
			onErr(err)
			return
		}
		defer sess.Close()
		reqCtx := r.Context()
		if err := reqCtx.Err(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			select {
			case <-reqCtx.Done():
				_ = sess.Close()
			case <-done:
			}
		}()
		defer close(done)

		for {
			kind, stream, err := sess.AcceptStreamHello(maxHello)
			if err != nil {
				if reqCtx.Err() != nil {
					return
				}
				var fe *fserrors.Error
				if errors.As(err, &fe) && fe.Code == fserrors.CodeStreamHelloFailed {
					onErr(err)
					continue
				}
				onErr(err)
				return
			}
			go func(kind string, stream io.ReadWriteCloser) {
				defer stream.Close()
				defer func() {
					if r := recover(); r != nil {
						onErr(fmt.Errorf("direct stream handler panic (kind=%q): %v", kind, r))
					}
				}()
				opts.OnStream(reqCtx, kind, stream)
			}(kind, stream)
		}
	}, nil
}

type DirectHandlerResolvedOptions struct {
	AllowedOrigins []string
	AllowNoOrigin  bool

	Upgrader UpgraderOptions

	Handshake AcceptDirectResolverOptions

	MaxStreamHelloBytes int

	// OnStream is required and is invoked in its own goroutine for each accepted stream.
	//
	// The stream is closed after OnStream returns.
	OnStream func(ctx context.Context, kind string, stream io.ReadWriteCloser)

	// OnError is called on upgrade/handshake/serve failures. It must not panic.
	OnError func(err error)
}

// NewDirectHandlerResolved is like NewDirectHandler, but resolves per-channel handshake secrets at runtime.
func NewDirectHandlerResolved(opts DirectHandlerResolvedOptions) (http.HandlerFunc, error) {
	if opts.OnStream == nil {
		return nil, errors.New("missing OnStream (set DirectHandlerResolvedOptions.OnStream)")
	}
	checkOrigin := opts.Upgrader.CheckOrigin
	hasCustomOriginCheck := checkOrigin != nil
	if checkOrigin == nil {
		if !hasNonEmptyAllowedOrigins(opts.AllowedOrigins) {
			// Keep the default origin policy explicit and safe. AllowNoOrigin is an additive capability
			// (for non-browser clients that omit Origin) and does not replace the allow-list.
			return nil, errors.New("missing AllowedOrigins (set AllowedOrigins or set Upgrader.CheckOrigin)")
		}
		checkOrigin = ws.NewOriginChecker(opts.AllowedOrigins, opts.AllowNoOrigin)
	}
	maxHello := opts.MaxStreamHelloBytes
	if maxHello < 0 {
		return nil, errors.New("invalid MaxStreamHelloBytes (must be >= 0)")
	}
	if maxHello == 0 {
		maxHello = DefaultMaxStreamHelloBytes
	}
	upgrader := ws.UpgraderOptions{
		ReadBufferSize:  opts.Upgrader.ReadBufferSize,
		WriteBufferSize: opts.Upgrader.WriteBufferSize,
		CheckOrigin:     checkOrigin,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		onErr := func(err error) {
			if opts.OnError == nil || err == nil {
				return
			}
			defer func() {
				_ = recover()
			}()
			opts.OnError(err)
		}

		c, err := ws.Upgrade(w, r, upgrader)
		if err != nil {
			if !hasCustomOriginCheck && websocket.IsWebSocketUpgrade(r) && r.Header.Get("Origin") == "" && !opts.AllowNoOrigin {
				onErr(wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingOrigin, ErrMissingOrigin))
				return
			}
			onErr(wrapErr(fserrors.PathDirect, fserrors.StageConnect, fserrors.CodeUpgradeFailed, err))
			return
		}
		defer c.Close()
		sess, err := AcceptDirectWSResolved(r.Context(), c.Underlying(), opts.Handshake)
		if err != nil {
			onErr(err)
			return
		}
		defer sess.Close()
		reqCtx := r.Context()
		if err := reqCtx.Err(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			select {
			case <-reqCtx.Done():
				_ = sess.Close()
			case <-done:
			}
		}()
		defer close(done)

		for {
			kind, stream, err := sess.AcceptStreamHello(maxHello)
			if err != nil {
				if reqCtx.Err() != nil {
					return
				}
				var fe *fserrors.Error
				if errors.As(err, &fe) && fe.Code == fserrors.CodeStreamHelloFailed {
					onErr(err)
					continue
				}
				onErr(err)
				return
			}
			go func(kind string, stream io.ReadWriteCloser) {
				defer stream.Close()
				defer func() {
					if r := recover(); r != nil {
						onErr(fmt.Errorf("direct stream handler panic (kind=%q): %v", kind, r))
					}
				}()
				opts.OnStream(reqCtx, kind, stream)
			}(kind, stream)
		}
	}, nil
}

func safeResolve(ctx context.Context, resolve func(context.Context, DirectHandshakeInit) (DirectHandshakeSecrets, error), init DirectHandshakeInit) (out DirectHandshakeSecrets, err error) {
	defer func() {
		if recover() != nil {
			out = DirectHandshakeSecrets{}
			err = errors.New("direct resolve panic")
		}
	}()
	return resolve(ctx, init)
}
