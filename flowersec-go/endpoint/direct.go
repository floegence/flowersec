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

	"github.com/floegence/flowersec/flowersec-go/v2/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/v2/fserrors"
	e2eev1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/e2ee/v1"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/contextutil"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/wsutil"
	fsyamux "github.com/floegence/flowersec/flowersec-go/v2/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/v2/realtime/ws"
	"github.com/gorilla/websocket"
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
	// ClockSkew is the allowed E2EE handshake timestamp skew. A value of 0 is strict.
	ClockSkew time.Duration

	HandshakeTimeout *time.Duration // Total E2EE handshake timeout (nil uses default; 0 disables).

	ServerFeatures uint32

	MaxHandshakePayload      int
	MaxRecordBytes           int
	MaxBufferedBytes         int
	MaxOutboundBufferedBytes int
	OutboundRecordChunkBytes int

	HandshakeCache *HandshakeCache
	YamuxLimits    YamuxLimits
	Liveness       LivenessOptions
}

// AcceptDirectWS performs the server-side E2EE handshake on an upgraded websocket connection
// and returns a multiplexed endpoint session.
func AcceptDirectWS(ctx context.Context, c *websocket.Conn, opts AcceptDirectOptions) (Session, error) {
	if c == nil {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingConn, ErrMissingConn)
	}
	return acceptDirectWSConn(ctx, ws.Wrap(c), opts)
}

func acceptDirectWSConn(ctx context.Context, c *ws.Conn, opts AcceptDirectOptions) (Session, error) {
	if c == nil {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingConn, ErrMissingConn)
	}
	channelID := strings.TrimSpace(opts.ChannelID)
	if channelID == "" {
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
	clockSkew := opts.ClockSkew
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
	if opts.MaxOutboundBufferedBytes < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("max outbound buffered bytes must be >= 0"))
	}
	if opts.OutboundRecordChunkBytes < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("outbound record chunk bytes must be >= 0"))
	}
	if _, err := fsyamux.ValidateLimits(opts.YamuxLimits); err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, err)
	}
	if opts.Liveness.Interval < 0 || opts.Liveness.Timeout < 0 || (opts.Liveness.Interval == 0) != (opts.Liveness.Timeout == 0) {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("liveness interval and timeout must both be > 0 or both be zero"))
	}
	handshakeCtx, handshakeCancel := contextutil.WithTimeout(ctx, handshakeTimeout)
	defer handshakeCancel()

	// Guard against a single oversized websocket message causing an OOM before E2EE framing checks run.
	c.SetReadLimit(wsutil.ReadLimit(opts.MaxHandshakePayload, opts.MaxRecordBytes))

	bt := e2ee.NewWebSocketMessageTransport(c)
	secure, err := e2ee.ServerHandshake(handshakeCtx, bt, opts.HandshakeCache, e2ee.ServerHandshakeOptions{
		PSK:                      opts.PSK,
		Suite:                    e2ee.Suite(suite),
		ChannelID:                channelID,
		InitExpireAtUnixS:        opts.InitExpireAtUnixS,
		ClockSkew:                clockSkew,
		ServerFeatures:           opts.ServerFeatures,
		MaxHandshakePayload:      opts.MaxHandshakePayload,
		MaxRecordBytes:           opts.MaxRecordBytes,
		MaxBufferedBytes:         opts.MaxBufferedBytes,
		MaxOutboundBufferedBytes: opts.MaxOutboundBufferedBytes,
		OutboundRecordChunkBytes: opts.OutboundRecordChunkBytes,
	})
	if err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.ClassifyHandshakeCode(err), err)
	}

	mux, err := fsyamux.NewServer(secure, opts.YamuxLimits, opts.Liveness)
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

// DirectHandshakeInit contains structurally validated fields from the client handshake init.
// The peer is not authenticated until the subsequent PSK handshake succeeds.
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

// DirectHandshakeCredential delays one-time credential consumption until the peer proves
// possession of the PSK. CommitAuthenticated runs after E2EE authentication and before Yamux.
// It must be idempotent, cancellation-safe, and must bound its backing transaction with its own
// deadline because an external side effect cannot be rolled back after the SDK deadline wins.
type DirectHandshakeCredential struct {
	Secrets             DirectHandshakeSecrets
	CommitAuthenticated func(context.Context) error
}

// AcceptDirectResolverOptions configures a direct handshake where per-channel secrets are resolved
// at runtime based on the client handshake init.
type AcceptDirectResolverOptions struct {
	HandshakeTimeout *time.Duration // Total E2EE handshake timeout (nil uses default; 0 disables).

	// ClockSkew is the allowed E2EE handshake timestamp skew. A value of 0 is strict.
	ClockSkew time.Duration

	ServerFeatures uint32

	MaxHandshakePayload      int
	MaxRecordBytes           int
	MaxBufferedBytes         int
	MaxOutboundBufferedBytes int
	OutboundRecordChunkBytes int

	HandshakeCache *HandshakeCache
	YamuxLimits    YamuxLimits
	Liveness       LivenessOptions

	// Resolve returns the PSK and init_exp for the given unauthenticated client init. It must
	// not consume one-time credentials, must honor ctx, and must not panic.
	Resolve func(ctx context.Context, init DirectHandshakeInit) (DirectHandshakeSecrets, error)

	// ResolveCredential resolves secrets without consuming them and must honor ctx. When set,
	// CommitAuthenticated is invoked after PSK authentication succeeds and before a Yamux
	// session is created.
	ResolveCredential func(ctx context.Context, init DirectHandshakeInit) (DirectHandshakeCredential, error)
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
	return acceptDirectWSResolvedConn(ctx, ws.Wrap(c), opts)
}

func acceptDirectWSResolvedConn(ctx context.Context, c *ws.Conn, opts AcceptDirectResolverOptions) (Session, error) {
	if c == nil {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingConn, ErrMissingConn)
	}
	if opts.Resolve == nil && opts.ResolveCredential == nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, ErrMissingResolver)
	}
	if opts.Resolve != nil && opts.ResolveCredential != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, ErrMultipleResolvers)
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
	clockSkew := opts.ClockSkew
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
	if opts.MaxOutboundBufferedBytes < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("max outbound buffered bytes must be >= 0"))
	}
	if opts.OutboundRecordChunkBytes < 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("outbound record chunk bytes must be >= 0"))
	}
	if _, err := fsyamux.ValidateLimits(opts.YamuxLimits); err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, err)
	}
	if opts.Liveness.Interval < 0 || opts.Liveness.Timeout < 0 || (opts.Liveness.Interval == 0) != (opts.Liveness.Timeout == 0) {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, fmt.Errorf("liveness interval and timeout must both be > 0 or both be zero"))
	}
	handshakeCtx, handshakeCancel := contextutil.WithTimeout(ctx, handshakeTimeout)
	defer handshakeCancel()

	maxHello := opts.MaxHandshakePayload
	if maxHello <= 0 {
		maxHello = 8 * 1024
	}

	// Guard against a single oversized websocket message causing an OOM before E2EE framing checks run.
	c.SetReadLimit(wsutil.ReadLimit(opts.MaxHandshakePayload, opts.MaxRecordBytes))

	bt := e2ee.NewWebSocketMessageTransport(c)
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
	channelID := strings.TrimSpace(initMsg.ChannelId)
	if channelID == "" {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingChannelID, ErrMissingChannelID)
	}
	if channelID != initMsg.ChannelId {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidInput, errors.New("channel_id must not have leading/trailing whitespace"))
	}
	if len(channelID) > 256 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidInput, errors.New("channel_id must not exceed 256 bytes"))
	}
	if initMsg.Version != e2ee.ProtocolVersion {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeHandshakeFailed, e2ee.ErrInvalidVersion)
	}
	if initMsg.Role != e2eev1.Role_client {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeHandshakeFailed, errors.New("unexpected role in init"))
	}
	suite := Suite(initMsg.Suite)
	switch suite {
	case SuiteX25519HKDFAES256GCM, SuiteP256HKDFAES256GCM:
	default:
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeHandshakeFailed, e2ee.ErrUnsupportedSuite)
	}

	resolveInput := DirectHandshakeInit{
		ChannelID:      channelID,
		Version:        initMsg.Version,
		Suite:          suite,
		ClientFeatures: initMsg.ClientFeatures,
	}
	credential := DirectHandshakeCredential{}
	if opts.ResolveCredential != nil {
		credential, err = safeResolveCredential(handshakeCtx, opts.ResolveCredential, resolveInput)
	} else {
		credential.Secrets, err = safeResolve(handshakeCtx, opts.Resolve, resolveInput)
	}
	if err != nil {
		_ = c.Close()
		if code := fserrors.ClassifyHandshakeCode(err); code == fserrors.CodeTimeout || code == fserrors.CodeCanceled {
			return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, code, err)
		}
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeResolveFailed, err)
	}
	secrets := credential.Secrets
	if secrets.InitExpireAtUnixS <= 0 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingInitExp, ErrMissingInitExp)
	}
	if len(secrets.PSK) != 32 {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidPSK, ErrInvalidPSK)
	}

	secure, err := e2ee.ServerHandshake(handshakeCtx, &replayBinaryTransport{first: firstFrame, t: bt}, opts.HandshakeCache, e2ee.ServerHandshakeOptions{
		PSK:                      secrets.PSK,
		Suite:                    e2ee.Suite(initMsg.Suite),
		ChannelID:                channelID,
		InitExpireAtUnixS:        secrets.InitExpireAtUnixS,
		ClockSkew:                clockSkew,
		ServerFeatures:           opts.ServerFeatures,
		MaxHandshakePayload:      opts.MaxHandshakePayload,
		MaxRecordBytes:           opts.MaxRecordBytes,
		MaxBufferedBytes:         opts.MaxBufferedBytes,
		MaxOutboundBufferedBytes: opts.MaxOutboundBufferedBytes,
		OutboundRecordChunkBytes: opts.OutboundRecordChunkBytes,
	})
	if err != nil {
		_ = c.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.ClassifyHandshakeCode(err), err)
	}
	if credential.CommitAuthenticated != nil {
		if err := safeCommitAuthenticated(handshakeCtx, credential.CommitAuthenticated); err != nil {
			_ = secure.Close()
			if code := fserrors.ClassifyHandshakeCode(err); code == fserrors.CodeTimeout || code == fserrors.CodeCanceled {
				return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, code, err)
			}
			return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeCredentialCommitFailed, err)
		}
	}
	if err := handshakeCtx.Err(); err != nil {
		_ = secure.Close()
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.ClassifyHandshakeCode(err), err)
	}

	mux, err := fsyamux.NewServer(secure, opts.YamuxLimits, opts.Liveness)
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

	// MaxPendingHandshakes bounds concurrent WebSocket upgrades and E2EE handshakes.
	// A value of 0 uses the safe default of 256.
	MaxPendingHandshakes int

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
	admission, admissionErr := newDirectHandshakeAdmission(opts.MaxPendingHandshakes)
	if admissionErr != nil {
		return nil, admissionErr
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
	handshake := opts.Handshake
	if handshake.ClockSkew == 0 {
		handshake.ClockSkew = defaults.HandshakeClockSkew
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
		if !admission.tryAcquire() {
			http.Error(w, "direct handshake capacity exhausted", http.StatusServiceUnavailable)
			onErr(wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeResourceExhausted, errors.New("direct handshake capacity exhausted")))
			return
		}
		admitted := true
		releaseAdmission := func() {
			if admitted {
				admission.release()
				admitted = false
			}
		}
		defer releaseAdmission()

		c, err := ws.Upgrade(w, r, upgrader)
		if err != nil {
			releaseAdmission()
			if !hasCustomOriginCheck && websocket.IsWebSocketUpgrade(r) && r.Header.Get("Origin") == "" && !opts.AllowNoOrigin {
				onErr(wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingOrigin, ErrMissingOrigin))
				return
			}
			onErr(wrapErr(fserrors.PathDirect, fserrors.StageConnect, fserrors.CodeUpgradeFailed, err))
			return
		}
		defer c.Close()
		sess, err := acceptDirectWSConn(r.Context(), c, handshake)
		releaseAdmission()
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

	// MaxPendingHandshakes bounds concurrent WebSocket upgrades and E2EE handshakes.
	// A value of 0 uses the safe default of 256.
	MaxPendingHandshakes int

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
	admission, admissionErr := newDirectHandshakeAdmission(opts.MaxPendingHandshakes)
	if admissionErr != nil {
		return nil, admissionErr
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
	handshake := opts.Handshake
	if handshake.ClockSkew == 0 {
		handshake.ClockSkew = defaults.HandshakeClockSkew
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
		if !admission.tryAcquire() {
			http.Error(w, "direct handshake capacity exhausted", http.StatusServiceUnavailable)
			onErr(wrapErr(fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeResourceExhausted, errors.New("direct handshake capacity exhausted")))
			return
		}
		admitted := true
		releaseAdmission := func() {
			if admitted {
				admission.release()
				admitted = false
			}
		}
		defer releaseAdmission()

		c, err := ws.Upgrade(w, r, upgrader)
		if err != nil {
			releaseAdmission()
			if !hasCustomOriginCheck && websocket.IsWebSocketUpgrade(r) && r.Header.Get("Origin") == "" && !opts.AllowNoOrigin {
				onErr(wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingOrigin, ErrMissingOrigin))
				return
			}
			onErr(wrapErr(fserrors.PathDirect, fserrors.StageConnect, fserrors.CodeUpgradeFailed, err))
			return
		}
		defer c.Close()
		sess, err := acceptDirectWSResolvedConn(r.Context(), c, handshake)
		releaseAdmission()
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

func callResolve(ctx context.Context, resolve func(context.Context, DirectHandshakeInit) (DirectHandshakeSecrets, error), init DirectHandshakeInit) (out DirectHandshakeSecrets, err error) {
	defer func() {
		if recover() != nil {
			out = DirectHandshakeSecrets{}
			err = errors.New("direct resolve panic")
		}
	}()
	return resolve(ctx, init)
}

func safeResolve(ctx context.Context, resolve func(context.Context, DirectHandshakeInit) (DirectHandshakeSecrets, error), init DirectHandshakeInit) (DirectHandshakeSecrets, error) {
	results := make(chan callbackResult[DirectHandshakeSecrets], 1)
	go func() {
		secrets, err := callResolve(ctx, resolve, init)
		results <- callbackResult[DirectHandshakeSecrets]{value: secrets, err: err}
	}()
	return awaitCallbackResult(ctx, results)
}

func callResolveCredential(ctx context.Context, resolve func(context.Context, DirectHandshakeInit) (DirectHandshakeCredential, error), init DirectHandshakeInit) (out DirectHandshakeCredential, err error) {
	defer func() {
		if recover() != nil {
			out = DirectHandshakeCredential{}
			err = errors.New("direct credential resolve panic")
		}
	}()
	return resolve(ctx, init)
}

func safeResolveCredential(ctx context.Context, resolve func(context.Context, DirectHandshakeInit) (DirectHandshakeCredential, error), init DirectHandshakeInit) (DirectHandshakeCredential, error) {
	results := make(chan callbackResult[DirectHandshakeCredential], 1)
	go func() {
		credential, err := callResolveCredential(ctx, resolve, init)
		results <- callbackResult[DirectHandshakeCredential]{value: credential, err: err}
	}()
	return awaitCallbackResult(ctx, results)
}

func callCommitAuthenticated(ctx context.Context, commit func(context.Context) error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("direct credential commit panic")
		}
	}()
	return commit(ctx)
}

func safeCommitAuthenticated(ctx context.Context, commit func(context.Context) error) error {
	results := make(chan callbackResult[struct{}], 1)
	go func() {
		results <- callbackResult[struct{}]{err: callCommitAuthenticated(ctx, commit)}
	}()
	_, err := awaitCallbackResult(ctx, results)
	return err
}

type callbackResult[T any] struct {
	value T
	err   error
}

func awaitCallbackResult[T any](ctx context.Context, results <-chan callbackResult[T]) (T, error) {
	var zero T
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case result := <-results:
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		return result.value, result.err
	}
}
