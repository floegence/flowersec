package endpoint

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/internal/contextutil"
	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/realtime/ws"
	hyamux "github.com/hashicorp/yamux"
)

type AcceptDirectOptions struct {
	ChannelID string
	PSK       []byte
	Suite     e2ee.Suite

	InitExpireAtUnixS int64
	ClockSkew         time.Duration

	HandshakeTimeout time.Duration // Total E2EE handshake timeout (0 uses default; <0 disables).

	ServerFeatures uint32

	MaxHandshakePayload int
	MaxRecordBytes      int
	MaxBufferedBytes    int

	HandshakeCache *e2ee.ServerHandshakeCache
	YamuxConfig    *hyamux.Config
}

// AcceptDirectWS performs the server-side E2EE handshake on an upgraded websocket connection
// and returns a multiplexed endpoint session.
func AcceptDirectWS(ctx context.Context, c *ws.Conn, opts AcceptDirectOptions) (*Session, error) {
	if c == nil {
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingConn, ErrMissingConn)
	}
	if opts.ChannelID == "" {
		_ = c.Close()
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingChannelID, ErrMissingChannelID)
	}
	if opts.InitExpireAtUnixS <= 0 {
		_ = c.Close()
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingInitExp, ErrMissingInitExp)
	}
	if len(opts.PSK) != 32 {
		_ = c.Close()
		return nil, wrapErr(PathDirect, StageValidate, CodeInvalidPSK, ErrInvalidPSK)
	}
	switch opts.Suite {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
	default:
		_ = c.Close()
		return nil, wrapErr(PathDirect, StageValidate, CodeInvalidSuite, ErrInvalidSuite)
	}

	handshakeTimeout := opts.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = defaults.HandshakeTimeout
	}
	handshakeCtx, handshakeCancel := contextutil.WithTimeout(ctx, handshakeTimeout)
	defer handshakeCancel()

	cache := opts.HandshakeCache
	if cache == nil {
		cache = e2ee.NewServerHandshakeCache()
	}

	bt := e2ee.NewWebSocketMessageTransport(c)
	secure, err := e2ee.ServerHandshake(handshakeCtx, bt, cache, e2ee.ServerHandshakeOptions{
		PSK:                 opts.PSK,
		Suite:               opts.Suite,
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
		return nil, wrapErr(PathDirect, StageHandshake, CodeHandshakeFailed, err)
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
		return nil, wrapErr(PathDirect, StageYamux, CodeMuxFailed, err)
	}

	return &Session{
		path:   PathDirect,
		secure: secure,
		mux:    mux,
	}, nil
}

type DirectHandlerOptions struct {
	AllowedOrigins []string
	AllowNoOrigin  bool

	Upgrader ws.UpgraderOptions

	Handshake AcceptDirectOptions

	MaxStreamHelloBytes int

	OnStream func(kind string, stream io.ReadWriteCloser)
}

// DirectHandler returns an http.HandlerFunc that upgrades to WebSocket, runs the server handshake,
// and then dispatches yamux streams by StreamHello(kind).
func DirectHandler(opts DirectHandlerOptions) http.HandlerFunc {
	checkOrigin := opts.Upgrader.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = ws.NewOriginChecker(opts.AllowedOrigins, opts.AllowNoOrigin)
	}
	maxHello := opts.MaxStreamHelloBytes
	if maxHello <= 0 {
		maxHello = DefaultMaxStreamHelloBytes
	}
	upgrader := ws.UpgraderOptions{
		ReadBufferSize:  opts.Upgrader.ReadBufferSize,
		WriteBufferSize: opts.Upgrader.WriteBufferSize,
		CheckOrigin:     checkOrigin,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := ws.Upgrade(w, r, upgrader)
		if err != nil {
			return
		}
		defer c.Close()
		sess, err := AcceptDirectWS(r.Context(), c, opts.Handshake)
		if err != nil {
			return
		}
		defer sess.Close()
		if opts.OnStream == nil {
			return
		}
		_ = sess.ServeStreams(r.Context(), maxHello, opts.OnStream)
	}
}
