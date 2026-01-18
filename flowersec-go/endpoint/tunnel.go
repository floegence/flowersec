package endpoint

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/floegence/flowersec/flowersec-go/internal/contextutil"
	"github.com/floegence/flowersec/flowersec-go/internal/endpointid"
	"github.com/floegence/flowersec/flowersec-go/realtime/ws"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

// ConnectTunnel attaches to a tunnel as role=server and returns a multiplexed endpoint session.
func ConnectTunnel(ctx context.Context, grant *controlv1.ChannelInitGrant, origin string, opts ...ConnectOption) (*Session, error) {
	if grant == nil {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingGrant, ErrMissingGrant)
	}
	if grant.Role != controlv1.Role_server {
		return nil, wrapErr(PathTunnel, StageValidate, CodeRoleMismatch, ErrExpectedRoleServer)
	}
	if grant.TunnelUrl == "" {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingTunnelURL, ErrMissingTunnelURL)
	}
	if origin == "" {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingOrigin, ErrMissingOrigin)
	}
	if grant.ChannelId == "" {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingChannelID, ErrMissingChannelID)
	}
	if grant.ChannelInitExpireAtUnixS <= 0 {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingInitExp, ErrMissingInitExp)
	}
	cfg, err := applyConnectOptions(opts)
	if err != nil {
		return nil, wrapErr(PathTunnel, StageValidate, CodeInvalidOption, err)
	}
	psk, err := base64url.Decode(grant.E2eePskB64u)
	if err != nil || len(psk) != 32 {
		if err == nil {
			err = ErrInvalidPSK
		}
		return nil, wrapErr(PathTunnel, StageValidate, CodeInvalidPSK, err)
	}
	suite := e2ee.Suite(grant.DefaultSuite)
	switch suite {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
	default:
		return nil, wrapErr(PathTunnel, StageValidate, CodeInvalidSuite, ErrInvalidSuite)
	}

	connectTimeout := cfg.connectTimeout
	handshakeTimeout := cfg.handshakeTimeout

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	h := cloneHeader(cfg.header)
	h.Set("Origin", origin)
	c, _, err := ws.Dial(connectCtx, grant.TunnelUrl, ws.DialOptions{Header: h, Dialer: cfg.dialer})
	if err != nil {
		return nil, wrapErr(PathTunnel, StageConnect, CodeDialFailed, err)
	}

	endpointInstanceID := cfg.endpointInstanceID
	if endpointInstanceID == "" {
		endpointInstanceID, err = endpointid.Random(24)
		if err != nil {
			_ = c.Close()
			return nil, wrapErr(PathTunnel, StageValidate, CodeRandomFailed, err)
		}
	}
	if err := endpointid.Validate(endpointInstanceID); err != nil {
		_ = c.Close()
		return nil, wrapErr(PathTunnel, StageValidate, CodeInvalidEndpointInstanceID, ErrInvalidEndpointInstanceID)
	}

	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          grant.ChannelId,
		Role:               tunnelv1.Role_server,
		Token:              grant.Token,
		EndpointInstanceId: endpointInstanceID,
	}
	attachJSON, _ := json.Marshal(attach)
	if err := c.WriteMessage(connectCtx, websocket.TextMessage, attachJSON); err != nil {
		_ = c.Close()
		return nil, wrapErr(PathTunnel, StageAttach, CodeAttachFailed, err)
	}

	sess, err := serveAfterAttach(ctx, c, PathTunnel, endpointInstanceID, serverHandshakeOptions{
		psk:              psk,
		suite:            suite,
		channelID:        grant.ChannelId,
		initExpireAtUnix: grant.ChannelInitExpireAtUnixS,
		clockSkew:        cfg.clockSkew,
		serverFeatures:   cfg.serverFeatures,
		maxHandshake:     cfg.maxHandshakePayload,
		maxRecordBytes:   cfg.maxRecordBytes,
		maxBufferedBytes: cfg.maxBufferedBytes,
		handshakeTimeout: handshakeTimeout,
		cache:            cfg.handshakeCache,
		yamuxConfig:      cfg.yamuxConfig,
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return sess, nil
}

type serverHandshakeOptions struct {
	psk              []byte
	suite            e2ee.Suite
	channelID        string
	initExpireAtUnix int64
	clockSkew        time.Duration
	serverFeatures   uint32
	maxHandshake     int
	maxRecordBytes   int
	maxBufferedBytes int
	handshakeTimeout time.Duration
	cache            *e2ee.ServerHandshakeCache
	yamuxConfig      *hyamux.Config
}

func serveAfterAttach(ctx context.Context, c *ws.Conn, path Path, endpointInstanceID string, opts serverHandshakeOptions) (*Session, error) {
	handshakeCtx, handshakeCancel := contextutil.WithTimeout(ctx, opts.handshakeTimeout)
	defer handshakeCancel()

	cache := opts.cache
	if cache == nil {
		cache = e2ee.NewServerHandshakeCache()
	}
	bt := e2ee.NewWebSocketMessageTransport(c)
	secure, err := e2ee.ServerHandshake(handshakeCtx, bt, cache, e2ee.ServerHandshakeOptions{
		PSK:                 opts.psk,
		Suite:               opts.suite,
		ChannelID:           opts.channelID,
		InitExpireAtUnixS:   opts.initExpireAtUnix,
		ClockSkew:           opts.clockSkew,
		ServerFeatures:      opts.serverFeatures,
		MaxHandshakePayload: opts.maxHandshake,
		MaxRecordBytes:      opts.maxRecordBytes,
		MaxBufferedBytes:    opts.maxBufferedBytes,
	})
	if err != nil {
		return nil, wrapErr(path, StageHandshake, CodeHandshakeFailed, err)
	}

	ycfg := opts.yamuxConfig
	if ycfg == nil {
		ycfg = hyamux.DefaultConfig()
		ycfg.EnableKeepAlive = false
		ycfg.LogOutput = io.Discard
	}
	mux, err := hyamux.Server(secure, ycfg)
	if err != nil {
		_ = secure.Close()
		return nil, wrapErr(path, StageYamux, CodeMuxFailed, err)
	}

	return &Session{
		path:               path,
		endpointInstanceID: endpointInstanceID,
		secure:             secure,
		mux:                mux,
	}, nil
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return http.Header{}
	}
	out := make(http.Header, len(h))
	for k, vv := range h {
		cp := make([]string, len(vv))
		copy(cp, vv)
		out[k] = cp
	}
	return out
}
