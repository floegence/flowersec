package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/floegence/flowersec/flowersec-go/internal/contextutil"
	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/internal/endpointid"
	"github.com/floegence/flowersec/flowersec-go/internal/wsutil"
	"github.com/floegence/flowersec/flowersec-go/realtime/ws"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

// ConnectTunnel attaches to a tunnel as role=client and returns an RPC-ready session.
func ConnectTunnel(ctx context.Context, grant *controlv1.ChannelInitGrant, opts ...ConnectOption) (Client, error) {
	if grant == nil {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingGrant, ErrMissingGrant)
	}
	if grant.Role != controlv1.Role_client {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeRoleMismatch, ErrExpectedRoleClient)
	}
	if grant.TunnelUrl == "" {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingTunnelURL, ErrMissingTunnelURL)
	}
	if grant.ChannelId == "" {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingChannelID, ErrMissingChannelID)
	}
	if grant.Token == "" {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingToken, ErrMissingToken)
	}
	if grant.ChannelInitExpireAtUnixS <= 0 {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingInitExp, ErrMissingInitExp)
	}
	cfg, err := applyConnectOptions(opts)
	if err != nil {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidOption, err)
	}
	origin := strings.TrimSpace(cfg.origin)
	if origin == "" {
		origin = strings.TrimSpace(cfg.header.Get("Origin"))
	}
	if origin == "" {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingOrigin, ErrMissingOrigin)
	}
	keepalive := cfg.keepaliveInterval
	if !cfg.keepaliveSet {
		keepalive = defaults.KeepaliveInterval(grant.IdleTimeoutSeconds)
	}
	psk, err := base64url.Decode(grant.E2eePskB64u)
	if err != nil || len(psk) != 32 {
		if err == nil {
			err = ErrInvalidPSK
		}
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidPSK, err)
	}
	suite := e2ee.Suite(grant.DefaultSuite)
	switch suite {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
	default:
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidSuite, ErrInvalidSuite)
	}

	endpointInstanceID := cfg.endpointInstanceID
	if endpointInstanceID == "" {
		endpointInstanceID, err = endpointid.Random(24)
		if err != nil {
			return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeRandomFailed, err)
		}
	} else if err := endpointid.Validate(endpointInstanceID); err != nil {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidEndpointInstanceID, ErrInvalidEndpointInstanceID)
	}
	connectTimeout := cfg.connectTimeout
	handshakeTimeout := cfg.handshakeTimeout

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	h := cloneHeader(cfg.header)
	h.Set("Origin", origin)
	c, _, err := ws.Dial(connectCtx, grant.TunnelUrl, ws.DialOptions{Header: h, Dialer: cfg.dialer})
	if err != nil {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageConnect, fserrors.ClassifyConnectCode(err), err)
	}
	// Guard against a single oversized websocket message causing an OOM before size checks run.
	c.SetReadLimit(wsutil.ReadLimit(cfg.maxHandshakePayload, cfg.maxRecordBytes))
	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          grant.ChannelId,
		Role:               tunnelv1.Role_client,
		Token:              grant.Token,
		EndpointInstanceId: endpointInstanceID,
	}
	attachJSON, _ := json.Marshal(attach)
	if err := c.WriteMessage(connectCtx, websocket.TextMessage, attachJSON); err != nil {
		_ = c.Close()
		code := classifyTunnelAttachWriteCode(err)
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageAttach, code, err)
	}

	out, err := dialAfterAttach(ctx, c, fserrors.PathTunnel, endpointInstanceID, dialE2EEOptions{
		psk:               psk,
		suite:             suite,
		channelID:         grant.ChannelId,
		clientFeatures:    cfg.clientFeatures,
		maxHandshakeBytes: cfg.maxHandshakePayload,
		maxRecordBytes:    cfg.maxRecordBytes,
		maxBufferedBytes:  cfg.maxBufferedBytes,
		handshakeTimeout:  handshakeTimeout,
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if keepalive > 0 {
		out.startKeepalive(keepalive)
	}
	return out, nil
}

// ConnectDirect connects to a direct websocket endpoint and returns an RPC-ready session.
func ConnectDirect(ctx context.Context, info *directv1.DirectConnectInfo, opts ...ConnectOption) (Client, error) {
	if info == nil {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingConnectInfo, ErrMissingConnectInfo)
	}
	if info.WsUrl == "" {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingWSURL, ErrMissingWSURL)
	}
	if info.ChannelId == "" {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingChannelID, ErrMissingChannelID)
	}
	if info.ChannelInitExpireAtUnixS <= 0 {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingInitExp, ErrMissingInitExp)
	}
	cfg, err := applyConnectOptions(opts)
	if err != nil {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, err)
	}
	origin := strings.TrimSpace(cfg.origin)
	if origin == "" {
		origin = strings.TrimSpace(cfg.header.Get("Origin"))
	}
	if origin == "" {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingOrigin, ErrMissingOrigin)
	}
	keepalive := time.Duration(0)
	if cfg.keepaliveSet {
		keepalive = cfg.keepaliveInterval
	}
	if cfg.endpointInstanceID != "" {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, ErrEndpointInstanceIDNotAllowed)
	}
	psk, err := base64url.Decode(info.E2eePskB64u)
	if err != nil || len(psk) != 32 {
		if err == nil {
			err = ErrInvalidPSK
		}
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidPSK, err)
	}
	suite := e2ee.Suite(info.DefaultSuite)
	switch suite {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
	default:
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidSuite, ErrInvalidSuite)
	}

	connectTimeout := cfg.connectTimeout
	handshakeTimeout := cfg.handshakeTimeout

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	h := cloneHeader(cfg.header)
	h.Set("Origin", origin)
	c, _, err := ws.Dial(connectCtx, info.WsUrl, ws.DialOptions{Header: h, Dialer: cfg.dialer})
	if err != nil {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageConnect, fserrors.ClassifyConnectCode(err), err)
	}
	// Guard against a single oversized websocket message causing an OOM before size checks run.
	c.SetReadLimit(wsutil.ReadLimit(cfg.maxHandshakePayload, cfg.maxRecordBytes))

	out, err := dialAfterAttach(ctx, c, fserrors.PathDirect, "", dialE2EEOptions{
		psk:               psk,
		suite:             suite,
		channelID:         info.ChannelId,
		clientFeatures:    cfg.clientFeatures,
		maxHandshakeBytes: cfg.maxHandshakePayload,
		maxRecordBytes:    cfg.maxRecordBytes,
		maxBufferedBytes:  cfg.maxBufferedBytes,
		handshakeTimeout:  handshakeTimeout,
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if keepalive > 0 {
		out.startKeepalive(keepalive)
	}
	return out, nil
}

func classifyTunnelAttachWriteCode(err error) fserrors.Code {
	if code, ok := fserrors.ClassifyTunnelAttachCloseCode(err); ok {
		return code
	}
	return fserrors.ClassifyAttachCode(err)
}

type dialE2EEOptions struct {
	psk            []byte
	suite          e2ee.Suite
	channelID      string
	clientFeatures uint32

	maxHandshakeBytes int
	maxRecordBytes    int
	maxBufferedBytes  int

	handshakeTimeout time.Duration
}

func dialAfterAttach(ctx context.Context, c *ws.Conn, path fserrors.Path, endpointInstanceID string, opts dialE2EEOptions) (*session, error) {
	handshakeCtx, handshakeCancel := contextutil.WithTimeout(ctx, opts.handshakeTimeout)
	defer handshakeCancel()

	bt := e2ee.NewWebSocketMessageTransport(c)
	secure, err := e2ee.ClientHandshake(handshakeCtx, bt, e2ee.ClientHandshakeOptions{
		PSK:                 opts.psk,
		Suite:               opts.suite,
		ChannelID:           opts.channelID,
		ClientFeatures:      opts.clientFeatures,
		MaxHandshakePayload: opts.maxHandshakeBytes,
		MaxRecordBytes:      opts.maxRecordBytes,
		MaxBufferedBytes:    opts.maxBufferedBytes,
	})
	if err != nil {
		// Tunnel attach rejections are communicated via websocket close status + reason tokens.
		// Surface them as attach-layer failures instead of a generic handshake error.
		if path == fserrors.PathTunnel {
			if code, ok := fserrors.ClassifyTunnelAttachCloseCode(err); ok {
				return nil, wrapErr(path, fserrors.StageAttach, code, err)
			}
		}
		return nil, wrapErr(path, fserrors.StageHandshake, fserrors.ClassifyHandshakeCode(err), err)
	}

	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Client(secure, ycfg)
	if err != nil {
		_ = secure.Close()
		return nil, wrapErr(path, fserrors.StageYamux, fserrors.CodeMuxFailed, err)
	}

	rpcStream, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		_ = secure.Close()
		return nil, wrapErr(path, fserrors.StageYamux, fserrors.CodeOpenStreamFailed, err)
	}
	if err := streamhello.WriteStreamHello(rpcStream, "rpc"); err != nil {
		_ = rpcStream.Close()
		_ = sess.Close()
		_ = secure.Close()
		return nil, wrapErr(path, fserrors.StageRPC, fserrors.CodeStreamHelloFailed, err)
	}
	rpcClient := rpc.NewClient(rpcStream)

	out := &session{
		path:               path,
		endpointInstanceID: endpointInstanceID,
		secure:             secure,
		mux:                sess,
		rpc:                rpcClient,
	}
	return out, nil
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
