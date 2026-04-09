package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/connectcontract"
	"github.com/floegence/flowersec/flowersec-go/internal/contextutil"
	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/internal/endpointid"
	"github.com/floegence/flowersec/flowersec-go/internal/wsutil"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/realtime/ws"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

// ConnectTunnel attaches to a tunnel as role=client and returns an RPC-ready session.
func ConnectTunnel(ctx context.Context, grant *controlv1.ChannelInitGrant, opts ...ConnectOption) (Client, error) {
	start := time.Now()
	prepared, err := connectcontract.PrepareTunnelGrant(grant, controlv1.Role_client)
	if err != nil {
		return nil, wrapTunnelGrantValidateError(err)
	}
	cfg, err := applyConnectOptions(opts)
	if err != nil {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidOption, err)
	}
	observer := observability.NormalizeClientObserver(cfg.observer, observability.ClientObserverContext{
		Path: fserrors.PathTunnel,
	})
	origin := strings.TrimSpace(cfg.origin)
	if origin == "" {
		origin = strings.TrimSpace(cfg.header.Get("Origin"))
	}
	if origin == "" {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingOrigin, ErrMissingOrigin)
	}
	keepalive := cfg.keepaliveInterval
	if !cfg.keepaliveSet {
		keepalive = defaults.KeepaliveInterval(prepared.IdleTimeoutSeconds)
	}

	endpointInstanceID := cfg.endpointInstanceID
	if !cfg.endpointInstanceIDSet {
		endpointInstanceID, err = endpointid.Random(24)
		if err != nil {
			return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeRandomFailed, err)
		}
	} else if endpointInstanceID == "" {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidEndpointInstanceID, ErrInvalidEndpointInstanceID)
	} else if err := endpointid.Validate(endpointInstanceID); err != nil {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidEndpointInstanceID, ErrInvalidEndpointInstanceID)
	}
	connectTimeout := cfg.connectTimeout
	handshakeTimeout := cfg.handshakeTimeout

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	h := cloneHeader(cfg.header)
	h.Set("Origin", origin)
	c, _, err := ws.Dial(connectCtx, prepared.TunnelURL, ws.DialOptions{Header: h, Dialer: cfg.dialer})
	if err != nil {
		observer.OnConnect(fserrors.PathTunnel, observability.ConnectResultFail, classifyConnectObserverReason(err), time.Since(start))
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageConnect, fserrors.ClassifyConnectCode(err), err)
	}
	observer.OnConnect(fserrors.PathTunnel, observability.ConnectResultOK, "", time.Since(start))
	// Guard against a single oversized websocket message causing an OOM before size checks run.
	c.SetReadLimit(wsutil.ReadLimit(cfg.maxHandshakePayload, cfg.maxRecordBytes))
	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          prepared.ChannelID,
		Role:               tunnelv1.Role_client,
		Token:              prepared.Token,
		EndpointInstanceId: endpointInstanceID,
	}
	attachJSON, _ := json.Marshal(attach)
	if err := c.WriteMessage(connectCtx, websocket.TextMessage, attachJSON); err != nil {
		_ = c.Close()
		observer.OnAttach(observability.AttachResultFail, "send_failed")
		code := classifyTunnelAttachWriteCode(err)
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageAttach, code, err)
	}

	out, err := dialAfterAttach(ctx, c, fserrors.PathTunnel, endpointInstanceID, dialE2EEOptions{
		psk:               prepared.PSK,
		suite:             prepared.Suite,
		channelID:         prepared.ChannelID,
		clientFeatures:    cfg.clientFeatures,
		maxHandshakeBytes: cfg.maxHandshakePayload,
		maxRecordBytes:    cfg.maxRecordBytes,
		maxBufferedBytes:  cfg.maxBufferedBytes,
		handshakeTimeout:  handshakeTimeout,
		observer:          observer,
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
	start := time.Now()
	cfg, err := applyConnectOptions(opts)
	if err != nil {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, err)
	}
	observer := observability.NormalizeClientObserver(cfg.observer, observability.ClientObserverContext{
		Path: fserrors.PathDirect,
	})
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
	if cfg.endpointInstanceIDSet {
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidOption, ErrEndpointInstanceIDNotAllowed)
	}
	prepared, err := connectcontract.PrepareDirectConnectInfo(info)
	if err != nil {
		return nil, wrapDirectConnectValidateError(err)
	}

	connectTimeout := cfg.connectTimeout
	handshakeTimeout := cfg.handshakeTimeout

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	h := cloneHeader(cfg.header)
	h.Set("Origin", origin)
	c, _, err := ws.Dial(connectCtx, prepared.WSURL, ws.DialOptions{Header: h, Dialer: cfg.dialer})
	if err != nil {
		observer.OnConnect(fserrors.PathDirect, observability.ConnectResultFail, classifyConnectObserverReason(err), time.Since(start))
		return nil, wrapErr(fserrors.PathDirect, fserrors.StageConnect, fserrors.ClassifyConnectCode(err), err)
	}
	observer.OnConnect(fserrors.PathDirect, observability.ConnectResultOK, "", time.Since(start))
	// Guard against a single oversized websocket message causing an OOM before size checks run.
	c.SetReadLimit(wsutil.ReadLimit(cfg.maxHandshakePayload, cfg.maxRecordBytes))

	out, err := dialAfterAttach(ctx, c, fserrors.PathDirect, "", dialE2EEOptions{
		psk:               prepared.PSK,
		suite:             prepared.Suite,
		channelID:         prepared.ChannelID,
		clientFeatures:    cfg.clientFeatures,
		maxHandshakeBytes: cfg.maxHandshakePayload,
		maxRecordBytes:    cfg.maxRecordBytes,
		maxBufferedBytes:  cfg.maxBufferedBytes,
		handshakeTimeout:  handshakeTimeout,
		observer:          observer,
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
	observer         observability.ClientObserver
}

func dialAfterAttach(ctx context.Context, c *ws.Conn, path fserrors.Path, endpointInstanceID string, opts dialE2EEOptions) (*session, error) {
	handshakeStart := time.Now()
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
				opts.observer.OnAttach(observability.AttachResultFail, observability.AttachReason(code))
				opts.observer.OnHandshake(path, observability.HandshakeResultFail, code, time.Since(handshakeStart))
				return nil, wrapErr(path, fserrors.StageAttach, code, err)
			}
		}
		handshakeCode := fserrors.ClassifyHandshakeCode(err)
		if path == fserrors.PathTunnel {
			switch handshakeCode {
			case fserrors.CodeTimeout:
				opts.observer.OnAttach(observability.AttachResultFail, observability.AttachReasonTimeout)
			case fserrors.CodeCanceled:
				opts.observer.OnAttach(observability.AttachResultFail, observability.AttachReasonCanceled)
			default:
				opts.observer.OnAttach(observability.AttachResultFail, observability.AttachReasonAttachFailed)
			}
		}
		opts.observer.OnHandshake(path, observability.HandshakeResultFail, handshakeCode, time.Since(handshakeStart))
		return nil, wrapErr(path, fserrors.StageHandshake, fserrors.ClassifyHandshakeCode(err), err)
	}
	if path == fserrors.PathTunnel {
		opts.observer.OnAttach(observability.AttachResultOK, observability.AttachReasonOK)
	}
	opts.observer.OnHandshake(path, observability.HandshakeResultOK, "", time.Since(handshakeStart))

	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Client(secure, ycfg)
	if err != nil {
		_ = secure.Close()
		return nil, wrapErr(path, fserrors.StageYamux, fserrors.CodeMuxFailed, err)
	}

	rpcStream, err := openBootstrapStream(handshakeCtx, path, secure, func() (io.ReadWriteCloser, error) {
		return sess.OpenStream()
	})
	if err != nil {
		_ = sess.Close()
		_ = secure.Close()
		return nil, err
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

func openBootstrapStream(ctx context.Context, path fserrors.Path, secure interface{ SetWriteDeadline(time.Time) error }, open func() (io.ReadWriteCloser, error)) (io.ReadWriteCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, wrapErr(path, fserrors.StageYamux, classifyContextCode(err), err)
	}

	restoreSecureDeadline := armDeadlineWake(ctx, func(t time.Time) error {
		return secure.SetWriteDeadline(t)
	})
	defer restoreSecureDeadline()

	stream, err := open()
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, wrapErr(path, fserrors.StageYamux, classifyContextCode(cerr), cerr)
		}
		return nil, wrapErr(path, fserrors.StageYamux, fserrors.CodeOpenStreamFailed, err)
	}

	stopStreamWake := armStreamCancel(ctx, stream)
	defer stopStreamWake()

	if d, ok := ctx.Deadline(); ok {
		if ds, ok := any(stream).(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = ds.SetWriteDeadline(d)
			defer func() { _ = ds.SetWriteDeadline(time.Time{}) }()
		}
	}
	if err := streamhello.WriteStreamHello(stream, "rpc"); err != nil {
		_ = stream.Close()
		if cerr := ctx.Err(); cerr != nil {
			return nil, wrapErr(path, fserrors.StageYamux, classifyContextCode(cerr), cerr)
		}
		return nil, wrapErr(path, fserrors.StageRPC, fserrors.CodeStreamHelloFailed, err)
	}
	if err := ctx.Err(); err != nil {
		_ = stream.Close()
		return nil, wrapErr(path, fserrors.StageYamux, classifyContextCode(err), err)
	}
	return stream, nil
}

func armDeadlineWake(ctx context.Context, setDeadline func(time.Time) error) func() {
	if ctx == nil {
		return func() {}
	}
	if d, ok := ctx.Deadline(); ok {
		_ = setDeadline(d)
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			select {
			case <-stop:
				return
			default:
			}
			_ = setDeadline(time.Now())
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		_ = setDeadline(time.Time{})
	}
}

func armStreamCancel(ctx context.Context, stream io.Closer) func() {
	if ctx == nil {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			select {
			case <-stop:
				return
			default:
			}
			_ = stream.Close()
		case <-stop:
		}
	}()
	return func() {
		close(stop)
	}
}

func classifyConnectObserverReason(err error) observability.ConnectReason {
	switch fserrors.ClassifyConnectCode(err) {
	case fserrors.CodeTimeout:
		return observability.ConnectReasonTimeout
	case fserrors.CodeCanceled:
		return observability.ConnectReasonCanceled
	default:
		return observability.ConnectReasonWebsocketError
	}
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

func wrapTunnelGrantValidateError(err error) error {
	switch {
	case errors.Is(err, connectcontract.ErrMissingGrant):
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingGrant, ErrMissingGrant)
	case errors.Is(err, connectcontract.ErrRoleMismatch):
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeRoleMismatch, ErrExpectedRoleClient)
	case errors.Is(err, connectcontract.ErrMissingTunnelURL):
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingTunnelURL, ErrMissingTunnelURL)
	case errors.Is(err, connectcontract.ErrMissingChannelID):
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingChannelID, ErrMissingChannelID)
	case errors.Is(err, connectcontract.ErrInvalidChannelID):
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	case errors.Is(err, connectcontract.ErrMissingToken):
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingToken, ErrMissingToken)
	case errors.Is(err, connectcontract.ErrMissingInitExp):
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingInitExp, ErrMissingInitExp)
	case errors.Is(err, connectcontract.ErrInvalidPSK):
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidPSK, ErrInvalidPSK)
	case errors.Is(err, connectcontract.ErrInvalidSuite):
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidSuite, ErrInvalidSuite)
	default:
		return wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}
}

func wrapDirectConnectValidateError(err error) error {
	switch {
	case errors.Is(err, connectcontract.ErrMissingConnectInfo):
		return wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingConnectInfo, ErrMissingConnectInfo)
	case errors.Is(err, connectcontract.ErrMissingWSURL):
		return wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingWSURL, ErrMissingWSURL)
	case errors.Is(err, connectcontract.ErrMissingChannelID):
		return wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingChannelID, ErrMissingChannelID)
	case errors.Is(err, connectcontract.ErrInvalidChannelID):
		return wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	case errors.Is(err, connectcontract.ErrMissingInitExp):
		return wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeMissingInitExp, ErrMissingInitExp)
	case errors.Is(err, connectcontract.ErrInvalidPSK):
		return wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidPSK, ErrInvalidPSK)
	case errors.Is(err, connectcontract.ErrInvalidSuite):
		return wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidSuite, ErrInvalidSuite)
	default:
		return wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}
}
