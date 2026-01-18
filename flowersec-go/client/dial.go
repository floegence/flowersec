package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/floegence/flowersec/flowersec-go/internal/contextutil"
	"github.com/floegence/flowersec/flowersec-go/internal/endpointid"
	"github.com/floegence/flowersec/flowersec-go/realtime/ws"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	rpchello "github.com/floegence/flowersec/flowersec-go/rpc/hello"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

// ConnectTunnel attaches to a tunnel as role=client and returns an RPC-ready session.
func ConnectTunnel(ctx context.Context, grant *controlv1.ChannelInitGrant, origin string, opts ...TunnelConnectOption) (*Client, error) {
	if grant == nil {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingGrant, ErrMissingGrant)
	}
	if grant.Role != controlv1.Role_client {
		return nil, wrapErr(PathTunnel, StageValidate, CodeRoleMismatch, ErrExpectedRoleClient)
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
	cfg, err := applyTunnelConnectOptions(opts)
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

	endpointInstanceID := cfg.endpointInstanceID
	if endpointInstanceID == "" {
		endpointInstanceID, err = endpointid.Random(24)
		if err != nil {
			return nil, wrapErr(PathTunnel, StageValidate, CodeRandomFailed, err)
		}
	} else if err := endpointid.Validate(endpointInstanceID); err != nil {
		return nil, wrapErr(PathTunnel, StageValidate, CodeInvalidEndpointInstanceID, ErrInvalidEndpointInstanceID)
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
		return nil, wrapErr(PathTunnel, StageAttach, CodeAttachFailed, err)
	}

	out, err := dialAfterAttach(ctx, c, PathTunnel, endpointInstanceID, dialE2EEOptions{
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
	return out, nil
}

// ConnectDirect connects to a direct websocket endpoint and returns an RPC-ready session.
func ConnectDirect(ctx context.Context, info *directv1.DirectConnectInfo, origin string, opts ...DirectConnectOption) (*Client, error) {
	if info == nil {
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingConnectInfo, ErrMissingConnectInfo)
	}
	if info.WsUrl == "" {
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingWSURL, ErrMissingWSURL)
	}
	if origin == "" {
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingOrigin, ErrMissingOrigin)
	}
	if info.ChannelId == "" {
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingChannelID, ErrMissingChannelID)
	}
	cfg, err := applyDirectConnectOptions(opts)
	if err != nil {
		return nil, wrapErr(PathDirect, StageValidate, CodeInvalidOption, err)
	}
	psk, err := base64url.Decode(info.E2eePskB64u)
	if err != nil || len(psk) != 32 {
		if err == nil {
			err = ErrInvalidPSK
		}
		return nil, wrapErr(PathDirect, StageValidate, CodeInvalidPSK, err)
	}
	suite := e2ee.Suite(info.DefaultSuite)
	switch suite {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
	default:
		return nil, wrapErr(PathDirect, StageValidate, CodeInvalidSuite, ErrInvalidSuite)
	}

	connectTimeout := cfg.connectTimeout
	handshakeTimeout := cfg.handshakeTimeout

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	h := cloneHeader(cfg.header)
	h.Set("Origin", origin)
	c, _, err := ws.Dial(connectCtx, info.WsUrl, ws.DialOptions{Header: h, Dialer: cfg.dialer})
	if err != nil {
		return nil, wrapErr(PathDirect, StageConnect, CodeDialFailed, err)
	}

	out, err := dialAfterAttach(ctx, c, PathDirect, "", dialE2EEOptions{
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
	return out, nil
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

func dialAfterAttach(ctx context.Context, c *ws.Conn, path Path, endpointInstanceID string, opts dialE2EEOptions) (*Client, error) {
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
		return nil, wrapErr(path, StageHandshake, CodeHandshakeFailed, err)
	}

	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Client(secure, ycfg)
	if err != nil {
		_ = secure.Close()
		return nil, wrapErr(path, StageYamux, CodeMuxFailed, err)
	}

	rpcStream, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		_ = secure.Close()
		return nil, wrapErr(path, StageYamux, CodeOpenStreamFailed, err)
	}
	if err := rpchello.WriteStreamHello(rpcStream, "rpc"); err != nil {
		_ = rpcStream.Close()
		_ = sess.Close()
		_ = secure.Close()
		return nil, wrapErr(path, StageRPC, CodeStreamHelloFailed, err)
	}
	rpcClient := rpc.NewClient(rpcStream)

	out := &Client{
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
