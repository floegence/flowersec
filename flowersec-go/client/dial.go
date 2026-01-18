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
	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/internal/endpointid"
	"github.com/floegence/flowersec/flowersec-go/realtime/ws"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	rpchello "github.com/floegence/flowersec/flowersec-go/rpc/hello"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

// TunnelConnectOptions configures timeouts and limits for tunnel clients.
type TunnelConnectOptions struct {
	Origin string // Explicit Origin header value (required).

	Header http.Header       // Optional headers for the WebSocket handshake.
	Dialer *websocket.Dialer // Optional websocket dialer (proxy/TLS/etc).

	ConnectTimeout   time.Duration // WebSocket connect timeout (0 uses default; <0 disables).
	HandshakeTimeout time.Duration // Total E2EE handshake timeout (0 uses default; <0 disables).

	MaxHandshakePayload int // Maximum handshake JSON payload size (0 uses default).
	MaxRecordBytes      int // Maximum encrypted record size on the wire (0 uses default).
	MaxBufferedBytes    int // Maximum buffered plaintext bytes in SecureChannel (0 uses default).

	ClientFeatures uint32 // Feature bitset advertised during the E2EE handshake.

	EndpointInstanceID string // Optional endpoint instance ID (base64url); empty generates a random value.
}

// DirectConnectOptions configures timeouts and limits for direct clients.
type DirectConnectOptions struct {
	Origin string // Explicit Origin header value (required).

	Header http.Header       // Optional headers for the WebSocket handshake.
	Dialer *websocket.Dialer // Optional websocket dialer (proxy/TLS/etc).

	ConnectTimeout   time.Duration // WebSocket connect timeout (0 uses default; <0 disables).
	HandshakeTimeout time.Duration // Total E2EE handshake timeout (0 uses default; <0 disables).

	MaxHandshakePayload int // Maximum handshake JSON payload size (0 uses default).
	MaxRecordBytes      int // Maximum encrypted record size on the wire (0 uses default).
	MaxBufferedBytes    int // Maximum buffered plaintext bytes in SecureChannel (0 uses default).

	ClientFeatures uint32 // Feature bitset advertised during the E2EE handshake.
}

// ConnectTunnel attaches to a tunnel as role=client and returns an RPC-ready session.
func ConnectTunnel(ctx context.Context, grant *controlv1.ChannelInitGrant, opts TunnelConnectOptions) (*Client, error) {
	if grant == nil {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingGrant, ErrMissingGrant)
	}
	if grant.Role != controlv1.Role_client {
		return nil, wrapErr(PathTunnel, StageValidate, CodeRoleMismatch, ErrExpectedRoleClient)
	}
	if grant.TunnelUrl == "" {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingTunnelURL, ErrMissingTunnelURL)
	}
	if opts.Origin == "" {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingOrigin, ErrMissingOrigin)
	}
	if grant.ChannelId == "" {
		return nil, wrapErr(PathTunnel, StageValidate, CodeMissingChannelID, ErrMissingChannelID)
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

	endpointInstanceID := opts.EndpointInstanceID
	if endpointInstanceID == "" {
		endpointInstanceID, err = endpointid.Random(24)
		if err != nil {
			return nil, wrapErr(PathTunnel, StageValidate, CodeRandomFailed, err)
		}
	} else if err := endpointid.Validate(endpointInstanceID); err != nil {
		return nil, wrapErr(PathTunnel, StageValidate, CodeInvalidEndpointInstanceID, ErrInvalidEndpointInstanceID)
	}

	connectTimeout := opts.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = defaults.ConnectTimeout
	}
	handshakeTimeout := opts.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = defaults.HandshakeTimeout
	}

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	h := cloneHeader(opts.Header)
	h.Set("Origin", opts.Origin)
	c, _, err := ws.Dial(connectCtx, grant.TunnelUrl, ws.DialOptions{Header: h, Dialer: opts.Dialer})
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
		clientFeatures:    opts.ClientFeatures,
		maxHandshakeBytes: opts.MaxHandshakePayload,
		maxRecordBytes:    opts.MaxRecordBytes,
		maxBufferedBytes:  opts.MaxBufferedBytes,
		handshakeTimeout:  handshakeTimeout,
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return out, nil
}

// ConnectDirect connects to a direct websocket endpoint and returns an RPC-ready session.
func ConnectDirect(ctx context.Context, info *directv1.DirectConnectInfo, opts DirectConnectOptions) (*Client, error) {
	if info == nil {
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingConnectInfo, ErrMissingConnectInfo)
	}
	if info.WsUrl == "" {
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingWSURL, ErrMissingWSURL)
	}
	if opts.Origin == "" {
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingOrigin, ErrMissingOrigin)
	}
	if info.ChannelId == "" {
		return nil, wrapErr(PathDirect, StageValidate, CodeMissingChannelID, ErrMissingChannelID)
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

	connectTimeout := opts.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = defaults.ConnectTimeout
	}
	handshakeTimeout := opts.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = defaults.HandshakeTimeout
	}

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	h := cloneHeader(opts.Header)
	h.Set("Origin", opts.Origin)
	c, _, err := ws.Dial(connectCtx, info.WsUrl, ws.DialOptions{Header: h, Dialer: opts.Dialer})
	if err != nil {
		return nil, wrapErr(PathDirect, StageConnect, CodeDialFailed, err)
	}

	out, err := dialAfterAttach(ctx, c, PathDirect, "", dialE2EEOptions{
		psk:               psk,
		suite:             suite,
		channelID:         info.ChannelId,
		clientFeatures:    opts.ClientFeatures,
		maxHandshakeBytes: opts.MaxHandshakePayload,
		maxRecordBytes:    opts.MaxRecordBytes,
		maxBufferedBytes:  opts.MaxBufferedBytes,
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
