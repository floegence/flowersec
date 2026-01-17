package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/floegence/flowersec/crypto/e2ee"
	controlv1 "github.com/floegence/flowersec/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/gen/flowersec/direct/v1"
	tunnelv1 "github.com/floegence/flowersec/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/internal/base64url"
	"github.com/floegence/flowersec/internal/contextutil"
	"github.com/floegence/flowersec/realtime/ws"
	"github.com/floegence/flowersec/rpc"
	rpchello "github.com/floegence/flowersec/rpc/hello"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

// DialOptions configures timeouts and limits for both tunnel and direct clients.
type DialOptions struct {
	Origin string // Explicit Origin header value (required).

	ConnectTimeout   time.Duration // WebSocket connect timeout (0 disables).
	HandshakeTimeout time.Duration // Total E2EE handshake timeout (0 disables).

	MaxHandshakePayload int // Maximum handshake JSON payload size (0 uses default).
	MaxRecordBytes      int // Maximum encrypted record size on the wire (0 uses default).
	MaxBufferedBytes    int // Maximum buffered plaintext bytes in SecureChannel (0 uses default).

	ClientFeatures uint32 // Feature bitset advertised during the E2EE handshake.

	EndpointInstanceID string // Optional; only used for DialTunnel.
}

// DialTunnel attaches to a tunnel as role=client and returns an RPC-ready session.
func DialTunnel(ctx context.Context, grant *controlv1.ChannelInitGrant, opts DialOptions) (*Client, error) {
	if grant == nil {
		return nil, errors.New("missing grant")
	}
	if grant.Role != controlv1.Role_client {
		return nil, errors.New("expected role=client")
	}
	if grant.TunnelUrl == "" {
		return nil, errors.New("missing tunnel_url")
	}
	if opts.Origin == "" {
		return nil, errors.New("missing origin")
	}
	psk, err := base64url.Decode(grant.E2eePskB64u)
	if err != nil {
		return nil, err
	}

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, opts.ConnectTimeout)
	defer connectCancel()

	h := http.Header{}
	h.Set("Origin", opts.Origin)
	c, _, err := ws.Dial(connectCtx, grant.TunnelUrl, ws.DialOptions{Header: h})
	if err != nil {
		return nil, err
	}

	endpointInstanceID := opts.EndpointInstanceID
	if endpointInstanceID == "" {
		endpointInstanceID, err = randomB64u(24)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
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
		return nil, err
	}

	out, err := dialAfterAttach(ctx, c, PathTunnel, endpointInstanceID, dialE2EEOptions{
		psk:               psk,
		suite:             e2ee.Suite(grant.DefaultSuite),
		channelID:         grant.ChannelId,
		clientFeatures:    opts.ClientFeatures,
		maxHandshakeBytes: opts.MaxHandshakePayload,
		maxRecordBytes:    opts.MaxRecordBytes,
		maxBufferedBytes:  opts.MaxBufferedBytes,
		handshakeTimeout:  opts.HandshakeTimeout,
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return out, nil
}

// DialDirect connects to a direct websocket endpoint and returns an RPC-ready session.
func DialDirect(ctx context.Context, info *directv1.DirectConnectInfo, opts DialOptions) (*Client, error) {
	if info == nil {
		return nil, errors.New("missing connect info")
	}
	if info.WsUrl == "" {
		return nil, errors.New("missing ws_url")
	}
	if opts.Origin == "" {
		return nil, errors.New("missing origin")
	}
	psk, err := base64url.Decode(info.E2eePskB64u)
	if err != nil {
		return nil, err
	}

	connectCtx, connectCancel := contextutil.WithTimeout(ctx, opts.ConnectTimeout)
	defer connectCancel()

	h := http.Header{}
	h.Set("Origin", opts.Origin)
	c, _, err := ws.Dial(connectCtx, info.WsUrl, ws.DialOptions{Header: h})
	if err != nil {
		return nil, err
	}

	out, err := dialAfterAttach(ctx, c, PathDirect, "", dialE2EEOptions{
		psk:               psk,
		suite:             e2ee.Suite(info.DefaultSuite),
		channelID:         info.ChannelId,
		clientFeatures:    opts.ClientFeatures,
		maxHandshakeBytes: opts.MaxHandshakePayload,
		maxRecordBytes:    opts.MaxRecordBytes,
		maxBufferedBytes:  opts.MaxBufferedBytes,
		handshakeTimeout:  opts.HandshakeTimeout,
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
		return nil, err
	}

	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Client(secure, ycfg)
	if err != nil {
		_ = secure.Close()
		return nil, err
	}

	rpcStream, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		_ = secure.Close()
		return nil, err
	}
	if err := rpchello.WriteStreamHello(rpcStream, "rpc"); err != nil {
		_ = rpcStream.Close()
		_ = sess.Close()
		_ = secure.Close()
		return nil, err
	}
	rpcClient := rpc.NewClient(rpcStream)

	out := &Client{
		Path:               path,
		EndpointInstanceID: endpointInstanceID,
		Secure:             secure,
		Mux:                sess,
		RPC:                rpcClient,
		rpcStream:          rpcStream,
	}
	return out, nil
}

func randomB64u(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64url.Encode(b), nil
}
