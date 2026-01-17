package connect

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/floegence/flowersec/crypto/e2ee"
	directv1 "github.com/floegence/flowersec/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/internal/base64url"
	"github.com/floegence/flowersec/realtime/ws"
	"github.com/floegence/flowersec/rpc"
	hyamux "github.com/hashicorp/yamux"
)

// DirectClientOptions configures timeouts and buffer limits for direct clients.
type DirectClientOptions struct {
	ConnectTimeout   time.Duration // WebSocket connect timeout (0 disables).
	HandshakeTimeout time.Duration // Total E2EE handshake timeout (0 disables).
	MaxRecordBytes   int           // Max encrypted record size on the wire (0 uses default).
	Origin           string        // Explicit Origin header value (required).
}

// DirectClient is a convenience wrapper for a direct WS + E2EE + yamux + RPC client stack.
type DirectClient struct {
	Conn io.Closer

	Secure io.Closer
	Mux    io.Closer
	RPC    *rpc.Client

	closeAll func() error
}

// Close tears down all resources in a best-effort manner.
func (c *DirectClient) Close() error {
	if c == nil || c.closeAll == nil {
		return nil
	}
	return c.closeAll()
}

// ConnectDirectClientRPC connects to a direct websocket endpoint and returns an RPC-ready client.
func ConnectDirectClientRPC(ctx context.Context, info *directv1.DirectConnectInfo, opts DirectClientOptions) (*DirectClient, error) {
	if info == nil {
		return nil, errors.New("missing connect info")
	}
	if info.WsUrl == "" {
		return nil, errors.New("missing ws_url")
	}
	psk, err := base64url.Decode(info.E2eePskB64u)
	if err != nil {
		return nil, err
	}

	connectCtx, connectCancel := rpc.WithTimeout(ctx, opts.ConnectTimeout)
	defer connectCancel()

	if opts.Origin == "" {
		return nil, errors.New("missing origin")
	}
	h := http.Header{}
	h.Set("Origin", opts.Origin)
	c, _, err := ws.Dial(connectCtx, info.WsUrl, ws.DialOptions{Header: h})
	if err != nil {
		return nil, err
	}
	uc := c.Underlying()

	handshakeCtx, handshakeCancel := rpc.WithTimeout(ctx, opts.HandshakeTimeout)
	defer handshakeCancel()

	maxRecordBytes := opts.MaxRecordBytes
	if maxRecordBytes <= 0 {
		maxRecordBytes = 1 << 20
	}

	bt := e2ee.NewWebSocketBinaryTransport(uc)
	secure, err := e2ee.ClientHandshake(handshakeCtx, bt, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.Suite(info.DefaultSuite),
		ChannelID:           info.ChannelId,
		ClientFeatureBits:   0,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      maxRecordBytes,
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Client(secure, ycfg)
	if err != nil {
		_ = secure.Close()
		_ = c.Close()
		return nil, err
	}

	rpcStream, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		_ = secure.Close()
		_ = c.Close()
		return nil, err
	}
	if err := rpc.WriteStreamHello(rpcStream, "rpc"); err != nil {
		_ = rpcStream.Close()
		_ = sess.Close()
		_ = secure.Close()
		_ = c.Close()
		return nil, err
	}
	client := rpc.NewClient(rpcStream)

	out := &DirectClient{
		Conn:   c,
		Secure: secure,
		Mux:    sess,
		RPC:    client,
	}
	out.closeAll = func() error {
		client.Close()
		_ = rpcStream.Close()
		_ = sess.Close()
		_ = secure.Close()
		return c.Close()
	}
	return out, nil
}
