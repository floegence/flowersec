package connect

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/floegence/flowersec/crypto/e2ee"
	controlv1 "github.com/floegence/flowersec/gen/flowersec/controlplane/v1"
	tunnelv1 "github.com/floegence/flowersec/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/internal/base64url"
	"github.com/floegence/flowersec/realtime/ws"
	"github.com/floegence/flowersec/rpc"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

// TunnelClientOptions configures timeouts and buffer limits for tunnel clients.
type TunnelClientOptions struct {
	ConnectTimeout   time.Duration // WebSocket connect timeout (0 disables).
	HandshakeTimeout time.Duration // Total E2EE handshake timeout (0 disables).
	MaxRecordBytes   int           // Max encrypted record size on the wire (0 uses default).
}

// TunnelClient is a convenience wrapper for a tunnel + E2EE + yamux + RPC client stack.
type TunnelClient struct {
	Conn io.Closer

	Secure io.Closer
	Mux    io.Closer
	RPC    *rpc.Client

	closeAll func() error
}

// Close tears down all resources in a best-effort manner.
func (c *TunnelClient) Close() error {
	if c == nil || c.closeAll == nil {
		return nil
	}
	return c.closeAll()
}

// ConnectTunnelClientRPC attaches to a tunnel as role=client and returns an RPC-ready client.
func ConnectTunnelClientRPC(ctx context.Context, grant *controlv1.ChannelInitGrant, opts TunnelClientOptions) (*TunnelClient, error) {
	if grant == nil {
		return nil, errors.New("missing grant")
	}
	if grant.Role != controlv1.Role_client {
		return nil, errors.New("expected role=client")
	}
	if grant.TunnelUrl == "" {
		return nil, errors.New("missing tunnel_url")
	}
	psk, err := base64url.Decode(grant.E2eePskB64u)
	if err != nil {
		return nil, err
	}

	connectCtx, connectCancel := rpc.WithTimeout(ctx, opts.ConnectTimeout)
	defer connectCancel()

	c, _, err := ws.Dial(connectCtx, grant.TunnelUrl, ws.DialOptions{})
	if err != nil {
		return nil, err
	}
	uc := c.Underlying()

	endpointInstanceID, err := randomB64u(24)
	if err != nil {
		_ = c.Close()
		return nil, err
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

	handshakeCtx, handshakeCancel := rpc.WithTimeout(ctx, opts.HandshakeTimeout)
	defer handshakeCancel()

	maxRecordBytes := opts.MaxRecordBytes
	if maxRecordBytes <= 0 {
		maxRecordBytes = 1 << 20
	}

	bt := e2ee.NewWebSocketBinaryTransport(uc)
	secure, err := e2ee.ClientHandshake(handshakeCtx, bt, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.Suite(grant.DefaultSuite),
		ChannelID:           grant.ChannelId,
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

	out := &TunnelClient{
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

func randomB64u(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64url.Encode(b), nil
}
