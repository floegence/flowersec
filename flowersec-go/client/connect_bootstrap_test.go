package client

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/crypto/e2ee"
	directv1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/direct/v1"
	fsyamux "github.com/floegence/flowersec/flowersec-go/v2/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/v2/streamhello"
	"github.com/gorilla/websocket"
)

func TestConnectDirect_RPCBootstrapDoesNotRequireYamuxPingACK(t *testing.T) {
	const (
		origin    = "http://example.com"
		channelID = "ch_pingless_bootstrap"
	)
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	initExp := time.Now().Add(2 * time.Minute).Unix()
	rpcBootstrapped := make(chan struct{})
	serverErr := make(chan error, 1)

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		serverErr <- servePingDroppingDirectPeer(conn, psk, channelID, initExp, rpcBootstrapped)
	}))
	t.Cleanup(server.Close)

	client, err := ConnectDirect(
		context.Background(),
		&directv1.DirectConnectInfo{
			WsUrl:                    "ws" + strings.TrimPrefix(server.URL, "http"),
			ChannelId:                channelID,
			E2eePskB64u:              base64.RawURLEncoding.EncodeToString(psk),
			ChannelInitExpireAtUnixS: initExp,
			DefaultSuite:             directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
		},
		WithOrigin(origin),
		WithConnectTimeout(time.Second),
		WithHandshakeTimeout(time.Second),
		WithTransportSecurityPolicy(AllowPlaintextForLoopback),
	)
	if err != nil {
		t.Fatalf("ConnectDirect() failed before RPC bootstrap: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	select {
	case <-rpcBootstrapped:
	case <-time.After(time.Second):
		t.Fatal("peer did not receive the RPC StreamHello")
	}

	probeCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = client.ProbeLiveness(probeCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ProbeLiveness() error = %v, want deadline exceeded", err)
	}
	var flowersecErr *Error
	if !errors.As(err, &flowersecErr) {
		t.Fatalf("ProbeLiveness() error type = %T, want *client.Error", err)
	}
	if flowersecErr.Path != PathDirect || flowersecErr.Stage != StageYamux || flowersecErr.Code != CodeTimeout {
		t.Fatalf("ProbeLiveness() error = %+v, want direct/yamux/timeout", flowersecErr)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("ping-dropping peer failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ping-dropping peer did not stop after probe timeout")
	}
}

func servePingDroppingDirectPeer(
	conn *websocket.Conn,
	psk []byte,
	channelID string,
	initExp int64,
	rpcBootstrapped chan<- struct{},
) error {
	defer conn.Close()
	handshakeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	secure, err := e2ee.ServerHandshake(
		handshakeCtx,
		e2ee.NewWebSocketBinaryTransport(conn),
		nil,
		e2ee.ServerHandshakeOptions{
			PSK:               psk,
			Suite:             e2ee.SuiteX25519HKDFAES256GCM,
			ChannelID:         channelID,
			InitExpireAtUnixS: initExp,
			ClockSkew:         30 * time.Second,
		},
	)
	cancel()
	if err != nil {
		return err
	}
	defer secure.Close()

	mux, err := fsyamux.NewServer(&dropYamuxPingACKConn{Conn: secure}, fsyamux.YamuxLimits{}, fsyamux.LivenessOptions{})
	if err != nil {
		return err
	}
	defer mux.Close()

	stream, err := mux.AcceptStream()
	if err != nil {
		return err
	}
	defer stream.Close()
	hello, err := streamhello.ReadStreamHello(stream, 8*1024)
	if err != nil {
		return err
	}
	if hello.Kind != "rpc" {
		return errors.New("unexpected bootstrap stream kind: " + hello.Kind)
	}
	close(rpcBootstrapped)
	<-mux.CloseChan()
	return nil
}

type dropYamuxPingACKConn struct {
	net.Conn
	mu sync.Mutex
}

func (c *dropYamuxPingACKConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 12 && p[0] == 0 && p[1] == 2 && binary.BigEndian.Uint16(p[2:4])&2 != 0 {
		return len(p), nil
	}
	return writeFull(c.Conn, p)
}

func writeFull(w io.Writer, p []byte) (int, error) {
	written := 0
	for written < len(p) {
		n, err := w.Write(p[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
