package e2e_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/controlplane/channelinit"
	"github.com/floegence/flowersec/controlplane/issuer"
	"github.com/floegence/flowersec/crypto/e2ee"
	controlv1 "github.com/floegence/flowersec/gen/flowersec/controlplane/v1"
	rpcv1 "github.com/floegence/flowersec/gen/flowersec/rpc/v1"
	tunnelv1 "github.com/floegence/flowersec/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/internal/base64url"
	"github.com/floegence/flowersec/rpc"
	"github.com/floegence/flowersec/tunnel/server"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

func TestE2E_RPCOverTunnelE2EEYamux(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	iss, keyFile := newTestIssuer(t)
	defer os.Remove(keyFile)

	tunnelCfg := server.DefaultConfig()
	tunnelCfg.IssuerKeysFile = keyFile
	tunnelCfg.TunnelAudience = "flowersec-tunnel:dev"
	tunnelCfg.IdleTimeout = 2 * time.Second
	tunnelCfg.CleanupInterval = 50 * time.Millisecond
	tun, err := server.New(tunnelCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	mux := http.NewServeMux()
	tun.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + tunnelCfg.Path

	ci := &channelinit.Service{
		Issuer: iss,
		Params: channelinit.Params{
			TunnelURL:       wsURL,
			TunnelAudience:  tunnelCfg.TunnelAudience,
			IssuerID:        "issuer-dev",
			TokenExpSeconds: 60,
		},
	}
	grantC, grantS, err := ci.NewChannelInit("chan_e2e_1")
	if err != nil {
		t.Fatal(err)
	}

	psk, err := base64url.Decode(grantC.E2eePskB64u)
	if err != nil || len(psk) != 32 {
		t.Fatalf("bad psk: %v len=%d", err, len(psk))
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runServerEndpoint(ctx, t, wsURL, grantS, psk)
	}()

	// Client endpoint does one RPC call and then closes.
	got := runBrowserClientEndpoint(ctx, t, wsURL, grantC, psk)
	if got != `{"ok":true}` {
		t.Fatalf("unexpected rpc response payload: %s", got)
	}
}

func TestE2E_BufferingBeforePair(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	iss, keyFile := newTestIssuer(t)
	defer os.Remove(keyFile)

	tunnelCfg := server.DefaultConfig()
	tunnelCfg.IssuerKeysFile = keyFile
	tunnelCfg.TunnelAudience = "flowersec-tunnel:dev"
	tunnelCfg.IdleTimeout = 2 * time.Second
	tunnelCfg.CleanupInterval = 50 * time.Millisecond
	tun, err := server.New(tunnelCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	mux := http.NewServeMux()
	tun.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + tunnelCfg.Path

	ci := &channelinit.Service{
		Issuer: iss,
		Params: channelinit.Params{
			TunnelURL:       wsURL,
			TunnelAudience:  tunnelCfg.TunnelAudience,
			IssuerID:        "issuer-dev",
			TokenExpSeconds: 60,
		},
	}
	grantC, grantS, err := ci.NewChannelInit("chan_e2e_buf_1")
	if err != nil {
		t.Fatal(err)
	}
	psk, _ := base64url.Decode(grantC.E2eePskB64u)

	clientDone := make(chan error, 1)
	go func() {
		clientDone <- runClientHandshakeOnly(ctx, wsURL, grantC, psk)
	}()

	time.Sleep(150 * time.Millisecond)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runServerHandshakeOnly(ctx, wsURL, grantS, psk)
	}()

	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
}

func TestE2E_IdleTimeoutClosesChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	iss, keyFile := newTestIssuer(t)
	defer os.Remove(keyFile)

	tunnelCfg := server.DefaultConfig()
	tunnelCfg.IssuerKeysFile = keyFile
	tunnelCfg.TunnelAudience = "flowersec-tunnel:dev"
	tunnelCfg.IdleTimeout = 150 * time.Millisecond
	tunnelCfg.CleanupInterval = 20 * time.Millisecond
	tun, err := server.New(tunnelCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	mux := http.NewServeMux()
	tun.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + tunnelCfg.Path

	ci := &channelinit.Service{
		Issuer: iss,
		Params: channelinit.Params{
			TunnelURL:       wsURL,
			TunnelAudience:  tunnelCfg.TunnelAudience,
			IssuerID:        "issuer-dev",
			TokenExpSeconds: 60,
		},
	}
	grantC, grantS, err := ci.NewChannelInit("chan_e2e_idle_1")
	if err != nil {
		t.Fatal(err)
	}
	psk, _ := base64url.Decode(grantC.E2eePskB64u)

	serverSecureCh := make(chan *e2ee.SecureConn, 1)
	go func() {
		c, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
		if err != nil {
			serverSecureCh <- nil
			return
		}
		attach := tunnelv1.Attach{V: 1, ChannelId: grantS.ChannelId, Role: tunnelv1.Role_server, Token: grantS.Token, EndpointInstanceId: randomB64u(24)}
		b, _ := json.Marshal(attach)
		_ = c.WriteMessage(websocket.TextMessage, b)
		bt := e2ee.NewWebSocketBinaryTransport(c)
		cache := e2ee.NewServerHandshakeCache()
		secure, err := e2ee.ServerHandshake(ctx, bt, cache, e2ee.HandshakeOptions{
			PSK:                 psk,
			Suite:               e2ee.SuiteX25519HKDFAES256GCM,
			ChannelID:           grantS.ChannelId,
			InitExpireAtUnixS:   grantS.ChannelInitExpireAtUnixS,
			ClockSkew:           30 * time.Second,
			ServerFeatureBits:   1,
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
		})
		if err != nil {
			serverSecureCh <- nil
			return
		}
		serverSecureCh <- secure
	}()

	c, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	attach := tunnelv1.Attach{V: 1, ChannelId: grantC.ChannelId, Role: tunnelv1.Role_client, Token: grantC.Token, EndpointInstanceId: randomB64u(24)}
	b, _ := json.Marshal(attach)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatal(err)
	}
	bt := e2ee.NewWebSocketBinaryTransport(c)
	secureC, err := e2ee.ClientHandshake(ctx, bt, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           grantC.ChannelId,
		ClientFeatureBits:   1,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer secureC.Close()

	secureS := <-serverSecureCh
	if secureS == nil {
		t.Fatal("server handshake failed")
	}
	defer secureS.Close()

	// Trigger encrypted state by starting a yamux client session (will send encrypted frames).
	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Client(secureC, ycfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.Close()

	time.Sleep(400 * time.Millisecond)
	if err := secureC.SendPing(); err == nil {
		t.Fatal("expected connection to be closed by idle timeout")
	}
}

func runClientHandshakeOnly(ctx context.Context, wsURL string, grant *controlv1.ChannelInitGrant, psk []byte) error {
	c, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	attach := tunnelv1.Attach{V: 1, ChannelId: grant.ChannelId, Role: tunnelv1.Role_client, Token: grant.Token, EndpointInstanceId: fixedEID()}
	b, _ := json.Marshal(attach)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		return err
	}
	bt := e2ee.NewWebSocketBinaryTransport(c)
	secure, err := e2ee.ClientHandshake(ctx, bt, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           grant.ChannelId,
		ClientFeatureBits:   0,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		return err
	}
	return secure.Close()
}

func runServerHandshakeOnly(ctx context.Context, wsURL string, grant *controlv1.ChannelInitGrant, psk []byte) error {
	c, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	attach := tunnelv1.Attach{V: 1, ChannelId: grant.ChannelId, Role: tunnelv1.Role_server, Token: grant.Token, EndpointInstanceId: fixedEID()}
	b, _ := json.Marshal(attach)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		return err
	}
	bt := e2ee.NewWebSocketBinaryTransport(c)
	cache := e2ee.NewServerHandshakeCache()
	secure, err := e2ee.ServerHandshake(ctx, bt, cache, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           grant.ChannelId,
		InitExpireAtUnixS:   grant.ChannelInitExpireAtUnixS,
		ClockSkew:           30 * time.Second,
		ServerFeatureBits:   0,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		return err
	}
	return secure.Close()
}

func runServerEndpoint(ctx context.Context, t *testing.T, wsURL string, grant *controlv1.ChannelInitGrant, psk []byte) {
	t.Helper()
	c, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          grant.ChannelId,
		Role:               tunnelv1.Role_server,
		Token:              grant.Token,
		EndpointInstanceId: randomB64u(24),
	}
	attachJSON, _ := json.Marshal(attach)
	if err := c.WriteMessage(websocket.TextMessage, attachJSON); err != nil {
		t.Fatal(err)
	}

	bt := e2ee.NewWebSocketBinaryTransport(c)
	cache := e2ee.NewServerHandshakeCache()
	secure, err := e2ee.ServerHandshake(ctx, bt, cache, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           grant.ChannelId,
		InitExpireAtUnixS:   grant.ChannelInitExpireAtUnixS,
		ClockSkew:           30 * time.Second,
		ServerFeatureBits:   1,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}

	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Server(secure, ycfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	stream, err := sess.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	h, err := rpc.ReadStreamHello(stream, 8*1024)
	if err != nil {
		t.Fatal(err)
	}
	if h.Kind != "rpc" {
		t.Fatalf("unexpected kind: %s", h.Kind)
	}

	router := rpc.NewRouter()
	router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		_ = payload
		return json.RawMessage(`{"ok":true}`), nil
	})
	srv := rpc.NewServer(stream, router)
	_ = srv.Serve(ctx)
}

func runBrowserClientEndpoint(ctx context.Context, t *testing.T, wsURL string, grant *controlv1.ChannelInitGrant, psk []byte) string {
	t.Helper()
	c, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          grant.ChannelId,
		Role:               tunnelv1.Role_client,
		Token:              grant.Token,
		EndpointInstanceId: randomB64u(24),
	}
	attachJSON, _ := json.Marshal(attach)
	if err := c.WriteMessage(websocket.TextMessage, attachJSON); err != nil {
		t.Fatal(err)
	}

	bt := e2ee.NewWebSocketBinaryTransport(c)
	secure, err := e2ee.ClientHandshake(ctx, bt, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           grant.ChannelId,
		ClientFeatureBits:   1,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}

	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Client(secure, ycfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	if err := rpc.WriteStreamHello(stream, "rpc"); err != nil {
		t.Fatal(err)
	}
	client := rpc.NewClient(stream)
	payload, rpcErr, err := client.Call(ctx, 1, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if rpcErr != nil {
		t.Fatalf("rpc error: %v", rpcErr)
	}
	return string(payload)
}

func newTestIssuer(t *testing.T) (*issuer.Keyset, string) {
	t.Helper()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	priv := ed25519.NewKeyFromSeed(seed)
	ks, err := issuer.New("k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ks.ExportTunnelKeyset()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "issuer_keys.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return ks, p
}

func randomB64u(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return base64url.Encode(b)
}

func fixedEID() string {
	return base64url.Encode(make([]byte, 16))
}
