package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/client"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/v2/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/direct/v1"
	e2eev1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/e2ee/v1"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/interopprotocol"
	fsyamux "github.com/floegence/flowersec/flowersec-go/v2/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/v2/tunnel/server"
	"github.com/gorilla/websocket"
)

const interopOrigin = "https://interop.flowersec.test"

type environment struct {
	repoRoot   string
	issuer     *issuer.Keyset
	tunnel     *server.Server
	tunnelHTTP *httptest.Server
	tunnelURL  string
	upstream   *httptest.Server
	tempDir    string
	sequence   int64
	mu         sync.Mutex
}

func newEnvironment(repoRoot string) (*environment, error) {
	keyset, err := deterministicIssuer()
	if err != nil {
		return nil, err
	}
	tempDir, err := os.MkdirTemp("", "flowersec-interop-*")
	if err != nil {
		return nil, err
	}
	keyData, err := keyset.ExportTunnelKeyset()
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	keyPath := filepath.Join(tempDir, "issuer-keys.json")
	if err := os.WriteFile(keyPath, keyData, 0o600); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	config := server.DefaultConfig()
	config.IssuerKeysFile = keyPath
	config.TunnelAudience = "flowersec-interop"
	config.TunnelIssuer = "flowersec-interop"
	config.AllowedOrigins = []string{interopOrigin}
	config.CleanupInterval = 50 * time.Millisecond
	tunnel, err := server.New(config)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	mux := http.NewServeMux()
	tunnel.Register(mux)
	tunnelHTTP := httptest.NewServer(mux)
	tunnelURL := "ws" + strings.TrimPrefix(tunnelHTTP.URL, "http") + config.Path

	return &environment{
		repoRoot: repoRoot, issuer: keyset, tunnel: tunnel,
		tunnelHTTP: tunnelHTTP, tunnelURL: tunnelURL,
		upstream: newReferenceUpstream(), tempDir: tempDir,
	}, nil
}

func (e *environment) Close() error {
	if e.upstream != nil {
		e.upstream.Close()
	}
	if e.tunnelHTTP != nil {
		e.tunnelHTTP.Close()
	}
	if e.tunnel != nil {
		e.tunnel.Close()
	}
	if e.tempDir != "" {
		if err := os.RemoveAll(e.tempDir); err != nil {
			return fmt.Errorf("remove interop temporary directory: %w", err)
		}
	}
	return nil
}

func (e *environment) runGoBaseline(ctx context.Context, value variant, workload interopprotocol.Workload) (timedResult, error) {
	started := time.Now()
	var metrics interopprotocol.Metrics
	diagnostics := make([]interopprotocol.Diagnostic, 0, workload.LimitChecks)
	var err error
	switch value.Transport {
	case "direct":
		metrics, err = e.runGoDirect(ctx, value.Suite, workload, &diagnostics)
	case "tunnel":
		metrics, err = e.runGoTunnel(ctx, value.Suite, workload, &diagnostics)
	default:
		err = fmt.Errorf("unsupported transport %q", value.Transport)
	}
	return timedResult{Metrics: metrics, Diagnostics: diagnostics, Duration: time.Since(started)}, err
}

func (e *environment) runGoDirect(
	ctx context.Context,
	suiteName string,
	workload interopprotocol.Workload,
	diagnostics *[]interopprotocol.Diagnostic,
) (interopprotocol.Metrics, error) {
	credential, info, err := e.directCredential(suiteName)
	if err != nil {
		return interopprotocol.Metrics{}, err
	}
	serverCtx, cancelServer := context.WithCancel(ctx)
	defer cancelServer()
	serverDone := make(chan error, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(request *http.Request) bool {
		return request.Header.Get("Origin") == interopOrigin
	}}
	directServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			serverDone <- fmt.Errorf("upgrade direct WebSocket: %w", upgradeErr)
			return
		}
		defer connection.Close()
		session, acceptErr := endpoint.AcceptDirectWS(serverCtx, connection, endpoint.AcceptDirectOptions{
			ChannelID: credential.ChannelID, Suite: endpoint.Suite(credential.Suite),
			PSK: mustDecodePSK(credential.PSK), InitExpireAtUnixS: credential.InitExpiresAtUnix,
			ClockSkew:   30 * time.Second,
			YamuxLimits: serverYamuxLimits(workload),
		})
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serverDone <- e.serveReferenceSession(serverCtx, session, workload)
	}))
	defer directServer.Close()
	info.WsUrl = "ws" + strings.TrimPrefix(directServer.URL, "http")

	connected, err := client.ConnectDirect(ctx, info,
		client.WithOrigin(interopOrigin),
		client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
		client.WithLivenessDisabled(),
	)
	if err != nil {
		cancelServer()
		return interopprotocol.Metrics{}, errors.Join(err, waitServer(serverDone, ctx))
	}
	metrics, exerciseErr := exerciseGoClient(ctx, connected, e.upstream.URL, workload, diagnostics)
	closeErr := connected.Close()
	cancelServer()
	serverErr := waitServer(serverDone, ctx)
	if err := errors.Join(exerciseErr, closeErr, serverErr); err != nil {
		return metrics, err
	}
	reconnectMetrics, reconnectErr := e.runGoReconnect(ctx, variant{Transport: "direct", Suite: suiteName}, workload)
	metrics.Sessions += reconnectMetrics.Sessions
	metrics.Reconnects += reconnectMetrics.Reconnects
	if reconnectErr != nil {
		return metrics, reconnectErr
	}
	limitMetrics, limitErr := e.runGoLimits(ctx, variant{Transport: "direct", Suite: suiteName}, workload, diagnostics)
	mergeLimitMetrics(&metrics, limitMetrics)
	return metrics, limitErr
}

func (e *environment) runGoTunnel(
	ctx context.Context,
	suiteName string,
	workload interopprotocol.Workload,
	diagnostics *[]interopprotocol.Diagnostic,
) (interopprotocol.Metrics, error) {
	clientGrant, serverGrant, err := e.grants(suiteName)
	if err != nil {
		return interopprotocol.Metrics{}, err
	}
	serverCtx, cancelServer := context.WithCancel(ctx)
	defer cancelServer()
	serverDone := make(chan error, 1)
	go func() {
		session, connectErr := endpoint.ConnectTunnel(serverCtx, serverGrant,
			endpoint.WithOrigin(interopOrigin),
			endpoint.WithTransportSecurityPolicy(endpoint.AllowPlaintextForLoopback),
			endpoint.WithLivenessDisabled(),
			endpoint.WithYamuxLimits(serverYamuxLimits(workload)),
		)
		if connectErr != nil {
			serverDone <- connectErr
			return
		}
		serverDone <- e.serveReferenceSession(serverCtx, session, workload)
	}()
	connected, err := client.ConnectTunnel(ctx, clientGrant,
		client.WithOrigin(interopOrigin),
		client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
		client.WithLivenessDisabled(),
	)
	if err != nil {
		cancelServer()
		return interopprotocol.Metrics{}, errors.Join(err, waitServer(serverDone, ctx))
	}
	metrics, exerciseErr := exerciseGoClient(ctx, connected, e.upstream.URL, workload, diagnostics)
	closeErr := connected.Close()
	cancelServer()
	serverErr := waitServer(serverDone, ctx)
	if err := errors.Join(exerciseErr, closeErr, serverErr); err != nil {
		return metrics, err
	}
	reconnectMetrics, reconnectErr := e.runGoReconnect(ctx, variant{Transport: "tunnel", Suite: suiteName}, workload)
	metrics.Sessions += reconnectMetrics.Sessions
	metrics.Reconnects += reconnectMetrics.Reconnects
	if reconnectErr != nil {
		return metrics, reconnectErr
	}
	limitMetrics, limitErr := e.runGoLimits(ctx, variant{Transport: "tunnel", Suite: suiteName}, workload, diagnostics)
	mergeLimitMetrics(&metrics, limitMetrics)
	return metrics, limitErr
}

func mergeLimitMetrics(metrics *interopprotocol.Metrics, limits interopprotocol.Metrics) {
	metrics.Sessions += limits.Sessions
	metrics.LimitChecks += limits.LimitChecks
	metrics.ResourceRejections += limits.ResourceRejections
	metrics.BackpressureChecks += limits.BackpressureChecks
}

func serverYamuxLimits(workload interopprotocol.Workload) endpoint.YamuxLimits {
	required := uint32(max(workload.Streams.Concurrent, workload.Streams.MixedTransferCount()) + 1)
	return endpoint.YamuxLimits{
		MaxActiveStreams:  max(defaults.YamuxMaxActiveStreams, required),
		MaxInboundStreams: max(defaults.YamuxMaxInboundStreams, required),
	}
}

func (e *environment) serveReferenceSession(ctx context.Context, session endpoint.Session, workload interopprotocol.Workload) error {
	return serveReferenceSession(ctx, session, e.upstream.URL, workload)
}

func (e *environment) directCredential(suiteName string) (interopprotocol.DirectCredential, *directv1.DirectConnectInfo, error) {
	suite, endpointSuite, err := resolveSuite(suiteName)
	if err != nil {
		return interopprotocol.DirectCredential{}, nil, err
	}
	e.mu.Lock()
	e.sequence++
	sequence := e.sequence
	e.mu.Unlock()
	psk := make([]byte, 32)
	for index := range psk {
		psk[index] = byte((int(sequence) + index) % 251)
	}
	channelID := fmt.Sprintf("interop-direct-%d", sequence)
	expires := time.Now().Add(2 * time.Minute).Unix()
	encoded := base64.RawURLEncoding.EncodeToString(psk)
	credential := interopprotocol.DirectCredential{
		ChannelID: channelID, Suite: int(endpointSuite), PSK: encoded, InitExpiresAtUnix: expires,
	}
	return credential, &directv1.DirectConnectInfo{
		ChannelId: channelID, E2eePskB64u: encoded,
		ChannelInitExpireAtUnixS: expires, DefaultSuite: directv1.Suite(suite),
	}, nil
}

func (e *environment) grants(suiteName string) (*controlv1.ChannelInitGrant, *controlv1.ChannelInitGrant, error) {
	suite, _, err := resolveSuite(suiteName)
	if err != nil {
		return nil, nil, err
	}
	e.mu.Lock()
	e.sequence++
	sequence := e.sequence
	e.mu.Unlock()
	service := channelinit.Service{
		Issuer: e.issuer,
		Params: channelinit.Params{
			TunnelURL: e.tunnelURL, TunnelAudience: "flowersec-interop", IssuerID: "flowersec-interop",
			AllowedSuites: []e2eev1.Suite{e2eev1.Suite(suite)}, DefaultSuite: e2eev1.Suite(suite),
		},
	}
	return service.NewChannelInit(fmt.Sprintf("interop-tunnel-%d", sequence))
}

func resolveSuite(name string) (controlv1.Suite, endpoint.Suite, error) {
	switch name {
	case "x25519":
		return controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM, endpoint.SuiteX25519HKDFAES256GCM, nil
	case "p256":
		return controlv1.Suite_P256_HKDF_SHA256_AES_256_GCM, endpoint.SuiteP256HKDFAES256GCM, nil
	default:
		return 0, 0, fmt.Errorf("unsupported suite %q", name)
	}
}

func deterministicIssuer() (*issuer.Keyset, error) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		return nil, err
	}
	return issuer.New("interop-key", ed25519.NewKeyFromSeed(seed))
}

func mustDecodePSK(value string) []byte {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func newReferenceUpstream() *httptest.Server {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/http", func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "read failed", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("X-Flowersec-Upstream", "go-reference")
		writer.WriteHeader(http.StatusOK)
		if _, err := writer.Write(body); err != nil {
			return
		}
	})
	mux.HandleFunc("/ws", func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		for {
			messageType, payload, err := connection.ReadMessage()
			if err != nil {
				return
			}
			if err := connection.WriteMessage(messageType, payload); err != nil {
				return
			}
		}
	})
	return httptest.NewServer(mux)
}

func waitServer(done <-chan error, ctx context.Context) error {
	select {
	case err := <-done:
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, fsyamux.ErrStreamReset) {
			return nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
