package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/framing/jsonframe"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/rpc"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/rpcwire"
	session "github.com/floegence/flowersec/flowersec-go/v7/internal/sessionv3"
)

func TestDirectMethodsAuthenticatedTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections atomic.Int32
	var peers sync.WaitGroup
	notified := make(chan struct{}, 2)
	blocked := make(chan struct{})
	streamWaiting := make(chan struct{})
	shutdownBlocked := make(chan struct{})
	allowExit := make(chan struct{})
	t.Cleanup(func() { close(allowExit); listener.Close(); peers.Wait() })
	framed := []byte{0, 0, 0, 3, 0, 'a', 255, 0, 0, 0, 0}
	peers.Go(func() {
		for {
			peer, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			peers.Go(func() {
				defer peer.Close()
				_ = peer.SetDeadline(time.Now().Add(8 * time.Second))
				input, err := io.ReadAll(peer)
				if err != nil {
					return
				}
				switch string(input) {
				case `{"ask":true}`:
					_, _ = io.WriteString(peer, `{"answer":42}`)
				case `"notice"`:
					notified <- struct{}{}
				case `"invalid"`:
					_, _ = io.WriteString(peer, `bad`)
				case `"large"`:
					_, _ = io.WriteString(peer, strings.Repeat("1", 33))
				case "stream":
					_, _ = peer.Write(framed)
				case "wait-for-reset":
					close(streamWaiting)
					<-allowExit
				case "truncated":
					_, _ = peer.Write([]byte{0, 0, 0, 3, 'a'})
				case `"stall"`:
					close(blocked)
					<-allowExit
				case `"shutdown"`:
					close(shutdownBlocked)
					<-allowExit
				default:
					t.Errorf("unexpected TCP payload %q", input)
				}
			})
		}
	})
	address := listener.Addr().String()
	unary := directMethodSpec{Shape: "unary", TypeID: 100, AllowedChannels: []string{"direct-client-test"}, Upstream: address, TimeoutMS: 2500, MaxRequest: 24, MaxResponse: 32}
	notice := unary
	notice.TypeID, notice.Shape, notice.MaxResponse = 101, "notification", 0
	stream := unary
	stream.Shape, stream.TypeID, stream.Kind, stream.Metadata, stream.MaxItems, stream.MaxTotal = "stream", 0, "reports", map[string]any{"scope": "rows"}, 2, 32
	forbidden := unary
	forbidden.TypeID, forbidden.AllowedChannels = 102, []string{"another-channel"}
	otherListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer otherListener.Close()
	wrongTarget := unary
	wrongTarget.TypeID, wrongTarget.Upstream = 103, otherListener.Addr().String()
	stall := unary
	stall.TypeID, stall.TimeoutMS = 104, 200
	service := &directServiceConfig{Slots: 2, RPCFrameBytes: 4096, Methods: []directMethodSpec{unary, notice, stream, forbidden, wrongTarget, stall}}
	server := httptest.NewUnstartedServer(nil)
	issued := directTestArtifactForTCP(t, "wss://"+server.Listener.Addr().String()+webSocketDirectPath, address)
	var admits, releases atomic.Int32
	authority := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/release" {
			releases.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 64<<10))
		if err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		request, err := controlplane.ParseRuntimeAuthorizationRequest(body)
		if err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if admits.Add(1) != 1 {
			http.Error(w, "spent", 403)
			return
		}
		decision, err := controlplane.AuthorizeRuntime(request, issued.AuthorizationRecord(), "methods-lease")
		if err != nil || !decision.Allowed() {
			http.Error(w, "invalid", 400)
			return
		}
		_, _ = w.Write(decision.JSON())
	}))
	t.Cleanup(authority.Close)
	config, err := decodeConfig([]byte(validConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	config.Role, config.DirectServices = "direct-server", service
	config.TLS.CertificateFile, config.TLS.PrivateKeyFile = writeTestCertificate(t)
	config.AllowedOrigins = []string{"https://app.example"}
	host, err := newRuntimeServer(config, &httpAuthorizationProvider{url: authority.URL, releaseURL: authority.URL + "/release", client: authority.Client()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(t.Context())
	server.Config.Handler = host.webSocketHandler(serverCtx)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(func() { stopServer(); server.Close(); host.sessionWG.Wait() })
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	artifact, err := flowersec.ParseArtifact(issued.ArtifactJSON())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	client, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{TrustRoots: roots, Origin: "https://app.example"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if connections.Load() != 0 {
		t.Fatal("admission dialed a method")
	}
	callError := func(id uint32, payload any, code uint32) {
		t.Helper()
		err := client.RPC().Call(ctx, id, payload, nil)
		var app *flowersec.RPCError
		if !errors.As(err, &app) || app.Code != code {
			t.Fatalf("Call(%d) = %v, want %d", id, err, code)
		}
	}
	var answer struct {
		Answer int `json:"answer"`
	}
	if err := client.RPC().Call(ctx, 100, map[string]bool{"ask": true}, &answer); err != nil || answer.Answer != 42 {
		t.Fatalf("answer=%+v err=%v", answer, err)
	}
	for _, id := range []uint32{101, 102, 103, 999} {
		callError(id, "denied", 404)
	}
	callError(100, strings.Repeat("x", 24), 413)
	if err := client.RPC().Notify(ctx, 100, "wrong shape"); err != nil {
		t.Fatal(err)
	}
	if err := client.RPC().Notify(ctx, 101, "notice"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-notified:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	metadata, err := flowersec.NewStreamMetadata(stream.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	readStream := func(kind string, meta flowersec.StreamMetadata, input string) ([]byte, error) {
		t.Helper()
		current, err := client.OpenStream(ctx, kind, meta)
		if err != nil {
			return nil, err
		}
		defer current.Close()
		if _, err = io.WriteString(current, input); err != nil {
			return nil, err
		}
		if err = current.CloseWrite(); err != nil {
			return nil, err
		}
		return io.ReadAll(current)
	}
	for _, denied := range []struct {
		kind  string
		meta  flowersec.StreamMetadata
		input string
	}{{"unknown", metadata, "bypass"}, {stream.Kind, flowersec.EmptyStreamMetadata(), "mismatch"}, {stream.Kind, metadata, strings.Repeat("x", 25)}} {
		if _, err := readStream(denied.kind, denied.meta, denied.input); err == nil {
			t.Fatal("unauthorized or oversized stream did not fail")
		}
	}
	if got := connections.Load(); got != 2 {
		t.Fatalf("after authorized unary/notify and denied traffic: %d TCP connections", got)
	}
	if got, err := readStream(stream.Kind, metadata, "stream"); err != nil || !bytes.Equal(got, framed) {
		t.Fatalf("stream=%x err=%v", got, err)
	}
	if got, err := readStream(stream.Kind, metadata, "truncated"); err == nil || len(got) != 0 {
		t.Fatalf("truncated item=%x err=%v", got, err)
	}
	waiting, err := client.OpenStream(ctx, stream.Kind, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(waiting, "wait-for-reset"); err != nil {
		t.Fatal(err)
	}
	if err := waiting.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-streamWaiting:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := waiting.Reset(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(host.services.slots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("reset did not release the upstream method slot before its deadline")
		}
		time.Sleep(time.Millisecond)
	}
	callError(100, "invalid", 502)
	callError(100, "large", 502)
	callError(104, "stall", 504)
	select {
	case <-blocked:
	default:
		t.Fatal("timed exchange never reached TCP")
	}
	if err := client.RPC().Call(ctx, 100, map[string]bool{"ask": true}, &answer); err != nil {
		t.Fatalf("session did not recover after timeout: %v", err)
	}
	partial, err := client.OpenStream(ctx, stream.Kind, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(partial, "incomplete"); err != nil {
		t.Fatal(err)
	}
	callDone := make(chan error, 1)
	go func() { callDone <- client.RPC().Call(ctx, unary.TypeID, "shutdown", nil) }()
	select {
	case <-shutdownBlocked:
	case <-ctx.Done():
		t.Fatal("active call did not reach upstream before shutdown")
	}
	if releases.Load() != 0 {
		t.Fatal("released an active method lease")
	}
	stopServer()
	select {
	case err := <-callDone:
		if err == nil {
			t.Fatal("shutdown completed a blocked call successfully")
		}
	case <-ctx.Done():
		t.Fatal("shutdown did not end the blocked call")
	}
	if _, err := io.ReadAll(partial); err == nil {
		t.Fatal("shutdown reported clean EOF on an incomplete request")
	}
	host.sessionWG.Wait()
	if admits.Load() != 1 || releases.Load() != 1 || len(host.services.slots) != 0 {
		t.Fatalf("admits/releases/active slots=%d/%d/%d", admits.Load(), releases.Load(), len(host.services.slots))
	}
	_ = otherListener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
	other, err := otherListener.Accept()
	if err == nil {
		other.Close()
		t.Fatal("dialed a target absent from original grant")
	}
}

func TestDirectMethodLimitsAndStrictConfig(t *testing.T) {
	config := directServiceConfig{Slots: 2, RPCFrameBytes: 256, Methods: []directMethodSpec{{Shape: "stream", Kind: "items", AllowedChannels: []string{"chan"}, Upstream: "127.0.0.1:8888", TimeoutMS: 100, MaxRequest: 32, MaxResponse: 3, MaxItems: 2, MaxTotal: 4}}}
	host, err := prepareDirectServices(&config)
	if err != nil {
		t.Fatal(err)
	}
	method := host.streams["items"]
	for _, sample := range []struct {
		name             string
		input, published []byte
	}{
		{"partial header", []byte{0}, nil}, {"oversize item", []byte{0, 0, 0, 4}, nil}, {"partial item", []byte{0, 0, 0, 3, 1}, nil},
		{"total", []byte{0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2}, []byte{0, 0, 0, 3, 1, 2, 3}}, {"count includes empty", make([]byte, 12), make([]byte, 8)},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := method.copyItems(&output, bytes.NewReader(sample.input)); err == nil || !bytes.Equal(output.Bytes(), sample.published) {
				t.Fatalf("published %x, err=%v", output.Bytes(), err)
			}
		})
	}
	raw, _ := json.Marshal(config)
	base := strings.Replace(validConfigJSON(), `"tls":`, `"role":"direct-server","direct_services":`+string(raw)+`,"tls":`, 1)
	for _, invalid := range []string{strings.Replace(base, `"role":"direct-server",`, "", 1), strings.Replace(base, `"upstream":`, `"upstream":"127.0.0.1:3","upstream":`, 1), strings.Replace(base, `"kind":"items"`, `"kind":"flowersec.rpc.v5"`, 1), strings.Replace(base, `"slots":2`, `"slots":0`, 1), strings.Replace(base, `"127.0.0.1:8888"`, `"localhost:8888"`, 1), strings.Replace(base, `["chan"]`, `[]`, 1)} {
		parsed, err := decodeConfig([]byte(invalid))
		if err == nil {
			_, err = prepareDirectServices(parsed.DirectServices)
		}
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid method config unexpectedly accepted: %v", err)
		}
	}
}

func TestDirectMethodQueueDeadlinePreventsLateDial(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	first := directMethodSpec{Shape: "unary", TypeID: 1, Upstream: listener.Addr().String(), AllowedChannels: []string{"reports"}, TimeoutMS: 3000, MaxRequest: 16, MaxResponse: 16}
	queued := first
	queued.TypeID, queued.TimeoutMS = 2, 40
	host, err := prepareDirectServices(&directServiceConfig{Methods: []directMethodSpec{first, queued}, Slots: 1, RPCFrameBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	var config session.Config
	host.installRPC(&config, directMethodGrant{channel: "reports", target: upstreamTarget{Network: "tcp", Address: first.Upstream}})
	client, server := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(4 * time.Second))
	endpoint, err := rpc.NewServerWithOptions(server, config.RPCRouter, config.RPCServerOptions)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = endpoint.Serve(ctx) }()
	defer func() { cancel(); _ = client.Close(); <-done }()
	send := func(id uint32, seq uint64) {
		t.Helper()
		if err := jsonframe.WriteJSONFrame(client, rpcwire.RpcEnvelope{TypeId: id, RequestId: seq, Payload: json.RawMessage(`true`)}); err != nil {
			t.Fatal(err)
		}
	}
	send(1, 1)
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
	input, err := io.ReadAll(peer)
	if err != nil || string(input) != "true" {
		t.Fatalf("first call TCP payload=%q err=%v", input, err)
	}
	send(2, 2)
	send(99, 0)
	<-time.After(time.Duration(queued.TimeoutMS+20) * time.Millisecond)
	if _, err := io.WriteString(peer, "null"); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint64{1, 2} {
		raw, err := jsonframe.ReadJSONFrame(client, 1024)
		if err != nil {
			t.Fatal(err)
		}
		var response rpcwire.RpcEnvelope
		if err = json.Unmarshal(raw, &response); err != nil || response.ResponseTo != id || id == 1 && response.Error != nil || id == 2 && (response.Error == nil || response.Error.Code != 504) {
			t.Fatalf("unexpected response for %d: %s (%v)", id, raw, err)
		}
	}
	_ = listener.SetDeadline(time.Now().Add(20 * time.Millisecond))
	extra, err := listener.AcceptTCP()
	if err == nil {
		extra.Close()
		t.Fatal("expired queued call reached TCP")
	}
}
