package websocket

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv4"
	ws "github.com/gorilla/websocket"
)

var _ sessionv4.InitialMessages = (*Messages)(nil)

func testOptions() Options {
	return Options{MaxMessageBytes: 264, ReadBufferBytes: 125, WriteBufferBytes: 125,
		HandshakeBytes: 4096, MaxControlsPerSecond: 8, HandshakeTimeout: time.Second, MessageTimeout: time.Second,
		RuntimeBytes: 16384, ProviderRuntimeBytes: 65536, ProviderTasks: 4}
}

func reservations(t *testing.T, charge resourcev4.Vector) (*resourcev4.Root, resourcev4.Reference, resourcev4.Reference) {
	t.Helper()
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 2, ReservationSlots: 4, ReferenceSlots: 8}
	backing, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit = charge
	config.Limit[resourcev4.SDKBytes] += backing + 1024
	config.Limit[resourcev4.Items]++
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	key := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := root.Reserve(key, resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	key.Instance, key.Backing = [16]byte{2}, [16]byte{2}
	ref, err := root.Reserve(key, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	t.Cleanup(environment.Release)
	t.Cleanup(ref.Release)
	return root, ref, environment
}

func cleanupMessages(t *testing.T, messages *Messages) {
	t.Helper()
	t.Cleanup(func() {
		_ = messages.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := messages.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := messages.Retire(); err != nil {
			t.Error(err)
		}
	})
}

func localPolicy(u *url.URL, remote netip.AddrPort, _ http.Header) error {
	if err := checkEndpoint(u, remote); err != nil {
		return err
	}
	if u.Scheme != "ws" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.Path != "/flowersec/v4/local" {
		return resourcev4.ErrConfiguration
	}
	return nil
}

func rawServer(t *testing.T, handler func(*ws.Conn)) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := ws.Upgrader{Subprotocols: []string{SubprotocolLocal}, ReadBufferSize: 125, WriteBufferSize: 125}
		conn, err := u.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		handler(conn)
	}))
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http") + "/flowersec/v4/local"
}

func preparedAddress(t *testing.T, address string) netip.AddrPort {
	t.Helper()
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := netip.ParseAddrPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func dialPair(t *testing.T, options Options) (*Messages, *ws.Conn, *resourcev4.Root) {
	t.Helper()
	peers := make(chan *ws.Conn, 1)
	address := rawServer(t, func(conn *ws.Conn) { peers <- conn })
	charge, err := Charge(options)
	if err != nil {
		t.Fatal(err)
	}
	root, ref, environment := reservations(t, charge)
	ctx, cancel := context.WithCancel(context.Background())
	messages, err := Dial(ctx, DialConfig{URL: address, RemoteAddress: preparedAddress(t, address), Subprotocol: SubprotocolLocal, CheckPolicy: localPolicy}, options, ref, environment)
	cancel() // A successful prepare transfers out of this canceled call context.
	if err != nil {
		t.Fatal(err)
	}
	cleanupMessages(t, messages)
	peer := <-peers
	t.Cleanup(func() { _ = peer.Close() })
	return messages, peer, root
}

func TestMessageBoundariesAndFragmentation(t *testing.T) {
	m, peer, _ := dialPair(t, testOptions())
	g, err := m.ConnectionGuarantees()
	if err != nil || g.LocalConsumerTls13Verification != protocolv4.V4ConsumerTLS13VerificationNotApplicable || g.ReliableProgress != protocolv4.V4ReliableProgressSharedOrdered || g.Datagram {
		t.Fatalf("loopback invented stronger assurances: %+v %v", g, err)
	}
	first := bytes.Repeat([]byte{7}, 250)
	writer, err := peer.NextWriter(ws.BinaryMessage)
	if err != nil {
		t.Fatal(err)
	}
	// A 125-byte Gorilla writer forces physical continuation frames.
	if _, err := writer.Write(first[:200]); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(first[200:]); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	second := []byte("second")
	if err := peer.WriteMessage(ws.BinaryMessage, second); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 264)
	if n, err := m.ReadMessage(context.Background(), dst); err != nil || !bytes.Equal(dst[:n], first) {
		t.Fatalf("first: %d %v", n, err)
	}
	if n, err := m.ReadMessage(context.Background(), dst); err != nil || !bytes.Equal(dst[:n], second) {
		t.Fatalf("second: %d %v", n, err)
	}
	if err := m.WriteMessage(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteMessage(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	kind, body, err := peer.ReadMessage()
	if err != nil || kind != ws.BinaryMessage || !bytes.Equal(body, first) {
		t.Fatalf("write: %d %x %v", kind, body, err)
	}
}

func TestMessageInputRejectsEnvelopeBoundaries(t *testing.T) {
	valid, err := (protocolv4.Envelope{FrameType: protocolv4.FramePing, Payload: []byte{1}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		frames [][]byte
	}{
		{"empty", [][]byte{{}}}, {"short", [][]byte{{1, 2}}},
		{"split", [][]byte{valid[:8], valid[8:]}},
		{"concatenated", [][]byte{append(append([]byte{}, valid...), valid...)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider, peer, _ := dialPair(t, testOptions())
			options := sessionv4.SessionMessageInputOptions{MaxFrame: 256, WriteSlots: 3, RuntimeBytes: 16384}
			charge, err := sessionv4.SessionMessageInputCharge(options)
			if err != nil {
				t.Fatal(err)
			}
			_, ref, environment := reservations(t, charge)
			input, err := sessionv4.NewSessionMessageInput(context.Background(), provider, options, ref, environment)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = input.Close()
				if err := input.WaitCleanup(context.Background()); err != nil {
					t.Error(err)
				}
				if err := input.Retire(); err != nil {
					t.Error(err)
				}
			})
			for _, wire := range tc.frames {
				if err := peer.WriteMessage(ws.BinaryMessage, wire); err != nil {
					t.Fatal(err)
				}
			}
			var dst [512]byte
			if n, err := input.Read(dst[:]); n != 0 || !errors.Is(err, sessionv4.ErrSessionMessageFraming) {
				t.Fatalf("exposed invalid envelope: %d %v", n, err)
			}
		})
	}
}

func TestRejectsTextOversizeAndTruncation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		kind, size       int
		shortDestination bool
		want             error
	}{
		{"text", ws.TextMessage, 10, false, ErrNonBinary},
		{"message-limit", ws.BinaryMessage, 265, false, protocolv4.ErrPayloadTooLarge},
		{"destination-limit", ws.BinaryMessage, 100, true, protocolv4.ErrPayloadTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, peer, _ := dialPair(t, testOptions())
			if err := peer.WriteMessage(tc.kind, bytes.Repeat([]byte{1}, tc.size)); err != nil {
				t.Fatal(err)
			}
			dst := make([]byte, 264)
			if tc.shortDestination {
				dst = dst[:99]
			}
			if _, err := m.ReadMessage(context.Background(), dst); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if _, err := m.ReadMessage(context.Background(), dst); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("reused failed carrier: %v", err)
			}
		})
	}
	t.Run("partial-physical-frame", func(t *testing.T) {
		m, peer, _ := dialPair(t, testOptions())
		if _, err := peer.NetConn().Write([]byte{0x82, 10, 1, 2}); err != nil {
			t.Fatal(err)
		}
		_ = peer.Close()
		if n, err := m.ReadMessage(context.Background(), make([]byte, 264)); n != 2 || err == nil {
			t.Fatalf("truncation: %d %v", n, err)
		}
	})
}

func TestExtensionAndSubprotocolRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		want         error
	}{
		{"compression", "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n", ErrExtensions},
		{"unknown-extension", "Sec-WebSocket-Extensions: unexpected\r\n", ErrExtensions},
		{"subprotocol", "Sec-WebSocket-Protocol: other\r\n", ErrSubprotocol},
		{"http-1.0", "", ErrHTTPVersion},
		{"large-header", "X-Large: " + strings.Repeat("x", 4096) + "\r\n", ErrHeaderLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peerClosed := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Sec-WebSocket-Extensions") != "" {
					t.Error("dial offered an extension")
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				key := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				protocol := "Sec-WebSocket-Protocol: " + SubprotocolLocal + "\r\n"
				if tc.name == "subprotocol" {
					protocol = ""
				}
				version := "HTTP/1.1"
				if tc.name == "http-1.0" {
					version = "HTTP/1.0"
				}
				_, _ = fmt.Fprintf(conn, "%s 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s%s\r\n", version, base64.StdEncoding.EncodeToString(key[:]), protocol, tc.header)
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				var byte [1]byte
				if _, err := conn.Read(byte[:]); err != nil {
					close(peerClosed)
				}
			}))
			defer server.Close()
			o := testOptions()
			charge, _ := Charge(o)
			root, ref, environment := reservations(t, charge)
			before := root.Snapshot().Charged
			_, err := Dial(context.Background(), DialConfig{URL: "ws" + strings.TrimPrefix(server.URL, "http") + "/flowersec/v4/local", RemoteAddress: preparedAddress(t, server.URL), Subprotocol: SubprotocolLocal, CheckPolicy: localPolicy}, o, ref, environment)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			select {
			case <-peerClosed:
			case <-time.After(time.Second):
				t.Fatal("failed upgrade retained its socket")
			}
			after := root.Snapshot().Charged
			for i := range before {
				if before[i]-after[i] != charge[i] {
					t.Fatalf("failed prepare retained charge %d: %d -> %d", i, before[i], after[i])
				}
			}
		})
	}
}

func TestUpgradeDeclinesBrowserCompressionOfferAndChecksPolicy(t *testing.T) {
	o := testOptions()
	charge, _ := Charge(o)
	_, ref, environment := reservations(t, charge)
	result := make(chan *Messages, 1)
	errs := make(chan error, 1)
	var policyCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, err := Upgrade(r.Context(), w, r, UpgradeConfig{Subprotocol: SubprotocolLocal, CheckPolicy: func(r *http.Request) error {
			policyCalls.Add(1)
			if r.Header.Get("Origin") != "http://trusted.invalid" {
				return errors.New("test: origin rejected")
			}
			return nil
		}}, o, ref, environment)
		if err != nil {
			errs <- err
			return
		}
		result <- m
	}))
	defer server.Close()
	dialer := ws.Dialer{Subprotocols: []string{SubprotocolLocal}, EnableCompression: true}
	peer, response, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), http.Header{"Origin": {"http://trusted.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if response.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatal("server negotiated browser extension offer")
	}
	var m *Messages
	select {
	case m = <-result:
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("upgrade incomplete")
	}
	cleanupMessages(t, m)
	if err := peer.WriteMessage(ws.BinaryMessage, []byte("binary")); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 264)
	if n, err := m.ReadMessage(context.Background(), dst); err != nil || string(dst[:n]) != "binary" {
		t.Fatalf("request-context handoff: %d %v", n, err)
	}
	if policyCalls.Load() != 1 {
		t.Fatal("policy callback count", policyCalls.Load())
	}
}

func TestCancellationActualCloseAndRetirement(t *testing.T) {
	m, peer, root := dialPair(t, testOptions())
	before := root.Snapshot().Charged
	if err := m.Retire(); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("retired a live provider", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { _, err := m.ReadMessage(ctx, make([]byte, 264)); finished <- err }()
	deadline := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		started := m.reading
		m.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("read did not start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation retained read")
	}
	if err := m.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if root.Snapshot().Charged != before {
		t.Fatal("cleanup returned ownership before retirement")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("physical peer remained open")
	}
	copied := *m
	if err := copied.Close(); err != nil {
		t.Fatal(err)
	}
	if err := copied.Retire(); err != nil {
		t.Fatal(err)
	}
	after := root.Snapshot().Charged
	if err := m.Retire(); err != nil || root.Snapshot().Charged != after {
		t.Fatal("duplicate retirement changed charge", err)
	}
	charge, _ := Charge(testOptions())
	for i := range before {
		if before[i]-after[i] != charge[i] {
			t.Fatalf("retirement dimension %d", i)
		}
	}
}

func TestDeadlineAndControlRate(t *testing.T) {
	t.Run("message-deadline", func(t *testing.T) {
		o := testOptions()
		o.MessageTimeout = 20 * time.Millisecond
		m, _, _ := dialPair(t, o)
		_, err := m.ReadMessage(context.Background(), make([]byte, 264))
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("missing read deadline: %v", err)
		}
	})
	t.Run("control-rate", func(t *testing.T) {
		o := testOptions()
		o.MaxControlsPerSecond = 2
		m, peer, _ := dialPair(t, o)
		for i := 0; i < 3; i++ {
			if err := peer.WriteControl(ws.PongMessage, []byte("p"), time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := m.ReadMessage(context.Background(), make([]byte, 264)); !errors.Is(err, ErrControlRate) {
			t.Fatal(err)
		}
	})
}

func TestPreAdmissionAndOriginalPolicyErrors(t *testing.T) {
	o := testOptions()
	charge, _ := Charge(o)
	for _, dimension := range []int{resourcev4.SDKBytes, resourcev4.ProviderBytes, resourcev4.WorkSlots, resourcev4.Tasks, resourcev4.Connections} {
		t.Run(fmt.Sprint(dimension), func(t *testing.T) {
			short := charge
			short[dimension]--
			_, ref, environment := reservations(t, short)
			calls := 0
			_, err := Dial(context.Background(), DialConfig{URL: "ws://127.0.0.1/flowersec/v4/local", RemoteAddress: netip.MustParseAddrPort("127.0.0.1:80"), Subprotocol: SubprotocolLocal, CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { calls++; return nil }}, o, ref, environment)
			if !errors.Is(err, resourcev4.ErrCapacity) || calls != 0 || ref.Check() != nil {
				t.Fatalf("admission: %v calls=%d", err, calls)
			}
		})
	}
	_, ref, environment := reservations(t, charge)
	want := errors.New("test: trusted policy refusal")
	_, err := Dial(context.Background(), DialConfig{URL: "ws://127.0.0.1/flowersec/v4/local", RemoteAddress: netip.MustParseAddrPort("127.0.0.1:80"), Subprotocol: SubprotocolLocal, CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { return want }}, o, ref, environment)
	if err != want {
		t.Fatal("policy identity changed", err)
	}
	o.RuntimeBytes = math.MaxUint64
	if _, err := Charge(o); !errors.Is(err, resourcev4.ErrConfiguration) {
		t.Fatal("overflow accepted", err)
	}
}

func TestWSSUsesOwnedTLSAndExplicitPolicy(t *testing.T) {
	peers := make(chan *ws.Conn, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			t.Error("not TLS 1.3")
		}
		u := ws.Upgrader{Subprotocols: []string{SubprotocolDirect}}
		conn, err := u.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		peers <- conn
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	o := testOptions()
	charge, _ := Charge(o)
	_, ref, environment := reservations(t, charge)
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	m, err := Dial(context.Background(), DialConfig{URL: "wss" + strings.TrimPrefix(server.URL, "https") + "/flowersec/v4/direct", RemoteAddress: preparedAddress(t, server.URL), Subprotocol: SubprotocolDirect, TLSConfig: tlsConfig, CheckPolicy: func(u *url.URL, _ netip.AddrPort, _ http.Header) error {
		if u.Scheme != "wss" {
			return resourcev4.ErrConfiguration
		}
		return nil
	}}, o, ref, environment)
	if err != nil {
		t.Fatal(err)
	}
	cleanupMessages(t, m)
	g, err := m.ConnectionGuarantees()
	if err != nil || g.LocalConsumerTls13Verification != protocolv4.V4ConsumerTLS13VerificationConsumerEnforced || g.ReliableProgress != protocolv4.V4ReliableProgressSharedOrdered || g.BoundStreamInputIsolation != protocolv4.V4BoundStreamInputIsolationSharedFailureScope {
		t.Fatalf("actual TLS assurance lost: %+v %v", g, err)
	}
	peer := <-peers
	defer peer.Close()
	if err := m.WriteMessage(context.Background(), []byte("secure")); err != nil {
		t.Fatal(err)
	}
	_, body, err := peer.ReadMessage()
	if err != nil || string(body) != "secure" {
		t.Fatalf("%q %v", body, err)
	}
}

type countedConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countedConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestOwnedConnectionCloseExactlyOnce(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	counted := &countedConn{Conn: a}
	owned := &ownedConn{Conn: counted}
	var group sync.WaitGroup
	for i := 0; i < 10; i++ {
		group.Add(1)
		go func() { defer group.Done(); _ = owned.Close() }()
	}
	group.Wait()
	if counted.closes.Load() != 1 {
		t.Fatal("physical close count", counted.closes.Load())
	}
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestDialCancellationWhileAwaitingUpgrade(t *testing.T) {
	started, closed := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		close(started)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		if _, err := conn.Read(one[:]); errors.Is(err, io.EOF) {
			close(closed)
		}
	}))
	defer server.Close()
	o := testOptions()
	charge, _ := Charge(o)
	root, ref, environment := reservations(t, charge)
	before := root.Snapshot().Charged
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := Dial(ctx, DialConfig{URL: "ws" + strings.TrimPrefix(server.URL, "http") + "/flowersec/v4/local", RemoteAddress: preparedAddress(t, server.URL), Subprotocol: SubprotocolLocal, CheckPolicy: localPolicy}, o, ref, environment)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upgrade did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial cancellation did not interrupt HTTP response read")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("dial cancellation retained physical socket")
	}
	after := root.Snapshot().Charged
	for i := range before {
		if before[i]-after[i] != charge[i] {
			t.Fatalf("canceled prepare dimension %d", i)
		}
	}
}

type blockedCloseConn struct {
	net.Conn
	started, release chan struct{}
	closes           atomic.Int32
}

func (c *blockedCloseConn) Close() error {
	c.closes.Add(1)
	close(c.started)
	<-c.release
	return c.Conn.Close()
}

func TestCloseRetainsChargeUntilOriginalProviderReturns(t *testing.T) {
	m, _, root := dialPair(t, testOptions())
	// Wrap the real accepted socket's Close to expose its original tail. The
	// production factory never accepts an arbitrary caller-built connection.
	m.mu.Lock()
	delayed := &blockedCloseConn{Conn: m.transport.Conn, started: make(chan struct{}), release: make(chan struct{})}
	m.transport.Conn = delayed
	m.mu.Unlock()
	before := root.Snapshot().Charged
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-delayed.started:
	case <-time.After(time.Second):
		t.Fatal("original close not called")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := m.WaitCleanup(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || root.Snapshot().Charged != before {
		t.Fatal("close tail lost its reservation", err)
	}
	if err := m.Retire(); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("retired while physical Close blocked", err)
	}
	copy := *m
	_ = copy.Close()
	close(delayed.release)
	if err := m.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if delayed.closes.Load() != 1 {
		t.Fatal("duplicate original Close", delayed.closes.Load())
	}
	if root.Snapshot().Charged != before {
		t.Fatal("cleanup refunded before explicit retirement")
	}
}

func TestFragmentedMessageCumulativeLimit(t *testing.T) {
	m, peer, _ := dialPair(t, testOptions())
	writer, err := peer.NextWriter(ws.BinaryMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte{1}, 300)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadMessage(context.Background(), make([]byte, 264)); !errors.Is(err, protocolv4.ErrPayloadTooLarge) {
		t.Fatalf("fragmented limit: %v", err)
	}
}

func TestUpgradePolicyErrorPrecedesHijack(t *testing.T) {
	o := testOptions()
	charge, _ := Charge(o)
	root, ref, environment := reservations(t, charge)
	before := root.Snapshot().Charged
	want := errors.New("test: denied Origin and application authentication")
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/flowersec/v4/local", nil)
	request.Header.Set("Sec-WebSocket-Protocol", SubprotocolLocal)
	_, err := Upgrade(request.Context(), httptest.NewRecorder(), request, UpgradeConfig{Subprotocol: SubprotocolLocal, CheckPolicy: func(*http.Request) error { return want }}, o, ref, environment)
	if err != want {
		t.Fatal("upgrade policy identity changed", err)
	}
	after := root.Snapshot().Charged
	for i := range before {
		if before[i]-after[i] != charge[i] {
			t.Fatalf("policy failure dimension %d", i)
		}
	}
}

func TestPreparedEndpointRejectsMismatchBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	endpoint := preparedAddress(t, server.URL)
	wrongPort := endpoint.Port() + 1
	if endpoint.Port() == 65535 {
		wrongPort = endpoint.Port() - 1
	}
	for _, tc := range []struct {
		name     string
		endpoint netip.AddrPort
	}{
		{"missing", netip.AddrPort{}},
		{"zero-port", netip.AddrPortFrom(endpoint.Addr(), 0)},
		{"different-port", netip.AddrPortFrom(endpoint.Addr(), wrongPort)},
		{"different-numeric-host", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), endpoint.Port())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := testOptions()
			charge, _ := Charge(o)
			_, ref, environment := reservations(t, charge)
			calls := 0
			_, err := Dial(context.Background(), DialConfig{URL: "ws" + strings.TrimPrefix(server.URL, "http"), RemoteAddress: tc.endpoint, Subprotocol: SubprotocolLocal,
				CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { calls++; return nil }}, o, ref, environment)
			if !errors.Is(err, ErrEndpoint) || calls != 0 || requests.Load() != 0 {
				t.Fatalf("invalid endpoint reached policy/network: %v, %d, %d", err, calls, requests.Load())
			}
		})
	}
	t.Run("hostname-policy-refusal", func(t *testing.T) {
		o := testOptions()
		charge, _ := Charge(o)
		_, ref, environment := reservations(t, charge)
		want := errors.New("test: prepared address is not authorized for hostname")
		calls := 0
		authority := net.JoinHostPort("unresolved.invalid", fmt.Sprint(endpoint.Port()))
		_, err := Dial(context.Background(), DialConfig{URL: "ws://" + authority, RemoteAddress: endpoint, Subprotocol: SubprotocolLocal,
			CheckPolicy: func(u *url.URL, got netip.AddrPort, _ http.Header) error {
				calls++
				if u.Host != authority || got != endpoint {
					t.Error("policy did not receive original authority and prepared address")
				}
				return want
			}}, o, ref, environment)
		if err != want || calls != 1 || requests.Load() != 0 {
			t.Fatalf("endpoint policy boundary: %v, %d, %d", err, calls, requests.Load())
		}
	})
}

func TestPreparedEndpointPreservesHostnameAndSNIWithoutResolution(t *testing.T) {
	var lookups atomic.Int32
	originalResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("test: implicit DNS is forbidden")
	}}
	defer func() { net.DefaultResolver = originalResolver }()
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit-server-name=%v", explicit), func(t *testing.T) {
			type received struct {
				host, name string
				conn       *ws.Conn
			}
			accepted := make(chan received, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				u := ws.Upgrader{Subprotocols: []string{SubprotocolDirect}}
				conn, err := u.Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				accepted <- received{r.Host, r.TLS.ServerName, conn}
			}))
			server.StartTLS()
			defer server.Close()
			certificate := server.Certificate()
			if len(certificate.DNSNames) == 0 {
				t.Fatal("test server certificate lacks a hostname")
			}
			verificationName := certificate.DNSNames[0]
			authorityName := verificationName
			tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			if explicit {
				authorityName = "prepared-only.invalid"
				tlsConfig.ServerName = verificationName
			}
			endpoint := preparedAddress(t, server.URL)
			authority := net.JoinHostPort(authorityName, fmt.Sprint(endpoint.Port()))
			o := testOptions()
			charge, _ := Charge(o)
			_, ref, environment := reservations(t, charge)
			m, err := Dial(context.Background(), DialConfig{URL: "wss://" + authority + "/flowersec/v4/direct", RemoteAddress: endpoint, Subprotocol: SubprotocolDirect, TLSConfig: tlsConfig,
				CheckPolicy: func(u *url.URL, remote netip.AddrPort, _ http.Header) error {
					if u.Host != authority || remote != endpoint {
						return ErrEndpoint
					}
					return nil
				}}, o, ref, environment)
			if err != nil {
				t.Fatal(err)
			}
			cleanupMessages(t, m)
			peer := <-accepted
			defer peer.conn.Close()
			if peer.host != authority || peer.name != verificationName {
				t.Fatalf("authority/SNI replaced by dial address: %q %q", peer.host, peer.name)
			}
			if lookups.Load() != 0 {
				t.Fatal("numeric endpoint triggered DNS", lookups.Load())
			}
			if err := m.WriteMessage(context.Background(), []byte("one prepared endpoint")); err != nil {
				t.Fatal(err)
			}
			_, body, err := peer.conn.ReadMessage()
			if err != nil || string(body) != "one prepared endpoint" {
				t.Fatalf("%q %v", body, err)
			}
		})
	}
}

func TestTLSCancellationRetainsOriginalPrepareCallbackTail(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.VerifyConnection = func(tls.ConnectionState) error { close(entered); <-release; return nil }
	o := testOptions()
	charge, _ := Charge(o)
	root, ref, environment := reservations(t, charge)
	before := root.Snapshot().Charged
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint := preparedAddress(t, server.URL)
	finished := make(chan error, 1)
	go func() {
		_, err := Dial(ctx, DialConfig{URL: "wss" + strings.TrimPrefix(server.URL, "https"), RemoteAddress: endpoint, Subprotocol: SubprotocolDirect, TLSConfig: tlsConfig,
			CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { return nil }}, o, ref, environment)
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("TLS verification did not start")
	}
	cancel()
	select {
	case err := <-finished:
		t.Fatal("prepare returned while original TLS callback remained", err)
	case <-time.After(10 * time.Millisecond):
	}
	if root.Snapshot().Charged != before {
		t.Fatal("cancellation refunded unfinished TLS prepare")
	}
	releaseOnce()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS cancellation did not complete")
	}
	after := root.Snapshot().Charged
	for i := range before {
		if before[i]-after[i] != charge[i] {
			t.Fatalf("TLS failure retained dimension %d", i)
		}
	}
}
