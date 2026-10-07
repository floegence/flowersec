package interopharness

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// ServeHTTPListener keeps the application and transport on the same original
// finite listener. TLS is selected only by the actual ClientHello. Plain HTTP
// cannot reach a network transport Upgrade; its original CheckPolicy still
// requires completed TLS 1.3. Local bridges deliberately use plain HTTP only.
func (s *Server) ServeHTTPListener(reporter *Reporter, listener net.Listener, application http.Handler, allowNetworkTLS bool) error {
	if s.HTTPHandler == nil || listener == nil {
		return errors.New("original HTTP listener and admitted transport handler are required")
	}
	declaration := resourcev4.Vector{resourcev4.ProviderBytes: 64 << 20, resourcev4.Tasks: 16, resourcev4.WorkSlots: 8, resourcev4.NativeHandles: 9, resourcev4.Connections: 8, resourcev4.Items: 16, resourcev4.Timers: 8}
	reservation := s.Runtime.Authority.Reserve(declaration)
	reporter.Cleanup(reservation.Release)
	bounded := newLimitedListener(listener, 8)
	var incoming net.Listener = bounded
	if allowNetworkTLS {
		incoming = &httpTLSListener{Listener: bounded, config: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{s.certificate}, SessionTicketsDisabled: true}}
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/flowersec/v4/direct" || request.URL.Path == "/flowersec/v4/local" {
			s.HTTPHandler.ServeHTTP(w, request)
			return
		}
		if application == nil {
			http.NotFound(w, request)
			return
		}
		application.ServeHTTP(w, request)
	})
	callbacks := newHTTPCallbackGate()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !callbacks.enter() {
			http.Error(w, "listener is closing", http.StatusServiceUnavailable)
			return
		}
		defer callbacks.leave()
		handler.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan error, 1)
	go func() { done <- server.Serve(incoming) }()
	reporter.Cleanup(func() {
		callbacks.seal()
		_ = server.Close()
		_ = bounded.Close()
		bounded.CloseConnections()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				reporter.Error(err)
			}
		case <-time.After(5 * time.Second):
			reporter.Error("HTTP listener retained its original Serve tail")
			return
		}
		select {
		case <-callbacks.drained:
		case <-time.After(5 * time.Second):
			reporter.Error("HTTP listener retained its original request callbacks")
		}
	})
	return nil
}

type httpTLSListener struct {
	net.Listener
	config *tls.Config
}

func (l *httpTLSListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err = connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			_ = connection.Close()
			continue
		}
		reader := bufio.NewReaderSize(connection, 1024)
		first, err := reader.Peek(1)
		if err != nil {
			_ = connection.Close()
			if errors.Is(err, net.ErrClosed) {
				return nil, err
			}
			continue
		}
		if err = connection.SetReadDeadline(time.Time{}); err != nil {
			_ = connection.Close()
			continue
		}
		original := &peekHTTPConnection{Conn: connection, reader: reader}
		if first[0] == 22 {
			return tls.Server(original, l.config), nil
		}
		// Only ordinary HTTP methods may enter the plaintext application owner.
		if first[0] < 'A' || first[0] > 'Z' {
			_ = original.Close()
			continue
		}
		return original, nil
	}
}

type peekHTTPConnection struct {
	net.Conn
	reader io.Reader
}

func (c *peekHTTPConnection) Read(output []byte) (int, error) { return c.reader.Read(output) }

// Sealing and entry share one lock. Close waits only for callbacks admitted
// before sealing, so a late net/http dispatch cannot race a zero-count Wait.
type httpCallbackGate struct {
	mu      sync.Mutex
	active  uint32
	sealed  bool
	drained chan struct{}
}

func newHTTPCallbackGate() *httpCallbackGate { return &httpCallbackGate{drained: make(chan struct{})} }
func (g *httpCallbackGate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return false
	}
	g.active++
	return true
}
func (g *httpCallbackGate) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active--
	if g.sealed && g.active == 0 {
		close(g.drained)
	}
}
func (g *httpCallbackGate) seal() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return
	}
	g.sealed = true
	if g.active == 0 {
		close(g.drained)
	}
}
