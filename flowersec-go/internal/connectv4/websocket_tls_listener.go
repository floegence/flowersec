package connectv4

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// WebSocketTLSListenerConfig fixes one certificate/key generation at the actual
// TLS terminator. Signer and Clock are borrowed immutable dependencies; their
// owner must outlive WaitCleanup. HTTP parsing, timeouts and scheduling remain
// host responsibilities. PerConnection includes the qualified TLS/HTTP runtime
// allowance in addition to the SDK-owned connection bookkeeping below.
type WebSocketTLSListenerConfig struct {
	CertificateDER   [][]byte
	Signer           crypto.Signer
	Clock            *timev4.Clock
	Root             *resourcev4.Root
	Owner            resourcev4.OwnerKey
	Accounts         [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	AccountCount     uint8
	RuntimeBytes     uint64
	PerConnection    resourcev4.Vector
	HandshakeTimeout time.Duration
}

// WebSocketTLSListener owns only its explicitly transferred listener and TLS
// configuration. Close stops acceptance, preserving established connections
// for their original Serve/Session Drain owners. Retire joins actual accepted
// socket and signing tails. It creates no tasks or per-connection lookup table.
type WebSocketTLSListener struct {
	mu                                  sync.Mutex
	listener                            net.Listener
	config                              WebSocketTLSListenerConfig
	certificate                         tls.Certificate
	chain                               []*x509.Certificate
	reservation, shared                 resourcev4.Reference
	serial, active                      uint64
	accepting, closing, closed, retired bool
	closeError                          error
	closeDone, done                     chan struct{}
	cleaned                             bool
}

func WebSocketTLSListenerCharge(c WebSocketTLSListenerConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || c.Signer == nil || c.RuntimeBytes == 0 || c.HandshakeTimeout <= 0 ||
		int(c.AccountCount) > len(c.Accounts) || len(c.CertificateDER) == 0 || len(c.CertificateDER) > 16 ||
		c.PerConnection[resourcev4.ProviderBytes] == 0 || c.PerConnection[resourcev4.Tasks] == 0 ||
		c.PerConnection[resourcev4.Timers] == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	var total uint64
	for _, der := range c.CertificateDER {
		if len(der) == 0 || len(der) > 65536 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		total += uint64(len(der))
	}
	if total > 262144 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	// DER copies, parsed X.509 nodes/strings and constructor public-key work
	// have a conservative finite backing allowance, before the first parse.
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(WebSocketTLSListener{})) + 64*total,
		resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.NativeHandles: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func websocketTLSConnectionCharge(c WebSocketTLSListenerConfig) (resourcev4.Vector, error) {
	return c.PerConnection.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(websocketTLSSocket{})) + uint64(unsafe.Sizeof(websocketTLSSigner{})) + uint64(unsafe.Sizeof(tls.Config{})) + uint64(unsafe.Sizeof(tls.Certificate{})) + 1024,
		resourcev4.Items: 1, resourcev4.Connections: 1, resourcev4.NativeHandles: 1, resourcev4.TLSHandshakes: 1, resourcev4.WorkSlots: 3})
}

// NewWebSocketTLSListener transfers the listener only on success. The caller's
// original bounded constructor responsibility owns any key-provider call here.
// Configure http.Server.ConnContext and ConnState to the corresponding methods
// before Serve. They bind the original connection and release the initial
// handshake/header deadline only after actual TLS completion.
// ServeTLS is unnecessary: Accept already returns the original *tls.Conn.
func NewWebSocketTLSListener(listener net.Listener, c WebSocketTLSListenerConfig, reservation, dependencies resourcev4.Reference) (*WebSocketTLSListener, error) {
	if listener == nil || reservation == dependencies {
		return nil, resourcev4.ErrConfiguration
	}
	cost, err := WebSocketTLSListenerCharge(c)
	if err != nil {
		return nil, err
	}
	if _, err = websocketTLSConnectionCharge(c); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		shared.Release()
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			owned.Release()
			shared.Release()
		}
	}()
	chain := make([]*x509.Certificate, len(c.CertificateDER))
	der := make([][]byte, len(chain))
	for i, original := range c.CertificateDER {
		der[i] = bytes.Clone(original)
		chain[i], err = x509.ParseCertificate(der[i])
		if err != nil {
			return nil, tlspolicy.ErrCertificate
		}
	}
	public, err := x509.MarshalPKIXPublicKey(c.Signer.Public())
	if err != nil || !bytes.Equal(public, chain[0].RawSubjectPublicKeyInfo) {
		return nil, tlspolicy.ErrCertificate
	}
	if err = shared.Check(); err == nil {
		err = owned.Check()
	}
	if err != nil {
		return nil, err
	}
	c.CertificateDER = nil
	l := &WebSocketTLSListener{listener: listener, config: c, chain: chain,
		certificate: tls.Certificate{Certificate: der, Leaf: chain[0]}, reservation: owned, shared: shared,
		closeDone: make(chan struct{}), done: make(chan struct{})}
	success = true
	return l, nil
}

type websocketTLSCapacityError struct{}

func (websocketTLSCapacityError) Error() string {
	return "connectv4: TLS listener capacity unavailable"
}
func (websocketTLSCapacityError) Timeout() bool   { return false }
func (websocketTLSCapacityError) Temporary() bool { return true }
func (websocketTLSCapacityError) Unwrap() error   { return resourcev4.ErrCapacity }

func (l *WebSocketTLSListener) Accept() (_ net.Conn, err error) {
	l.mu.Lock()
	if l.closing || l.retired {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	if l.accepting {
		l.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	if l.serial == math.MaxUint64 {
		l.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	if err = l.reservation.Check(); err == nil {
		err = l.shared.Check()
	}
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	charge, err := websocketTLSConnectionCharge(l.config)
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	l.serial++
	var id [24]byte
	copy(id[:16], l.config.Owner.Backing[:])
	binary.BigEndian.PutUint64(id[16:], l.serial)
	digest := sha256.Sum256(id[:])
	owner := l.config.Owner
	copy(owner.Backing[:], digest[:16])
	ref, err := l.config.Root.Reserve(owner, charge, l.config.Accounts[:l.config.AccountCount]...)
	if err != nil {
		l.mu.Unlock()
		if errors.Is(err, resourcev4.ErrCapacity) {
			return nil, websocketTLSCapacityError{}
		}
		return nil, err
	}
	if err = ref.CheckSameEnvironment(l.reservation); err != nil {
		ref.Release()
		l.mu.Unlock()
		return nil, err
	}
	l.accepting, l.active = true, l.active+1
	l.mu.Unlock()
	transferred := false
	defer func() {
		l.mu.Lock()
		l.accepting = false
		l.mu.Unlock()
		if !transferred {
			ref.Release()
			l.finishConnection()
		}
	}()
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	defer func() {
		if !transferred {
			_ = conn.Close()
		}
	}()
	l.mu.Lock()
	closed := l.closing
	l.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	if err = ref.Check(); err == nil {
		err = l.shared.Check()
	}
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(l.config.HandshakeTimeout)
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	socket := &websocketTLSSocket{Conn: conn, listener: l, reservation: ref, handshakeDeadline: deadline, readDeadline: deadline, writeDeadline: deadline, closeDone: make(chan struct{})}
	certificate := l.certificate
	certificate.PrivateKey = &websocketTLSSigner{socket: socket, signer: l.config.Signer, public: l.chain[0].PublicKey}
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{certificate}, SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if err := socket.begin(); err != nil {
				return err
			}
			defer socket.end()
			if state.Version != tls.VersionTLS13 || state.DidResume || state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
				return tlspolicy.ErrCertificate
			}
			now, err := l.config.Clock.Sample()
			if err != nil {
				return err
			}
			return tlspolicy.CheckCertificateTime(l.chain[0], now.Interval)
		}}
	connection := tls.Server(socket, config)
	transferred = true
	return connection, nil
}

func (l *WebSocketTLSListener) finishConnection() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	l.completeLocked()
}
func (l *WebSocketTLSListener) completeLocked() {
	if l.closed && l.active == 0 && !l.cleaned {
		l.cleaned = true
		close(l.done)
	}
}
func (l *WebSocketTLSListener) Addr() net.Addr { return l.listener.Addr() }
func (l *WebSocketTLSListener) Close() error {
	l.mu.Lock()
	if l.closing {
		done := l.closeDone
		l.mu.Unlock()
		<-done
		return l.closeError
	}
	l.closing = true
	l.mu.Unlock()
	err := l.listener.Close()
	l.mu.Lock()
	l.closed, l.closeError = true, err
	close(l.closeDone)
	l.completeLocked()
	l.mu.Unlock()
	return err
}
func (l *WebSocketTLSListener) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (l *WebSocketTLSListener) Retire() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.cleaned {
		return resourcev4.ErrCapacity
	}
	if !l.retired {
		l.retired = true
		l.certificate, l.chain, l.config = tls.Certificate{}, nil, WebSocketTLSListenerConfig{}
		l.reservation.Release()
		l.shared.Release()
	}
	return nil
}

type websocketTLSContextKey struct{}
type websocketTLSBinding struct {
	socket     *websocketTLSSocket
	connection *tls.Conn
}

// ConnContext binds the actual TLS connection, not a request header, proxy
// assertion or caller-provided tls.ConnectionState. Unrelated listeners cannot
// obtain the binding merely by installing this callback.
func (l *WebSocketTLSListener) ConnContext(ctx context.Context, conn net.Conn) context.Context {
	c, ok := conn.(*tls.Conn)
	if !ok {
		return ctx
	}
	s, ok := c.NetConn().(*websocketTLSSocket)
	if !ok || s.listener != l {
		return ctx
	}
	return context.WithValue(ctx, websocketTLSContextKey{}, websocketTLSBinding{s, c})
}

// ConnState permits the borrowed HTTP host to choose subsequent request and
// keepalive deadlines only after the actual TLS handshake and first headers.
// Before then, attempts to extend or clear the original finite cap are clamped.
func (l *WebSocketTLSListener) ConnState(conn net.Conn, state http.ConnState) {
	if state != http.StateActive {
		return
	}
	c, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	s, ok := c.NetConn().(*websocketTLSSocket)
	if !ok || s.listener != l {
		return
	}
	actual := c.ConnectionState()
	if !actual.HandshakeComplete || actual.Version != tls.VersionTLS13 {
		return
	}
	_ = s.finishHandshake()
}
func (l *WebSocketTLSListener) accepted(r *http.Request) (websocketTLSBinding, error) {
	b, ok := r.Context().Value(websocketTLSContextKey{}).(websocketTLSBinding)
	if !ok || b.socket.listener != l || r.TLS == nil {
		return websocketTLSBinding{}, tlspolicy.ErrCertificate
	}
	if err := b.socket.begin(); err != nil {
		return websocketTLSBinding{}, err
	}
	defer b.socket.end()
	state := b.connection.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.DidResume ||
		state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" ||
		r.TLS.Version != state.Version || !r.TLS.HandshakeComplete || r.TLS.ServerName != state.ServerName {
		return websocketTLSBinding{}, tlspolicy.ErrCertificate
	}
	if err := b.socket.finishHandshake(); err != nil {
		return websocketTLSBinding{}, err
	}
	return b, nil
}

// The original socket retains the listener/certificate owner through every
// actual I/O, key-provider and physical Close tail, even after logical Close.
type websocketTLSSocket struct {
	net.Conn
	mu                          sync.Mutex
	listener                    *WebSocketTLSListener
	reservation                 resourcev4.Reference
	active                      uint32
	handshakeDeadline           time.Time
	readDeadline, writeDeadline time.Time
	handshaken                  bool
	closing, closed, released   bool
	closeError                  error
	closeDone                   chan struct{}
}

func (s *websocketTLSSocket) begin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return net.ErrClosed
	}
	if s.active >= 8 {
		return resourcev4.ErrCapacity
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	if err := s.listener.shared.Check(); err != nil {
		return err
	}
	s.active++
	return nil
}
func (s *websocketTLSSocket) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	s.completeLocked()
}
func (s *websocketTLSSocket) completeLocked() {
	if s.closed && s.active == 0 && !s.released {
		s.released = true
		s.reservation.Release()
		s.listener.finishConnection()
	}
}
func (s *websocketTLSSocket) Read(p []byte) (int, error) {
	if err := s.begin(); err != nil {
		return 0, err
	}
	defer s.end()
	return s.Conn.Read(p)
}
func (s *websocketTLSSocket) Write(p []byte) (int, error) {
	if err := s.begin(); err != nil {
		return 0, err
	}
	defer s.end()
	return s.Conn.Write(p)
}
func (s *websocketTLSSocket) SetDeadline(t time.Time) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.Conn.SetDeadline(s.deadline(t, true, true))
}
func (s *websocketTLSSocket) SetReadDeadline(t time.Time) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.Conn.SetReadDeadline(s.deadline(t, true, false))
}
func (s *websocketTLSSocket) SetWriteDeadline(t time.Time) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.Conn.SetWriteDeadline(s.deadline(t, false, true))
}

func (s *websocketTLSSocket) deadline(t time.Time, read, write bool) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if read {
		s.readDeadline = t
	}
	if write {
		s.writeDeadline = t
	}
	if !s.handshaken && (t.IsZero() || t.After(s.handshakeDeadline)) {
		return s.handshakeDeadline
	}
	return t
}

func (s *websocketTLSSocket) finishHandshake() error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	s.mu.Lock()
	if s.handshaken {
		s.mu.Unlock()
		return nil
	}
	if !time.Now().Before(s.handshakeDeadline) {
		s.mu.Unlock()
		return os.ErrDeadlineExceeded
	}
	s.handshaken = true
	read, write := s.readDeadline, s.writeDeadline
	s.mu.Unlock()
	if err := s.Conn.SetReadDeadline(read); err != nil {
		return err
	}
	return s.Conn.SetWriteDeadline(write)
}
func (s *websocketTLSSocket) Close() error {
	s.mu.Lock()
	if s.closing {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return s.closeError
	}
	s.closing = true
	s.mu.Unlock()
	err := s.Conn.Close()
	s.mu.Lock()
	s.closed, s.closeError = true, err
	close(s.closeDone)
	s.completeLocked()
	s.mu.Unlock()
	return err
}

type websocketTLSSigner struct {
	socket *websocketTLSSocket
	signer crypto.Signer
	public crypto.PublicKey
}

func (s *websocketTLSSigner) Public() crypto.PublicKey { return s.public }
func (s *websocketTLSSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := s.socket.begin(); err != nil {
		return nil, err
	}
	defer s.socket.end()
	return s.signer.Sign(r, digest, opts)
}
