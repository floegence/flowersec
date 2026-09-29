package controlv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NamespaceHTTPSConfig fixes one complete-namespace visibility registration.
// BootstrapSigner is the independent trust root, never the online Head signer.
// The caller separately owns the native mTLS 1.3 listener and all header,
// connection and certificate/provider work. No request can select a namespace,
// signer, backend or issuance policy outside this registration.
type NamespaceHTTPSConfig struct {
	Clock                                     *timev4.Clock
	Trust                                     *protocolv4.NamespaceTrustStore
	Scope                                     protocolv4.NamespacePublicationScope
	BootstrapSigner                           protocolv4.MapSigner
	ClientCertificateDER                      []byte
	RequestsPerMinute, Burst                  uint16
	WorkMS, BootstrapValidityMS, RuntimeBytes uint64
}

// NamespaceHTTPSService serves the existing consumer control protocol at
// /head, /state, /trust and nonce-bound /bootstrap. Refresh reads never sign a
// new Head. The sole response position holds full original bytes through the
// actual ResponseWriter return, and there is no waiting request queue.
type NamespaceHTTPSService struct {
	mu                                            sync.Mutex
	c                                             NamespaceHTTPSConfig
	store                                         *ledgerv4.SQLitePublicationStore
	root                                          protocolv4.NamespaceTrustRoot
	client                                        [32]byte
	notBefore, notAfter                           uint64
	origin                                        timev4.Mark
	creditedMS, credit                            uint64
	state, head, trust                            []byte
	codec                                         *protocolv4.SignedMapCodec
	reservation, dependencies, storeRef, trustRef resourcev4.Reference
	busy, closed, cleaned                         bool
	cancel                                        context.CancelFunc
	done                                          chan struct{}
}

func NamespaceHTTPSServiceCharge(c NamespaceHTTPSConfig) (resourcev4.Vector, error) {
	if c.Clock == nil || c.Trust == nil || c.BootstrapSigner == nil || len(c.ClientCertificateDER) == 0 || len(c.ClientCertificateDER) > 16384 || c.RequestsPerMinute == 0 || c.RequestsPerMinute > 600 || c.Burst == 0 || c.Burst > c.RequestsPerMinute || c.WorkMS == 0 || c.WorkMS > 90000 || c.BootstrapValidityMS == 0 || c.BootstrapValidityMS > 90000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if err := c.Trust.CheckPublicationScope(c.Scope); err != nil {
		return resourcev4.Vector{}, err
	}
	r, err := c.Trust.Rules()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	s, h := r.PublicationCapacity()
	b, err := protocolv4.SchemaByteLimit("TrustBootstrapResponse")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := protocolv4.SignedMapBackingBytes("TrustBootstrapResponse", b, b)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	headLimit, err := protocolv4.SchemaByteLimit("FreshnessHead")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	headDecoder, err := protocolv4.DecoderBackingBytes(headLimit, headLimit)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec += headDecoder
	t, err := protocolv4.SchemaByteLimit("TrustConfig")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespaceHTTPSService{})) + controlCallContextBytes + s + h + uint64(t) + codec + 4*16384, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 2, resourcev4.Timers: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewNamespaceHTTPSService(store *ledgerv4.SQLitePublicationStore, c NamespaceHTTPSConfig, reservation, dependencies resourcev4.Reference) (_ *NamespaceHTTPSService, err error) {
	cost, err := NamespaceHTTPSServiceCharge(c)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, resourcev4.ErrConfiguration
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	s := &NamespaceHTTPSService{c: c, store: store, done: make(chan struct{})}
	adopted := false
	defer func() {
		if !adopted {
			s.release()
		}
	}()
	s.reservation, err = reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	s.dependencies, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	s.trustRef, err = c.Trust.ReferenceFor(c.Clock, s.reservation)
	if err != nil {
		return nil, err
	}
	s.storeRef, err = store.ReferencePublicationStore(c.Scope, s.reservation)
	if err != nil {
		return nil, err
	}
	s.root, err = c.Trust.PublicationRoot(c.Scope)
	if err != nil {
		return nil, err
	}
	key := c.BootstrapSigner.PublicKey()
	if len(key) != 32 || [32]byte(key) != s.root.PublicKey {
		return nil, resourcev4.ErrConfiguration
	}
	cert, err := x509.ParseCertificate(c.ClientCertificateDER)
	if err != nil || cert.NotBefore.UnixMilli() < 0 || cert.NotAfter.UnixMilli() <= cert.NotBefore.UnixMilli() {
		return nil, resourcev4.ErrConfiguration
	}
	s.client = sha256.Sum256(cert.Raw)
	s.notBefore = uint64(cert.NotBefore.UnixMilli())
	s.notAfter = uint64(cert.NotAfter.UnixMilli())
	s.c.ClientCertificateDER = nil
	r, err := c.Trust.Rules()
	if err != nil {
		return nil, err
	}
	state, head := r.PublicationCapacity()
	s.state = make([]byte, int(state))
	s.head = make([]byte, int(head))
	t, err := protocolv4.SchemaByteLimit("TrustConfig")
	if err != nil {
		return nil, err
	}
	s.trust = make([]byte, t)
	b, err := protocolv4.SchemaByteLimit("TrustBootstrapResponse")
	if err != nil {
		return nil, err
	}
	s.codec, err = protocolv4.NewSignedMapCodec("TrustBootstrapResponse", b, b)
	if err != nil {
		return nil, err
	}
	s.origin, err = c.Clock.Monotonic()
	if err != nil {
		return nil, err
	}
	s.credit = uint64(c.Burst) * 60000
	adopted = true
	return s, nil
}

func (s *NamespaceHTTPSService) checkLocked() error {
	if s.closed {
		return resourcev4.ErrClosed
	}
	for _, ref := range []resourcev4.Reference{s.reservation, s.dependencies, s.storeRef, s.trustRef} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (s *NamespaceHTTPSService) begin() (*controlCallContext, int) {
	if s == nil || !s.mu.TryLock() {
		return nil, http.StatusTooManyRequests
	}
	defer s.mu.Unlock()
	if s.checkLocked() != nil {
		return nil, http.StatusServiceUnavailable
	}
	if s.busy {
		return nil, http.StatusTooManyRequests
	}
	call := newControlCallContext(time.Duration(s.c.WorkMS) * time.Millisecond)
	s.busy, s.cancel = true, call.stopCall
	return call, http.StatusOK
}

func (s *NamespaceHTTPSService) authenticate(r *http.Request) int {
	now, err := s.c.Clock.Sample()
	if err != nil {
		return http.StatusServiceUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checkLocked() != nil || !now.BelongsTo(s.c.Clock) || !now.Mark.SameEra(s.origin) || now.Mark.Milliseconds < s.origin.Milliseconds || now.LowerMS < s.notBefore || now.UpperMS >= s.notAfter {
		return http.StatusServiceUnavailable
	}
	elapsed, _, err := s.c.Clock.Profile().Rate.Elapsed(now.Mark.Milliseconds - s.origin.Milliseconds)
	if err != nil || elapsed < s.creditedMS {
		return http.StatusServiceUnavailable
	}
	delta := elapsed - s.creditedMS
	capacity := uint64(s.c.Burst) * 60000
	if delta >= 60000 {
		s.credit = capacity
	} else {
		s.credit = min(capacity, s.credit+uint64(s.c.RequestsPerMinute)*delta)
	}
	s.creditedMS = elapsed
	if s.credit < 60000 {
		return http.StatusTooManyRequests
	}
	s.credit -= 60000
	tlsState := r.TLS
	if tlsState == nil || !tlsState.HandshakeComplete || tlsState.Version != tls.VersionTLS13 || tlsState.DidResume || len(tlsState.PeerCertificates) == 0 || len(tlsState.PeerCertificates) > 8 || len(tlsState.VerifiedChains) == 0 || len(tlsState.VerifiedChains[0]) == 0 {
		return http.StatusForbidden
	}
	cert, verified := tlsState.PeerCertificates[0], tlsState.VerifiedChains[0][0]
	if cert == nil || verified == nil || len(cert.Raw) == 0 || len(cert.Raw) > 16384 || !bytes.Equal(cert.Raw, verified.Raw) || sha256.Sum256(cert.Raw) != s.client {
		return http.StatusForbidden
	}
	return http.StatusOK
}

func (s *NamespaceHTTPSService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call, status := s.begin()
	if status != http.StatusOK {
		directIssueHTTPFailure(w, status)
		return
	}
	defer s.finish()
	defer call.finish()
	if r == nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if status = s.authenticate(r); status != http.StatusOK {
		directIssueHTTPFailure(w, status)
		return
	}
	if r.Method != http.MethodGet || r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.URL.RawPath != "" || r.URL.ForceQuery || len(r.URL.RawQuery) > 1024 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Encoding") != "" {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	query, err := parseNamespaceQuery(r)
	if err != nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if call.startHTTP(r.Context(), w) != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	window, err := timev4.NewWindow(s.c.Clock, s.c.WorkMS)
	if err != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	defer window.Cancel()
	var trustBytes int
	var headBytes int
	var responseEnd uint64
	guard := func() error {
		if err := call.Err(); err != nil {
			return err
		}
		if err := window.Check(); err != nil {
			return err
		}
		if err := s.dependencies.Check(); err != nil {
			return err
		}
		if err := s.storeRef.Check(); err != nil {
			return err
		}
		now, err := s.c.Clock.Sample()
		if err != nil {
			return err
		}
		if !now.BelongsTo(s.c.Clock) || !now.Mark.SameEra(s.origin) || now.LowerMS < s.notBefore || now.UpperMS >= s.notAfter || responseEnd != 0 && !now.Interval.ValidBefore(responseEnd) {
			return timev4.ErrExpired
		}
		if err := s.c.Trust.CheckPublicationScope(s.c.Scope); err != nil {
			return err
		}
		if trustBytes != 0 {
			if err := s.c.Trust.CheckPublicationTrust(s.c.Scope, s.trust[:trustBytes]); err != nil {
				return err
			}
		}
		if headBytes != 0 {
			if err := s.c.Trust.CheckPublicationHead(s.c.Scope, s.head[:headBytes]); err != nil {
				return err
			}
		}
		return s.store.CheckReadAccess(s.c.Scope, s.client[:])
	}
	if guard() != nil {
		directIssueHTTPFailure(w, http.StatusForbidden)
		return
	}
	if r.URL.Path != "/state" && (query.tenant != s.c.Scope.Tenant || query.authority != s.c.Scope.Authority) {
		directIssueHTTPFailure(w, http.StatusForbidden)
		return
	}
	var response []byte
	var signed *protocolv4.SignedMap
	defer func() {
		if signed != nil {
			signed.Release()
		}
	}()
	switch r.URL.Path {
	case "/head", "/state", "/bootstrap":
		_, n, h, e := s.store.ReadPublished(call, s.client[:], query.digest, s.state, s.head)
		if e != nil {
			directIssueHTTPFailure(w, http.StatusServiceUnavailable)
			return
		}
		response = s.head[:h]
		headBytes = h
		if r.URL.Path == "/state" {
			if uint64(n) != query.size {
				directIssueHTTPFailure(w, http.StatusBadRequest)
				return
			}
			response = s.state[:n]
		}
		if r.URL.Path == "/bootstrap" {
			t, e := s.c.Trust.CopyPublicationTrust(s.c.Scope, s.trust)
			if e != nil {
				directIssueHTTPFailure(w, http.StatusServiceUnavailable)
				return
			}
			trustBytes = t
			now, e := s.c.Clock.Sample()
			if e != nil || now.LowerMS > ^uint64(0)-s.c.BootstrapValidityMS {
				directIssueHTTPFailure(w, http.StatusServiceUnavailable)
				return
			}
			responseEnd = now.LowerMS + s.c.BootstrapValidityMS
			fields := []protocolv4.Field{{Name: "schema_revision", Kind: protocolv4.TextString, Text: "4"}, {Name: "tenant_id", Kind: protocolv4.TextString, Text: s.c.Scope.Tenant}, {Name: "revocation_authority_id", Kind: protocolv4.TextString, Text: s.c.Scope.Authority}, {Name: "request_nonce", Kind: protocolv4.ByteString, Bytes: query.nonce[:]}, {Name: "issued_at_ms", Number: now.LowerMS}, {Name: "not_after_ms", Number: now.LowerMS + s.c.BootstrapValidityMS}, {Name: "trust_config", Kind: protocolv4.ByteString, Bytes: s.trust[:t]}, {Name: "freshness_head", Kind: protocolv4.ByteString, Bytes: s.head[:h]}, {Name: "signing_key_id", Kind: protocolv4.ByteString, Bytes: s.root.KeyID[:]}}
			signed, e = s.codec.SignWith(fields, s.root.PublicKey, s.c.BootstrapSigner, protocolv4.DecodeContext{}, guard)
			if e != nil {
				directIssueHTTPFailure(w, http.StatusServiceUnavailable)
				return
			}
			response, e = signed.Bytes()
			if e != nil {
				directIssueHTTPFailure(w, http.StatusServiceUnavailable)
				return
			}
		}
	case "/trust":
		n, e := s.c.Trust.CopyPublicationTrust(s.c.Scope, s.trust)
		if e != nil {
			directIssueHTTPFailure(w, http.StatusServiceUnavailable)
			return
		}
		response = s.trust[:n]
		trustBytes = n
	default:
		directIssueHTTPFailure(w, http.StatusNotFound)
		return
	}
	if guard() != nil {
		directIssueHTTPFailure(w, http.StatusForbidden)
		return
	}
	s.mu.Lock()
	allowed := s.checkLocked() == nil && call.cause() == nil
	s.mu.Unlock()
	if !allowed {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response[:len(response):len(response)])
}

type namespaceHTTPQuery struct {
	tenant, authority string
	nonce, digest     [32]byte
	size              uint64
}

func parseNamespaceQuery(r *http.Request) (q namespaceHTTPQuery, err error) {
	v := r.URL.Query()
	if v.Encode() != r.URL.RawQuery {
		return q, ErrResponse
	}
	for _, values := range v {
		if len(values) != 1 {
			return q, ErrResponse
		}
	}
	decode := func(name string, dst *[32]byte) error {
		value := v.Get(name)
		if len(value) != 64 {
			return ErrResponse
		}
		n, e := hex.Decode(dst[:], []byte(value))
		if e != nil || n != 32 || hex.EncodeToString(dst[:]) != value || *dst == ([32]byte{}) {
			return ErrResponse
		}
		return nil
	}
	if r.URL.Path == "/state" {
		if len(v) != 2 {
			return q, ErrResponse
		}
		if err = decode("digest", &q.digest); err != nil {
			return q, err
		}
		q.size, err = strconv.ParseUint(v.Get("encoded_bytes"), 10, 64)
		if err != nil || q.size == 0 || strconv.FormatUint(q.size, 10) != v.Get("encoded_bytes") {
			return q, ErrResponse
		}
		return q, nil
	}
	want := 2
	if r.URL.Path == "/bootstrap" {
		want = 3
		if err = decode("nonce", &q.nonce); err != nil {
			return q, err
		}
	}
	if len(v) != want {
		return q, ErrResponse
	}
	q.tenant, q.authority = v.Get("tenant_id"), v.Get("revocation_authority_id")
	if len(q.tenant) == 0 || len(q.tenant) > 128 || len(q.authority) == 0 || len(q.authority) > 128 {
		return q, ErrResponse
	}
	return q, nil
}

func (s *NamespaceHTTPSService) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancel()
	s.cancel = nil
	s.busy = false
	clear(s.state)
	clear(s.head)
	clear(s.trust)
	if s.closed {
		s.release()
	}
}
func (s *NamespaceHTTPSService) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	if !s.busy {
		s.release()
	}
}
func (s *NamespaceHTTPSService) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *NamespaceHTTPSService) release() {
	if s.cleaned {
		return
	}
	clear(s.state)
	clear(s.head)
	clear(s.trust)
	s.state, s.head, s.trust = nil, nil, nil
	s.codec = nil
	s.storeRef.Release()
	s.trustRef.Release()
	s.dependencies.Release()
	s.reservation.Release()
	s.c = NamespaceHTTPSConfig{}
	s.store = nil
	s.root = protocolv4.NamespaceTrustRoot{}
	s.cleaned = true
	close(s.done)
}
