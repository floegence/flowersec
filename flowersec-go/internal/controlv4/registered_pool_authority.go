package controlv4

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// RegisteredPoolAuthorityConfig is installed before B registers. Issue must
// complete original signing, outbox COMMIT and relay publication in that call.
type RegisteredPoolAuthorityConfig struct {
	Authority                 string
	Parent                    [32]byte
	Candidate                 uint64
	ServerKey, ServerGrantKey [32]byte
	ServerCertificateDER      []byte
	Issue                     func(context.Context) ([2][]byte, *ledgerv4.SQLitePoolWinnerContinuation, error)
	CancelOriginal            func()
	WorkMS                    uint64
}

type RegisteredPoolAuthority struct {
	mu                                        sync.Mutex
	config                                    RegisteredPoolAuthorityConfig
	reservation, shared                       resourcev4.Reference
	certificate                               [32]byte
	incarnation                               string
	grants                                    [2][]byte
	winner                                    *ledgerv4.SQLitePoolWinnerContinuation
	grantDigest                               [32]byte
	publicationEnd                            time.Time
	cancel                                    context.CancelFunc
	ready, stop, done                         chan struct{}
	installed, busy, closed, closing, cleaned bool
}

func RegisteredPoolAuthorityCharge(c RegisteredPoolAuthorityConfig) (resourcev4.Vector, error) {
	if c.Authority == "" || len(c.Authority) > 128 || c.Parent == ([32]byte{}) || c.Candidate >= 16 || c.ServerKey == ([32]byte{}) || c.ServerGrantKey == ([32]byte{}) || c.Issue == nil || c.CancelOriginal == nil || c.WorkMS == 0 || c.WorkMS > 60000 || len(c.ServerCertificateDER) == 0 || len(c.ServerCertificateDER) > 16384 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := x509.ParseCertificate(c.ServerCertificateDER); err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := protocolv4.SignedMapBackingBytes("Grant", 65536, 16384)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	// Request text, JSON fields, signing input, base64 projections and the
	// encoded response coexist until the original physical writer returns.
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RegisteredPoolAuthority{})) + 8*registeredControlBodyLimit + 2*65536 + codec + 16384, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 2, resourcev4.Timers: 2}, nil
}

func NewRegisteredPoolAuthority(c RegisteredPoolAuthorityConfig, reservation, environment resourcev4.Reference) (*RegisteredPoolAuthority, error) {
	cost, err := RegisteredPoolAuthorityCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	shared, err := environment.Borrow()
	if err != nil {
		owned.Release()
		return nil, err
	}
	p := &RegisteredPoolAuthority{config: c, certificate: sha256.Sum256(c.ServerCertificateDER), publicationEnd: time.Now().Add(time.Duration(c.WorkMS) * time.Millisecond), reservation: owned, shared: shared, ready: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	p.config.ServerCertificateDER = nil
	return p, nil
}

func (p *RegisteredPoolAuthority) check() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return resourcev4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	return p.shared.Check()
}

// WaitPublished observes issuer COMMIT and B's verified installation ACK.
// It does not wait for or authorize consumer TxA-P, server Allow or HOP.
func (p *RegisteredPoolAuthority) WaitPublished(ctx context.Context) (err error) {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()
	timer := time.NewTimer(time.Until(p.publicationEnd))
	defer timer.Stop()
	select {
	case <-p.ready:
		return p.check()
	case <-p.stop:
		return resourcev4.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func (p *RegisteredPoolAuthority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/flowersec/control/tunnel" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.TransferEncoding) != 0 || r.ContentLength <= 0 || r.ContentLength > registeredControlBodyLimit || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || sha256.Sum256(r.TLS.PeerCertificates[0].Raw) != p.certificate {
		directIssueHTTPFailure(w, http.StatusForbidden)
		return
	}
	p.mu.Lock()
	if p.closed || p.busy {
		p.mu.Unlock()
		directIssueHTTPFailure(w, http.StatusConflict)
		return
	}
	requestEnd := time.Now().Add(time.Duration(p.config.WorkMS) * time.Millisecond)
	if !p.installed && p.publicationEnd.Before(requestEnd) {
		requestEnd = p.publicationEnd
	}
	ctx, cancel := context.WithDeadline(r.Context(), requestEnd)
	p.busy, p.cancel = true, cancel
	p.mu.Unlock()
	success := false
	defer func() {
		cancel()
		if !success {
			p.Close()
		}
		p.mu.Lock()
		p.busy, p.cancel = false, nil
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return p.check()
	}
	controller := http.NewResponseController(w)
	end, _ := ctx.Deadline()
	if controller.SetReadDeadline(end) != nil || controller.SetWriteDeadline(end) != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, registeredControlBodyLimit+1))
	defer clear(body)
	if err != nil || int64(len(body)) != r.ContentLength {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	var envelope struct {
		Payload string `json:"payload"`
		Proof   string `json:"proof"`
	}
	if decodeRegisteredJSON(body, &envelope) != nil || len(envelope.Payload) == 0 || len(envelope.Payload) > 131072 {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Proof)
	defer clear(signature)
	message := append([]byte(registeredControlDomain), []byte(envelope.Payload)...)
	defer clear(message)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != envelope.Proof || !ed25519.Verify(ed25519.PublicKey(p.config.ServerKey[:]), message, signature) {
		directIssueHTTPFailure(w, http.StatusForbidden)
		return
	}
	var q struct {
		Kind         string `json:"kind"`
		Incarnation  string `json:"incarnation"`
		Parent       string `json:"parent"`
		Candidate    uint64 `json:"candidate"`
		Grant        string `json:"grant,omitempty"`
		Continuation string `json:"continuation,omitempty"`
	}
	var shape map[string]json.RawMessage
	if decodeRegisteredJSON([]byte(envelope.Payload), &q) != nil || decodeRegisteredJSON([]byte(envelope.Payload), &shape) != nil || q.Parent != base64.StdEncoding.EncodeToString(p.config.Parent[:]) || q.Candidate != p.config.Candidate || string(shape["candidate"]) != strconv.FormatUint(p.config.Candidate, 10) {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	incarnation, err := base64.StdEncoding.Strict().DecodeString(q.Incarnation)
	defer clear(incarnation)
	if err != nil || len(incarnation) != 32 || [32]byte(incarnation) == ([32]byte{}) || base64.StdEncoding.EncodeToString(incarnation) != q.Incarnation {
		directIssueHTTPFailure(w, http.StatusForbidden)
		return
	}
	reply := RegisteredControlReply{Incarnation: q.Incarnation, Authority: p.config.Authority}
	acknowledge := false
	err = func() error {
		if err := guard(); err != nil {
			return err
		}
		switch q.Kind {
		case "prepare":
			if len(shape) != 4 || p.incarnation != "" {
				return ledgerv4.ErrOwner
			}
			p.incarnation = q.Incarnation
			p.grants, p.winner, err = p.config.Issue(ctx)
			if err != nil {
				return err
			}
			if p.winner == nil {
				return ledgerv4.ErrOwner
			}
			codec, err := protocolv4.NewSignedMapCodec("Grant", 65536, 16384)
			if err != nil {
				return err
			}
			grant, err := codec.Verify(p.grants[1], p.config.ServerGrantKey, protocolv4.DecodeContext{})
			if err != nil {
				return err
			}
			p.grantDigest, err = grant.Digest("grant_digest")
			grant.Release()
			if err != nil {
				return err
			}
			nonce, lease, projection, err := p.winner.Publication()
			if err != nil {
				return err
			}
			reply.ClientGrant, reply.ServerGrant = base64.StdEncoding.EncodeToString(p.grants[0]), base64.StdEncoding.EncodeToString(p.grants[1])
			reply.Continuation, reply.Lease, reply.Projection = base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(lease), base64.StdEncoding.EncodeToString(projection)
		case "prepared_ack", "winner_continue":
			if q.Incarnation != p.incarnation || p.winner == nil {
				return ledgerv4.ErrOwner
			}
			nonce, err := base64.StdEncoding.Strict().DecodeString(q.Continuation)
			defer clear(nonce)
			if err != nil || len(nonce) != 32 || base64.StdEncoding.EncodeToString(nonce) != q.Continuation {
				return ledgerv4.ErrOwner
			}
			if q.Kind == "prepared_ack" {
				if len(shape) != 6 || p.installed || q.Grant != base64.StdEncoding.EncodeToString(p.grantDigest[:]) {
					return ledgerv4.ErrOwner
				}
				if err = p.winner.Acknowledge(nonce); err != nil {
					return err
				}
				p.mu.Lock()
				p.installed = true
				p.mu.Unlock()
				reply.Prepared, acknowledge = true, true
			} else {
				if len(shape) != 5 || !p.installed {
					return ledgerv4.ErrOwner
				}
				if err = p.winner.Continue(ctx, nonce, guard); err != nil {
					return err
				}
				reply.Matched = true
			}
		default:
			return ledgerv4.ErrOwner
		}
		return guard()
	}()
	if err != nil {
		directIssueHTTPFailure(w, http.StatusConflict)
		return
	}
	encoded, err := json.Marshal(reply)
	defer clear(encoded)
	if err != nil || len(encoded) > registeredControlBodyLimit {
		directIssueHTTPFailure(w, http.StatusConflict)
		return
	}
	// This application control protocol uses one response per connection. The
	// original handler owns the socket through flush and Close; the ready signal
	// cannot run from an HTTP header write or a detached completion callback.
	conn, buffered, err := controller.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	// Hijacked connections are outside net/http cancellation and shutdown.
	// Retain the request position until its cancellation closer also returns.
	closed := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close(); close(closed) })
	defer func() {
		if !stopClose() {
			<-closed
		}
	}()
	if conn.SetDeadline(end) != nil {
		return
	}
	if _, err = fmt.Fprintf(buffered, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", len(encoded)); err == nil {
		_, err = buffered.Write(encoded)
	}
	if err == nil {
		err = buffered.Flush()
	}
	closeErr := conn.Close()
	if err != nil || closeErr != nil || guard() != nil {
		return
	}
	if acknowledge {
		close(p.ready)
	}
	success = true
}

func (p *RegisteredPoolAuthority) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed, p.closing = true, true
	close(p.stop)
	cancel, stop := p.cancel, p.config.CancelOriginal
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if stop != nil {
		stop()
	}
	p.mu.Lock()
	p.closing = false
	p.cleanupLocked()
	p.mu.Unlock()
}

func (p *RegisteredPoolAuthority) cleanupLocked() {
	if !p.closed || p.closing || p.busy || p.cleaned {
		return
	}
	p.winner.Close()
	for _, grant := range p.grants {
		clear(grant)
	}
	p.grants, p.winner, p.config = [2][]byte{}, nil, RegisteredPoolAuthorityConfig{}
	p.shared.Release()
	p.reservation.Release()
	p.cleaned = true
	close(p.done)
}

func (p *RegisteredPoolAuthority) WaitCleanup(ctx context.Context) error {
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
