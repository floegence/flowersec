package controlv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// LiveAuthorizationMaterial is the host's retained original lookup result.
// Plan must retain the exact original projection on duplicate requests. The
// service independently checks Artifact against the current Trust and plan.
// Deadline belongs to the original request owner; it is never renewed here.
type LiveAuthorizationMaterial struct {
	Plan        *protocolv4.LiveActivationPlan
	Artifact    *protocolv4.Credential
	Trust       *protocolv4.NamespaceTrustStore
	Deadline    *timev4.Deadline
	ServerAllow LiveServerAllowConfig
}

// LiveAuthorizationAccess retains the authenticated registration, lookup,
// signer and policy dependencies until Close returns. Check is bounded and
// nonblocking; Authorize runs only after the original durable TxA confirms.
// Close must join actual host work and release only this request's borrow.
type LiveAuthorizationAccess interface {
	ledgerv4.SQLiteLiveAuthority
	Material() (LiveAuthorizationMaterial, error)
	Check(context.Context) error
	Authorize(context.Context) (bool, error)
	Close()
}

// LiveAuthorizationHost is independent trusted deployment configuration.
// Acquire must bind the native TLS certificate digest to authorized tenant,
// client IdentityCertificate and audience before looking up the exact original
// Artifact/attempt/winner. A body field or boolean is not authentication.
// CheckShare assigns this service a finite deployment-wide rate/capacity share;
// recreating the service must not recreate consumed admission rights.
type LiveAuthorizationHost interface {
	CheckLiveAuthorizationShare(ledgerv4.SQLiteIdentity, uint16, uint16) error
	AcquireLiveAuthorization(context.Context, [32]byte, sessionv4.LiveAuthorizationRequest) (LiveAuthorizationAccess, error)
}

type LiveAuthorizationHTTPSConfig struct {
	Store                    *ledgerv4.SQLiteStore
	Clock                    *timev4.Clock
	Host                     LiveAuthorizationHost
	ClientCertificateDER     []byte
	MaxRecordBytes           uint32
	RequestsPerMinute, Burst uint16
	WorkMS, RuntimeBytes     uint64
	Tunnel                   bool
	// OnOriginalTunnel runs only inside the newly committed TxB publication.
	// Reads and duplicate requests never dispatch a relay route.
	OnOriginalTunnel func(context.Context, sessionv4.LiveAuthorizationRequest, [3][]byte, func() error) error
}

// LiveAuthorizationHTTPSService mounts POST /live/authorize on a separately
// bounded native TLS 1.3 listener with required client certificates and disabled
// tickets. It has one original request owner, no queue or waiter joins. Header,
// connection and TLS task budgets belong to the listener dependencies.
// Tunnel mode reserves both Grant verification and original server publication.
// A duplicate can read exact committed material but never rerun old policy.
type LiveAuthorizationHTTPSService struct {
	mu                                  sync.Mutex
	c                                   LiveAuthorizationHTTPSConfig
	client                              [32]byte
	notBefore, notAfter                 uint64
	identity                            ledgerv4.SQLiteIdentity
	reservation, shared, storeReference resourcev4.Reference
	codec                               *LiveAuthorizationCodec
	reader                              *LiveSpendService
	spendWork, invokeWork               *resourcev4.ProtectedReservation
	origin                              timev4.Mark
	creditedMS, credit, generation      uint64
	request                             [liveRequestBytes]byte
	projection, response                []byte
	cancel                              context.CancelFunc
	done                                chan struct{}
	busy, closed, cleaned               bool
	terminal                            error
}

// Charges returns five separately preadmitted responsibilities: service,
// original spend buffers, invocation, material-read service, and read buffers.
func LiveAuthorizationHTTPSServiceCharges(c LiveAuthorizationHTTPSConfig) (service, spend, invoke, reader, read resourcev4.Vector, err error) {
	if c.Host == nil || c.WorkMS == 0 || c.WorkMS > 90000 || len(c.ClientCertificateDER) == 0 || len(c.ClientCertificateDER) > 16384 {
		err = resourcev4.ErrConfiguration
		return
	}
	reader, read, err = LiveSpendServiceCharges(liveAuthorizationReadConfig(c))
	if err != nil {
		return
	}
	spend, invoke, err = ledgerv4.SQLiteLiveSpendCharges(c.MaxRecordBytes, c.Tunnel)
	if err != nil {
		return
	}
	spend, err = resourcev4.ProtectedCharge(spend)
	if err != nil {
		return
	}
	invoke, err = resourcev4.ProtectedCharge(invoke)
	if err != nil {
		return
	}
	codec, e := LiveAuthorizationCodecBackingBytes()
	if e != nil {
		err = e
		return
	}
	credential, e := protocolv4.CredentialBackingBytes("Artifact")
	if e != nil {
		err = e
		return
	}
	proof, e := protocolv4.SchemaByteLimit("ActivationAuthorization")
	if e != nil {
		err = e
		return
	}
	var tunnelCost resourcev4.Vector
	if c.Tunnel {
		tunnelCost = resourcev4.Vector{resourcev4.SDKBytes: uint64(liveTunnelMaterialLimit()-proof) + uint64(unsafe.Sizeof(sessionv4.TunnelServerAllowRequest{}))}
	}
	service, err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(LiveAuthorizationHTTPSService{})) + 2*controlCallContextBytes + 2*uint64(unsafe.Sizeof(timev4.Window{})) + uint64(unsafe.Sizeof(liveAuthorizationReadAccess{})) + codec + credential + 2*uint64(proof) + 4*16384, resourcev4.Items: 1, resourcev4.Tasks: 3, resourcev4.WorkSlots: 1, resourcev4.Timers: 3}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err == nil {
		service, err = service.Add(tunnelCost)
	}
	return
}

func liveAuthorizationReadConfig(c LiveAuthorizationHTTPSConfig) LiveSpendServiceConfig {
	return LiveSpendServiceConfig{Store: c.Store, Clock: c.Clock, MaxRecordBytes: c.MaxRecordBytes, RequestsPerMinute: c.RequestsPerMinute, Burst: c.Burst, WorkMS: min(c.WorkMS, 2000), RuntimeBytes: c.RuntimeBytes, Tunnel: c.Tunnel}
}

func NewLiveAuthorizationHTTPSService(c LiveAuthorizationHTTPSConfig, reservation, spend, invoke, reader, read, dependencies resourcev4.Reference) (_ *LiveAuthorizationHTTPSService, err error) {
	cost, _, _, _, _, err := LiveAuthorizationHTTPSServiceCharges(c)
	if err != nil {
		return nil, err
	}
	for _, ref := range []resourcev4.Reference{spend, invoke, reader, read, dependencies} {
		if err = reservation.CheckSameEnvironment(ref); err != nil {
			return nil, err
		}
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	p := &LiveAuthorizationHTTPSService{c: c, reservation: owned, done: make(chan struct{})}
	adopted := false
	defer func() {
		if !adopted {
			p.Close()
		}
	}()
	p.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	var limit uint32
	p.storeReference, p.identity, limit, err = c.Store.LiveAuthorizationReference(owned)
	if err != nil {
		return nil, err
	}
	if limit != c.MaxRecordBytes {
		return nil, resourcev4.ErrConfiguration
	}
	if err = c.Host.CheckLiveAuthorizationShare(p.identity, c.RequestsPerMinute, c.Burst); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(c.ClientCertificateDER)
	if err != nil || cert.NotBefore.UnixMilli() < 0 || cert.NotAfter.UnixMilli() <= cert.NotBefore.UnixMilli() {
		return nil, resourcev4.ErrConfiguration
	}
	p.client = sha256.Sum256(cert.Raw)
	p.notBefore, p.notAfter = uint64(cert.NotBefore.UnixMilli()), uint64(cert.NotAfter.UnixMilli())
	p.c.ClientCertificateDER = nil
	p.origin, err = c.Clock.Monotonic()
	if err != nil {
		return nil, err
	}
	p.credit = uint64(c.Burst) * 60000
	p.codec, err = NewLiveAuthorizationCodec()
	if err != nil {
		return nil, err
	}
	minimum, invocation, _ := ledgerv4.SQLiteLiveSpendCharges(c.MaxRecordBytes, c.Tunnel)
	p.spendWork, err = resourcev4.NewProtectedReservation(spend, minimum)
	if err != nil {
		return nil, err
	}
	p.invokeWork, err = resourcev4.NewProtectedReservation(invoke, invocation)
	if err != nil {
		return nil, err
	}
	p.reader, err = NewLiveSpendService(liveAuthorizationReadConfig(c), reader, read, dependencies)
	if err != nil {
		return nil, err
	}
	proof, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	responseLimit := proof
	if c.Tunnel {
		responseLimit = liveTunnelMaterialLimit()
	}
	p.projection, p.response = make([]byte, proof), make([]byte, responseLimit)
	adopted = true
	return p, nil
}

func (p *LiveAuthorizationHTTPSService) checkLocked() error {
	if p.closed {
		return resourcev4.ErrClosed
	}
	if p.terminal != nil {
		return p.terminal
	}
	for _, ref := range []resourcev4.Reference{p.reservation, p.shared, p.storeReference} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (p *LiveAuthorizationHTTPSService) currentLocked(now timev4.Sample) error {
	if err := p.checkLocked(); err != nil {
		return err
	}
	if !now.BelongsTo(p.c.Clock) || !now.Mark.SameEra(p.origin) || now.LowerMS < p.notBefore || now.UpperMS >= p.notAfter {
		return timev4.ErrExpired
	}
	return nil
}

func (p *LiveAuthorizationHTTPSService) begin() (*controlCallContext, int) {
	if p == nil || !p.mu.TryLock() {
		return nil, http.StatusTooManyRequests
	}
	defer p.mu.Unlock()
	if p.busy {
		return nil, http.StatusTooManyRequests
	}
	if p.checkLocked() != nil {
		return nil, http.StatusServiceUnavailable
	}
	call := newControlCallContext(time.Duration(p.c.WorkMS) * time.Millisecond)
	p.busy, p.cancel = true, call.stopCall
	return call, http.StatusOK
}

func (p *LiveAuthorizationHTTPSService) authenticate(r *http.Request) int {
	now, err := p.c.Clock.Sample()
	if err != nil {
		return http.StatusServiceUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.currentLocked(now) != nil || now.Milliseconds < p.origin.Milliseconds {
		return http.StatusServiceUnavailable
	}
	elapsed, _, err := p.c.Clock.Profile().Rate.Elapsed(now.Milliseconds - p.origin.Milliseconds)
	if err != nil || elapsed < p.creditedMS {
		return http.StatusServiceUnavailable
	}
	delta := elapsed - p.creditedMS
	capacity := uint64(p.c.Burst) * 60000
	if delta >= 60000 {
		p.credit = capacity
	} else {
		p.credit = min(capacity, p.credit+uint64(p.c.RequestsPerMinute)*delta)
	}
	p.creditedMS = elapsed
	if p.credit < 60000 {
		return http.StatusTooManyRequests
	}
	p.credit -= 60000
	s := r.TLS
	if s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 || s.DidResume || len(s.PeerCertificates) == 0 || len(s.PeerCertificates) > 8 || len(s.VerifiedChains) == 0 || len(s.VerifiedChains[0]) == 0 {
		return http.StatusForbidden
	}
	cert, verified := s.PeerCertificates[0], s.VerifiedChains[0][0]
	if cert == nil || verified == nil || len(cert.Raw) == 0 || len(cert.Raw) > 16384 || !bytes.Equal(cert.Raw, verified.Raw) || sha256.Sum256(cert.Raw) != p.client {
		return http.StatusForbidden
	}
	if p.generation == ^uint64(0) {
		return http.StatusServiceUnavailable
	}
	p.generation++
	return http.StatusOK
}

func (p *LiveAuthorizationHTTPSService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call, status := p.begin()
	if status != http.StatusOK {
		directIssueHTTPFailure(w, status)
		return
	}
	defer p.finish()
	defer call.finish()
	if r == nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if status = p.authenticate(r); status != http.StatusOK {
		directIssueHTTPFailure(w, status)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/live/authorize" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength <= 0 || r.ContentLength > liveRequestBytes || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Type") != "application/cbor" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if call.startHTTP(r.Context(), w) != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	window, err := timev4.NewWindow(p.c.Clock, p.c.WorkMS)
	if err != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	defer window.Cancel()
	if _, err = io.ReadFull(r.Body, p.request[:int(r.ContentLength)]); err != nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	q, err := p.codec.Decode(p.request[:int(r.ContentLength)])
	if err != nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	guard := func() error {
		if err := window.Check(); err != nil {
			return err
		}
		now, err := p.c.Clock.Sample()
		if err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if err := call.cause(); err != nil {
			return err
		}
		return p.currentLocked(now)
	}
	if err = guard(); err != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	written := false
	_, err = p.authorize(call, q, p.request[:int(r.ContentLength)], guard, func(ctx context.Context, proof []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := guard(); err != nil {
			return err
		}
		end, ok := ctx.Deadline()
		if !ok {
			return resourcev4.ErrConfiguration
		}
		if err := http.NewResponseController(w).SetWriteDeadline(end); err != nil {
			return err
		}
		// The original authority/read guard has just checked current trust and
		// ACL. Retain that entire owner through the actual response handoff.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", strconv.Itoa(len(proof)))
		written = true
		w.WriteHeader(http.StatusOK)
		n, err := w.Write(proof)
		if err == nil && n != len(proof) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		// Write may still hold a short response in the HTTP buffer. Retain the
		// original authorization owner through its actual local flush; this
		// completion is not a statement of remote receipt.
		if err = http.NewResponseController(w).Flush(); err != nil {
			return err
		}
		return guard()
	})
	if err != nil && !written {
		status = http.StatusServiceUnavailable
		if errors.Is(err, ledgerv4.ErrDenied) {
			status = http.StatusForbidden
		} else if errors.Is(err, ledgerv4.ErrConflict) || errors.Is(err, ledgerv4.ErrMaterialNotReady) {
			status = http.StatusConflict
		}
		directIssueHTTPFailure(w, status)
		return
	}
}

func (p *LiveAuthorizationHTTPSService) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancel()
	p.cancel, p.busy = nil, false
	clear(p.request[:])
	clear(p.projection)
	clear(p.response)
	p.cleanupLocked()
}
func (p *LiveAuthorizationHTTPSService) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	p.cleanupLocked()
}
func (p *LiveAuthorizationHTTPSService) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	if p.reader != nil {
		p.reader.Close()
	}
	if p.spendWork != nil {
		p.spendWork.Close()
		if !p.spendWork.CleanupComplete() {
			return
		}
	}
	if p.invokeWork != nil {
		p.invokeWork.Close()
		if !p.invokeWork.CleanupComplete() {
			return
		}
	}
	clear(p.response)
	clear(p.projection)
	p.response, p.projection = nil, nil
	p.c = LiveAuthorizationHTTPSConfig{}
	p.codec, p.reader = nil, nil
	p.reservation.Release()
	p.shared.Release()
	p.storeReference.Release()
	p.reservation, p.shared, p.storeReference = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}
func (p *LiveAuthorizationHTTPSService) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// authorize owns the complete original host/SQLite tail. Even a cancelled
// callback cannot release this service slot before its actual return.
func (p *LiveAuthorizationHTTPSService) authorize(ctx context.Context, q sessionv4.LiveAuthorizationRequest, wire []byte, guard func() error, deliver func(context.Context, []byte) error) (n int, err error) {
	access, err := p.c.Host.AcquireLiveAuthorization(ctx, p.client, q)
	if access != nil {
		defer access.Close()
	}
	if err != nil {
		return 0, err
	}
	if access == nil {
		return 0, ledgerv4.ErrDenied
	}
	material, err := access.Material()
	if err != nil {
		return 0, err
	}
	if material.Plan == nil || material.Artifact == nil || material.Trust == nil || !material.Deadline.BelongsTo(p.c.Clock) {
		return 0, resourcev4.ErrConfiguration
	}
	trust, err := material.Trust.ReferenceFor(p.c.Clock, p.reservation)
	if err != nil {
		return 0, err
	}
	defer trust.Release()
	if err = material.Plan.CheckEnvironment(p.reservation); err != nil {
		return 0, err
	}
	fields, size, err := material.Plan.CopyProjection(p.projection)
	if err != nil {
		return 0, err
	}
	if fields.Tunnel && !p.c.Tunnel || fields.Tenant != q.Tenant || fields.Audience != q.Audience || fields.Profile != q.CryptoProfile || fields.Issuer != q.Issuer || fields.Lease != q.Lease || fields.Attempt != q.Attempt || fields.Artifact != q.Artifact || fields.ClientIdentity != q.ClientIdentity || fields.ServerIdentity != q.ServerIdentity || fields.Winner != q.Winner || fields.ActivationEnd > q.ActivationNotAfterMS {
		return 0, ledgerv4.ErrConflict
	}
	deadline, err := material.Deadline.Fork(min(q.ActivationNotAfterMS, fields.ActivationEnd))
	if err != nil {
		return 0, err
	}
	check := func() error {
		if err := guard(); err != nil {
			return err
		}
		if err := trust.Check(); err != nil {
			return err
		}
		if err := deadline.Check(); err != nil {
			return err
		}
		if err := access.Check(ctx); err != nil {
			return err
		}
		binding, err := material.Trust.ResolveCredential(material.Artifact)
		if err != nil {
			return err
		}
		if err = material.Trust.Policy(binding.Policy); err != nil {
			return err
		}
		now, err := p.c.Clock.Sample()
		if err != nil {
			return err
		}
		if err = material.Artifact.CheckAdmission(now.Interval); err != nil {
			return err
		}
		requirement := binding.Policy.Requirements()
		return material.Plan.CheckTrust(binding.Namespace, material.Artifact, binding.Issuer, requirement.StalenessMS, requirement.SignerLifetimeMS, fields.SessionEnd, now.Interval)
	}
	if err = check(); err != nil {
		return 0, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("flowersec/live-authorization-1/request\x00"))
	_, _ = digest.Write(wire)
	var request [32]byte
	copy(request[:], digest.Sum(nil))
	readAccess := &liveAuthorizationReadAccess{identity: p.identity, target: ledgerv4.LiveSpendReadTarget{Tenant: q.Tenant, Audience: q.Audience, Issuer: q.Issuer, Lease: q.Lease, Attempt: q.Attempt, ClientIdentity: q.ClientIdentity, RequestDigest: request}, check: check, projection: p.projection[:size:size], access: access, fields: fields, plan: material.Plan}
	publish := func(call context.Context, proof []byte) error {
		if err := call.Err(); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		if len(proof) == 0 || len(proof) > len(p.response) {
			return resourcev4.ErrCapacity
		}
		n = copy(p.response, proof)
		return deliver(call, p.response[:n:n])
	}
	publishTunnel := func(call context.Context, bytes [2][]byte) error {
		if err := call.Err(); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		var err error
		n, err = encodeLiveTunnelMaterial(p.response, bytes)
		if err != nil {
			return err
		}
		return deliver(call, p.response[:n:n])
	}
	if fields.Tunnel {
		err = p.reader.DeliverOriginalClientTunnelMaterial(ctx, readAccess, deadline, q.AttemptNo, publishTunnel)
	} else {
		err = p.reader.DeliverOriginalClientMaterial(ctx, readAccess, deadline, q.AttemptNo, publish)
	}
	if err == nil {
		return n, nil
	}
	if !errors.Is(err, ledgerv4.ErrSpendNotObserved) {
		return 0, err
	}
	var allow sessionv4.TunnelServerAllowRequest
	if fields.Tunnel {
		allow, err = liveServerAllowRequest(material.Plan, fields, material.ServerAllow, deadline.Cap())
		if err != nil {
			return 0, err
		}
	}
	var relay *ledgerv4.SQLiteLiveRelayPublication
	if fields.Tunnel && material.ServerAllow.Relay != nil {
		relay, err = ledgerv4.NewSQLiteLiveRelayPublication(ctx, p.c.Store, material.Plan, *material.ServerAllow.Relay)
		if err != nil {
			return 0, err
		}
		defer relay.Close()
	}
	// Absence is only a reason to attempt the unique TxA INSERT. A concurrent
	// winner still conflicts transactionally; it never permits policy replay.
	var refs [2]resourcev4.Reference
	if err = resourcev4.CheckoutProtectedBatch([]*resourcev4.ProtectedReservation{p.spendWork, p.invokeWork}, refs[:]); err != nil {
		return 0, err
	}
	defer refs[0].Release()
	defer refs[1].Release()
	var invocation [16]byte
	if _, err = rand.Read(invocation[:]); err != nil || invocation == ([16]byte{}) {
		return 0, ledgerv4.ErrStorageUnavailable
	}
	owner := ledgerv4.LiveSpendOwner{Invocation: invocation, Generation: p.generation, RequestDigest: request, ClientMaterialNotAfter: deadline.Cap()}
	original, err := ledgerv4.NewSQLiteLiveSpend(ctx, p.c.Store, access, material.Plan, owner, p.c.Clock, deadline, check, refs[0], refs[1], p.reservation)
	if err != nil {
		return 0, err
	}
	defer func() {
		if cleanup := original.Cleanup(); cleanup != nil {
			p.mu.Lock()
			p.terminal = cleanup
			p.mu.Unlock()
			if err == nil {
				err = cleanup
				n = 0
			}
		}
	}()
	if relay != nil {
		if err = original.AttachRelayPublication(relay); err != nil {
			return 0, err
		}
	}
	if fields.Tunnel {
		err = original.AuthorizeMaterial(access.Authorize, func(call context.Context, bytes [3][]byte) error {
			if p.c.OnOriginalTunnel != nil {
				if err := check(); err != nil {
					return err
				}
				if err := p.c.OnOriginalTunnel(call, q, bytes, check); err != nil {
					return err
				}
			}
			if err := publishLiveServerAllow(call, p.c.Clock, material.ServerAllow, allow, [2][]byte{bytes[0], bytes[2]}, check); err != nil {
				return err
			}
			return p.publishInitialClient(call, func(body context.Context) error { return publishTunnel(body, [2][]byte{bytes[0], bytes[1]}) })
		})
	} else {
		err = original.Authorize(access.Authorize, func(call context.Context, wire []byte) error {
			return p.publishInitialClient(call, func(body context.Context) error { return publish(body, wire) })
		})
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

type liveAuthorizationReadAccess struct {
	identity   ledgerv4.SQLiteIdentity
	target     ledgerv4.LiveSpendReadTarget
	fields     protocolv4.LiveActivationFields
	projection []byte
	check      func() error
	access     LiveAuthorizationAccess
	plan       *protocolv4.LiveActivationPlan
}

func (a *liveAuthorizationReadAccess) Target(identity ledgerv4.SQLiteIdentity) (ledgerv4.LiveSpendReadTarget, error) {
	if identity != a.identity {
		return ledgerv4.LiveSpendReadTarget{}, ledgerv4.ErrFenced
	}
	if err := a.check(); err != nil {
		return ledgerv4.LiveSpendReadTarget{}, err
	}
	if err := a.access.CheckLiveSpend(identity, a.fields); err != nil {
		return ledgerv4.LiveSpendReadTarget{}, err
	}
	return a.target, nil
}
func (a *liveAuthorizationReadAccess) CheckMaterial(identity ledgerv4.SQLiteIdentity, target ledgerv4.LiveSpendReadTarget, proof *protocolv4.SignedMap) error {
	if identity != a.identity || target != a.target {
		return ledgerv4.ErrConflict
	}
	if err := a.check(); err != nil {
		return err
	}
	return proof.MatchUnsignedProjection(a.projection)
}

func (a *liveAuthorizationReadAccess) CheckClientGrant(identity ledgerv4.SQLiteIdentity, target ledgerv4.LiveSpendReadTarget, grant *protocolv4.SignedMap) error {
	if identity != a.identity || target != a.target {
		return ledgerv4.ErrConflict
	}
	if err := a.check(); err != nil {
		return err
	}
	return a.plan.CheckClientGrant(grant)
}

// Body work starts only once complete original TxB bytes are ready. Original
// invocation/claim deadlines remain independent and can only shorten this task.
func (p *LiveAuthorizationHTTPSService) publishInitialClient(ctx context.Context, publish func(context.Context) error) error {
	window, err := timev4.NewWindow(p.c.Clock, 2000)
	if err != nil {
		return err
	}
	defer window.Cancel()
	call := newControlCallContext(2 * time.Second)
	defer call.finish()
	if err = call.start(ctx); err != nil {
		return err
	}
	if err = window.Check(); err != nil {
		return err
	}
	if err = publish(call); err != nil {
		return err
	}
	if err = window.Check(); err != nil {
		return err
	}
	return call.cause()
}

// ServeRegisteredAuthorization shares the original service admission, fixed
// mTLS identity, rate share and TxA/TxB owner with the registered JSON adapter.
// The adapter has already verified the nonce signature and canonical request;
// this method rechecks the actual native TLS peer and encodes the request itself.
func (p *LiveAuthorizationHTTPSService) ServeRegisteredAuthorization(w http.ResponseWriter, r *http.Request, q sessionv4.LiveAuthorizationRequest, deliver func(context.Context, []byte, func() error) error) (err error) {
	if deliver == nil || r == nil {
		return resourcev4.ErrConfiguration
	}
	call, status := p.begin()
	if status != http.StatusOK {
		return ErrBusy
	}
	defer p.finish()
	defer call.finish()
	if status = p.authenticate(r); status != http.StatusOK {
		return ledgerv4.ErrDenied
	}
	if err = call.start(r.Context()); err != nil {
		return err
	}
	size, err := EncodeLiveAuthorizationRequest(p.request[:], q)
	if err != nil {
		return err
	}
	guard := func() error {
		if err := call.cause(); err != nil {
			return err
		}
		now, err := p.c.Clock.Sample()
		if err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.currentLocked(now)
	}
	_, err = p.authorize(call, q, p.request[:size:size], guard, func(ctx context.Context, material []byte) error { return deliver(ctx, material, guard) })
	return err
}
