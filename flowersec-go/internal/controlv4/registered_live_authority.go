package controlv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
)

// RegisteredLiveAuthorityConfig is an independent installation. Neither a
// live_register body nor issued material may select its TLS peers or signers.
type RegisteredLiveAuthorityConfig struct {
	Authority, Tenant, Audience                         string
	Parent                                              [32]byte
	Candidate                                           uint64
	ClientKey, ServerKey, ActivationKey, ServerGrantKey [32]byte
	ClientCertificateDER, ServerCertificateDER          []byte
	Service                                             *LiveAuthorizationHTTPSService
	PrepareOriginalCarrier                              func(context.Context, protocolv4.Direction) error
	// CancelOriginal fences the actual route when this one publication fails.
	CancelOriginal       func()
	WorkMS, RuntimeBytes uint64
}

// RegisteredLiveAuthority retains the one original B incarnation, A prepared
// attempt and publication. Its channels represent actual SDK reservation and
// digest acknowledgments; no restored row can recreate them.
type RegisteredLiveAuthority struct {
	mu                                                                                  sync.Mutex
	config                                                                              RegisteredLiveAuthorityConfig
	reservation, dependencies                                                           resourcev4.Reference
	clientTLS, serverTLS                                                                [32]byte
	recipient, incarnation, attempt                                                     [16]byte
	clientIncarnation, serverIncarnation                                                string
	registered, prepared, used, reservationTaken, reserved, materialTaken, acknowledged bool
	busy                                                                                [2]bool
	closed, cleaned                                                                     bool
	ready, attemptReady, reservedReady, materialReady, ackReady, stop, done             chan struct{}
	publication                                                                         [2][]byte
	digests                                                                             [2][32]byte
}

func RegisteredLiveAuthorityCharge(c RegisteredLiveAuthorityConfig) (resourcev4.Vector, error) {
	if c.Authority == "" || len(c.Authority) > 128 || c.Tenant == "" || c.Audience == "" || c.Parent == ([32]byte{}) || c.Candidate >= 16 || c.ClientKey == ([32]byte{}) || c.ServerKey == ([32]byte{}) || c.ActivationKey == ([32]byte{}) || c.ServerGrantKey == ([32]byte{}) || c.Service == nil || c.PrepareOriginalCarrier == nil || c.WorkMS == 0 || c.WorkMS > 60000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for _, wire := range [][]byte{c.ClientCertificateDER, c.ServerCertificateDER} {
		if len(wire) == 0 || len(wire) > 16384 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		if _, err := x509.ParseCertificate(wire); err != nil {
			return resourcev4.Vector{}, err
		}
	}
	var backing uint64
	for _, schema := range []string{"ActivationAuthorization", "Grant"} {
		cost, err := protocolv4.SignedMapBackingBytes(schema, 65536, 16384)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		backing += cost
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RegisteredLiveAuthority{})) + 2*registeredControlBodyLimit + 4*65536 + backing + c.RuntimeBytes, resourcev4.Items: 1, resourcev4.WorkSlots: 2, resourcev4.Tasks: 2}, nil
}
func NewRegisteredLiveAuthority(c RegisteredLiveAuthorityConfig, reservation, dependencies resourcev4.Reference) (p *RegisteredLiveAuthority, err error) {
	cost, err := RegisteredLiveAuthorityCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		owned.Release()
		return nil, err
	}
	p = &RegisteredLiveAuthority{config: c, reservation: owned, dependencies: shared, clientTLS: sha256.Sum256(c.ClientCertificateDER), serverTLS: sha256.Sum256(c.ServerCertificateDER), ready: make(chan struct{}), attemptReady: make(chan struct{}), reservedReady: make(chan struct{}), materialReady: make(chan struct{}), ackReady: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	p.config.ClientCertificateDER = nil
	p.config.ServerCertificateDER = nil
	return p, nil
}
func (p *RegisteredLiveAuthority) check() error {
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.dependencies.Check(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return resourcev4.ErrClosed
	}
	return nil
}
func (p *RegisteredLiveAuthority) wait(ctx context.Context, signal <-chan struct{}, guard func() error) error {
	if err := guard(); err != nil {
		return err
	}
	select {
	case <-signal:
		return guard()
	case <-p.stop:
		return resourcev4.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *RegisteredLiveAuthority) WaitRegistered(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	return p.wait(ctx, p.ready, p.check)
}
func (p *RegisteredLiveAuthority) ServerAllow() (sessionv4.LiveServerAllowConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.registered || !p.reserved {
		return sessionv4.LiveServerAllowConfig{}, ledgerv4.ErrMaterialNotReady
	}
	return sessionv4.LiveServerAllowConfig{Provider: p, Recipient: p.recipient, Incarnation: p.incarnation}, nil
}
func (p *RegisteredLiveAuthority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p == nil || r == nil || r.Method != http.MethodPost || r.URL.Path != "/flowersec/control/live" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Type") != "application/json" || len(r.TransferEncoding) != 0 || r.ContentLength <= 0 || r.ContentLength > registeredControlBodyLimit {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(p.config.WorkMS)*time.Millisecond)
	defer cancel()
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
	if err = decodeRegisteredJSON(body, &envelope); err != nil || len(envelope.Payload) == 0 || len(envelope.Payload) > 131072 {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	var payload RegisteredControlPayload
	var shape map[string]json.RawMessage
	if err = decodeRegisteredJSON([]byte(envelope.Payload), &shape); err != nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if err = decodeRegisteredJSON([]byte(envelope.Payload), &payload); err != nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	expectedFields := 0
	switch payload.Kind {
	case "live_register", "live_client_prepared", "live_reserved":
		expectedFields = 5
	case "live_authorize", "live_allow_ack":
		expectedFields = 7
	case "live_reservation", "live_receive":
		expectedFields = 4
	}
	if expectedFields == 0 || len(shape) != expectedFields {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	client := payload.Kind == "live_client_prepared" || payload.Kind == "live_authorize"
	role := protocolv4.ServerToClient
	if client {
		role = protocolv4.ClientToServer
	}
	if err = p.authenticate(r, payload, envelope, client); err != nil {
		directIssueHTTPFailure(w, http.StatusForbidden)
		return
	}
	p.mu.Lock()
	if p.closed || p.busy[role] {
		p.mu.Unlock()
		directIssueHTTPFailure(w, http.StatusConflict)
		return
	}
	p.busy[role] = true
	p.mu.Unlock()
	success := false
	defer func() {
		p.mu.Lock()
		p.busy[role] = false
		p.mu.Unlock()
		if !success {
			p.Close()
		}
		p.cleanup()
	}()
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return p.check()
	}
	reply := RegisteredControlReply{Incarnation: payload.Incarnation, Authority: p.config.Authority}
	if payload.Kind == "live_authorize" {
		err = p.authorize(w, r.WithContext(ctx), payload, reply, guard)
	} else {
		err = p.exchange(ctx, payload, role, &reply, guard)
		if err == nil {
			err = writeRegisteredReply(w, reply, guard)
		}
	}
	if err != nil {
		directIssueHTTPFailure(w, http.StatusConflict)
		return
	}
	success = true
}
func decodeRegisteredJSON(wire []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return ErrResponse
	}
	return nil
}
func (p *RegisteredLiveAuthority) authenticate(r *http.Request, q RegisteredControlPayload, envelope struct {
	Payload string `json:"payload"`
	Proof   string `json:"proof"`
}, client bool) error {
	if q.Parent != base64.StdEncoding.EncodeToString(p.config.Parent[:]) || q.Candidate != p.config.Candidate {
		return ledgerv4.ErrDenied
	}
	size := 16
	key, certificate := p.config.ServerKey, p.serverTLS
	if client {
		size = 32
		key, certificate = p.config.ClientKey, p.clientTLS
	}
	incarnation, err := DecodeRegisteredControlBytes(q.Incarnation, size, size)
	defer clear(incarnation)
	if err != nil || registeredZero(incarnation) {
		return ledgerv4.ErrDenied
	}
	native := r.TLS
	if native == nil || !native.HandshakeComplete || native.Version != tls.VersionTLS13 || native.DidResume || len(native.PeerCertificates) == 0 || len(native.VerifiedChains) == 0 || len(native.VerifiedChains[0]) == 0 || !bytes.Equal(native.PeerCertificates[0].Raw, native.VerifiedChains[0][0].Raw) || sha256.Sum256(native.PeerCertificates[0].Raw) != certificate {
		return ledgerv4.ErrDenied
	}
	proof, err := DecodeRegisteredControlBytes(envelope.Proof, 64, 64)
	defer clear(proof)
	if err != nil {
		return err
	}
	message := append([]byte(registeredControlDomain), []byte(envelope.Payload)...)
	defer clear(message)
	if !ed25519.Verify(ed25519.PublicKey(key[:]), message, proof) {
		return ledgerv4.ErrDenied
	}
	return p.check()
}
func registeredZero(value []byte) bool {
	var result byte
	for _, b := range value {
		result |= b
	}
	return result == 0
}
func (p *RegisteredLiveAuthority) exchange(ctx context.Context, q RegisteredControlPayload, role protocolv4.Direction, reply *RegisteredControlReply, guard func() error) error {
	// Re-encoding enforces the protocol's exact operation fields, including no
	// surplus nonempty field. Authentication has already checked the raw envelope.
	fields := RegisteredControlPayload{Kind: q.Kind, Incarnation: q.Incarnation, Parent: q.Parent, Candidate: q.Candidate}
	switch q.Kind {
	case "live_register":
		fields.Recipient = q.Recipient
	case "live_client_prepared", "live_reserved":
		fields.Attempt = q.Attempt
	case "live_allow_ack":
		fields.Attempt = q.Attempt
		fields.Activation = q.Activation
		fields.Grant = q.Grant
	case "live_reservation", "live_receive":
	default:
		return ErrResponse
	}
	expected, _ := json.Marshal(fields)
	actual, _ := json.Marshal(q)
	if !bytes.Equal(expected, actual) {
		return ErrResponse
	}
	if q.Kind == "live_register" {
		if role != protocolv4.ServerToClient {
			return ledgerv4.ErrDenied
		}
		recipient, err := decodeAttempt(q.Recipient)
		if err != nil {
			return err
		}
		incarnation, err := decodeAttempt(q.Incarnation)
		if err != nil {
			return err
		}
		p.mu.Lock()
		registered := p.registered
		p.mu.Unlock()
		if registered {
			return ErrResponse
		}
		if err = p.config.PrepareOriginalCarrier(ctx, role); err != nil {
			return err
		}
		if err = guard(); err != nil {
			return err
		}
		p.mu.Lock()
		p.recipient, p.incarnation = recipient, incarnation
		p.serverIncarnation = q.Incarnation
		p.registered = true
		close(p.ready)
		p.mu.Unlock()
		reply.Registered = true
		return nil
	}
	if q.Kind == "live_client_prepared" {
		if role != protocolv4.ClientToServer {
			return ledgerv4.ErrDenied
		}
		attempt, err := decodeAttempt(q.Attempt)
		if err != nil {
			return err
		}
		p.mu.Lock()
		invalid := p.prepared || p.used || !p.registered
		p.mu.Unlock()
		if invalid {
			return ErrResponse
		}
		if err = p.config.PrepareOriginalCarrier(ctx, role); err != nil {
			return err
		}
		if err = guard(); err != nil {
			return err
		}
		p.mu.Lock()
		p.attempt = attempt
		p.clientIncarnation = q.Incarnation
		p.prepared = true
		p.mu.Unlock()
		reply.Prepared = true
		return nil
	}
	p.mu.Lock()
	valid := role == protocolv4.ServerToClient && p.registered && q.Incarnation == p.serverIncarnation
	p.mu.Unlock()
	if !valid {
		return ledgerv4.ErrDenied
	}
	switch q.Kind {
	case "live_reservation":
		if err := p.wait(ctx, p.attemptReady, guard); err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.reservationTaken {
			return ErrResponse
		}
		p.reservationTaken = true
		reply.Attempt = base64.StdEncoding.EncodeToString(p.attempt[:])
		return nil
	case "live_reserved":
		attempt, err := decodeAttempt(q.Attempt)
		if err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.reservationTaken || p.reserved || attempt != p.attempt {
			return ErrResponse
		}
		p.reserved = true
		close(p.reservedReady)
		reply.Reserved = true
		return nil
	case "live_receive":
		if err := p.wait(ctx, p.materialReady, guard); err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.reserved || p.materialTaken {
			return ErrResponse
		}
		p.materialTaken = true
		reply.Attempt = base64.StdEncoding.EncodeToString(p.attempt[:])
		reply.Activation = base64.StdEncoding.EncodeToString(p.publication[0])
		reply.Grant = base64.StdEncoding.EncodeToString(p.publication[1])
		return nil
	case "live_allow_ack":
		attempt, err := decodeAttempt(q.Attempt)
		if err != nil {
			return err
		}
		activation, err := DecodeRegisteredControlBytes(q.Activation, 32, 32)
		if err != nil {
			return err
		}
		defer clear(activation)
		grant, err := DecodeRegisteredControlBytes(q.Grant, 32, 32)
		if err != nil {
			return err
		}
		defer clear(grant)
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.materialTaken || p.acknowledged || attempt != p.attempt || !bytes.Equal(activation, p.digests[0][:]) || !bytes.Equal(grant, p.digests[1][:]) {
			return ErrResponse
		}
		p.acknowledged = true
		close(p.ackReady)
		reply.Delivered = true
		return nil
	}
	return ErrResponse
}
func (p *RegisteredLiveAuthority) authorize(w http.ResponseWriter, r *http.Request, payload RegisteredControlPayload, reply RegisteredControlReply, guard func() error) error {
	if payload.Request == nil || payload.Recipient != "" || payload.Attempt != "" || payload.Activation != "" || payload.Grant != "" {
		return ErrResponse
	}
	request, err := decodeRegisteredLiveRequest(*payload.Request, p.config.Authority)
	if err != nil {
		return err
	}
	authentication, err := DecodeRegisteredControlBytes(payload.Authentication, 32+liveRequestBytes, 0)
	if err != nil {
		return err
	}
	defer clear(authentication)
	signature, err := DecodeRegisteredControlBytes(payload.Signature, 64, 64)
	if err != nil {
		return err
	}
	defer clear(signature)
	var canonical [liveRequestBytes]byte
	defer clear(canonical[:])
	size, err := EncodeLiveAuthorizationRequest(canonical[:], request)
	if err != nil {
		return err
	}
	if len(authentication) != 32+size || registeredZero(authentication[:32]) || !bytes.Equal(authentication[32:], canonical[:size]) || !ed25519.Verify(ed25519.PublicKey(p.config.ClientKey[:]), authentication, signature) {
		return ledgerv4.ErrDenied
	}
	p.mu.Lock()
	invalid := p.used || !p.registered || !p.prepared || payload.Incarnation != p.clientIncarnation || request.Attempt != p.attempt || request.Artifact != p.config.Parent || request.Tenant != p.config.Tenant || request.Audience != p.config.Audience || request.Winner.Index != p.config.Candidate
	if !invalid {
		p.used = true
		close(p.attemptReady)
	}
	p.mu.Unlock()
	if invalid {
		return ledgerv4.ErrDenied
	}
	if err = p.wait(r.Context(), p.reservedReady, guard); err != nil {
		return err
	}
	return p.config.Service.ServeRegisteredAuthorization(w, r, request, func(ctx context.Context, material []byte, check func() error) error {
		reply.Grant = base64.StdEncoding.EncodeToString(material)
		return writeRegisteredReply(w, reply, func() error {
			if err := guard(); err != nil {
				return err
			}
			return check()
		})
	})
}
func decodeRegisteredLiveRequest(q RegisteredLiveAuthorizationRequest, authority string) (result sessionv4.LiveAuthorizationRequest, err error) {
	if q.Authority != authority {
		return result, ledgerv4.ErrDenied
	}
	end, err := strconv.ParseUint(q.ActivationNotAfterMS, 10, 64)
	if err != nil || strconv.FormatUint(end, 10) != q.ActivationNotAfterMS {
		return result, ErrResponse
	}
	result = sessionv4.LiveAuthorizationRequest{Tenant: q.Tenant, Audience: q.Audience, CryptoProfile: q.CryptoProfile, ActivationNotAfterMS: end, AttemptNo: q.AttemptNo}
	result.Winner.Index = q.CandidateIndex
	for _, item := range []struct {
		value string
		dst   []byte
	}{{q.Issuer, result.Issuer[:]}, {q.Lease, result.Lease[:]}, {q.Attempt, result.Attempt[:]}, {q.Artifact, result.Artifact[:]}, {q.ClientIdentity, result.ClientIdentity[:]}, {q.ServerIdentity, result.ServerIdentity[:]}, {q.CandidateID, result.Winner.CandidateID[:]}, {q.RouteDigest, result.Winner.RouteDigest[:]}} {
		wire, e := DecodeRegisteredControlBytes(item.value, len(item.dst), len(item.dst))
		if e != nil {
			return sessionv4.LiveAuthorizationRequest{}, e
		}
		copy(item.dst, wire)
		clear(wire)
	}
	return result, nil
}
func writeRegisteredReply(w http.ResponseWriter, reply RegisteredControlReply, guard func() error) error {
	if err := guard(); err != nil {
		return err
	}
	wire, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	defer clear(wire)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Length", strconv.Itoa(len(wire)))
	n, err := w.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	// Completing the local response handoff requires flushing the original
	// HTTP/TLS writer. This does not assert receipt by the remote SDK owner.
	if err = http.NewResponseController(w).Flush(); err != nil {
		return err
	}
	return guard()
}
func (p *RegisteredLiveAuthority) PublishServerAllow(context.Context, sessionv4.TunnelServerAllowRequest, []byte, func() error) error {
	return resourcev4.ErrConfiguration
}
func (p *RegisteredLiveAuthority) PublishOriginalLiveServerAllow(ctx context.Context, q sessionv4.TunnelServerAllowRequest, material [2][]byte, guard func() error) error {
	if err := guard(); err != nil {
		return err
	}
	var digests [2][32]byte
	for side, schema := range []string{"ActivationAuthorization", "Grant"} {
		if len(material[side]) == 0 || len(material[side]) > 65536 {
			return resourcev4.ErrCapacity
		}
		codec, err := protocolv4.NewSignedMapCodec(schema, 65536, 16384)
		if err != nil {
			return err
		}
		key := p.config.ActivationKey
		domain := "activation_digest"
		if side == 1 {
			key = p.config.ServerGrantKey
			domain = "grant_digest"
		}
		signed, err := codec.Verify(material[side], key, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
		if err != nil {
			return err
		}
		digests[side], err = signed.Digest(domain)
		signed.Release()
		if err != nil {
			return err
		}
	}
	p.mu.Lock()
	if p.closed || !p.used || !p.reserved || p.publication[0] != nil || q.Attempt != p.attempt || q.Recipient != p.recipient || q.Incarnation != p.incarnation || q.Artifact != p.config.Parent || q.Candidate.Index != p.config.Candidate {
		p.mu.Unlock()
		return ledgerv4.ErrDenied
	}
	p.publication = [2][]byte{append([]byte(nil), material[0]...), append([]byte(nil), material[1]...)}
	p.digests = digests
	close(p.materialReady)
	p.mu.Unlock()
	return p.wait(ctx, p.ackReady, guard)
}
func (p *RegisteredLiveAuthority) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	first := !p.closed
	if first {
		p.closed = true
		close(p.stop)
	}
	p.mu.Unlock()
	if first {
		p.config.Service.Close()
		if p.config.CancelOriginal != nil {
			p.config.CancelOriginal()
		}
	}
	p.cleanup()
}
func (p *RegisteredLiveAuthority) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed || p.busy[0] || p.busy[1] || p.cleaned {
		return
	}
	for _, wire := range p.publication {
		clear(wire)
	}
	p.publication = [2][]byte{}
	p.reservation.Release()
	p.dependencies.Release()
	p.cleaned = true
	close(p.done)
}
func (p *RegisteredLiveAuthority) WaitCleanup(ctx context.Context) error {
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

var _ sessionv4.OriginalLiveTunnelServerAllowProvider = (*RegisteredLiveAuthority)(nil)
