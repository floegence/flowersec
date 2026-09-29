package sessionv4

import (
	"bytes"
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// TunnelServerAllowRecipient pins one server leg and its original local control
// registration. Preprepared recipients use the carrier's incarnation; deferred
// recipients use their original registration incarnation and separately fix the
// physical carrier identity. Neither value comes from a remote instruction.
type TunnelServerAllowRecipient struct {
	mu                    sync.Mutex
	prepared              *PreparedCarrier
	carrierIncarnation    [16]byte
	prepareCancel         context.CancelFunc
	lease                 artifactLeaseUse
	identity              identityUse
	subscriptions         *protocolv4.CredentialSubscriptions
	deadline              *timev4.Deadline
	entranceActive        bool
	reservation, carrier  resourcev4.Reference
	registrationHold      resourcev4.Reference
	expected              TunnelServerAllowRequest
	delivered             TunnelServerAllowRequest
	grant                 []byte
	grantMap              *protocolv4.SignedMap
	grantCodec            *protocolv4.SignedMapCodec
	live                  bool
	done                  chan struct{}
	busy, allowed, closed bool
	cleaned               bool
	controlRegistered     bool
}

// ControlReferenceFor binds one control listener to this original registration.
// Closing or replacing that listener cannot register a new recipient on the
// old carrier. The original registration is intentionally nonrecoverable.
func (r *TunnelServerAllowRecipient) ControlReferenceFor(clock *timev4.Clock, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if r == nil || clock == nil {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.controlRegistered || r.prepared == nil {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	if err := r.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	r.prepared.mu.Lock()
	defer r.prepared.mu.Unlock()
	if r.prepared.closed || !r.deadline.BelongsTo(clock) {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	if err := r.subscriptions.CheckPreparationClock(clock); err != nil {
		return resourcev4.Reference{}, err
	}
	ref, err := r.reservation.Borrow()
	if err == nil {
		r.controlRegistered = true
	}
	return ref, err
}

func TunnelServerAllowRecipientCharge(runtimeBytes uint64, live ...bool) (resourcev4.Vector, error) {
	if runtimeBytes == 0 || len(live) > 1 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	closure, err := protocolv4.EndpointCredentialsBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if len(live) == 1 && live[0] {
		limit, err := protocolv4.SchemaByteLimit("Grant")
		if err != nil {
			return resourcev4.Vector{}, err
		}
		codec, err := protocolv4.SignedMapBackingBytes("Grant", limit, limit)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		closure += codec + closure
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(TunnelServerAllowRecipient{})) + closure + 256, resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func NewTunnelServerAllowRecipient(material *ConnectionMaterial, prepared *PreparedCarrier, recipient [16]byte, runtimeBytes uint64, reservation, subscriptions, environment resourcev4.Reference, live ...bool) (*TunnelServerAllowRecipient, error) {
	if material == nil || prepared == nil || prepared.preparedCarrier == nil || recipient == ([16]byte{}) {
		return nil, cryptov4.ErrConfiguration
	}
	prepared.mu.Lock()
	binding, incarnation, deadline := prepared.binding, prepared.incarnation, prepared.deadline
	prepared.mu.Unlock()
	pin, identity, err := captureTunnelServerMaterial(material, environment)
	if err != nil {
		return nil, err
	}
	r, err := newUnattachedTunnelServerRecipient(pin, identity, binding, deadline, recipient, incarnation, runtimeBytes, reservation, subscriptions, environment, live...)
	if err != nil {
		return nil, err
	}
	if err = r.attachPrepared(prepared, environment); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func captureTunnelServerMaterial(material *ConnectionMaterial, environment resourcev4.Reference) (pin artifactLeaseUse, identity identityUse, err error) {
	if material == nil {
		return pin, identity, cryptov4.ErrConfiguration
	}
	material.mu.Lock()
	defer material.mu.Unlock()
	if material.closed || material.cleaned || material.used || material.building || material.identity.identity == nil || material.identity.identity.role != protocolv4.ServerToClient {
		return pin, identity, resourcev4.ErrOwner
	}
	pin, err = material.lease.borrow(environment)
	if err == nil {
		identity, err = material.identity.borrow(environment)
	}
	if err != nil {
		pin.release()
		pin = artifactLeaseUse{}
	}
	return
}

// This constructor consumes the two already captured uses. All credential,
// subscription and result backing is fixed before carrier preparation starts.
func newUnattachedTunnelServerRecipient(pin artifactLeaseUse, identity identityUse, binding PreparedCarrierBinding, deadline *timev4.Deadline, recipient, incarnation [16]byte, runtimeBytes uint64, reservation, subscriptions, environment resourcev4.Reference, live ...bool) (_ *TunnelServerAllowRecipient, err error) {
	r := &TunnelServerAllowRecipient{lease: pin, identity: identity, done: make(chan struct{}), live: len(live) == 1 && live[0]}
	adopted := false
	defer func() {
		if !adopted {
			r.Close()
		}
	}()
	charge, err := TunnelServerAllowRecipientCharge(runtimeBytes, live...)
	if err != nil {
		return nil, err
	}
	if pin.lease == nil || identity.identity == nil || recipient == ([16]byte{}) || binding.Role != protocolv4.ServerToClient || binding.Attempt == ([16]byte{}) {
		return nil, cryptov4.ErrConfiguration
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	r.reservation, err = reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	l := pin.lease
	r.deadline = deadline
	if binding.Session != l.session || deadline == nil || incarnation == ([16]byte{}) {
		return nil, resourcev4.ErrOwner
	}
	grant, relay, tunnel, err := l.endpointCredentialMaps(binding.Candidate.Index, protocolv4.ServerToClient)
	if err != nil || !tunnel {
		if err == nil {
			err = cryptov4.ErrConfiguration
		}
		return nil, err
	}
	entry := l.tunnelMaterial(binding.Candidate.Index, protocolv4.ServerToClient)
	if entry == nil || entry.pendingGrant != r.live {
		return nil, cryptov4.ErrConfiguration
	}
	if r.live {
		limit, _ := protocolv4.SchemaByteLimit("Grant")
		r.grantCodec, err = protocolv4.NewSignedMapCodec("Grant", limit, limit)
		if err != nil {
			return nil, err
		}
	}
	closure, err := l.endpointClosure(binding.Candidate.Index, protocolv4.ServerToClient)
	if err != nil {
		return nil, err
	}
	if err = subscriptions.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	r.subscriptions, err = closure.Subscribe(l.credentialBindings(binding.Candidate.Index, protocolv4.ServerToClient, true), l.session.SessionNotAfterMS, subscriptions)
	if err != nil {
		return nil, err
	}
	if _, err = r.subscriptions.CheckOriginalFor(environment, l.session, protocolv4.ServerToClient, binding.Candidate); err != nil {
		return nil, err
	}
	relayDigest, err := relay.Digest("certificate_digest")
	if err != nil {
		return nil, err
	}
	candidate := l.maps[0].Field("candidates").Index(int(binding.Candidate.Index))
	id, _ := candidate.Named("Candidate", "candidate_id").ByteString()
	leg, _ := candidate.Named("Candidate", "server_leg").Named("Leg", "leg_id").ByteString()
	if len(leg) != 16 || !bytes.Equal(id, binding.Candidate.CandidateID[:]) {
		return nil, resourcev4.ErrOwner
	}
	tenant, _ := l.maps[0].Field("tenant_id").Text()
	audience, _ := l.maps[0].Field("audience").Text()
	initiationEnd, _ := l.maps[0].Field("initiation_not_after_ms").Uint()
	r.expected = TunnelServerAllowRequest{Tenant: tenant, Audience: audience, Artifact: l.session.ArtifactDigest, RelayIdentity: relayDigest,
		Attempt: binding.Attempt, Leg: [16]byte(leg), Recipient: recipient, Incarnation: incarnation,
		Candidate: binding.Candidate, NotAfterMS: min(initiationEnd, deadline.Cap())}
	if r.live {
		r.expected.NotAfterMS = min(r.expected.NotAfterMS, entry.liveGrant.Scope.ExpiresMS)
	} else {
		r.expected.Grant, err = grant.Digest("grant_digest")
		if err != nil {
			return nil, err
		}
		attempt, _ := grant.Field("attempt_id").ByteString()
		pairing, _ := grant.Field("pairing_id").ByteString()
		route, _ := grant.Field("route_digest").ByteString()
		if len(pairing) != 16 || !bytes.Equal(attempt, binding.Attempt[:]) || !bytes.Equal(route, binding.Candidate.RouteDigest[:]) {
			return nil, resourcev4.ErrOwner
		}
		r.expected.Pairing = [16]byte(pairing)
		notAfter, _ := grant.Field("not_after_ms").Uint()
		r.expected.NotAfterMS = min(r.expected.NotAfterMS, notAfter)
		if err = r.expected.Check(); err != nil {
			return nil, err
		}
		r.grant, err = grant.Bytes()
		if err != nil {
			return nil, err
		}
	}
	adopted = true
	return r, nil
}

// preflightAllow verifies an original instruction against an unattached local
// recipient. It grants no carrier permission. A live Grant replaces only its
// already reserved pending scope; the physical handle is attached afterwards.
func (r *TunnelServerAllowRecipient) preflightAllow(ctx context.Context, request TunnelServerAllowRequest, wire []byte) (err error) {
	if ctx == nil || request.Check() != nil {
		return resourcev4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.busy || r.prepared != nil || r.allowed {
		r.mu.Unlock()
		return resourcev4.ErrOwner
	}
	expected := r.expected
	if request.NotAfterMS > expected.NotAfterMS {
		r.mu.Unlock()
		return protocolv4.ErrHopAuthContext
	}
	expected.NotAfterMS = request.NotAfterMS
	pending := r.live && r.grantMap == nil
	if pending {
		expected.Grant, expected.Pairing = request.Grant, request.Pairing
	}
	if request != expected || !pending && !bytes.Equal(wire, r.grant) {
		r.mu.Unlock()
		return protocolv4.ErrHopAuthContext
	}
	r.busy = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.busy = false; r.cleanupLocked(); r.mu.Unlock() }()
	if err = ctx.Err(); err != nil {
		return err
	}
	if pending {
		if err = r.captureLiveGrant(request, wire); err != nil {
			return err
		}
		r.mu.Lock()
		r.expected.Grant, r.expected.Pairing = request.Grant, request.Pairing
		r.mu.Unlock()
	}
	if _, err = r.subscriptions.CheckPreparation(); err != nil {
		return err
	}
	now, err := r.deadline.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(request.NotAfterMS) {
		return protocolv4.ErrHopAuthContext
	}
	return ctx.Err()
}

// The control registration incarnation is independent of this newly prepared
// physical carrier. Both identities remain immutable and are checked separately.
func (r *TunnelServerAllowRecipient) attachPrepared(prepared *PreparedCarrier, environment resourcev4.Reference) error {
	if prepared == nil || prepared.preparedCarrier == nil {
		return resourcev4.ErrOwner
	}
	if err := prepared.Check(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.prepared != nil {
		return resourcev4.ErrOwner
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	b := prepared.binding
	if prepared.relay || prepared.allowRegistered || prepared.admission != nil || prepared.activated || prepared.closed || b.Role != protocolv4.ServerToClient || b.Session != r.lease.lease.session || b.Candidate != r.expected.Candidate || b.Attempt != r.expected.Attempt || prepared.deadline != r.deadline || prepared.incarnation == ([16]byte{}) {
		return resourcev4.ErrOwner
	}
	if err := prepared.reservation.CheckSameEnvironment(environment); err != nil {
		return err
	}
	ref, err := prepared.reservation.Borrow()
	if err != nil {
		return err
	}
	r.prepared, r.carrier, r.carrierIncarnation = prepared, ref, prepared.incarnation
	prepared.allowRegistered, prepared.allowRecipient = true, r
	return nil
}

// Binding is distributed only by the independently authenticated registration
// channel. It is public routing data and confers no activation permission.
// A live registration leaves Grant and Pairing unset until the original allow
// arrives; Recipient and Incarnation already name the fixed local registration.
func (r *TunnelServerAllowRecipient) Binding() (TunnelServerAllowRequest, error) {
	if r == nil {
		return TunnelServerAllowRequest{}, resourcev4.ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return TunnelServerAllowRequest{}, resourcev4.ErrClosed
	}
	return r.expected, nil
}

// Receive records the original instruction under the actual carrier's gate.
// The control listener authenticates and authorizes its caller before invoking
// this method. Exact duplicates acknowledge the same fact without reactivation.
func (r *TunnelServerAllowRecipient) Receive(ctx context.Context, request TunnelServerAllowRequest, grant []byte) (err error) {
	if r == nil || ctx == nil || request.Check() != nil {
		return resourcev4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.busy || r.prepared == nil {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	expected := r.expected
	if request.NotAfterMS == 0 || request.NotAfterMS > expected.NotAfterMS {
		r.mu.Unlock()
		return protocolv4.ErrHopAuthContext
	}
	expected.NotAfterMS = request.NotAfterMS
	pending := r.live && r.grantMap == nil
	if pending {
		expected.Grant, expected.Pairing = request.Grant, request.Pairing
	}
	if request != expected || r.allowed && request != r.delivered || !pending && !bytes.Equal(grant, r.grant) {
		r.mu.Unlock()
		return protocolv4.ErrHopAuthContext
	}
	r.busy = true
	prepared, duplicate := r.prepared, r.allowed
	r.mu.Unlock()
	returned, captured := false, false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		if err != nil && captured {
			r.Close()
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.busy = false
		r.cleanupLocked()
	}()
	err = func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if pending {
			if err := r.captureLiveGrant(request, grant); err != nil {
				return err
			}
			captured = true
		}
		if _, err := r.subscriptions.CheckPreparation(); err != nil {
			return err
		}
		if !duplicate {
			if err := prepared.Check(); err != nil {
				return err
			}
		}
		prepared.mu.Lock()
		deadline := r.deadline
		prepared.mu.Unlock()
		if deadline == nil {
			return resourcev4.ErrOwner
		}
		now, err := deadline.Sample()
		if err != nil {
			return err
		}
		if err = deadline.CheckAt(now); err != nil || !now.Interval.ValidBefore(request.NotAfterMS) {
			return protocolv4.ErrHopAuthContext
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed {
			return resourcev4.ErrClosed
		}
		if err = r.reservation.Check(); err != nil {
			return err
		}
		prepared.mu.Lock()
		defer prepared.mu.Unlock()
		if prepared.closed || prepared.allowRecipient != r || prepared.incarnation != r.carrierIncarnation || prepared.activated && !duplicate {
			return resourcev4.ErrOwner
		}
		if pending {
			r.expected.Grant, r.expected.Pairing = request.Grant, request.Pairing
		}
		r.allowed, prepared.allowGranted = true, true
		r.delivered = request
		return nil
	}()
	returned = true
	return err
}

func (r *TunnelServerAllowRecipient) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.subscriptions.NotifyPreparation()
	if r.prepared != nil {
		r.prepared.mu.Lock()
		if r.prepared.allowRecipient == r {
			if !r.prepared.activated {
				r.prepared.sealLocked(cryptov4.ErrClosed)
			}
			r.prepared.allowRecipient = nil
		}
		r.prepared.mu.Unlock()
	}
	r.cleanupLocked()
}

func (r *TunnelServerAllowRecipient) cleanupLocked() {
	if !r.closed || r.busy || r.entranceActive || r.cleaned {
		return
	}
	if r.prepareCancel != nil {
		r.prepareCancel()
		r.prepareCancel = nil
	}
	if r.subscriptions != nil {
		r.subscriptions.Close()
	}
	r.subscriptions = nil
	if r.grantMap != nil {
		r.grantMap.Release()
	}
	r.grantMap, r.grantCodec = nil, nil
	r.identity.release()
	r.lease.release()
	r.carrier.Release()
	r.registrationHold.Release()
	r.reservation.Release()
	r.carrier, r.reservation, r.registrationHold = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	r.prepared, r.grant = nil, nil
	r.cleaned = true
	close(r.done)
}

func (r *TunnelServerAllowRecipient) WaitCleanup(ctx context.Context) error {
	if r == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// captureLiveGrant runs only in the original serialized receive position.
// Its codec and replacement closure were reserved when the recipient was made.
func (r *TunnelServerAllowRecipient) captureLiveGrant(request TunnelServerAllowRequest, wire []byte) error {
	l := r.lease.lease
	entry := l.tunnelMaterial(request.Candidate.Index, protocolv4.ServerToClient)
	if entry == nil || !entry.pendingGrant || r.grantMap != nil {
		return cryptov4.ErrTransition
	}
	grant, err := r.grantCodec.Verify(wire, entry.liveGrant.Validation.Issuer.Key, protocolv4.DecodeContext{})
	if err != nil {
		return err
	}
	adopted := false
	defer func() {
		if !adopted {
			grant.Release()
		}
	}()
	closure, err := protocolv4.BindEndpointCredentials(protocolv4.ServerToClient, l.maps[0], entry.index, l.maps[2], l.maps[3], grant, entry.maps[1])
	if err != nil {
		return err
	}
	digest, err := grant.Digest("grant_digest")
	if err != nil || digest != request.Grant {
		return protocolv4.ErrHopAuthContext
	}
	attempt, _ := grant.Field("attempt_id").ByteString()
	pairing, _ := grant.Field("pairing_id").ByteString()
	if !bytes.Equal(attempt, request.Attempt[:]) || !bytes.Equal(pairing, request.Pairing[:]) {
		return protocolv4.ErrHopAuthContext
	}
	if err = r.subscriptions.CompleteLiveGrant(closure); err != nil {
		return err
	}
	r.grantMap = grant
	r.grant, err = grant.Bytes()
	adopted = true
	return err
}
