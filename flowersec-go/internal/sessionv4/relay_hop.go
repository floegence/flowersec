package sessionv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type RelayHopConfig struct {
	Pair                                         *RelayMessagePair
	Grant, EndpointCertificate, RelayCertificate *protocolv4.SignedMap
	Signer                                       cryptov4.IdentitySigner
	Validation                                   [4]protocolv4.CredentialValidation
	Clock                                        *timev4.Clock
	Initial                                      InitialConfig
	Relay                                        [16]byte
	Generation                                   uint64
	MapNodes                                     int
	RuntimeBytes, InitialRuntimeBytes            uint64
	MaxRecordBytes                               uint32
}

type RelayHopReservations struct{ Owner, Initial, Subscriptions, Meter, Claim, Invocation resourcev4.Reference }

// RelayHop owns HOP_AUTH, its original durable claim and the metered carrier.
// Its successful handshake still grants no forwarding until the original
// matching peer leg is present. It never interprets an e2e admission or READY.
type RelayHop struct {
	forwardDeadline                                                     *timev4.Deadline
	mu                                                                  sync.Mutex
	c                                                                   RelayHopConfig
	prepared                                                            *PreparedCarrier
	initial                                                             *InitialExchange
	hop                                                                 hopAuthentication
	codecs                                                              [3]*protocolv4.SignedMapCodec
	maps                                                                [3]*protocolv4.SignedMap
	subscriptions                                                       *protocolv4.CredentialSubscriptions
	budget                                                              *relayByteBudget
	ledger                                                              *ledgerv4.SQLiteRelayActivation
	facts                                                               protocolv4.RelayClaimFacts
	owner                                                               ledgerv4.RelayActivationOwner
	pairRef                                                             resourcev4.Reference
	pairRegistered, forwarding, building                                bool
	reservation, shared, claimRef, invocationRef                        resourcev4.Reference
	claimReservation, invocationReservation                             resourcev4.Reference
	guard                                                               relayHopAuthorization
	wake                                                                chan struct{}
	started, running, authenticated, closed, cleaning, cleaned, retired bool
	terminal                                                            error
}

type relayHopAuthorization struct{ owner *RelayHop }

func RelayHopCharges(c RelayHopConfig) (owner, initial, subscriptions, meter, claim, invocation resourcev4.Vector, err error) {
	if c.Pair == nil || c.Grant == nil || c.EndpointCertificate == nil || c.RelayCertificate == nil || c.Signer == nil || c.Clock == nil || !c.Initial.Deadline.BelongsTo(c.Clock) || c.Initial.Authorization != nil || c.Initial.Reservation != (resourcev4.Reference{}) || c.Initial.hop != nil || c.Initial.accepted != nil || c.Initial.original.enabled || c.Initial.Role > protocolv4.ServerToClient || c.Relay == ([16]byte{}) || c.Generation == 0 || c.MapNodes < 128 || c.MapNodes > 1<<20 || c.RuntimeBytes == 0 || c.InitialRuntimeBytes == 0 {
		err = cryptov4.ErrConfiguration
		return
	}
	if c.Initial.ActivationSourceProfile != "preauthorized_pool" && c.Initial.ActivationSourceProfile != "live_authority" {
		err = cryptov4.ErrConfiguration
		return
	}
	owner = resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RelayHop{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + 512, resourcev4.Items: 1, resourcev4.WorkSlots: 1}
	for _, schema := range []string{"Grant", "IdentityCertificate", "IdentityCertificate"} {
		var limit int
		limit, err = protocolv4.SchemaByteLimit(schema)
		if err != nil {
			return
		}
		var size uint64
		size, err = protocolv4.SignedMapBackingBytes(schema, limit, c.MapNodes)
		if err != nil {
			return
		}
		owner, err = owner.Add(resourcev4.Vector{resourcev4.SDKBytes: size})
		if err != nil {
			return
		}
	}
	var closure, facts, scratch uint64
	closure, err = protocolv4.RelayCredentialsBackingBytes()
	if err != nil {
		return
	}
	facts, err = protocolv4.RelayClaimFactsBackingBytes()
	if err != nil {
		return
	}
	scratch, err = hopAuthenticationScratchBytes()
	if err != nil {
		return
	}
	owner, err = owner.Add(resourcev4.Vector{resourcev4.SDKBytes: closure + facts + scratch})
	if err != nil {
		return
	}
	owner, err = owner.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return
	}
	initial, err = InitialCharge(c.Initial.Limits)
	if err != nil {
		return
	}
	initial, err = initial.Add(resourcev4.Vector{resourcev4.SDKBytes: c.InitialRuntimeBytes})
	if err != nil {
		return
	}
	subscriptions = protocolv4.CredentialSubscriptionsCharge()
	meter, err = relayByteBudgetCharge(c.Pair.meterSlots())
	if err != nil {
		return
	}
	claim, invocation, err = ledgerv4.SQLiteRelayActivationCharges(c.MaxRecordBytes)
	return
}

// Non-nil results own the actual carrier lifecycle, including when Initial
// construction fails after activation. Earlier failures leave it with caller.
func NewRelayHop(ctx context.Context, c RelayHopConfig, prepared *PreparedCarrier, refs RelayHopReservations, dependencies resourcev4.Reference) (_ *RelayHop, err error) {
	if ctx == nil || prepared == nil || prepared.preparedCarrier == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, _, _, _, claimCharge, invokeCharge, err := RelayHopCharges(c)
	if err != nil {
		return nil, err
	}
	for _, ref := range []resourcev4.Reference{refs.Owner, refs.Initial, refs.Subscriptions, refs.Meter, refs.Claim, refs.Invocation, prepared.reservation} {
		if err = ref.CheckSameEnvironment(dependencies); err != nil {
			return nil, err
		}
	}
	if err = prepared.Check(); err != nil {
		return nil, err
	}
	prepared.mu.Lock()
	valid := prepared.relay && prepared.deadline == c.Initial.Deadline && !prepared.allowRegistered && prepared.admission == nil && prepared.relayBudget == nil
	binding, incarnation, challenge := prepared.binding, prepared.incarnation, prepared.hopChallenge
	prepared.mu.Unlock()
	if !valid {
		return nil, resourcev4.ErrOwner
	}
	owned, err := refs.Owner.Take(charge)
	if err != nil {
		return nil, err
	}
	r := &RelayHop{building: true, c: c, reservation: owned, prepared: prepared, wake: make(chan struct{}, 1)}
	r.guard.owner = r
	defer func() { r.mu.Lock(); r.building = false; r.mu.Unlock(); c.Pair.notify() }()
	adopted := false
	defer func() {
		if !adopted {
			r.releaseUnadopted()
		}
	}()
	r.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	r.claimRef, err = refs.Claim.Borrow()
	if err != nil {
		return nil, err
	}
	r.invocationRef, err = refs.Invocation.Borrow()
	if err != nil {
		return nil, err
	}
	r.claimReservation, err = refs.Claim.Take(claimCharge)
	if err != nil {
		return nil, err
	}
	r.invocationReservation, err = refs.Invocation.Take(invokeCharge)
	if err != nil {
		return nil, err
	}
	for i, original := range []*protocolv4.SignedMap{c.Grant, c.EndpointCertificate, c.RelayCertificate} {
		schema := "IdentityCertificate"
		if i == 0 {
			schema = "Grant"
		}
		limit, _ := protocolv4.SchemaByteLimit(schema)
		r.codecs[i], err = protocolv4.NewSignedMapCodec(schema, limit, c.MapNodes)
		if err != nil {
			return nil, err
		}
		wire, err := original.Bytes()
		if err != nil {
			return nil, err
		}
		r.maps[i], err = r.codecs[i].Verify(wire, original.Key(), protocolv4.DecodeContext{})
		if err != nil {
			return nil, err
		}
	}
	r.c.Grant, r.c.EndpointCertificate, r.c.RelayCertificate = r.maps[0], r.maps[1], r.maps[2]
	closure, err := protocolv4.BindRelayCredentials(r.maps[0], r.maps[1], r.maps[2], c.Validation[0].Issuer)
	if err != nil {
		return nil, err
	}
	r.subscriptions, err = closure.Subscribe(c.Validation, binding.Session.SessionNotAfterMS, refs.Subscriptions)
	if err != nil {
		return nil, err
	}
	if err = r.subscriptions.CheckPreparationClock(c.Clock); err != nil {
		return nil, err
	}
	if err = r.prepare(binding, incarnation, challenge); err != nil {
		return nil, err
	}
	end, _ := r.maps[0].Field("not_after_ms").Uint()
	r.forwardDeadline, err = timev4.NewDeadline(c.Clock, min(end, binding.Session.SessionNotAfterMS))
	if err != nil {
		return nil, err
	}
	limit, _ := r.maps[0].Field("limits").Named("GrantLimits", "max_total_bytes").Uint()
	rate, _ := r.maps[0].Field("limits").Named("GrantLimits", "max_rate_bytes_per_s").Uint()
	envelope, _ := r.maps[0].Field("limits").Named("GrantLimits", "max_envelope_bytes").Uint()
	r.budget, err = newRelayByteBudget(limit, rate, envelope, c.Clock, c.Pair.meterSlots(), refs.Meter)
	if err != nil {
		return nil, err
	}
	r.owner = ledgerv4.RelayActivationOwner{Relay: c.Relay, Carrier: incarnation, Generation: c.Generation}
	if _, err = rand.Read(r.owner.Invocation[:]); err != nil {
		return nil, err
	}
	if r.owner.Invocation == ([16]byte{}) {
		return nil, resourcev4.ErrOwner
	}
	if err = r.guard.Check(); err != nil {
		return nil, err
	}
	if err = prepared.Check(); err != nil {
		return nil, err
	}
	if err = c.Pair.register(r); err != nil {
		return nil, err
	}
	// From registration onward the pair owns this original handle's cleanup.
	adopted = true
	prepared.mu.Lock()
	if prepared.closed || prepared.activated || prepared.relayBudget != nil {
		prepared.mu.Unlock()
		r.Close()
		return r, resourcev4.ErrOwner
	}
	prepared.activated, prepared.relayBudget = true, r.budget
	prepared.parent, prepared.deadline = nil, nil
	prepared.mu.Unlock()
	adopted = true
	initial := c.Initial
	initial.Role, initial.Authorization, initial.Reservation, initial.hop = binding.Role, &r.guard, refs.Initial, &r.hop
	if binding.MessageCarrier {
		r.initial, err = NewInitialMessages(ctx, initial, &prepared.messageAdapter)
	} else {
		r.initial, err = NewInitialStream(ctx, initial, &prepared.streamAdapter)
	}
	if err != nil {
		r.Close()
	}
	return r, err
}

func (r *RelayHop) prepare(binding PreparedCarrierBinding, incarnation [16]byte, challenge [32]byte) error {
	grant, endpoint, relay := r.maps[0], r.maps[1], r.maps[2]
	role, _ := endpoint.Field("role").Uint()
	profile, _ := relay.Field("crypto_profile_id").Text()
	if role != uint64(binding.Role) || profile != r.c.Initial.Profile || profile != binding.Session.Profile {
		return protocolv4.ErrHopAuthContext
	}
	parent := grant.Field("parent_ref")
	artifact, _ := parent.Named("GrantParentRef", "artifact_digest").ByteString()
	sessionEnd, _ := parent.Named("GrantParentRef", "session_not_after_ms").Uint()
	contract, _ := grant.Field("session_contract_digest").ByteString()
	digest := binding.Session.Contract.Digest()
	attempt, _ := grant.Field("attempt_id").ByteString()
	route, _ := grant.Field("route_digest").ByteString()
	candidate, _ := grant.Field("route_descriptor").Named("Route", "candidate_id").ByteString()
	maxEnvelope, _ := grant.Field("limits").Named("GrantLimits", "max_envelope_bytes").Uint()
	if !bytes.Equal(artifact, binding.Session.ArtifactDigest[:]) || sessionEnd != binding.Session.SessionNotAfterMS || !bytes.Equal(contract, digest[:]) || maxEnvelope != uint64(binding.Session.Contract.Limits().MaxFrame)+protocolv4.EnvelopePrefixSize || !bytes.Equal(attempt, binding.Attempt[:]) || !bytes.Equal(route, binding.Candidate.RouteDigest[:]) || !bytes.Equal(candidate, binding.Candidate.CandidateID[:]) {
		return protocolv4.ErrHopAuthContext
	}
	maximum, err := protocolv4.SchemaByteLimit("HOP_AUTH_HELLO")
	if err != nil {
		return err
	}
	if maximum > r.c.Initial.Limits.MaxFrame || uint64(r.c.Initial.Limits.MaxFrame)+protocolv4.EnvelopePrefixSize != maxEnvelope {
		return cryptov4.ErrCapacity
	}
	localKey, _ := relay.Field("ed25519_public_key").ByteString()
	peerKey, _ := endpoint.Field("ed25519_public_key").ByteString()
	if !bytes.Equal(localKey, r.c.Signer.PublicKey()) || len(localKey) != 32 || len(peerKey) != 32 {
		return protocolv4.ErrHopAuthContext
	}
	legName := "client_leg"
	if role == 1 {
		legName = "server_leg"
	}
	leg := grant.Field("route_descriptor").Named("Route", legName)
	dialer, _ := leg.Named("Leg", "dialer_role").Uint()
	listener, _ := leg.Named("Leg", "listener_role").Uint()
	if !(dialer == 2 && listener == role || dialer == role && listener == 2) {
		return protocolv4.ErrHopAuthContext
	}
	legID, _ := leg.Named("Leg", "leg_id").ByteString()
	pairing, _ := grant.Field("pairing_id").ByteString()
	grantDigest, err := grant.Digest("grant_digest")
	if err != nil {
		return err
	}
	r.hop = hopAuthentication{grant: grant, localCertificate: relay, relayCertificate: endpoint, signer: r.c.Signer, localKey: [32]byte(localKey), relayKey: [32]byte(peerKey), incarnation: incarnation, challenge: challenge, relay: true, role: 2, dialer: dialer == 2,
		context: protocolv4.HopChallengeContext{LegID: [16]byte(legID), DialerRole: uint8(dialer), ListenerRole: uint8(listener)}, possession: protocolv4.GrantPossessionInput{GrantDigest: grantDigest, RouteDigest: binding.Candidate.RouteDigest, LegID: [16]byte(legID), PairingID: [16]byte(pairing), Role: 2}}
	if r.hop.dialer {
		r.hop.context.DialerIncarnation, r.hop.context.DialerChallenge = incarnation, challenge
	} else {
		r.hop.context.ListenerIncarnation, r.hop.context.ListenerChallenge = incarnation, challenge
	}
	return nil
}

func (g *relayHopAuthorization) Check() error {
	r := g.owner
	r.mu.Lock()
	closed := r.closed
	cause := r.terminal
	ledger := r.ledger
	r.mu.Unlock()
	if closed {
		if cause != nil {
			return cause
		}
		return cryptov4.ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		return err
	}
	if err := r.shared.Check(); err != nil {
		return err
	}
	r.prepared.mu.Lock()
	valid := !r.prepared.closed && !r.prepared.retired && r.prepared.incarnation == r.owner.Carrier
	r.prepared.mu.Unlock()
	if !valid {
		return cryptov4.ErrClosed
	}
	if ledger != nil {
		if err := ledger.MatchActivationSource(r.c.Initial.ActivationSourceProfile); err != nil {
			return err
		}
		if err := ledger.CheckResolvedAuthority(); err != nil {
			return err
		}
	}
	_, err := r.subscriptions.CheckPreparation()
	if err == nil {
		err = r.forwardDeadline.Check()
	}
	if err == nil {
		r.mu.Lock()
		if r.closed {
			err = cryptov4.ErrClosed
		}
		r.mu.Unlock()
	}
	return err
}
func (g *relayHopAuthorization) RemainingMS() (uint64, error) {
	if err := g.Check(); err != nil {
		return 0, err
	}
	remaining, err := g.owner.subscriptions.PreparationRemainingMS()
	if err != nil {
		return 0, err
	}
	hard, err := g.owner.forwardDeadline.RemainingMS()
	return min(remaining, hard), err
}
func (g *relayHopAuthorization) Wake() <-chan struct{} {
	return g.owner.subscriptions.PreparationWake()
}
func (g *relayHopAuthorization) Notify()           { g.owner.subscriptions.NotifyPreparation() }
func (g *relayHopAuthorization) Close(cause error) { g.owner.seal(cause) }

func (r *RelayHop) seal(cause error) {
	r.mu.Lock()
	if cause == nil {
		cause = cryptov4.ErrClosed
	}
	if !r.closed {
		r.closed, r.terminal = true, cause
		r.reservation.Seal()
	}
	p, pair := r.prepared, r.c.Pair
	if r.forwardDeadline != nil {
		r.forwardDeadline.Cancel()
	}
	r.mu.Unlock()
	_ = p.Close()
	pair.notify()
}

func (r *RelayHop) Close() {
	if r == nil {
		return
	}
	r.seal(cryptov4.ErrClosed)
	r.mu.Lock()
	x, ledger := r.initial, r.ledger
	r.mu.Unlock()
	if ledger != nil {
		ledger.Close(cryptov4.ErrClosed)
	}
	if x != nil {
		x.Close(cryptov4.ErrClosed)
	}
}

func (r *RelayHop) WaitCleanup(ctx context.Context) error {
	if r == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.cleaned {
		r.mu.Unlock()
		return nil
	}
	if !r.closed || r.running || r.forwarding || r.building || r.cleaning {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	r.cleaning = true
	x, ledger := r.initial, r.ledger
	r.mu.Unlock()
	err := error(nil)
	if x != nil {
		err = x.WaitCleanup(ctx)
	}
	if err == nil && ledger != nil {
		err = ledger.Cleanup()
	}
	if err == nil {
		err = r.prepared.WaitCleanup(ctx)
	}
	r.mu.Lock()
	r.cleaning = false
	r.cleaned = err == nil
	r.mu.Unlock()
	return err
}

func (r *RelayHop) Retire() error {
	if r == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.retired {
		r.mu.Unlock()
		return nil
	}
	if !r.cleaned || r.running || r.forwarding || r.building || r.cleaning {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	r.cleaning = true
	p := r.prepared
	r.mu.Unlock()
	err := p.Retire()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleaning = false
	if err != nil {
		return err
	}
	r.releaseUnadopted()
	r.initial, r.ledger, r.prepared = nil, nil, nil
	r.retired = true
	return nil
}

func (r *RelayHop) releaseUnadopted() {
	if r.forwardDeadline != nil {
		r.forwardDeadline.Cancel()
	}
	if r.subscriptions != nil {
		r.subscriptions.Close()
	}
	if r.budget != nil {
		r.budget.close()
	}
	for _, signed := range r.maps {
		if signed != nil {
			signed.Release()
		}
	}
	r.maps, r.codecs = [3]*protocolv4.SignedMap{}, [3]*protocolv4.SignedMapCodec{}
	if r.pairRegistered {
		r.c.Pair.release(r)
	}
	r.hop, r.c, r.facts = hopAuthentication{}, RelayHopConfig{}, protocolv4.RelayClaimFacts{}
	r.claimReservation.Release()
	r.invocationReservation.Release()
	r.claimRef.Release()
	r.invocationRef.Release()
	r.shared.Release()
	r.reservation.Release()
}
