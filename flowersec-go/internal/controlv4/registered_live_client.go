package controlv4

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strconv"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// RegisteredLiveAuthorizationRequest is the exact JSON projection consumed by
// the registered original live authority. Decimal time preserves uint64 bits.
type RegisteredLiveAuthorizationRequest struct {
	Authority            string `json:"authority"`
	Tenant               string `json:"tenant"`
	Audience             string `json:"audience"`
	CryptoProfile        string `json:"cryptoProfile"`
	CandidateIndex       uint64 `json:"candidateIndex"`
	ActivationNotAfterMS string `json:"activationNotAfterMS"`
	AttemptNo            uint8  `json:"attemptNo"`
	Issuer               string `json:"issuer"`
	Lease                string `json:"lease"`
	Attempt              string `json:"attempt"`
	Artifact             string `json:"artifact"`
	ClientIdentity       string `json:"clientIdentity"`
	ServerIdentity       string `json:"serverIdentity"`
	CandidateID          string `json:"candidateID"`
	RouteDigest          string `json:"routeDigest"`
}

func registeredLiveRequest(authority string, q sessionv4.LiveAuthorizationRequest) RegisteredLiveAuthorizationRequest {
	encode := base64.StdEncoding.EncodeToString
	return RegisteredLiveAuthorizationRequest{Authority: authority, Tenant: q.Tenant, Audience: q.Audience, CryptoProfile: q.CryptoProfile, CandidateIndex: q.Winner.Index, ActivationNotAfterMS: strconv.FormatUint(q.ActivationNotAfterMS, 10), AttemptNo: q.AttemptNo,
		Issuer: encode(q.Issuer[:]), Lease: encode(q.Lease[:]), Attempt: encode(q.Attempt[:]), Artifact: encode(q.Artifact[:]), ClientIdentity: encode(q.ClientIdentity[:]), ServerIdentity: encode(q.ServerIdentity[:]), CandidateID: encode(q.Winner.CandidateID[:]), RouteDigest: encode(q.Winner.RouteDigest[:])}
}

// RequestAuthorization is intentionally unavailable for this registered tunnel
// adapter; a tunnel response must include the client's original Grant as well.
func (p *RegisteredControlTransport) RequestAuthorization(context.Context, sessionv4.LiveAuthorizationRequest, []byte) (int, error) {
	return 0, resourcev4.ErrConfiguration
}

// RequestTunnelAuthorization runs only after the Session owner's actual native
// preparation. It announces that exact original attempt, then sends the fresh
// nonce plus canonical request signed by the independently installed A identity.
// The response remains opaque original bytes until Session verifies it against
// the prepared winner, current namespaces and original Activation owner.
func (p *RegisteredControlTransport) RequestTunnelAuthorization(ctx context.Context, q sessionv4.LiveAuthorizationRequest, dst [2][]byte) (sizes [2]int, err error) {
	if p == nil || ctx == nil {
		return sizes, resourcev4.ErrConfiguration
	}
	proofLimit, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	grantLimit, _ := protocolv4.SchemaByteLimit("Grant")
	if len(dst[0]) < proofLimit || len(dst[1]) < grantLimit {
		return sizes, resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return sizes, ErrBusy
	}
	if p.closed || p.busy || p.liveBusy || p.liveUsed || p.liveServerFailed || len(p.config.Incarnation) != 32 || q.Tenant != p.config.Tenant || q.Audience != p.config.Audience || q.Artifact != p.config.Parent || q.Winner.Index != p.config.Candidate || q.Attempt == ([16]byte{}) {
		p.mu.Unlock()
		return sizes, resourcev4.ErrConfiguration
	}
	p.liveUsed, p.liveBusy = true, true
	call := newControlCallContext(p.provider.config.Timeout)
	p.liveCancel = call.stopCall
	signer, authority, decoder := p.config.Identity, p.config.Authority, p.decoder
	p.mu.Unlock()
	// The once gate belongs to this original request; transport errors do not
	// permit a second nonce, a retry, or replaying preparation on this provider.
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err = ErrControlTaskExit
			call.cancel(err)
		}
		call.finish()
		p.mu.Lock()
		defer p.mu.Unlock()
		if err == nil {
			err = call.cause()
		}
		if err == nil {
			err = p.reservation.Check()
		}
		if err == nil {
			err = p.dependencies.Check()
		}
		if p.closed && err == nil {
			err = context.Canceled
		}
		if err != nil {
			sizes = [2]int{}
			clear(dst[0])
			clear(dst[1])
		}
		call.stopCall()
		p.liveBusy, p.liveCancel = false, nil
		p.cleanupLocked()
	}()
	if err = call.start(ctx); err == nil {
		sizes, err = p.requestRegisteredLive(call, q, dst, signer, authority, decoder)
	}
	returned = true
	return sizes, err
}

func (p *RegisteredControlTransport) requestRegisteredLive(call *controlCallContext, q sessionv4.LiveAuthorizationRequest, dst [2][]byte, signer protocolv4.MapSigner, authority string, decoder *protocolv4.Decoder) (sizes [2]int, err error) {
	var authentication [32 + liveRequestBytes]byte
	var signature, wire []byte
	defer func() { clear(authentication[:]); clear(signature); clear(wire) }()
	guard := func() error {
		if err := call.cause(); err != nil {
			return err
		}
		if err := p.reservation.Check(); err != nil {
			return err
		}
		return p.dependencies.Check()
	}
	requestSize, err := EncodeLiveAuthorizationRequest(authentication[32:], q)
	if err != nil {
		return sizes, err
	}
	if p.config.Relay != nil {
		if err = p.config.Relay.Prepare(call, q, guard); err != nil {
			return sizes, err
		}
	}
	if _, err = rand.Read(authentication[:32]); err != nil {
		return sizes, err
	}
	prepared := p.Payload("live_client_prepared")
	prepared.Attempt = base64.StdEncoding.EncodeToString(q.Attempt[:])
	reply, err := p.Call(call, prepared, guard)
	if err != nil {
		return sizes, err
	}
	if !reply.Prepared {
		return sizes, ErrResponse
	}
	signed := authentication[: 32+requestSize : 32+requestSize]
	signature, err = signer.Sign(signed)
	if err != nil {
		return sizes, err
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(signer.PublicKey()), signed, signature) {
		return sizes, ErrResponse
	}
	if err = guard(); err != nil {
		return sizes, err
	}
	payload := p.Payload("live_authorize")
	projection := registeredLiveRequest(authority, q)
	payload.Request = &projection
	payload.Authentication = base64.StdEncoding.EncodeToString(signed)
	payload.Signature = base64.StdEncoding.EncodeToString(signature)
	reply, err = p.Call(call, payload, guard)
	if err != nil {
		return sizes, err
	}
	wire, err = DecodeRegisteredControlBytes(reply.Grant, liveTunnelMaterialLimit(), 0)
	if err != nil {
		return sizes, err
	}
	if err = guard(); err != nil {
		return sizes, err
	}
	sizes, err = decodeLiveTunnelMaterial(decoder, wire, dst)
	if err != nil {
		return sizes, err
	}
	if p.config.Relay != nil {
		if err = p.config.Relay.Activate(call, q, dst[0][:sizes[0]:sizes[0]], dst[1][:sizes[1]:sizes[1]], guard); err != nil {
			return [2]int{}, err
		}
	}
	if err = guard(); err != nil {
		return [2]int{}, err
	}
	return sizes, nil
}

var _ sessionv4.LiveTunnelAuthorizationProvider = (*RegisteredControlTransport)(nil)

// RegisteredLiveServerMaterial is the exact publication returned to the B
// incarnation. The byte strings are the original activation and server Grant;
// the consumer must pass them to its original live registration/accept path.
type RegisteredLiveServerMaterial struct {
	Attempt           [16]byte
	Activation, Grant []byte
}

// RegisterLiveServer binds one independently installed B recipient and its
// incarnation before the original live authority may issue material.
func (p *RegisteredControlTransport) RegisterLiveServer(ctx context.Context, recipient [16]byte, guard func() error) (err error) {
	if p == nil || ctx == nil || guard == nil || recipient == ([16]byte{}) {
		return resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return ErrBusy
	}
	if len(p.config.Incarnation) != 16 || p.closed || p.busy || p.liveBusy || p.liveServerFailed || p.liveRegistered {
		p.mu.Unlock()
		return resourcev4.ErrConfiguration
	}
	p.liveRegistered, p.liveBusy = true, true
	p.mu.Unlock()
	defer func() {
		if recover() != nil {
			err = ErrControlTaskExit
		}
		p.finishLiveServerOperation(err)
	}()
	if p.config.Relay != nil {
		if err = p.config.Relay.BeforeServerRegistration(); err != nil {
			return err
		}
	}
	payload := p.Payload("live_register")
	payload.Recipient = base64.StdEncoding.EncodeToString(recipient[:])
	reply, err := p.Call(ctx, payload, guard)
	if err != nil {
		return err
	}
	if !reply.Registered {
		return ErrResponse
	}
	return nil
}

// ReceiveOriginalLivePublication reserves the authenticated attempt at the
// already admitted B registration before confirming live_reserved. Only the
// original TxB publication supplies Activation/Grant; installed trust and
// identity never come from this response.
func (p *RegisteredControlTransport) ReceiveOriginalLivePublication(ctx context.Context, guard func() error, reserve func([16]byte) error) (result RegisteredLiveServerMaterial, err error) {
	if p == nil || ctx == nil || guard == nil || reserve == nil {
		return result, resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return result, ErrBusy
	}
	if len(p.config.Incarnation) != 16 || p.closed || p.busy || p.liveBusy || p.liveServerFailed || !p.liveRegistered || p.liveMaterialTaken {
		p.mu.Unlock()
		return result, resourcev4.ErrConfiguration
	}
	p.liveMaterialTaken, p.liveBusy = true, true
	p.mu.Unlock()
	defer func() {
		if recover() != nil {
			err = ErrControlTaskExit
		}
		p.finishLiveServerOperation(err)
		if err != nil {
			clear(result.Activation)
			clear(result.Grant)
			result = RegisteredLiveServerMaterial{}
		}
	}()
	reservation := p.Payload("live_reservation")
	reply, err := p.Call(ctx, reservation, guard)
	if err != nil {
		return result, err
	}
	originalAttempt, err := decodeAttempt(reply.Attempt)
	if err != nil {
		return result, err
	}
	if err = guard(); err != nil {
		return result, err
	}
	if err = reserve(originalAttempt); err != nil {
		return result, err
	}
	if err = guard(); err != nil {
		return result, err
	}
	p.mu.Lock()
	p.liveAttempt = originalAttempt
	p.mu.Unlock()
	reserved := p.Payload("live_reserved")
	reserved.Attempt = base64.StdEncoding.EncodeToString(originalAttempt[:])
	confirmation, err := p.Call(ctx, reserved, guard)
	if err != nil {
		return result, err
	}
	if !confirmation.Reserved {
		return result, ErrResponse
	}
	material := p.Payload("live_receive")
	received, err := p.Call(ctx, material, guard)
	if err != nil {
		return result, err
	}
	result.Attempt, err = decodeAttempt(received.Attempt)
	if err != nil {
		return result, err
	}
	if result.Attempt != originalAttempt {
		return result, ErrResponse
	}
	result.Activation, err = DecodeRegisteredControlBytes(received.Activation, 65536, 0)
	if err != nil {
		return result, err
	}
	result.Grant, err = DecodeRegisteredControlBytes(received.Grant, 65536, 0)
	if err != nil {
		return result, err
	}
	return result, nil
}

// AcknowledgeOriginalLiveAllow records exact verified original digests after
// the B registration has completed its physical native preparation.
func (p *RegisteredControlTransport) AcknowledgeOriginalLiveAllow(ctx context.Context, attempt [16]byte, activationDigest, grantDigest [32]byte, guard func() error) (err error) {
	if p == nil || ctx == nil || guard == nil || attempt == ([16]byte{}) || activationDigest == ([32]byte{}) || grantDigest == ([32]byte{}) {
		return resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return ErrBusy
	}
	if len(p.config.Incarnation) != 16 || p.closed || p.busy || p.liveBusy || p.liveServerFailed || !p.liveRegistered || !p.liveMaterialTaken || p.liveAcknowledged || p.liveAttempt != attempt {
		p.mu.Unlock()
		return resourcev4.ErrConfiguration
	}
	p.liveAcknowledged, p.liveBusy = true, true
	p.mu.Unlock()
	defer func() {
		if recover() != nil {
			err = ErrControlTaskExit
		}
		p.finishLiveServerOperation(err)
	}()
	payload := p.Payload("live_allow_ack")
	payload.Attempt = base64.StdEncoding.EncodeToString(attempt[:])
	payload.Activation = base64.StdEncoding.EncodeToString(activationDigest[:])
	payload.Grant = base64.StdEncoding.EncodeToString(grantDigest[:])
	reply, err := p.Call(ctx, payload, guard)
	if err != nil {
		return err
	}
	if !reply.Delivered {
		return ErrResponse
	}
	return nil
}

func (p *RegisteredControlTransport) finishLiveServerOperation(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.liveServerFailed = true
	}
	p.liveBusy = false
	p.cleanupLocked()
}

func decodeAttempt(value string) ([16]byte, error) {
	var result [16]byte
	wire, err := DecodeRegisteredControlBytes(value, 16, 16)
	if err != nil {
		return result, err
	}
	copy(result[:], wire)
	clear(wire)
	if result == ([16]byte{}) {
		return [16]byte{}, ErrResponse
	}
	return result, nil
}

// AnnounceOriginalRelayReady runs after the original endpoint has physically
// bound its reverse listener. The enclosing live operation fences parent Close
// and retains both transports until the READY call has actually exited.
func (p *RegisteredControlTransport) AnnounceOriginalRelayReady(ctx context.Context, guard func() error) (err error) {
	if p == nil || ctx == nil || guard == nil {
		return resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return ErrBusy
	}
	if p.closed || p.busy || p.liveBusy || p.liveUsed || p.liveRegistered {
		p.mu.Unlock()
		return ErrBusy
	}
	relay := p.config.Relay
	if relay == nil {
		p.mu.Unlock()
		return nil
	}
	p.liveBusy = true
	p.mu.Unlock()
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err = ErrControlTaskExit
		}
		p.finishLiveServerOperation(err)
	}()
	err = relay.AnnounceReady(ctx, guard)
	returned = true
	return err
}
