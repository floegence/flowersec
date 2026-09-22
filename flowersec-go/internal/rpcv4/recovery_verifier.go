package rpcv4

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrRecoveryUnauthorized = errors.New("rpcv4: recovery unauthorized")

// ErrRecoveryRejected is a definite decision about the supplied token. Local
// capacity, unavailable time, cancellation and provider failures never use it.
var ErrRecoveryRejected = errors.New("rpcv4: recovery rejected")

// RecoveryKey is an immutable trusted service dependency. The token's key id
// can select only this registered set; it cannot install a key or namespace.
type RecoveryKey struct {
	ID         [16]byte
	Protection uint8
	Public     [32]byte
	MAC        *cryptov4.RecoveryMACKey
	// An optional independently provisioned application signing capability.
	// Session signing/record keys must never be registered here.
	Signer        protocolv4.MapSigner
	SignerBacking resourcev4.Reference
}

type RecoveryVerifierConfig struct {
	Service      ExecutionService
	Clock        *timev4.Clock
	Keys         []RecoveryKey
	RuntimeBytes uint64
}

// RecoveryVerifier is the service's bounded crypto workspace, not an operation
// registry or pending queue. History, nonce consumption and generation CAS
// remain exclusively in the original execution store's application transaction.
type RecoveryVerifier struct {
	mu          sync.Mutex
	service     ExecutionService
	clock       *timev4.Clock
	keys        []RecoveryKey
	keyRefs     []resourcev4.Reference
	codec       *protocolv4.ResumeCodec
	reservation resourcev4.Reference
	closed      bool
}

func RecoveryVerifierCharge(c RecoveryVerifierConfig) (resourcev4.Vector, error) {
	if c.Clock == nil || c.RuntimeBytes == 0 || len(c.Keys) == 0 || len(c.Keys) > 16 || !executionIdentifier(c.Service.Tenant) || !executionIdentifier(c.Service.Audience) || !executionIdentifier(c.Service.Namespace) {
		return resourcev4.Vector{}, ErrConfiguration
	}
	for i, key := range c.Keys {
		if key.Protection > 1 || key.Protection == 0 && (key.MAC != nil || key.Public == ([32]byte{})) || key.Protection == 1 && (key.MAC == nil || key.Public != ([32]byte{}) || key.Signer != nil) || (key.Signer == nil) != (key.SignerBacking == (resourcev4.Reference{})) {
			return resourcev4.Vector{}, ErrConfiguration
		}
		for _, previous := range c.Keys[:i] {
			if key.ID == previous.ID {
				return resourcev4.Vector{}, ErrConfiguration
			}
		}
	}
	n, err := protocolv4.ResumeCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	// Current input, token verification and detached projection may overlap.
	// This workspace admits one synchronous verification, never another queue.
	n += uint64(unsafe.Sizeof(RecoveryVerifier{})) + 3*128 + uint64(len(c.Keys))*(uint64(unsafe.Sizeof(RecoveryKey{}))+uint64(unsafe.Sizeof(resourcev4.Reference{}))) + 3*uint64(unsafe.Sizeof(protocolv4.ResumeToken{})) + uint64(unsafe.Sizeof(VerifiedRecovery{}))
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: uint64(len(c.Keys)) + 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewRecoveryVerifier(c RecoveryVerifierConfig, reservation resourcev4.Reference) (_ *RecoveryVerifier, err error) {
	charge, err := RecoveryVerifierCharge(c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	v := &RecoveryVerifier{clock: c.Clock, reservation: owned, keys: append([]RecoveryKey(nil), c.Keys...), keyRefs: make([]resourcev4.Reference, len(c.Keys))}
	defer func() {
		if err != nil {
			v.Close()
		}
	}()
	v.service = ExecutionService{Tenant: strings.Clone(c.Service.Tenant), Audience: strings.Clone(c.Service.Audience), Namespace: strings.Clone(c.Service.Namespace)}
	v.codec, err = protocolv4.NewResumeCodec()
	if err != nil {
		return nil, err
	}
	for i, key := range v.keys {
		if key.MAC != nil {
			v.keyRefs[i], err = key.MAC.Borrow(owned)
		} else if key.Signer != nil {
			err = owned.CheckSameEnvironment(key.SignerBacking)
			if err == nil {
				v.keyRefs[i], err = key.SignerBacking.Borrow()
			}
		}
		if err != nil {
			return nil, err
		}
		v.keys[i].SignerBacking = resourcev4.Reference{}
	}
	return v, nil
}

// RecoveryTarget is captured from the actual accepted target Stream by the
// SDK. Caller identity or a repeated stream id cannot substitute a new Session.
type RecoveryTarget struct {
	TransportContext [32]byte
	StreamID         uint64
}

// VerifiedRecovery carries a bounded authenticated candidate to the original
// store transaction. It is not evidence of token consumption or resume success.
type VerifiedRecovery struct {
	verifier *RecoveryVerifier
	token    protocolv4.VerifiedResumeToken
	header   protocolv4.ApplicationHeader
	claims   protocolv4.ResumeClaims
	original ExecutionTarget
	target   RecoveryTarget
	valid    bool
}

func (r VerifiedRecovery) Claims() protocolv4.ResumeClaims { return r.claims }
func (r VerifiedRecovery) Original() ExecutionTarget       { return r.original }
func (r VerifiedRecovery) Target() RecoveryTarget          { return r.target }
func (r VerifiedRecovery) Valid() bool                     { return r.valid }
func (VerifiedRecovery) String() string                    { return "Flowersec.VerifiedRecovery" }
func (VerifiedRecovery) GoString() string                  { return "Flowersec.VerifiedRecovery" }
func (VerifiedRecovery) MarshalJSON() ([]byte, error)      { return []byte("{}"), nil }

// Verify uses current SDK business authority before key work and immediately
// before handing the candidate to its original transaction. An administrator
// may act only when the same ExecutionAccess explicitly authorizes the full
// original target. Verification does not read, issue, consume or renew history.
func (v *RecoveryVerifier) Verify(ctx context.Context, request protocolv4.ResumeRequest, original ExecutionTarget, target RecoveryTarget, access ExecutionAccess) (VerifiedRecovery, error) {
	if v == nil || ctx == nil || access == nil {
		return VerifiedRecovery{}, ErrConfiguration
	}
	if !v.mu.TryLock() {
		return VerifiedRecovery{}, ErrCapacity
	}
	defer v.mu.Unlock()
	return v.verify(ctx, request, original, target, access)
}

func (v *RecoveryVerifier) verify(ctx context.Context, request protocolv4.ResumeRequest, original ExecutionTarget, target RecoveryTarget, access ExecutionAccess) (VerifiedRecovery, error) {
	if v.closed {
		return VerifiedRecovery{}, ErrClosed
	}
	if original.Service != v.service || target.TransportContext == ([32]byte{}) || target.StreamID == 0 || target.StreamID > uint64(^uint64(0)>>1) || request.StreamID != target.StreamID || request.TransportContext != target.TransportContext {
		return VerifiedRecovery{}, ErrRecoveryRejected
	}
	claims := request.Token.Claims()
	if claims.Tenant != v.service.Tenant || claims.Audience != v.service.Audience || claims.Namespace != v.service.Namespace || claims.Caller != original.Caller.Subject || claims.Operation != original.Operation || claims.RequestDigest != original.RequestDigest {
		return VerifiedRecovery{}, ErrRecoveryRejected
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := v.reservation.Check(); err != nil {
			return err
		}
		now, err := v.clock.Sample()
		if err != nil {
			return err
		}
		// Max issued duration is an issuance policy. A newer Session's shorter
		// issuance policy cannot rewrite the original token's fixed validity.
		if err := now.LowerBound(claims.IssuedAtMS, true); err != nil {
			if errors.Is(err, timev4.ErrFutureTimestamp) {
				return ErrRecoveryRejected
			}
			return err
		}
		if claims.ExpiresAtMS <= now.UpperMS {
			return ErrRecoveryRejected
		}
		return access.WithExecutionAccess(original, func(ref resourcev4.Reference) error { return ref.CheckSameEnvironment(v.reservation) })
	}
	if err := guard(); err != nil {
		return VerifiedRecovery{}, err
	}
	var proof protocolv4.VerifiedResumeToken
	var err error
	found := false
	for _, key := range v.keys {
		if key.ID != request.Token.KeyID() || key.Protection != request.Token.Protection() {
			continue
		}
		found = true
		if key.Protection == 0 {
			proof, err = v.codec.VerifySignedToken(request.Token, key.ID, key.Public)
		} else {
			proof, err = v.codec.VerifyMACToken(request.Token, key.ID, key.MAC, guard)
		}
		break
	}
	if !found {
		return VerifiedRecovery{}, ErrRecoveryRejected
	}
	if err != nil {
		if errors.Is(err, protocolv4.CBORFailure("signature_invalid")) || errors.Is(err, protocolv4.CBORFailure("resume_mac_invalid")) {
			return VerifiedRecovery{}, ErrRecoveryRejected
		}
		return VerifiedRecovery{}, err
	}
	if err = guard(); err != nil {
		return VerifiedRecovery{}, err
	}
	return VerifiedRecovery{verifier: v, token: proof, claims: proof.Claims(), original: original, target: target, valid: true}, nil
}

// VerifyInput binds the candidate to the actual complete, hashed recovery
// request held by the original execution owner. A separately verified token
// cannot substitute another payload after an operation id has been registered.
func (v *RecoveryVerifier) VerifyInput(ctx context.Context, input InputBorrow, original ExecutionTarget, target RecoveryTarget, access ExecutionAccess) (VerifiedRecovery, error) {
	return v.verifyInput(ctx, input, original, nil, target, access)
}

// VerifyCallerInput derives the original execution key from the authenticated
// token and the SDK's current caller authority. The token does not contain an
// old contract digest: its complete original request digest already binds that
// contract, and only the original store may resolve its retained contract row.
func (v *RecoveryVerifier) VerifyCallerInput(ctx context.Context, input InputBorrow, caller ExecutionPrincipal, target RecoveryTarget, access ExecutionAccess) (VerifiedRecovery, error) {
	if !executionIdentifier(caller.Subject) {
		return VerifiedRecovery{}, ErrRecoveryUnauthorized
	}
	return v.verifyInput(ctx, input, ExecutionTarget{}, &caller, target, access)
}

func (v *RecoveryVerifier) verifyInput(ctx context.Context, input InputBorrow, original ExecutionTarget, caller *ExecutionPrincipal, target RecoveryTarget, access ExecutionAccess) (VerifiedRecovery, error) {
	if v == nil || ctx == nil || access == nil {
		return VerifiedRecovery{}, ErrConfiguration
	}
	if !v.mu.TryLock() {
		return VerifiedRecovery{}, ErrCapacity
	}
	defer v.mu.Unlock()
	if v.closed {
		return VerifiedRecovery{}, ErrClosed
	}
	payload, header, err := input.Bytes()
	if err != nil {
		return VerifiedRecovery{}, err
	}
	if header.Kind() != "resume_request" {
		return VerifiedRecovery{}, ErrAssociation
	}
	request, err := v.codec.DecodeRequest(payload)
	if err != nil {
		return VerifiedRecovery{}, err
	}
	if caller != nil {
		claims := request.Token.Claims()
		original = ExecutionTarget{Service: v.service, Caller: *caller, Operation: claims.Operation, RequestDigest: claims.RequestDigest}
	}
	proof, err := v.verify(ctx, request, original, target, access)
	if err == nil {
		proof.header = header
	}
	return proof, err
}

// check preserves the same local key registration, time and authority through
// the store's original commit guards. It neither parses nor verifies again.
func (r VerifiedRecovery) check(ctx context.Context, access ExecutionAccess) error {
	v := r.verifier
	if !r.valid || v == nil || access == nil {
		return ErrOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := v.reservation.Check(); err != nil {
		return err
	}
	now, err := v.clock.Sample()
	if err != nil {
		return err
	}
	if err := now.LowerBound(r.claims.IssuedAtMS, true); err != nil {
		return err
	}
	if !now.ValidBefore(r.claims.ExpiresAtMS) {
		return timev4.ErrExpired
	}
	token := r.token.Token()
	found := false
	for i, key := range v.keys {
		if key.ID != token.KeyID() || key.Protection != token.Protection() {
			continue
		}
		if key.MAC != nil {
			if err := v.keyRefs[i].Check(); err != nil {
				return err
			}
		}
		found = true
		break
	}
	if !found {
		return ErrRecoveryUnauthorized
	}
	return access.WithExecutionAccess(r.original, func(ref resourcev4.Reference) error { return ref.CheckSameEnvironment(v.reservation) })
}

func (v *RecoveryVerifier) Borrow(backing resourcev4.Reference) (resourcev4.Reference, error) {
	if v == nil {
		return resourcev4.Reference{}, ErrOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return resourcev4.Reference{}, ErrClosed
	}
	if err := v.reservation.CheckSameEnvironment(backing); err != nil {
		return resourcev4.Reference{}, err
	}
	return v.reservation.Borrow()
}
func (v *RecoveryVerifier) Close() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return
	}
	v.closed = true
	for _, ref := range v.keyRefs {
		ref.Release()
	}
	clear(v.keys)
	clear(v.keyRefs)
	v.keys, v.keyRefs, v.codec, v.clock = nil, nil, nil, nil
	v.service = ExecutionService{}
	v.reservation.Release()
	v.reservation = resourcev4.Reference{}
}

func (v *RecoveryVerifier) borrowService(a ServiceAuthority, backing resourcev4.Reference) (resourcev4.Reference, error) {
	if v == nil {
		return resourcev4.Reference{}, ErrOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return resourcev4.Reference{}, ErrClosed
	}
	if v.service != (ExecutionService{Tenant: a.Tenant, Audience: a.Audience, Namespace: a.Namespace}) {
		return resourcev4.Reference{}, ErrAssociation
	}
	if err := v.reservation.CheckSameEnvironment(backing); err != nil {
		return resourcev4.Reference{}, err
	}
	return v.reservation.Borrow()
}
