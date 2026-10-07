// Package runtimehost composes actual runtime entry points from independently
// configured original owners. It supplies no credential or durable receipt.
package runtimehost

import (
	"context"
	"crypto/rand"
	"sync"
	"unsafe"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// RelayConfig fixes original signing policy, physical history, native listener
// factories and one finite forwarding position before the control endpoint is
// exposed. Prepare admits native listener backing without opening a carrier;
// the returned callbacks call the actual SDK PrepareTunnel methods later.
type RelayConfig struct {
	Policy          controlv4.PoolTunnelDeploymentPolicyConfig
	FenceSigner     protocolv4.MapSigner
	ProofValidityMS uint64
	RelaySigner     cryptov4.IdentitySigner
	RelayInstance   [16]byte
	RelayGeneration uint64
	Prepare         func(context.Context, uint64, []byte, protocolv4.ArtifactSessionParameters, *timev4.Deadline) ([2]sessionv4.TunnelCarrierPreparation, error)
	RuntimeBytes    uint64
}

type Relay struct {
	mu                                                     sync.Mutex
	config                                                 RelayConfig
	live                                                   *LiveRelayConfig
	registeredSource                                       string
	liveTable                                              *ledgerv4.SQLiteRelayAuthorityTable
	livePrepare                                            [2]sessionv4.TunnelCarrierPreparation
	livePrepared                                           [2]bool
	livePreparing                                          bool
	deployment                                             *controlv4.PoolTunnelDeployment
	proof                                                  *controlv4.PoolOwnerProofIssuer
	runtime                                                *fs.TunnelRuntime
	reservation, shared, dependencies                      resourcev4.Reference
	parser                                                 *protocolv4.Decoder
	topUp                                                  *protocolv4.TopUpCodec
	context                                                context.Context
	cancel                                                 context.CancelFunc
	route                                                  *fs.TunnelRoute
	running, dispatched, closed, serving, settled, cleaned bool
	active                                                 uint8
	idle, result, cleanupDone                              chan struct{}
	resultErr                                              error
}

func RelayCharge(c RelayConfig) (resourcev4.Vector, error) {
	if c.RuntimeBytes == 0 || c.Prepare == nil || c.RelaySigner == nil || c.RelayInstance == ([16]byte{}) || c.RelayGeneration == 0 || c.FenceSigner == nil || c.ProofValidityMS == 0 || c.Policy.Deployment.Source.IssuanceLimits.MaxBatchCount != 1 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for _, route := range c.Policy.Routes {
		if route == nil {
			continue
		}
		lookups, err := RelayAuthorityParallelLookups(route.Limits, relayActivePairs)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		if c.Policy.Deployment.Relay.ParallelLookups < lookups {
			return resourcev4.Vector{}, resourcev4.ErrCapacity
		}
	}
	parser, err := protocolv4.DecoderBackingBytes(524288, 256)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	topUp, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	n := uint64(unsafe.Sizeof(Relay{})) + parser + topUp + 524288 + 65536
	for _, schema := range []string{"Artifact", "IdentityCertificate", "IdentityCertificate", "Grant", "Grant", "IdentityCertificate"} {
		maximum, err := protocolv4.SchemaByteLimit(schema)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		backing, err := protocolv4.SignedMapBackingBytes(schema, maximum, 16384)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		n += backing
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewRelay(ctx context.Context, c RelayConfig, reservation, dependencies resourcev4.Reference) (_ *Relay, err error) {
	if ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	cost, err := RelayCharge(c)
	if err != nil {
		return nil, err
	}
	deployment := c.Policy.Deployment
	if err = reservation.CheckAllocationScope(deployment.Root, deployment.Owner, deployment.Accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	r := &Relay{config: c, reservation: owned, context: lifetime, cancel: cancel, result: make(chan struct{}), idle: closedRelaySignal()}
	success := false
	defer func() {
		if !success {
			r.Close()
			_ = r.WaitCleanup(context.Background())
		}
	}()
	r.dependencies = dependencies
	r.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	r.parser, err = protocolv4.NewDecoder(524288, 256)
	if err != nil {
		return nil, err
	}
	r.topUp, err = protocolv4.NewTopUpCodec()
	if err != nil {
		return nil, err
	}
	cost, err = controlv4.PoolTunnelDeploymentPolicyCharge(c.Policy)
	if err != nil {
		return nil, err
	}
	ref, owner, err := r.reserve(cost)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	policy := c.Policy
	policy.Deployment.Owner = owner
	r.deployment, err = controlv4.NewPoolTunnelDeploymentFromPolicy(ctx, policy, ref, dependencies)
	if err != nil {
		return nil, err
	}
	proof := controlv4.PoolOwnerProofIssuerConfig{Deployment: r.deployment, Signer: c.FenceSigner, ValidityMS: c.ProofValidityMS, RuntimeBytes: 65536}
	cost, err = controlv4.PoolOwnerProofIssuerCharge(proof)
	if err != nil {
		return nil, err
	}
	ref, _, err = r.reserve(cost)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	r.proof, err = controlv4.NewPoolOwnerProofIssuer(proof, ref, dependencies)
	if err != nil {
		return nil, err
	}
	runtime := fs.TunnelRuntimeOptions{MaxActivePairs: relayActivePairs, RuntimeBytes: 65536, Dependencies: dependencies}
	cost, err = fs.TunnelRuntimeCharge(runtime)
	if err != nil {
		return nil, err
	}
	ref, _, err = r.reserve(cost)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	runtime.Reservation = ref
	r.runtime, err = fs.NewTunnelRuntime(runtime)
	if err != nil {
		return nil, err
	}
	success = true
	return r, nil
}
func (r *Relay) reserve(cost resourcev4.Vector) (resourcev4.Reference, resourcev4.OwnerKey, error) {
	c := r.config.Policy.Deployment
	owner := c.Owner
	if _, err := rand.Read(owner.Instance[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	if _, err := rand.Read(owner.Backing[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	ref, err := c.Root.Reserve(owner, cost, c.Accounts...)
	return ref, owner, err
}
func (r *Relay) Service() (*controlv4.PoolService, error) {
	if r == nil || r.deployment == nil {
		return nil, resourcev4.ErrConfiguration
	}
	return r.deployment.Service()
}
func (r *Relay) OwnerProof() *controlv4.PoolOwnerProofIssuer { return r.proof }
func (r *Relay) Deployment() *controlv4.PoolTunnelDeployment { return r.deployment }

// Issue is the local deployment entry for an actual new source request. Its
// proof comes from the original source owner, and success comes from the real
// Service.Exchange after complete outbox COMMIT and public publication. A replay
// returns its original response and never dispatches a route or a consumer.
func (r *Relay) Issue(ctx context.Context, access ledgerv4.TopUpAccess, request protocolv4.TopUpRequestFacts, dst []byte) (int, error) {
	return r.issue(ctx, access, request, dst, nil)
}

// IssueToOriginalOwner invokes one trusted local handoff inside the original
// successful Exchange continuation. A replay never invokes it. The handoff
// consumes the only dispatch position, so this host cannot also start a route.
func (r *Relay) IssueToOriginalOwner(ctx context.Context, access ledgerv4.TopUpAccess, request protocolv4.TopUpRequestFacts, dst []byte,
	original func(context.Context, protocolv4.TopUpRequestFacts, []byte) error) (int, error) {
	if original == nil {
		return 0, resourcev4.ErrConfiguration
	}
	return r.issue(ctx, access, request, dst, original)
}
func (r *Relay) issue(ctx context.Context, access ledgerv4.TopUpAccess, request protocolv4.TopUpRequestFacts, dst []byte,
	original func(context.Context, protocolv4.TopUpRequestFacts, []byte) error) (int, error) {
	if r == nil || ctx == nil || len(dst) < 524288 {
		return 0, resourcev4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.running {
		r.mu.Unlock()
		return 0, controlv4.ErrBusy
	}
	r.running = true
	r.beginCallLocked()
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.running = false; r.endCallLocked(); r.mu.Unlock() }()
	digest, err := protocolv4.ComputeTopUpRequestDigest(request)
	if err != nil {
		return 0, err
	}
	if digest != request.Digest {
		return 0, ledgerv4.ErrDenied
	}
	var proof [512]byte
	n, err := r.proof.Issue(ctx, access, request, proof[:])
	if err != nil {
		return 0, err
	}
	defer clear(proof[:])
	var wire [4096]byte
	size, err := r.topUp.EncodeRequest(wire[:], request, proof[:n:n])
	if err != nil {
		return 0, err
	}
	defer clear(wire[:])
	service, err := r.deployment.Service()
	if err != nil {
		return 0, err
	}
	n, failure, err := service.Exchange(ctx, controlv4.ControlPoolTopUp, access, wire[:size:size], dst)
	if err != nil {
		return 0, err
	}
	if failure {
		return n, nil
	}
	doc, err := r.parser.DecodeShape(dst[:n:n], "", protocolv4.DecodeContext{})
	if err != nil {
		return 0, err
	}
	root := doc.Root()
	code, ok := root.Index(0).Text()
	response, bytesOK := root.Index(1).ByteString()
	if root.Len() != 4 || !ok || !bytesOK {
		doc.Release()
		return 0, controlv4.ErrResponse
	}
	if code == "replay" {
		doc.Release()
		return n, nil
	}
	if code != "success" || len(response) == 0 {
		doc.Release()
		return 0, controlv4.ErrResponse
	}
	// The parser owns response until this synchronous original callback returns.
	if original == nil {
		err = r.DispatchOriginal(ctx, request, response)
	} else {
		r.mu.Lock()
		if r.closed || r.dispatched {
			r.mu.Unlock()
			doc.Release()
			return 0, resourcev4.ErrCapacity
		}
		r.dispatched = true
		r.mu.Unlock()
		// The full successful reply remains owned by this exact call. It is not a
		// queryable restoration record, and a failed handoff is never retried.
		err = original(ctx, request, dst[:n:n])
		r.mu.Lock()
		r.finishLocked(err)
		r.mu.Unlock()
	}
	doc.Release()
	if err != nil {
		return 0, err
	}
	return n, nil
}

// DispatchOriginal is called exclusively by the original successful Exchange
// or the configured HTTPS success observer. Restored rows and replay responses
// never enter this method. The finite position is irreversible after dispatch.
func (r *Relay) DispatchOriginal(ctx context.Context, request protocolv4.TopUpRequestFacts, response []byte) (err error) {
	if r == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.dispatched {
		r.mu.Unlock()
		return resourcev4.ErrCapacity
	}
	r.dispatched = true
	r.beginCallLocked()
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.endCallLocked()
		if err != nil {
			r.finishLocked(err)
		}
		r.mu.Unlock()
	}()
	batch, err := r.topUp.ParseResponse(response, request)
	if err != nil {
		return err
	}
	defer batch.Release()
	facts, err := batch.Facts()
	if err != nil || facts.Count != 1 {
		return controlv4.ErrResponse
	}
	material, err := batch.Material(0)
	if err != nil {
		return err
	}
	parser, err := protocolv4.NewDecoder(65536, 256)
	if err != nil {
		return err
	}
	doc, err := parser.DecodeShape(material, "", protocolv4.DecodeContext{})
	if err != nil {
		return err
	}
	defer doc.Release()
	x := doc.Root()
	if x.Len() != 5 || x.Index(4).Len() != 2 {
		return controlv4.ErrResponse
	}
	var wires [6][]byte
	for i := range 3 {
		slot := i
		if i > 0 {
			slot = i + 1
		}
		wires[i], _ = x.Index(slot).ByteString()
	}
	var relayWire []byte
	for i := range 2 {
		entry := x.Index(4).Index(i)
		index, indexOK := entry.Index(0).Uint()
		side, sideOK := entry.Index(1).Uint()
		if entry.Len() != 4 || !indexOK || !sideOK || side != uint64(i) || index != r.config.Policy.Deployment.Authority.Batch.Indices[0] {
			return controlv4.ErrResponse
		}
		wires[3+i], _ = entry.Index(2).ByteString()
		wire, _ := entry.Index(3).ByteString()
		if i == 0 {
			relayWire = wire
		} else if !bytesEqual(relayWire, wire) {
			return controlv4.ErrResponse
		}
	}
	wires[5] = relayWire
	index := r.config.Policy.Deployment.Authority.Batch.Indices[0]
	original := r.config.Policy.Routes[index]
	if original == nil {
		return resourcev4.ErrOwner
	}
	base := r.config.Policy.Deployment.Authority.Artifact.Base
	trusts := [6]*protocolv4.NamespaceTrustStore{base.Trust[0], base.Trust[1], base.Trust[2], original.GrantTrust[0], original.GrantTrust[1], original.RelayTrust}
	schemas := [6]string{"Artifact", "IdentityCertificate", "IdentityCertificate", "Grant", "Grant", "IdentityCertificate"}
	var maps [6]*protocolv4.SignedMap
	var validations [6]protocolv4.CredentialValidation
	defer func() {
		for _, m := range maps {
			if m != nil {
				m.Release()
			}
		}
	}()
	for i := range maps {
		maximum, e := protocolv4.SchemaByteLimit(schemas[i])
		if e != nil {
			return e
		}
		codec, e := protocolv4.NewSignedMapCodec(schemas[i], maximum, 16384)
		if e != nil {
			return e
		}
		maps[i], e = codec.VerifyCredential(wires[i], trusts[i])
		if e != nil {
			return e
		}
		credential, e := maps[i].DetachCredential()
		if e != nil {
			return e
		}
		validations[i], e = trusts[i].ResolveCredential(credential)
		if e != nil {
			return e
		}
	}
	session, err := maps[0].SessionParameters()
	if err != nil {
		return err
	}
	route, routeDigest, err := maps[0].CopyCandidateRoute(index, make([]byte, 16384))
	if err != nil {
		return err
	}
	candidateID, _ := maps[0].Field("candidates").Index(int(index)).Named("Candidate", "candidate_id").ByteString()
	attempt, _ := maps[3].Field("attempt_id").ByteString()
	end, _ := maps[3].Field("not_after_ms").Uint()
	deadline, err := timev4.NewDeadline(base.Clock, end)
	if err != nil {
		return err
	}
	prepare, err := r.config.Prepare(r.context, index, route, session, deadline)
	if err != nil {
		return err
	}
	table, err := r.deployment.RelayTable()
	if err != nil {
		return err
	}
	storeRef, _, recordBytes, err := r.config.Policy.Deployment.RelayStore.RelayReference(r.dependencies)
	if err != nil {
		return err
	}
	storeRef.Release()
	config := fs.TunnelRouteConfig{Pair: sessionv4.RelayMessagePairConfig{Clock: base.Clock, PreparationDeadline: deadline, MaxEnvelopeBytes: uint32(original.Limits[0].EnvelopeBytes), RuntimeBytes: 65536},
		Prepare: prepare, Store: r.config.Policy.Deployment.RelayStore, Table: table, Root: r.config.Policy.Deployment.Root, Owner: r.config.Policy.Deployment.Owner, Accounts: r.config.Policy.Deployment.Accounts, RuntimeBytes: 65536}
	config.Pair.MaxPendingNativeMappings = uint32(min(original.Limits[0].PendingMappings, original.Limits[1].PendingMappings))
	config.Pair.MaxResidentNativeMappings = uint32(min(original.Limits[0].ResidentMappings, original.Limits[1].ResidentMappings))
	config.Pair.MaxTotalNativeMappings = min(original.Limits[0].TotalMappings, original.Limits[1].TotalMappings)
	config.Pair.MaxDatagramBytes = uint32(min(original.Limits[0].DatagramBytes, original.Limits[1].DatagramBytes))
	candidate := protocolv4.PoolMember{Index: index, CandidateID: [16]byte(candidateID), RouteDigest: routeDigest}
	for side := range 2 {
		config.Hops[side] = sessionv4.RelayHopConfig{Grant: maps[3+side], EndpointCertificate: maps[1+side], RelayCertificate: maps[5], Signer: r.config.RelaySigner,
			Validation: [4]protocolv4.CredentialValidation{validations[0], validations[1+side], validations[3+side], validations[5]}, Clock: base.Clock,
			Initial: sessionv4.InitialConfig{Role: protocolv4.Direction(side), Profile: base.CryptoProfile, ActivationSourceProfile: "preauthorized_pool", Limits: sessionv4.InitialLimits{MaxFrame: 65536, Nodes: 16384}, Deadline: deadline},
			Relay:   r.config.RelayInstance, Generation: r.config.RelayGeneration, MapNodes: 16384, RuntimeBytes: 65536, InitialRuntimeBytes: 65536, MaxRecordBytes: recordBytes}
		config.Carriers[side] = sessionv4.PreparedCarrierConfig{Candidate: candidate, Attempt: [16]byte(attempt), Session: session, Role: protocolv4.Direction(side), Deadline: deadline, RuntimeBytes: 65536}
	}
	cost, err := fs.TunnelRouteCharge(config)
	if err != nil {
		return err
	}
	ref, owner, err := r.reserve(cost)
	if err != nil {
		return err
	}
	defer ref.Release()
	config.Owner = owner
	tunnel, err := fs.NewTunnelRoute(config, ref, r.dependencies)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.route = tunnel
	closed := r.closed
	if !closed {
		r.serving = true
	}
	r.mu.Unlock()
	if closed {
		tunnel.Close()
		return resourcev4.ErrClosed
	}
	go func() {
		result := r.runtime.ServeRoute(r.context, tunnel)
		r.mu.Lock()
		r.serving = false
		r.finishLocked(result)
		r.mu.Unlock()
	}()
	return nil
}
func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
func closedRelaySignal() chan struct{} { signal := make(chan struct{}); close(signal); return signal }
func (r *Relay) beginCallLocked() {
	if r.active == 0 {
		r.idle = make(chan struct{})
	}
	r.active++
}
func (r *Relay) endCallLocked() {
	r.active--
	if r.active == 0 {
		close(r.idle)
		if r.closed && !r.serving {
			r.finishLocked(resourcev4.ErrClosed)
		}
	}
}
func (r *Relay) finishLocked(err error) {
	if !r.settled {
		r.resultErr = err
		r.settled = true
		close(r.result)
	}
}
func (r *Relay) Wait(ctx context.Context) error {
	if r == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-r.result:
		r.mu.Lock()
		err := r.resultErr
		r.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *Relay) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	r.cancel()
	route := r.route
	if r.active == 0 && !r.serving {
		r.finishLocked(resourcev4.ErrClosed)
	}
	r.mu.Unlock()
	if route != nil {
		route.Close()
	}
	if r.proof != nil {
		r.proof.Close()
	}
	if r.runtime != nil {
		r.runtime.Close()
	}
	if r.deployment != nil {
		r.deployment.Close()
	}
	if r.liveTable != nil {
		r.liveTable.Close()
	}
}
func (r *Relay) WaitCleanup(ctx context.Context) error {
	if r == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	for {
		r.mu.Lock()
		if r.cleaned {
			r.mu.Unlock()
			return nil
		}
		if !r.closed {
			r.mu.Unlock()
			return resourcev4.ErrCapacity
		}
		if prior := r.cleanupDone; prior != nil {
			r.mu.Unlock()
			select {
			case <-prior:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		done := make(chan struct{})
		r.cleanupDone = done
		idle := r.idle
		r.mu.Unlock()
		err := r.cleanup(ctx, idle)
		r.mu.Lock()
		if err == nil {
			r.cleaned = true
		}
		r.cleanupDone = nil
		close(done)
		r.mu.Unlock()
		return err
	}
}
func (r *Relay) cleanup(ctx context.Context, idle <-chan struct{}) error {
	select {
	case <-idle:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-r.result:
	case <-ctx.Done():
		return ctx.Err()
	}
	// The original source and dispatch callbacks have physically returned. A
	// route refused by ServeRoute still belongs to this host and must retire.
	if r.runtime != nil {
		if err := r.runtime.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	r.mu.Lock()
	route := r.route
	r.mu.Unlock()
	if route != nil {
		route.Close()
		if err := route.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if r.proof != nil {
		if err := r.proof.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if r.deployment != nil {
		if err := r.deployment.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if r.liveTable != nil {
		if err := r.liveTable.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	r.shared.Release()
	r.dependencies = resourcev4.Reference{}
	r.reservation.Release()
	return nil
}
