package runtimehost

import (
	"context"
	"unsafe"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// LiveRelayConfig fixes the original issuer's independent namespace, source
// store and relay table before control is exposed. An original TxB must attach
// LivePublication before any route or endpoint material can be dispatched.
type LiveRelayConfig struct {
	Root                                                             *resourcev4.Root
	Owner                                                            resourcev4.OwnerKey
	Accounts                                                         []resourcev4.Account
	Clock                                                            *timev4.Clock
	SourceStore, RelayStore                                          *ledgerv4.SQLiteStore
	SourceIdentity, RelayIdentity                                    ledgerv4.SQLiteIdentity
	Artifact, ClientCertificate, ServerCertificate, RelayCertificate []byte
	Trust                                                            [6]*protocolv4.NamespaceTrustStore
	Mapping                                                          protocolv4.RelayIssuerMapping
	Parent                                                           protocolv4.CredentialValidation
	Candidate                                                        uint64
	ParentDigest                                                     [32]byte
	Limits                                                           [2]protocolv4.RelayGrantLimits
	RelaySigner                                                      cryptov4.IdentitySigner
	RelayInstance                                                    [16]byte
	RelayGeneration                                                  uint64
	Prepare                                                          func(context.Context, uint64, []byte, protocolv4.ArtifactSessionParameters, *timev4.Deadline) ([2]sessionv4.TunnelCarrierPreparation, error)
	RuntimeBytes                                                     uint64
}

func LiveRelayCharge(c LiveRelayConfig) (resourcev4.Vector, error) {
	if c.SourceStore == nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	return registeredRelayCharge(c)
}

func registeredRelayCharge(c LiveRelayConfig) (resourcev4.Vector, error) {
	if c.Root == nil || len(c.Accounts) == 0 || c.Clock == nil || c.RelayStore == nil || c.Prepare == nil || c.RelaySigner == nil || c.RelayInstance == ([16]byte{}) || c.RelayGeneration == 0 || c.Candidate >= 16 || c.ParentDigest == ([32]byte{}) || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := RelayAuthorityParallelLookups(c.Limits, relayActivePairs); err != nil {
		return resourcev4.Vector{}, err
	}
	for _, trust := range c.Trust {
		if trust == nil {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	var n uint64 = uint64(unsafe.Sizeof(Relay{})) + 65536 + c.RuntimeBytes
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
	return resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1}, nil
}
func NewLiveRelay(ctx context.Context, c LiveRelayConfig, reservation, dependencies resourcev4.Reference) (r *Relay, err error) {
	return newRegisteredRelay(ctx, c, reservation, dependencies, "live_authority")
}

func newRegisteredRelay(ctx context.Context, c LiveRelayConfig, reservation, dependencies resourcev4.Reference, source string) (r *Relay, err error) {
	if ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	cost, err := LiveRelayCharge(c)
	if source == "preauthorized_pool" {
		cost, err = RegisteredPoolRelayCharge(c)
	}
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
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
	r = &Relay{live: &c, registeredSource: source, reservation: owned, context: lifetime, cancel: cancel, result: make(chan struct{}), idle: closedRelaySignal()}
	// The same allocation owner is used by the existing route host; pool policy
	// remains absent and cannot accidentally select a PoolService fallback.
	r.config.Policy.Deployment.Root = c.Root
	r.config.Policy.Deployment.Owner = c.Owner
	r.config.Policy.Deployment.Accounts = c.Accounts
	success := false
	original := r
	defer func() {
		if !success {
			original.Close()
			_ = original.WaitCleanup(context.Background())
		}
	}()
	r.dependencies = dependencies
	r.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	parallelLookups, err := RelayAuthorityParallelLookups(c.Limits, relayActivePairs)
	if err != nil {
		return nil, err
	}
	table := ledgerv4.SQLiteRelayAuthorityConfig{Identity: c.RelayIdentity, MaxParents: 1, ParallelLookups: parallelLookups, RuntimeBytes: 65536}
	cost, err = ledgerv4.SQLiteRelayAuthorityCharge(table)
	if err != nil {
		return nil, err
	}
	ref, _, err := r.reserve(cost)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	r.liveTable, err = ledgerv4.NewSQLiteRelayAuthorityTableContext(ctx, c.RelayStore, table, ref, dependencies)
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

// LivePublication is installed on the exact plan before the unique TxA INSERT.
// Its reservation belongs to the caller's original access and must be released
// by that access after service completion; no restore key is accepted here.
func (r *Relay) LivePublication() (ledgerv4.SQLiteLiveRelayPublicationConfig, error) {
	if r == nil || r.live == nil || r.registeredSource != "live_authority" {
		return ledgerv4.SQLiteLiveRelayPublicationConfig{}, resourcev4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.dispatched {
		return ledgerv4.SQLiteLiveRelayPublicationConfig{}, resourcev4.ErrClosed
	}
	cost, err := ledgerv4.SQLiteLiveRelayPublicationCharge()
	if err != nil {
		return ledgerv4.SQLiteLiveRelayPublicationConfig{}, err
	}
	ref, _, err := r.reserve(cost)
	if err != nil {
		return ledgerv4.SQLiteLiveRelayPublicationConfig{}, err
	}
	c := r.live
	return ledgerv4.SQLiteLiveRelayPublicationConfig{Table: r.liveTable, SourceIdentity: c.SourceIdentity, Mapping: c.Mapping, Parent: c.Parent, Reservation: ref, Dependencies: r.dependencies}, nil
}

// PrepareOriginalLiveCarrier admits actual native factories at registration and
// original A preparation. It does not issue a Grant or perform endpoint allow.
func (r *Relay) PrepareOriginalLiveCarrier(ctx context.Context, side protocolv4.Direction) (err error) {
	if r == nil || r.live == nil || ctx == nil || side > protocolv4.ServerToClient {
		return resourcev4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.livePreparing || r.livePrepared[side] {
		r.mu.Unlock()
		return resourcev4.ErrCapacity
	}
	r.livePreparing = true
	r.beginCallLocked()
	initialized := r.livePrepare[0] != nil
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.livePreparing = false
		if err == nil {
			r.livePrepared[side] = true
		}
		r.endCallLocked()
		if err != nil {
			r.finishLocked(err)
		}
		r.mu.Unlock()
	}()
	if err = ctx.Err(); err != nil {
		return err
	}
	if initialized {
		return nil
	}
	c := r.live
	codec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 16384)
	if err != nil {
		return err
	}
	parent, err := codec.VerifyCredential(c.Artifact, c.Trust[0])
	if err != nil {
		return err
	}
	defer parent.Release()
	session, err := parent.SessionParameters()
	if err != nil {
		return err
	}
	route, _, err := parent.CopyCandidateRoute(c.Candidate, make([]byte, 16384))
	if err != nil {
		return err
	}
	credential, err := parent.DetachCredential()
	if err != nil {
		return err
	}
	deadline, err := timev4.NewDeadline(c.Clock, credential.Scope().ExpiresMS)
	if err != nil {
		return err
	}
	prepare, err := c.Prepare(r.context, c.Candidate, route, session, deadline)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.livePrepare = prepare
	r.mu.Unlock()
	return nil
}

// DispatchOriginalLive accepts only the original service TxB callback. It never
// looks up old client material, captures receipts or restores a parent row.
func (r *Relay) DispatchOriginalLive(ctx context.Context, q sessionv4.LiveAuthorizationRequest, material [3][]byte, guard func() error) (err error) {
	if r == nil || r.registeredSource != "live_authority" {
		return resourcev4.ErrConfiguration
	}
	return r.dispatchOriginalRegistered(ctx, q, material, guard)
}

func (r *Relay) dispatchOriginalRegistered(ctx context.Context, q sessionv4.LiveAuthorizationRequest, material [3][]byte, guard func() error) (err error) {
	if r == nil || r.live == nil || ctx == nil || guard == nil {
		return resourcev4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.dispatched || !r.livePrepared[0] || !r.livePrepared[1] {
		r.mu.Unlock()
		return resourcev4.ErrCapacity
	}
	r.dispatched = true
	r.beginCallLocked()
	prepare := r.livePrepare
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.endCallLocked()
		if err != nil {
			r.finishLocked(err)
		}
		r.mu.Unlock()
	}()
	if err = guard(); err != nil {
		return err
	}
	c := r.live
	if q.Artifact != c.ParentDigest || q.Winner.Index != c.Candidate {
		return ledgerv4.ErrDenied
	}
	wires := [6][]byte{c.Artifact, c.ClientCertificate, c.ServerCertificate, material[1], material[2], c.RelayCertificate}
	var maps [6]*protocolv4.SignedMap
	var validations [6]protocolv4.CredentialValidation
	defer func() {
		for _, m := range maps {
			if m != nil {
				m.Release()
			}
		}
	}()
	for side, schema := range []string{"Artifact", "IdentityCertificate", "IdentityCertificate", "Grant", "Grant", "IdentityCertificate"} {
		maximum, e := protocolv4.SchemaByteLimit(schema)
		if e != nil {
			return e
		}
		codec, e := protocolv4.NewSignedMapCodec(schema, maximum, 16384)
		if e != nil {
			return e
		}
		maps[side], e = codec.VerifyCredential(wires[side], c.Trust[side])
		if e != nil {
			return e
		}
		credential, e := maps[side].DetachCredential()
		if e != nil {
			return e
		}
		validations[side], e = c.Trust[side].ResolveCredential(credential)
		if e != nil {
			return e
		}
	}
	session, err := maps[0].SessionParameters()
	if err != nil {
		return err
	}
	_, routeDigest, err := maps[0].CopyCandidateRoute(c.Candidate, make([]byte, 16384))
	if err != nil {
		return err
	}
	candidateID, ok := maps[0].Field("candidates").Index(int(c.Candidate)).Named("Candidate", "candidate_id").ByteString()
	if !ok || len(candidateID) != 16 || routeDigest != q.Winner.RouteDigest || [16]byte(candidateID) != q.Winner.CandidateID {
		return ledgerv4.ErrDenied
	}
	end := q.ActivationNotAfterMS
	for side := range 2 {
		attempt, ok := maps[3+side].Field("attempt_id").ByteString()
		notAfter, valid := maps[3+side].Field("not_after_ms").Uint()
		if !ok || len(attempt) != 16 || [16]byte(attempt) != q.Attempt || !valid {
			return ledgerv4.ErrDenied
		}
		end = min(end, notAfter)
	}
	deadline, err := timev4.NewDeadline(c.Clock, end)
	if err != nil {
		return err
	}
	storeRef, _, recordBytes, err := c.RelayStore.RelayReference(r.dependencies)
	if err != nil {
		return err
	}
	storeRef.Release()
	config := fs.TunnelRouteConfig{Pair: sessionv4.RelayMessagePairConfig{Clock: c.Clock, PreparationDeadline: deadline, MaxEnvelopeBytes: uint32(c.Limits[0].EnvelopeBytes), RuntimeBytes: 65536}, Prepare: prepare, Store: c.RelayStore, Table: r.liveTable, Root: c.Root, Owner: c.Owner, Accounts: c.Accounts, RuntimeBytes: 65536}
	config.Pair.MaxPendingNativeMappings = uint32(min(c.Limits[0].PendingMappings, c.Limits[1].PendingMappings))
	config.Pair.MaxResidentNativeMappings = uint32(min(c.Limits[0].ResidentMappings, c.Limits[1].ResidentMappings))
	config.Pair.MaxTotalNativeMappings = min(c.Limits[0].TotalMappings, c.Limits[1].TotalMappings)
	config.Pair.MaxDatagramBytes = uint32(min(c.Limits[0].DatagramBytes, c.Limits[1].DatagramBytes))
	for side := range 2 {
		config.Hops[side] = sessionv4.RelayHopConfig{Grant: maps[3+side], EndpointCertificate: maps[1+side], RelayCertificate: maps[5], Signer: c.RelaySigner, Validation: [4]protocolv4.CredentialValidation{validations[0], validations[1+side], validations[3+side], validations[5]}, Clock: c.Clock, Initial: sessionv4.InitialConfig{Role: protocolv4.Direction(side), Profile: session.Profile, ActivationSourceProfile: r.registeredSource, Limits: sessionv4.InitialLimits{MaxFrame: 65536, Nodes: 16384}, Deadline: deadline}, Relay: c.RelayInstance, Generation: c.RelayGeneration, MapNodes: 16384, RuntimeBytes: 65536, InitialRuntimeBytes: 65536, MaxRecordBytes: recordBytes}
		config.Carriers[side] = sessionv4.PreparedCarrierConfig{Candidate: q.Winner, Attempt: q.Attempt, Session: session, Role: protocolv4.Direction(side), Deadline: deadline, RuntimeBytes: 65536}
	}
	if err = guard(); err != nil {
		return err
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
	route, err := fs.NewTunnelRoute(config, ref, r.dependencies)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.route = route
	closed := r.closed
	if !closed {
		r.serving = true
	}
	r.mu.Unlock()
	if closed {
		route.Close()
		return resourcev4.ErrClosed
	}
	go func() {
		result := r.runtime.ServeRoute(r.context, route)
		r.mu.Lock()
		r.serving = false
		r.finishLocked(result)
		r.mu.Unlock()
	}()
	return nil
}
