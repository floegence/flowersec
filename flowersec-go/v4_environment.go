package flowersec

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// MaterialAcquisition is the public owner for one first-connect material
// attempt.  It captures the identity, source profile, generation and output
// reservations before provider I/O.  Acquire has a single-use contract;
// Close fences publication and WaitCleanup observes the same physical tail.
// The wrapper deliberately exposes no lease, key or mutable identity state.
type MaterialAcquisition struct {
	inner *sessionv4.MaterialAcquisition
}

// NewMaterialAcquisition creates the bounded first-connect recipe.  The
// source must be one of the closed protocol profiles (preauthorized_pool or
// live_authority); provider work starts only when Acquire is called.
func NewMaterialAcquisition(ctx context.Context, identity *ApplicationIdentity, generation MaterialGeneration, source string, requirements MaterialRequirements, deadline *Deadline, runtimeBytes, materialRuntimeBytes uint64, reservation, material ResourceReference) (*MaterialAcquisition, error) {
	inner, err := sessionv4.NewMaterialAcquisition(ctx, identity, generation, source, requirements, deadline, runtimeBytes, materialRuntimeBytes, reservation, material)
	if err != nil {
		return nil, err
	}
	return &MaterialAcquisition{inner: inner}, nil
}

// NewPreauthorizedPoolMaterialAcquisition is the closed preauthorized-pool
// recipe.  It avoids exposing a runtime source selector to callers.
func NewPreauthorizedPoolMaterialAcquisition(ctx context.Context, identity *ApplicationIdentity, generation MaterialGeneration, requirements MaterialRequirements, deadline *Deadline, runtimeBytes, materialRuntimeBytes uint64, reservation, material ResourceReference) (*MaterialAcquisition, error) {
	return NewMaterialAcquisition(ctx, identity, generation, "preauthorized_pool", requirements, deadline, runtimeBytes, materialRuntimeBytes, reservation, material)
}

// NewLiveAuthorityMaterialAcquisition is the closed live-authority recipe.
// It never falls back to a preauthorized pool after provider failure.
func NewLiveAuthorityMaterialAcquisition(ctx context.Context, identity *ApplicationIdentity, generation MaterialGeneration, requirements MaterialRequirements, deadline *Deadline, runtimeBytes, materialRuntimeBytes uint64, reservation, material ResourceReference) (*MaterialAcquisition, error) {
	return NewMaterialAcquisition(ctx, identity, generation, "live_authority", requirements, deadline, runtimeBytes, materialRuntimeBytes, reservation, material)
}

func (a *MaterialAcquisition) Acquire(provider ConnectionMaterialSource) (*ConnectionMaterial, error) {
	if a == nil || a.inner == nil || provider == nil || isNilInterface(provider) {
		return nil, cryptov4.ErrConfiguration
	}
	material, err := a.inner.Acquire(provider)
	if err != nil && material != nil {
		material.Close()
		material = nil
	}
	if material == nil {
		return nil, err
	}
	return &ConnectionMaterial{inner: material}, err
}

// MaterialAcquisitionBatch owns a finite set of same-source one-shot
// acquisitions. It publishes the materials only when every member succeeds;
// an earlier lease is retired if a later provider call fails.
type MaterialAcquisitionBatch struct {
	inner *sessionv4.MaterialAcquisitionBatch
}

// NewMaterialAcquisitionBatch transfers ownership of one to sixteen prepared
// acquisitions. Members must have the same identity, source, generation,
// requirements and deadline. Prepare every member before provider I/O.
func NewMaterialAcquisitionBatch(members ...*MaterialAcquisition) (*MaterialAcquisitionBatch, error) {
	if len(members) == 0 || len(members) > 16 {
		return nil, cryptov4.ErrConfiguration
	}
	inner := make([]*sessionv4.MaterialAcquisition, len(members))
	for index, member := range members {
		if member == nil || member.inner == nil {
			return nil, cryptov4.ErrConfiguration
		}
		inner[index] = member.inner
	}
	batch, err := sessionv4.NewMaterialAcquisitionBatch(inner...)
	if err != nil {
		return nil, err
	}
	return &MaterialAcquisitionBatch{inner: batch}, nil
}

func (b *MaterialAcquisitionBatch) Acquire(provider ConnectionMaterialSource) ([]*ConnectionMaterial, error) {
	if b == nil || b.inner == nil || provider == nil || isNilInterface(provider) {
		return nil, cryptov4.ErrConfiguration
	}
	materials, err := b.inner.Acquire(provider)
	if err != nil {
		for _, material := range materials {
			material.Close()
		}
		return nil, err
	}
	result := make([]*ConnectionMaterial, len(materials))
	for index, material := range materials {
		result[index] = &ConnectionMaterial{inner: material}
	}
	return result, nil
}

func (b *MaterialAcquisitionBatch) Close() {
	if b != nil && b.inner != nil {
		b.inner.Close()
	}
}
func (b *MaterialAcquisitionBatch) WaitCleanup(ctx context.Context) error {
	if b == nil || b.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return b.inner.WaitCleanup(ctx)
}

func (a *MaterialAcquisition) Close() {
	if a != nil && a.inner != nil {
		a.inner.Close()
	}
}

func (a *MaterialAcquisition) WaitCleanup(ctx context.Context) error {
	if a == nil || a.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return a.inner.WaitCleanup(ctx)
}

// LiveAuthoritySource is a closed source variant for live-authority
// issuance.  The provider remains responsible for issuer authentication and
// durable lease construction; this owner adds the source's local closed gate
// and never falls back to a pool or another provider.  A provider may expose
// Close/WaitCleanup itself; those methods are forwarded after the wrapper's
// own callers have drained.
type LiveAuthoritySource struct {
	mu             sync.Mutex
	provider       ConnectionMaterialSource
	active         uint32
	closed         bool
	providerClosed bool
	done           chan struct{}
}

func NewLiveAuthoritySource(provider ConnectionMaterialSource) (*LiveAuthoritySource, error) {
	if provider == nil || isNilInterface(provider) {
		return nil, cryptov4.ErrConfiguration
	}
	// A public live source must be able to name its complete immutable
	// namespace graph before Acquire starts. Without this capability the
	// source could discover an independent revocation owner only after the
	// provider call, too late to reserve its real subscriber slot. Component
	// providers remain usable through the lower-level material API, but they
	// cannot be wrapped as a public live source without this preflight.
	if _, complete := provider.(MaterialNamespaceSetProvider); !complete {
		if _, complete = provider.(MaterialNamespaceProvider); !complete {
			return nil, cryptov4.ErrConfiguration
		}
	}
	s := &LiveAuthoritySource{provider: provider, done: make(chan struct{})}
	return s, nil
}

func (s *LiveAuthoritySource) AcquireLease(ctx context.Context, request MaterialLeaseRequest) (*ArtifactLease, error) {
	if s == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	if s.closed || s.provider == nil {
		s.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if s.active != 0 {
		s.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	s.active++
	provider := s.provider
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
		s.closeProviderIfReady()
	}()
	lease, err := provider.AcquireLease(ctx, request)
	if err != nil && lease != nil {
		lease.Close()
		lease = nil
	}
	if err == nil && lease == nil {
		err = sessionv4.ErrSourceContractInvalid
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed && err == nil {
		if lease != nil {
			lease.Close()
		}
		return nil, cryptov4.ErrClosed
	}
	return lease, err
}

func (s *LiveAuthoritySource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.closeProviderIfReady()
}

// closeProviderIfReady transfers the wrapper's close fence to the underlying
// provider only after the last wrapper operation has returned. The provider
// close is performed outside the mutex so a provider can safely inspect this
// wrapper or complete its own callbacks during Close.
func (s *LiveAuthoritySource) closeProviderIfReady() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.closed || s.active != 0 || s.providerClosed {
		s.mu.Unlock()
		return
	}
	s.providerClosed = true
	provider := s.provider
	s.mu.Unlock()
	if c, ok := provider.(interface{ Close() }); ok {
		c.Close()
	}
	s.mu.Lock()
	if s.closed && s.active == 0 {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}
	s.mu.Unlock()
}

func (s *LiveAuthoritySource) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	provider := s.provider
	s.mu.Unlock()
	if c, ok := provider.(interface{ WaitCleanup(context.Context) error }); ok {
		return c.WaitCleanup(ctx)
	}
	return nil
}

func (*LiveAuthoritySource) String() string               { return "Flowersec.LiveAuthoritySource" }
func (*LiveAuthoritySource) GoString() string             { return "Flowersec.LiveAuthoritySource" }
func (*LiveAuthoritySource) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

var _ ConnectionMaterialSource = (*LiveAuthoritySource)(nil)

func isNilInterface(value any) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

type TransportEnvironmentOptions struct {
	Config                    EnvironmentConfig
	Reservation, Dependencies ResourceReference
}

// NewTransportEnvironment requires the original qualified clock and explicit
// verification-continuity registry before admitting current transport work.
func NewTransportEnvironment(options TransportEnvironmentOptions) (*TransportEnvironment, error) {
	if options.Config.Clock == nil || options.Config.Verification == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return newTransportEnvironment(options.Config, options.Reservation, options.Dependencies)
}

// ConnectOptions fixes source profile, necessary guarantees, original
// deadline, application plan and actual same-root scope before provider work.
// Exactly one spend authority is selected. Workspace references must be empty:
// this entry point reserves them together and transfers them to the original
// TransportEnvironment position. Spend inputs retain their original explicit charges.
type ConnectOptions struct {
	Preparation SourceConnectConfig
	Pool        *PoolSessionInput
	Live        *LiveSessionInput
}

func (e *TransportEnvironment) Connect(ctx context.Context, source ConnectionMaterialSource, options ConnectOptions) (*Session, error) {
	return e.ConnectSource(ctx, source, options)
}

func (e *TransportEnvironment) ConnectSource(ctx context.Context, source ConnectionMaterialSource, options ConnectOptions) (*Session, error) {
	if source == nil || isNilInterface(source) || options.Preparation.Provider != nil {
		return nil, cryptov4.ErrConfiguration
	}
	// Public source admission requires the provider's fixed namespace graph so
	// every credential subscriber position can be reserved before Acquire.
	// This check stays at the public boundary; component-only material callers
	// may continue using the lower-level provider contract without it.
	if _, complete := source.(MaterialNamespaceSetProvider); !complete {
		if _, complete = source.(MaterialNamespaceProvider); !complete {
			return nil, cryptov4.ErrConfiguration
		}
	}
	c := options.Preparation
	c.Provider = source
	return e.connectPrepared(ctx, nil, nil, c, options.Pool, options.Live)
}

func (e *TransportEnvironment) ConnectMaterial(ctx context.Context, material *ConnectionMaterial, options ConnectOptions) (*Session, error) {
	if material == nil || material.inner == nil || options.Preparation.Identity != nil || options.Preparation.Provider != nil || options.Preparation.MaterialRuntimeBytes != 0 {
		return nil, cryptov4.ErrConfiguration
	}
	return e.connectPrepared(ctx, material.inner, nil, options.Preparation, options.Pool, options.Live)
}

func (e *TransportEnvironment) connectPrepared(ctx context.Context, material *sessionv4.ConnectionMaterial, source *sessionv4.PreauthorizedPoolSource, c SourceConnectConfig, pool *PoolSessionInput, live *LiveSessionInput) (*Session, error) {
	if e == nil || e.inner == nil || ctx == nil || c.Root == nil || (pool == nil) == (live == nil) {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source != nil && (pool == nil || live != nil) {
		return nil, cryptov4.ErrConfiguration
	}
	c, err := reserveConnectionWorkspace(c, material == nil && source == nil)
	if err != nil {
		return nil, err
	}
	var s *sessionv4.EnvironmentSession
	var admitted bool
	if source != nil {
		s, admitted, err = e.inner.ConnectPoolSource(ctx, source, c, *pool)
	} else {
		s, admitted, err = e.inner.ConnectPrepared(ctx, c, material, pool, live)
	}
	if !admitted {
		releaseConnectionWorkspace(c)
	}
	if err != nil {
		return nil, err
	}
	return newSessionFromEnvironment(s), nil
}

// Every public connection entry point uses the same all-or-none allocation.
// On error the supplied configuration is unchanged and retains its ownership.
func reserveConnectionWorkspace(c SourceConnectConfig, acquire bool) (SourceConnectConfig, error) {
	if c.Root == nil {
		return c, cryptov4.ErrConfiguration
	}
	if c.Preparation != (ResourceReference{}) || c.Acquisition != (ResourceReference{}) || c.Material != (ResourceReference{}) || c.Establishment != (ResourceReference{}) || c.Subscriptions != (ResourceReference{}) || c.CarrierReservation != (ResourceReference{}) {
		return c, cryptov4.ErrConfiguration
	}
	var charges [6]ResourceVector
	var err error
	charges[0], err = sessionv4.SourcePreparationCharge(c)
	if err != nil {
		return c, err
	}
	charges[1], err = sessionv4.EstablishmentCharge(c.Limits)
	if err != nil {
		return c, err
	}
	charges[2] = CredentialSubscriptionsCharge()
	charges[3], err = sessionv4.SourceCarrierCharge(c.CarrierRuntimeBytes)
	if err != nil {
		return c, err
	}
	count := 4
	if acquire {
		charges[4], err = sessionv4.MaterialAcquisitionCharge(c.RuntimeBytes)
		if err != nil {
			return c, err
		}
		charges[5], err = sessionv4.ConnectionMaterialCharge(c.MaterialRuntimeBytes)
		if err != nil {
			return c, err
		}
		count = 6
	}
	// Both exact account handles are required before creating any workspace.
	accounts := [2]ResourceAccount{c.Scope.Tenant, c.Scope.Session}
	var requests [6]resourcev4.Request
	var refs [6]ResourceReference
	for i := range requests[:count] {
		requests[i] = resourcev4.Request{Owner: v4AssemblyOwner(c.Owner, "connection", uint64(i)), Charge: charges[i], Accounts: accounts[:]}
	}
	if err := c.Root.ReserveBatch(requests[:count], refs[:count]); err != nil {
		return c, err
	}
	c.Preparation, c.Establishment, c.Subscriptions, c.CarrierReservation = refs[0], refs[1], refs[2], refs[3]
	if acquire {
		c.Acquisition, c.Material = refs[4], refs[5]
	}
	return c, nil
}

func releaseConnectionWorkspace(c SourceConnectConfig) {
	for _, ref := range [...]ResourceReference{c.Preparation, c.Establishment, c.Subscriptions, c.CarrierReservation, c.Acquisition, c.Material} {
		ref.Release()
	}
}

func v4AssemblyOwner(owner ResourceOwnerKey, domain string, index uint64) ResourceOwnerKey {
	var input [80]byte
	copy(input[:24], "flowersec/v4/"+domain)
	copy(input[24:40], owner.Instance[:])
	copy(input[40:56], owner.Backing[:])
	binary.BigEndian.PutUint64(input[56:64], index)
	digest := sha256.Sum256(input[:])
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	return owner
}

// SessionPlanFactory is a trusted finite recipe. Each Create reserves new
// original metadata, ordinary task and protected Completion responsibility in
// one root batch. It invokes no application code; AuthorizeApplication runs
// only later under the resulting Session's original application permit.
// Handler plans are per-session inputs and cannot be reused across Create.
type SessionPlanFactory struct {
	Executor     *ApplicationExecutor
	Root         *ResourceRoot
	Dependencies ResourceReference
}

func (f SessionPlanFactory) Create(c SessionPlanConfig, owner ResourceOwnerKey, accounts ...ResourceAccount) (*SessionPlan, error) {
	if f.Executor == nil || f.Root == nil || len(accounts) > resourcev4.MaxAccountsPerCharge {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := sessionv4.SessionPlanCharge(c)
	if err != nil {
		return nil, err
	}
	charges := [3]ResourceVector{charge, f.Executor.TaskCharge(), f.Executor.CompletionCharge()}
	var requests [3]resourcev4.Request
	var refs [3]ResourceReference
	for i := range requests {
		requests[i] = resourcev4.Request{Owner: v4AssemblyOwner(owner, "application", uint64(i)), Charge: charges[i], Accounts: accounts}
	}
	if err := f.Root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	dependencies, err := f.Dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	defer dependencies.Release()
	return sessionv4.NewSessionPlan(c, f.Executor, refs[0], refs[1], refs[2], dependencies)
}
