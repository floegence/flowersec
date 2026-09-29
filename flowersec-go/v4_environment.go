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

type ApplicationIdentity = V4ApplicationIdentity
type ConnectionMaterial = V4AuthenticatedMaterial
type ConnectionMaterialSource = V4MaterialLeaseProvider
type TransportEnvironment = V4Environment

// V4MaterialAcquisition is the public owner for one first-connect material
// attempt.  It captures the identity, source profile, generation and output
// reservations before provider I/O.  Acquire has a single-use contract;
// Close fences publication and WaitCleanup observes the same physical tail.
// The wrapper deliberately exposes no lease, key or mutable identity state.
type V4MaterialAcquisition struct {
	inner *sessionv4.MaterialAcquisition
}

// NewV4MaterialAcquisition creates the bounded first-connect recipe.  The
// source must be one of the closed protocol profiles (preauthorized_pool or
// live_authority); provider work starts only when Acquire is called.
func NewV4MaterialAcquisition(ctx context.Context, identity *V4ApplicationIdentity, generation V4MaterialGeneration, source string, requirements V4MaterialRequirements, deadline *V4Deadline, runtimeBytes, materialRuntimeBytes uint64, reservation, material V4ResourceReference) (*V4MaterialAcquisition, error) {
	inner, err := sessionv4.NewMaterialAcquisition(ctx, identity, generation, source, requirements, deadline, runtimeBytes, materialRuntimeBytes, reservation, material)
	if err != nil {
		return nil, err
	}
	return &V4MaterialAcquisition{inner: inner}, nil
}

// NewV4PreauthorizedPoolMaterialAcquisition is the closed preauthorized-pool
// recipe.  It avoids exposing a runtime source selector to callers.
func NewV4PreauthorizedPoolMaterialAcquisition(ctx context.Context, identity *V4ApplicationIdentity, generation V4MaterialGeneration, requirements V4MaterialRequirements, deadline *V4Deadline, runtimeBytes, materialRuntimeBytes uint64, reservation, material V4ResourceReference) (*V4MaterialAcquisition, error) {
	return NewV4MaterialAcquisition(ctx, identity, generation, "preauthorized_pool", requirements, deadline, runtimeBytes, materialRuntimeBytes, reservation, material)
}

// NewV4LiveAuthorityMaterialAcquisition is the closed live-authority recipe.
// It never falls back to a preauthorized pool after provider failure.
func NewV4LiveAuthorityMaterialAcquisition(ctx context.Context, identity *V4ApplicationIdentity, generation V4MaterialGeneration, requirements V4MaterialRequirements, deadline *V4Deadline, runtimeBytes, materialRuntimeBytes uint64, reservation, material V4ResourceReference) (*V4MaterialAcquisition, error) {
	return NewV4MaterialAcquisition(ctx, identity, generation, "live_authority", requirements, deadline, runtimeBytes, materialRuntimeBytes, reservation, material)
}

func (a *V4MaterialAcquisition) Acquire(provider V4MaterialLeaseProvider) (*ConnectionMaterial, error) {
	if a == nil || a.inner == nil || provider == nil || isNilV4Interface(provider) {
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
	return &V4AuthenticatedMaterial{inner: material}, err
}

func (a *V4MaterialAcquisition) Close() {
	if a != nil && a.inner != nil {
		a.inner.Close()
	}
}

func (a *V4MaterialAcquisition) WaitCleanup(ctx context.Context) error {
	if a == nil || a.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return a.inner.WaitCleanup(ctx)
}

// V4LiveAuthoritySource is a closed source variant for live-authority
// issuance.  The provider remains responsible for issuer authentication and
// durable lease construction; this owner adds the source's local closed gate
// and never falls back to a pool or another provider.  A provider may expose
// Close/WaitCleanup itself; those methods are forwarded after the wrapper's
// own callers have drained.
type V4LiveAuthoritySource struct {
	mu       sync.Mutex
	provider V4MaterialLeaseProvider
	active   uint32
	closed   bool
	done     chan struct{}
}

func NewV4LiveAuthoritySource(provider V4MaterialLeaseProvider) (*V4LiveAuthoritySource, error) {
	if provider == nil || isNilV4Interface(provider) {
		return nil, cryptov4.ErrConfiguration
	}
	// A public live source must be able to name its complete immutable
	// namespace graph before Acquire starts. Without this capability the
	// source could discover an independent revocation owner only after the
	// provider call, too late to reserve its real subscriber slot. Component
	// providers remain usable through the lower-level material API, but they
	// cannot be wrapped as a public live source without this preflight.
	if _, complete := provider.(V4MaterialNamespaceSetProvider); !complete {
		if _, complete = provider.(V4MaterialNamespaceProvider); !complete {
			return nil, cryptov4.ErrConfiguration
		}
	}
	s := &V4LiveAuthoritySource{provider: provider, done: make(chan struct{})}
	return s, nil
}

func (s *V4LiveAuthoritySource) AcquireLease(ctx context.Context, request V4MaterialLeaseRequest) (*V4ArtifactLease, error) {
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
		if s.closed && s.active == 0 {
			select {
			case <-s.done:
			default:
				close(s.done)
			}
		}
		s.mu.Unlock()
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

func (s *V4LiveAuthoritySource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	provider := s.provider
	if s.active == 0 {
		close(s.done)
	}
	s.mu.Unlock()
	if c, ok := provider.(interface{ Close() }); ok {
		c.Close()
	}
}

func (s *V4LiveAuthoritySource) WaitCleanup(ctx context.Context) error {
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

func (*V4LiveAuthoritySource) String() string               { return "Flowersec.LiveAuthoritySource" }
func (*V4LiveAuthoritySource) GoString() string             { return "Flowersec.LiveAuthoritySource" }
func (*V4LiveAuthoritySource) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

var _ V4MaterialLeaseProvider = (*V4LiveAuthoritySource)(nil)

func isNilV4Interface(value any) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// NewConnectionMaterial captures original verified material, never an existing
// Session. CreateMaterial must host the result before ConnectMaterial uses it.
func NewConnectionMaterial(lease *V4ArtifactLease, identity *ApplicationIdentity, generation V4MaterialGeneration, runtimeBytes uint64, reservation V4ResourceReference) (*ConnectionMaterial, error) {
	return NewV4AuthenticatedMaterial(lease, identity, generation, runtimeBytes, reservation)
}

type TransportEnvironmentOptions struct {
	Config                    V4EnvironmentConfig
	Reservation, Dependencies V4ResourceReference
}

// NewTransportEnvironment requires the original qualified clock and explicit
// verification-continuity registry. Component-only construction remains
// available through NewV4Environment; it supplies no startup qualification.
func NewTransportEnvironment(options TransportEnvironmentOptions) (*TransportEnvironment, error) {
	if options.Config.Clock == nil || options.Config.Verification == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return NewV4Environment(options.Config, options.Reservation, options.Dependencies)
}

// V4ConnectOptions fixes source profile, necessary guarantees, original
// deadline, application plan and actual same-root scope before provider work.
// Exactly one spend authority is selected. Workspace references must be empty:
// this entry point reserves them together and transfers them to the original
// Environment position. Spend inputs retain their original explicit charges.
type V4ConnectOptions struct {
	Preparation V4SourceConnectConfig
	Pool        *V4PoolSessionInput
	Live        *V4LiveSessionInput
}

func (e *V4Environment) Connect(ctx context.Context, source ConnectionMaterialSource, options V4ConnectOptions) (*V4Session, error) {
	return e.ConnectSource(ctx, source, options)
}

func (e *V4Environment) ConnectSource(ctx context.Context, source ConnectionMaterialSource, options V4ConnectOptions) (*V4Session, error) {
	if source == nil || isNilV4Interface(source) || options.Preparation.Provider != nil {
		return nil, cryptov4.ErrConfiguration
	}
	// Public source admission requires the provider's fixed namespace graph so
	// every credential subscriber position can be reserved before Acquire.
	// This check stays at the public boundary; component-only material callers
	// may continue using the lower-level provider contract without it.
	if _, complete := source.(V4MaterialNamespaceSetProvider); !complete {
		if _, complete = source.(V4MaterialNamespaceProvider); !complete {
			return nil, cryptov4.ErrConfiguration
		}
	}
	c := options.Preparation
	c.Provider = source
	return e.connectPrepared(ctx, nil, nil, c, options.Pool, options.Live)
}

func (e *V4Environment) ConnectMaterial(ctx context.Context, material *ConnectionMaterial, options V4ConnectOptions) (*V4Session, error) {
	if material == nil || material.inner == nil || options.Preparation.Identity != nil || options.Preparation.Provider != nil || options.Preparation.MaterialRuntimeBytes != 0 {
		return nil, cryptov4.ErrConfiguration
	}
	return e.connectPrepared(ctx, material.inner, nil, options.Preparation, options.Pool, options.Live)
}

func (e *V4Environment) connectPrepared(ctx context.Context, material *sessionv4.ConnectionMaterial, source *sessionv4.PreauthorizedPoolSource, c V4SourceConnectConfig, pool *V4PoolSessionInput, live *V4LiveSessionInput) (*V4Session, error) {
	if e == nil || e.inner == nil || ctx == nil || c.Root == nil || (pool == nil) == (live == nil) {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source != nil && (pool == nil || live != nil) {
		return nil, cryptov4.ErrConfiguration
	}
	c, err := reserveV4ConnectionWorkspace(c, material == nil && source == nil)
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
		releaseV4ConnectionWorkspace(c)
	}
	if err != nil {
		return nil, err
	}
	return newV4SessionFromEnvironment(s), nil
}

// Every public connection entry point uses the same all-or-none allocation.
// On error the supplied configuration is unchanged and retains its ownership.
func reserveV4ConnectionWorkspace(c V4SourceConnectConfig, acquire bool) (V4SourceConnectConfig, error) {
	if c.Root == nil {
		return c, cryptov4.ErrConfiguration
	}
	if c.Preparation != (V4ResourceReference{}) || c.Acquisition != (V4ResourceReference{}) || c.Material != (V4ResourceReference{}) || c.Establishment != (V4ResourceReference{}) || c.Subscriptions != (V4ResourceReference{}) || c.CarrierReservation != (V4ResourceReference{}) {
		return c, cryptov4.ErrConfiguration
	}
	var charges [6]V4ResourceVector
	var err error
	charges[0], err = sessionv4.SourcePreparationCharge(c)
	if err != nil {
		return c, err
	}
	charges[1], err = sessionv4.EstablishmentCharge(c.Limits)
	if err != nil {
		return c, err
	}
	charges[2] = V4CredentialSubscriptionsCharge()
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
	accounts := [2]V4ResourceAccount{c.Scope.Tenant, c.Scope.Session}
	var requests [6]resourcev4.Request
	var refs [6]V4ResourceReference
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

func releaseV4ConnectionWorkspace(c V4SourceConnectConfig) {
	for _, ref := range [...]V4ResourceReference{c.Preparation, c.Establishment, c.Subscriptions, c.CarrierReservation, c.Acquisition, c.Material} {
		ref.Release()
	}
}

func v4AssemblyOwner(owner V4ResourceOwnerKey, domain string, index uint64) V4ResourceOwnerKey {
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

// V4SessionPlanFactory is a trusted finite recipe. Each Create reserves new
// original metadata, ordinary task and protected Completion responsibility in
// one root batch. It invokes no application code; AuthorizeApplication runs
// only later under the resulting Session's original application permit.
// Handler plans are per-session inputs and cannot be reused across Create.
type V4SessionPlanFactory struct {
	Executor     *V4ApplicationExecutor
	Root         *V4ResourceRoot
	Dependencies V4ResourceReference
}

func (f V4SessionPlanFactory) Create(c V4SessionPlanConfig, owner V4ResourceOwnerKey, accounts ...V4ResourceAccount) (*V4SessionPlan, error) {
	if f.Executor == nil || f.Root == nil || len(accounts) > resourcev4.MaxAccountsPerCharge {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := sessionv4.SessionPlanCharge(c)
	if err != nil {
		return nil, err
	}
	charges := [3]V4ResourceVector{charge, f.Executor.TaskCharge(), f.Executor.CompletionCharge()}
	var requests [3]resourcev4.Request
	var refs [3]V4ResourceReference
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
