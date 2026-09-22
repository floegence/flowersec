package sessionv4

import (
	"context"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// EnvironmentConfig bounds the original establishment, runtime caller and
// cancellation positions together. A position remains occupied until physical
// retirement, including failed establishment and late provider/application work.
// This is the lifecycle component of TransportEnvironment. Source acquisition
// and preparation use the same position as the resulting Session; immutable
// provider/trust configuration is assembled by its outer facade.
type EnvironmentConfig struct {
	Services                  bool
	ContractQueryAcquisitions uint8
	Positions                 uint32
	ResultOwners              uint32
	RuntimeBytes              uint64
	// Materials bounds static construction and every retained material owner,
	// including material attached to a Session until its actual retirement.
	Materials        uint32
	MaterialCreateMS uint64
	Clock            *timev4.Clock
	// ServiceRegistry is the environment-wide logical execution authority
	// registry. It is caller-owned and remains live across Session replacement;
	// Environment only coordinates lookup/bind admission and never closes it.
	ServiceRegistry *rpcv4.ServiceRegistry
}

// Environment owns its admitted Session lifecycles, borrowing the configured
// shared dependency owner. It never closes a caller-owned root, store, executor,
// key provider or trust namespace. Close seals local admission without I/O.
type Environment struct {
	services            bool
	mu                  sync.Mutex
	positions           []*EnvironmentSession
	groups              []*ServeGroup
	groupsActive        uint32
	reservation, shared resourcev4.Reference
	active              uint32
	closed, cleaned     bool
	retired             bool
	done                chan struct{}
	materials           []environmentMaterial
	materialActive      uint32
	materialClock       *timev4.Clock
	materialCreateMS    uint64
	materialWake        chan struct{}
	materialExited      bool
	queries             []*ContractQueryAcquisition
	queryActive         uint32
	serviceRegistry     *rpcv4.ServiceRegistry
	registryBorrow      resourcev4.Reference
	results             []*UnaryCall
	resultActive        uint32
	resultCursor        int
}

func environmentResultCapacity(c EnvironmentConfig) (uint32, error) {
	if !c.Services {
		if c.ResultOwners != 0 {
			return 0, cryptov4.ErrConfiguration
		}
		return 0, nil
	}
	if c.ResultOwners > resourcev4.MaxResultOwners {
		return 0, cryptov4.ErrConfiguration
	}
	if c.ResultOwners == 0 {
		return resourcev4.MaxResultOwners, nil
	}
	return c.ResultOwners, nil
}

func EnvironmentCharge(c EnvironmentConfig) (resourcev4.Vector, error) {
	results, err := environmentResultCapacity(c)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if c.Services && c.Clock == nil || c.ServiceRegistry != nil && !c.Services {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if c.Positions == 0 || c.Positions > 65536 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if c.Materials > 65536 || c.Materials != 0 && (c.Clock == nil || c.MaterialCreateMS == 0 || c.MaterialCreateMS > 90000) || c.Materials == 0 && c.MaterialCreateMS != 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if c.ContractQueryAcquisitions != 0 && (c.ContractQueryAcquisitions != 2 && c.ContractQueryAcquisitions != 4 || c.Clock == nil) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	per := uint64(unsafe.Sizeof(EnvironmentSession{})) + uint64(unsafe.Sizeof(environmentEstablishment{})) + uint64(unsafe.Sizeof((*EnvironmentSession)(nil))) + uint64(unsafe.Sizeof((*ServeGroup)(nil)))
	size := uint64(unsafe.Sizeof(Environment{})) + uint64(c.Positions)*per
	size += uint64(results) * uint64(unsafe.Sizeof((*UnaryCall)(nil)))
	size += uint64(c.Materials) * (uint64(unsafe.Sizeof(environmentMaterial{})) + uint64(unsafe.Sizeof(timev4.Window{})) + uint64(unsafe.Sizeof(timev4.Deadline{})))
	size += uint64(c.ContractQueryAcquisitions) * (uint64(unsafe.Sizeof(ContractQueryAcquisition{})) + 8*128 + uint64(unsafe.Sizeof((*ContractQueryAcquisition)(nil))) + uint64(unsafe.Sizeof(timev4.Deadline{})))
	if c.RuntimeBytes > math.MaxUint64-size || size+c.RuntimeBytes > uint64(math.MaxInt) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: size + c.RuntimeBytes, resourcev4.Items: 1 + 9*uint64(c.Positions) + uint64(c.Materials), resourcev4.Tasks: 2*uint64(c.Positions) + uint64(c.Materials), resourcev4.WorkSlots: 2*uint64(c.Positions) + uint64(c.Materials), resourcev4.Timers: uint64(c.Positions)}
	if c.Services || c.Materials != 0 || c.ContractQueryAcquisitions != 0 {
		charge[resourcev4.Tasks]++
		charge[resourcev4.Timers]++
	}
	for range c.ContractQueryAcquisitions {
		var err error
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes, resourcev4.Items: 4})
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	return charge, nil
}

func NewEnvironment(c EnvironmentConfig, reservation, dependencies resourcev4.Reference) (*Environment, error) {
	charge, err := EnvironmentCharge(c)
	if err != nil {
		return nil, err
	}
	if reservation == dependencies {
		return nil, cryptov4.ErrConfiguration
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	var registryBorrow resourcev4.Reference
	if c.ServiceRegistry != nil {
		registryBorrow, err = c.ServiceRegistry.Borrow(owned)
		if err != nil {
			owned.Release()
			shared.Release()
			return nil, err
		}
	}
	e := &Environment{services: c.Services, positions: make([]*EnvironmentSession, c.Positions), groups: make([]*ServeGroup, c.Positions), reservation: owned, shared: shared, done: make(chan struct{}), materialClock: c.Clock, materialCreateMS: c.MaterialCreateMS, queries: make([]*ContractQueryAcquisition, c.ContractQueryAcquisitions), materialExited: !c.Services && c.Materials == 0 && c.ContractQueryAcquisitions == 0, serviceRegistry: c.ServiceRegistry, registryBorrow: registryBorrow}
	resultCapacity, _ := environmentResultCapacity(c)
	e.results = make([]*UnaryCall, resultCapacity)
	if c.Materials != 0 {
		e.materials = make([]environmentMaterial, c.Materials)
	}
	if c.Services || c.Materials != 0 || c.ContractQueryAcquisitions != 0 {
		e.materialWake = make(chan struct{}, 1)
		go e.watchMaterials()
	}
	return e, nil
}

// BindExecutionService serializes logical service ownership at the
// Environment boundary. A second live binding for the same tenant/audience/
// namespace is rejected before any Session can route execution to it.
func (e *Environment) BindExecutionService(binding rpcv4.ServiceBinding) error {
	if e == nil {
		return rpcv4.ErrServiceNotBound
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return cryptov4.ErrClosed
	}
	if e.serviceRegistry == nil {
		return rpcv4.ErrServiceNotBound
	}
	err := e.serviceRegistry.Bind(binding)
	if err == nil {
		e.signalMaterials()
	}
	return err
}

func (e *Environment) LookupExecutionService(authority rpcv4.ServiceAuthority) (rpcv4.ServiceBinding, error) {
	if e == nil {
		return rpcv4.ServiceBinding{}, rpcv4.ErrServiceNotBound
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return rpcv4.ServiceBinding{}, cryptov4.ErrClosed
	}
	if e.serviceRegistry == nil {
		return rpcv4.ServiceBinding{}, rpcv4.ErrServiceNotBound
	}
	return e.serviceRegistry.Lookup(authority)
}

func (e *Environment) UnbindExecutionService(authority rpcv4.ServiceAuthority, history *rpcv4.VolatileExecutions) error {
	if e == nil {
		return rpcv4.ErrServiceNotBound
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return cryptov4.ErrClosed
	}
	if e.serviceRegistry == nil {
		return rpcv4.ErrServiceNotBound
	}
	return e.serviceRegistry.Unbind(authority, history)
}

// PoolSessionInput transfers the complete original prepared consumer graph on
// successful local admission. A rejected admission leaves all inputs untouched.
type PoolSessionInput struct {
	Establishment *SessionEstablishment
	Admission     *SessionAdmissionReservation
	Store         *ledgerv4.SQLiteStore
	Authority     ledgerv4.SQLitePoolAuthority
	Consume       resourcev4.Reference
}

// LiveSessionInput is the in-process reference authority composition. The
// original issuance owner stays borrowed; no receipt can construct this input.
type LiveSessionInput struct {
	Establishment       *SessionEstablishment
	Admission           *SessionAdmissionReservation
	Store               *ledgerv4.SQLiteStore
	Authority           ledgerv4.SQLiteLiveAuthority
	Issuance            *protocolv4.LiveActivationPlan
	Owner               ledgerv4.LiveSpendOwner
	Guard               func() error
	Policy              func(context.Context) (bool, error)
	Buffers, Invocation resourcev4.Reference
}

// AcceptedSessionInput captures the original entrance after its ClientHello
// lookup, including the same frozen application plan used by Connect. It does
// not introduce a consumer spend or acquire a different identity after FSB.
type AcceptedSessionInput struct {
	Establishment        *SessionEstablishment
	Entrance             *AcceptedEntrance
	Config               SessionAdmissionConfig
	Subscriptions        *protocolv4.CredentialSubscriptions
	Root                 *resourcev4.Root
	ResourceOwner        resourcev4.OwnerKey
	Environment, Preauth resourcev4.Reference
	Scope                SessionResourceScope
	Store                *ledgerv4.SQLiteStore
	Authority            ledgerv4.SQLiteAdmissionAuthority
	Owner                ledgerv4.AdmissionOwner
	Buffers, Invocation  resourcev4.Reference
}

type environmentEstablishment struct {
	pool     PoolSessionInput
	live     LiveSessionInput
	accepted AcceptedSessionInput
	source   *sourcePreparation
	intake   *acceptedIntake
	ingress  *acceptedIngress
	kind     uint8
}

func (e *Environment) ConnectPool(ctx context.Context, input PoolSessionInput) (*EnvironmentSession, error) {
	if input.Store == nil || input.Authority == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return e.start(ctx, environmentEstablishment{pool: input, kind: 1})
}

func (e *Environment) ConnectLiveSQLite(ctx context.Context, input LiveSessionInput) (*EnvironmentSession, error) {
	if input.Store == nil || input.Authority == nil || input.Issuance == nil || input.Guard == nil || input.Policy == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return e.start(ctx, environmentEstablishment{live: input, kind: 2})
}

func (e *Environment) Accept(ctx context.Context, input AcceptedSessionInput) (*EnvironmentSession, error) {
	if input.Store == nil || input.Authority == nil || input.Entrance == nil || input.Root == nil || input.Subscriptions == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return e.start(ctx, environmentEstablishment{accepted: input, kind: 3})
}

func (input *environmentEstablishment) owners() (*SessionEstablishment, *SessionAdmissionReservation, *AcceptedEntrance) {
	switch input.kind {
	case 1:
		return input.pool.Establishment, input.pool.Admission, nil
	case 2:
		return input.live.Establishment, input.live.Admission, nil
	default:
		return input.accepted.Establishment, nil, input.accepted.Entrance
	}
}

func (input *environmentEstablishment) check(ref resourcev4.Reference) error {
	var refs [4]resourcev4.Reference
	n := 0
	switch input.kind {
	case 1:
		refs[0], n = input.pool.Consume, 1
	case 2:
		refs[0], refs[1], n = input.live.Buffers, input.live.Invocation, 2
	case 3:
		refs[0], refs[1], refs[2], refs[3], n = input.accepted.Buffers, input.accepted.Invocation, input.accepted.Environment, input.accepted.Preauth, 4
	}
	for _, candidate := range refs[:n] {
		if err := ref.CheckSameEnvironment(candidate); err != nil {
			return err
		}
	}
	return nil
}

// start's only ownership transition is under the Environment and original
// admission/entrance gates. No provider, store or application code runs there.
func (e *Environment) admit(ctx context.Context, input environmentEstablishment) (*EnvironmentSession, error) {
	return e.admitAt(ctx, input, nil)
}

// admitAt installs the prepared graph in its original acquisition position.
// Existing source work must never compete for a second Environment position.
func (e *Environment) admitAt(ctx context.Context, input environmentEstablishment, existing *EnvironmentSession) (*EnvironmentSession, error) {
	if e == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p, a, entrance := input.owners()
	if p == nil || p.sessionEstablishment == nil || input.kind != 3 && a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	if existing != nil {
		existing.mu.Lock()
		defer existing.mu.Unlock()
		if existing.environment != e || existing.closed || existing.establishment != nil {
			e.mu.Unlock()
			return nil, cryptov4.ErrClosed
		}
	}
	if e.closed {
		e.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	slot := -1
	if existing != nil {
		slot = existing.position
	} else {
		for i, position := range e.positions {
			if position == nil {
				slot = i
				break
			}
		}
	}
	if slot < 0 {
		e.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	err := ctx.Err()
	if err == nil {
		err = e.reservation.Check()
	}
	if err == nil {
		err = e.shared.Check()
	}
	if err == nil {
		err = input.check(e.reservation)
	}
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	if a != nil {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.host != nil || a.claimed || a.busy || a.establishment != nil {
			err = cryptov4.ErrTransition
		} else {
			err = a.checkLocked()
		}
		if err == nil {
			err = a.owner.CheckSameEnvironment(e.reservation)
		}
	} else {
		entrance.mu.Lock()
		defer entrance.mu.Unlock()
		if entrance.host != existing || entrance.closed || entrance.busy || entrance.admission != nil {
			err = cryptov4.ErrTransition
		} else {
			err = entrance.owner.CheckSameEnvironment(e.reservation)
		}
	}
	p.mu.Lock()
	if err == nil && (p.host != nil || p.started || p.closed) {
		err = cryptov4.ErrTransition
	}
	if err == nil {
		err = p.reservation.CheckSameEnvironment(e.reservation)
	}
	if err == nil && ((input.kind == 1 && p.material.Source != "preauthorized_pool") || (input.kind == 2 && p.material.Source != "live_authority") || (input.kind == 3) != (p.material.Role == protocolv4.ServerToClient)) {
		err = cryptov4.ErrConfiguration
	}
	if err == nil && a != nil && (p.session != a.binding.Session || p.expected != a.binding.Candidate || p.material.Hello.Attempt != a.binding.Attempt || p.material.Source != a.config.Initial.ActivationSourceProfile) {
		err = cryptov4.ErrConfiguration
	}
	if err != nil {
		p.mu.Unlock()
		e.mu.Unlock()
		return nil, err
	}
	s := existing
	if s == nil {
		s = newEnvironmentSession(e, slot, ctx)
	}
	if a == nil {
		if err := input.accepted.Config.Application.claimPreparation(s); err != nil {
			p.mu.Unlock()
			e.mu.Unlock()
			return nil, err
		}
		s.application = input.accepted.Config.Application
	} else {
		s.application = a.application
	}
	if existing == nil {
		e.positions[slot], e.active = s, e.active+1
	}
	s.establishment, s.admission, s.entrance = p, a, entrance
	p.host = s
	if a != nil {
		a.host, a.ctx = s, &s.context
	} else {
		entrance.host = s
	}
	p.mu.Unlock()
	e.mu.Unlock()
	return s, nil
}

func (e *Environment) start(ctx context.Context, input environmentEstablishment) (*EnvironmentSession, error) {
	if input.kind == 3 {
		var err error
		input.accepted.Config, err = input.accepted.Config.CaptureRequirements()
		if err != nil {
			return nil, err
		}
	}
	s, err := e.admit(ctx, input)
	if err != nil {
		return nil, err
	}
	// Both tasks occupy fixed positions before any provider or store work.
	go s.watch(ctx)
	go s.run(input)
	return s.deliver(ctx)
}

func (e *Environment) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	for _, result := range e.results {
		if result != nil {
			result.Close()
		}
	}
	for _, g := range e.groups {
		if g != nil {
			g.Close()
		}
	}
	for _, s := range e.positions {
		if s != nil {
			s.Close()
		}
	}
	for i := range e.materials {
		p := &e.materials[i]
		if p.cancel != nil {
			p.cancel(cryptov4.ErrClosed)
		}
		if p.material != nil {
			p.material.Close()
		}
	}
	for _, q := range e.queries {
		if q != nil {
			q.Close()
		}
	}
	e.signalMaterials()
	e.completeLocked()
}

func (e *Environment) completeLocked() {
	if e.closed && e.active == 0 && e.groupsActive == 0 && e.materialActive == 0 && e.materialExited && e.queryActive == 0 && e.resultActive == 0 && !e.cleaned {
		e.cleaned = true
		close(e.done)
	}
}

func (e *Environment) WaitCleanup(ctx context.Context) error {
	if e == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Environment) Retire() error {
	if e == nil {
		return cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.cleaned {
		return cryptov4.ErrCapacity
	}
	if !e.retired {
		e.retired = true
		e.positions = nil
		e.groups = nil
		e.materials, e.materialClock, e.queries = nil, nil, nil
		e.results = nil
		e.registryBorrow.Release()
		e.registryBorrow = resourcev4.Reference{}
		e.serviceRegistry = nil
		e.shared.Release()
		e.reservation.Release()
		e.shared, e.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	}
	return nil
}
