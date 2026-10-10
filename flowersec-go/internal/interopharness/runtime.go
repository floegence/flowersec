package interopharness

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Runtime owns its application plans and Sessions, and may own or borrow the
// normal public Environment and executor from one original deployment.
// Authority contains only material and real resource/trust/store recipes. Both
// peers run the original verification, durable admission, Noise and READY.
type Runtime struct {
	Reporter             *Reporter
	Role                 uint8
	Authority            *sessionv4.PublicQUICTestHarness
	Environment          *fs.TransportEnvironment
	Executor             *fs.ApplicationExecutor
	Materials            [2]*fs.ConnectionMaterial
	Leases               [2]*fs.ArtifactLease
	Identities           [2]*fs.ApplicationIdentity
	Plans                [2]*fs.SessionPlan
	Handlers             [2]*fs.StreamHandlerPlan
	RPCDefinitions       [2]*RPCDefinition
	Services             [2]*fs.RPCServicesConfig
	QueryMethods         [2][]sessionv4.ContractQueryMethod
	AuthorizeServices    [2]func(*fs.ApplicationLease) error
	Authorized, Released [2]atomic.Int32
	SelectedCandidate    [2]atomic.Uint64
	SourceAcquisitions   atomic.Int32
	Sessions             [2]*fs.Session
	PoolSpend            *ledgerv4.PoolSpendObservation
	ServerAllow          fs.TunnelServerAllowConfig
	mu                   sync.Mutex
	ownsEnvironment      bool
	ownsExecutor         bool
	ownersClosed         bool
}

type HandlerConfig func(*Runtime, uint8) (fs.StreamHandlerPlanConfig, error)

// CloseOwners starts shutdown for the concrete owners created by Runtime. The
// Reporter also owns these callbacks, but callers that must retain a physical
// position after a bounded cleanup wait can start them directly and retry
// WaitOwners without losing the original owner.
func (r *Runtime) CloseOwners() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.ownersClosed = true
	sessions := r.Sessions
	r.mu.Unlock()
	for _, session := range sessions {
		if session != nil {
			_ = session.Close()
		}
	}
	for _, plan := range r.Plans {
		if plan != nil {
			plan.Close()
		}
	}
	for _, handler := range r.Handlers {
		if handler != nil {
			handler.Close()
		}
	}
	for _, material := range r.Materials {
		if material != nil {
			material.Close()
		}
	}
	for _, identity := range r.Identities {
		if identity != nil {
			identity.Close()
		}
	}
	for _, lease := range r.Leases {
		if lease != nil {
			lease.Close()
		}
	}
	if r.ownsEnvironment && r.Environment != nil {
		r.Environment.Close()
	}
	if r.ownsExecutor && r.Executor != nil {
		r.Executor.Close()
	}
}

// WaitOwners observes physical retirement of Runtime's owners. It never
// cancels a wait or replaces a live owner after a timeout.
func (r *Runtime) WaitOwners(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var result error
	r.mu.Lock()
	sessions := r.Sessions
	r.mu.Unlock()
	for _, session := range sessions {
		if session != nil {
			result = errors.Join(result, session.WaitCleanup(ctx))
		}
	}
	for _, handler := range r.Handlers {
		if handler != nil {
			result = errors.Join(result, handler.WaitCleanup(ctx))
		}
	}
	for _, material := range r.Materials {
		if material != nil {
			result = errors.Join(result, material.WaitCleanup(ctx))
		}
	}
	for _, identity := range r.Identities {
		if identity != nil {
			result = errors.Join(result, identity.WaitCleanup(ctx))
		}
	}
	for _, lease := range r.Leases {
		if lease != nil {
			result = errors.Join(result, lease.WaitCleanup(ctx))
		}
	}
	if r.ownsEnvironment && r.Environment != nil {
		result = errors.Join(result, r.Environment.WaitCleanup(ctx))
	}
	if result != nil {
		return result
	}
	// An unused SessionPlan retains its completion reservation until Retire.
	// Retire only after this position's original callbacks and Sessions have
	// exited. A borrowed deployment remains live for its independent siblings.
	for _, plan := range r.Plans {
		if plan != nil {
			result = errors.Join(result, plan.Retire())
		}
	}
	for _, handler := range r.Handlers {
		if handler != nil {
			result = errors.Join(result, handler.Retire())
		}
	}
	if result != nil {
		return result
	}
	if r.ownsExecutor && r.Executor != nil {
		select {
		case <-r.Executor.Done():
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		}
	}
	return result
}

func NewRuntime(ctx context.Context, reporter *Reporter, authority *sessionv4.PublicQUICTestHarness, roles []uint8, handlers HandlerConfig) (*Runtime, error) {
	runtime := &Runtime{Reporter: reporter, Authority: authority}
	if reporter != nil {
		reporter.Owner(runtime.CloseOwners, runtime.WaitOwners)
	}
	if len(roles) == 1 {
		runtime.Role = roles[0]
	}
	if authority.Pool != nil {
		runtime.PoolSpend = &ledgerv4.PoolSpendObservation{}
		pool := *authority.Pool
		pool.Observation = runtime.PoolSpend
		authority.Pool = &pool
	}
	err := runtime.initialize(ctx, roles, handlers)
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

func (r *Runtime) reserve(cost fs.ResourceVector, err error) fs.ResourceReference {
	if err != nil {
		r.Reporter.Fatal(err)
	}
	return r.Authority.Reserve(cost)
}
func (r *Runtime) initialize(ctx context.Context, roles []uint8, configure HandlerConfig, sharedEnvironment ...*fs.TransportEnvironment) (err error) {
	_, err = construct(r.Reporter, func() bool {
		h := r.Authority
		sessionPositions, materialPositions := uint32(8), uint32(8)
		if capacity := r.Reporter.Capacity; capacity != nil {
			if err := capacity.Validate(); err != nil {
				r.Reporter.Fatal(err)
			}
			sessionPositions, materialPositions = max(capacity.Sessions, 1), capacity.Materials
		}
		if r.Executor == nil {
			// Each live, retained or candidate Session reserves both contract
			// query directions before acquisition in this shared Environment.
			executorConfig := fs.ApplicationExecutorConfig{QueryOwners: 2 * sessionPositions, Running: 132, ResidentRunning: 128, Ready: 32, ResidentReady: 16, CompletionRunning: 2, CompletionReserved: 32, RuntimeBytes: 16384, RuntimeBytesPerTask: 131072}
			if r.Reporter.Capacity != nil {
				// Every original plan and live short-result floor keeps its own
				// Completion index. Worker/ready caps remain the original service.
				executorConfig.CompletionReserved = max(32, 2*materialPositions+8*sessionPositions)
			}
			r.Executor, err = fs.NewApplicationExecutor(executorConfig, r.reserve(fs.ApplicationExecutorCharge(executorConfig)))
			if err != nil {
				r.Reporter.Fatal(err)
			}
			r.ownsExecutor = true
			r.Reporter.Cleanup(func() {
				r.Executor.Close()
				select {
				case <-r.Executor.Done():
				case <-time.After(5 * time.Second):
					r.Reporter.Error("executor retained its original callbacks")
				}
			})
		}
		if len(sharedEnvironment) > 1 {
			r.Reporter.Fatal("at most one original shared Environment is permitted")
		}
		if len(sharedEnvironment) == 1 && sharedEnvironment[0] != nil {
			r.Environment = sharedEnvironment[0]
		} else {
			environmentConfig := fs.EnvironmentConfig{Services: true, Positions: sessionPositions, Materials: materialPositions, MaterialCreateMS: r.Reporter.operationMS(10000), Clock: h.Clock, Verification: h.Verification, RuntimeBytes: 131072}
			if r.Reporter.Capacity != nil {
				// The installed capacity workload retains eight service positions
				// and both an active and completed result per position. Declare
				// their finite local bounds instead of installing the ordinary
				// 256-method/4096-result host separately for every single peer.
				// Signed contracts and ordinary host defaults remain authoritative.
				environmentConfig.MaxBoundMethods = uint16(min(256, 8*sessionPositions))
				environmentConfig.ResultOwners = min(4096, 16*sessionPositions)
			}
			r.Environment, err = fs.NewTransportEnvironment(fs.TransportEnvironmentOptions{Config: environmentConfig, Reservation: r.reserve(fs.EnvironmentCharge(environmentConfig)), Dependencies: h.Environment})
			if err != nil {
				r.Reporter.Fatal(err)
			}
			r.ownsEnvironment = true
			r.Reporter.Cleanup(func() {
				r.Environment.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				r.Reporter.ErrorIf(r.Environment.WaitCleanup(cleanup))
			})
		}
		for _, role := range roles {
			if role > 1 || r.Leases[role] != nil {
				r.Reporter.Fatal("invalid or duplicate runtime role")
			}
			config := fs.StreamHandlerPlanConfig{RuntimeBytes: 16384}
			if configure != nil {
				config, err = configure(r, role)
				if err != nil {
					r.Reporter.Fatal(err)
				}
			}
			var handler *fs.StreamHandlerPlan
			if len(config.Handlers) != 0 {
				delegates, err := h.Environment.Borrow()
				if err != nil {
					r.Reporter.Fatal(err)
				}
				handler, err = fs.NewStreamHandlerPlan(config, r.Executor, r.reserve(fs.StreamHandlerPlanCharge(config)), delegates)
				if err != nil {
					delegates.Release()
					r.Reporter.Fatal(err)
				}
				r.Handlers[role] = handler
				r.Reporter.Cleanup(func() {
					handler.Close()
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := handler.WaitCleanup(cleanup); err != nil {
						r.Reporter.Error(err)
					} else {
						r.Reporter.ErrorIf(handler.Retire())
					}
				})
			}
			plan, err := (fs.SessionPlanFactory{Root: h.Root, Executor: r.Executor, Dependencies: h.Environment}).Create(fs.SessionPlanConfig{
				RuntimeBytes: 16384, Handlers: handler, Services: r.Services[role] != nil, ContractQueries: r.Services[role] != nil, ContractQueryMethods: r.QueryMethods[role],
				AuthorizeApplication: func(_ context.Context, request fs.AuthenticatedRequestContext) (fs.AuthorizeApplicationResult, error) {
					r.SelectedCandidate[role].Store(request.Binding().CandidateIndex)
					r.Authorized[role].Add(1)
					lease, err := request.ReserveLease(request.Binding(), role, func(context.Context) error { r.Released[role].Add(1); return nil })
					if err == nil && r.AuthorizeServices[role] != nil {
						err = r.AuthorizeServices[role](lease)
					}
					return fs.AuthorizeApplicationResult{Handlers: handler, Lease: lease}, err
				},
			}, h.Owner(), h.Scope[role].Tenant, h.Scope[role].Session)
			if err != nil {
				r.Reporter.Fatal(err)
			}
			r.Plans[role] = plan
			r.Reporter.Cleanup(func() { plan.Close(); r.Reporter.ErrorIf(plan.Retire()) })
			h.Admission[role].Application = plan
			h.Admission[role].RPC = r.Services[role]
			// A cloned authority may still name the base runtime's handler.
			// This attempt owns exactly its newly declared plan, including nil.
			h.Admission[role].Core.Handlers = fs.SessionStreamHandlerConfig{}
			if handler != nil {
				concurrency := uint32(0)
				timeout := uint64(30000)
				for _, registration := range config.Handlers {
					concurrency += registration.Slots
					if registration.Manual {
						timeout = 600000
					}
				}
				concurrency = min(concurrency, 128, h.Admission[role].Core.Open.Opening+h.Admission[role].Core.Open.IngressItems)
				h.Admission[role].Core.Handlers = fs.SessionStreamHandlerConfig{Plan: handler, Concurrency: concurrency, TimeoutMS: timeout, RuntimeBytes: 16384, RuntimeBytesPerInvocation: 65536}
			}
			if r.Reporter.Capacity != nil {
				// Validate this actual complete application/Core/RPC recipe before
				// material preparation, native acquisition or durable admission.
				if _, _, err = sessionv4.SessionAdmissionRequirements(h.Admission[role]); err != nil {
					r.Reporter.Fatal(err)
				}
			}
			lease, err := fs.NewArtifactLeaseFromBytes(h.Lease, r.reserve(fs.ArtifactLeaseCharge(h.Lease.MapBytes, h.Lease.MapNodes, h.Lease.RuntimeBytes, len(h.Lease.Tunnels))), h.Preauth)
			if err != nil {
				r.Reporter.Fatal(err)
			}
			r.Leases[role] = lease
			r.Reporter.Cleanup(func() {
				lease.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				r.Reporter.ErrorIf(lease.WaitCleanup(cleanup))
			})
			identityConfig := h.Identity[role]
			identity, err := fs.NewApplicationIdentityFromBytes(identityConfig, r.reserve(fs.ApplicationIdentityCharge(identityConfig.MapNodes, identityConfig.RuntimeBytes)), h.Preauth)
			if err != nil {
				r.Reporter.Fatal(err)
			}
			r.Identities[role] = identity
			r.Reporter.Cleanup(func() {
				identity.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				r.Reporter.ErrorIf(identity.WaitCleanup(cleanup))
			})
			if role == 0 {
				continue
			}
			material, err := fs.NewConnectionMaterial(lease, identity, h.Generation, 8192, r.reserve(fs.ConnectionMaterialCharge(8192)))
			if err != nil {
				r.Reporter.Fatal(err)
			}
			r.Materials[role] = material
			r.Reporter.Cleanup(func() {
				material.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				r.Reporter.ErrorIf(material.WaitCleanup(cleanup))
			})
		}
		return true
	})
	return err
}

func (r *Runtime) retainSession(role uint8, session *fs.Session) error {
	if session == nil {
		return errors.New("current admission returned no Session")
	}
	r.mu.Lock()
	if r.Sessions[role] != nil {
		r.mu.Unlock()
		_ = session.Close()
		return errors.New("runtime Session position is already occupied")
	}
	r.Sessions[role] = session
	closed := r.ownersClosed
	r.mu.Unlock()
	r.Reporter.Cleanup(func() {
		_ = session.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r.Reporter.ErrorIf(session.WaitCleanup(cleanup))
	})
	if closed {
		_ = session.Close()
		return errors.New("runtime owners are already closed")
	}
	return nil
}

// connectionRequirements follows the signed physical role. A network client
// dialer must enforce TLS 1.3 locally, including its relay leg; an endpoint
// listener has no consumer-side TLS verification promise.
func (r *Runtime) connectionRequirements() fs.RequiredGuarantees {
	h := r.Authority
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		r.Reporter.Fatal(err)
	}
	document, err := decoder.DecodeMap(h.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		r.Reporter.Fatal(err)
	}
	defer document.Release()
	root := document.Root()
	kind, ok := root.Named("Route", "path_kind").Uint()
	if !ok {
		r.Reporter.Fatal("signed route has no path kind")
	}
	leg := root.Named("Route", "direct_leg")
	if kind == 1 {
		name := "client_leg"
		if r.Role == 1 {
			name = "server_leg"
		}
		leg = root.Named("Route", name)
	}
	dialer, dialerOK := leg.Named("Leg", "dialer_role").Uint()
	access, accessOK := leg.Named("Leg", "access_class").Uint()
	if !dialerOK || !accessOK {
		r.Reporter.Fatal("signed route has no physical role or access class")
	}
	network, err := protocolv4.EnumValue("Leg", "access_class", "network")
	if err != nil {
		r.Reporter.Fatal(err)
	}
	return fs.RequiredGuarantees{LocalConsumerTls13Verification: r.Role == 0 && dialer == uint64(r.Role) && access == network, Datagram: h.Admission[r.Role].Core.Datagrams}
}

func (r *Runtime) Connect(ctx context.Context, carrier fs.ConsumerCarrierFactory) (*fs.Session, error) {
	return r.ConnectCandidates(ctx, carrier, 1)
}
func (r *Runtime) ConnectCandidates(ctx context.Context, carrier fs.ConsumerCarrierFactory, parallel uint8) (*fs.Session, error) {
	if parallel < 1 || parallel > 2 {
		return nil, errors.New("original candidate parallelism exceeds its fixed envelope")
	}
	r.mu.Lock()
	closed := r.ownersClosed
	r.mu.Unlock()
	if closed {
		return nil, errors.New("runtime owners are already closed")
	}
	h := r.Authority
	// Provisioning installs unused material, not an admitted connection. Pin
	// this operation's original deadline at the public Connect call and keep
	// it unchanged through source acquisition, spend, establishment and READY.
	admission := h.Admission[r.Role]
	deadline, err := timev4.NewAge(h.Clock, r.Reporter.operationMS(10000), admission.Core.Session.SessionNotAfterMS)
	if err != nil {
		return nil, err
	}
	admission.Initial.Deadline = deadline
	pool := h.Pool
	if pool != nil {
		original := *pool
		original.ServerAllow = r.ServerAllow
		pool = &original
	}
	source := &LeaseSource{runtime: r, lease: r.Leases[r.Role]}
	session, err := fs.Connect(ctx, source, fs.ConnectorOptions{Environment: r.Environment, ConnectOptions: fs.ConnectOptions{Pool: pool, Live: h.Live,
		Preparation: fs.SourceConnectConfig{Generation: h.Generation, Identity: r.Identities[r.Role], MaterialRuntimeBytes: 8192, LocalCapabilities: h.Hello.Offered,
			Requirements: fs.MaterialRequirements{ApplicationProfile: r.Reporter.AuthorityApplicationProfile(), RPCMaxGeneralOutstanding: h.Admission[r.Role].Core.Session.Contract.Limits().RPCMaxGeneralOutstanding, Connection: r.connectionRequirements()},
			Carrier:      carrier, Hello: h.Hello, Limits: h.Limits, Admission: admission, Root: h.Root, Owner: h.Owner(), Environment: h.Environment, Preauth: h.Preauth, Dependencies: h.Environment,
			Scope: h.Scope[r.Role], RuntimeBytes: 8192, CarrierRuntimeBytes: 8192, ParallelCandidates: parallel, CandidateStartIntervalConfigured: parallel > 1, AddressAttempts: 1, AttemptBudget: fs.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}, LiveIssuance: h.LiveIssuance}}})
	if err != nil {
		return nil, err
	}
	if err = r.retainSession(r.Role, session); err != nil {
		return nil, err
	}
	return session, nil
}

// LeaseSource names the original namespace set before source acquisition and
// returns the original lease once. It has no callback that pretends a spend.
type LeaseSource struct {
	mu       sync.Mutex
	runtime  *Runtime
	lease    *fs.ArtifactLease
	acquired bool
}

func (s *LeaseSource) AcquireLease(ctx context.Context, _ fs.MaterialLeaseRequest) (*fs.ArtifactLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acquired {
		return nil, errors.New("engineering source lease was already acquired")
	}
	s.acquired = true
	s.runtime.SourceAcquisitions.Add(1)
	return s.lease, nil
}
func (s *LeaseSource) PreparationNamespaces(clock *fs.Clock, environment fs.ResourceReference) ([3]*protocolv4.LiveNamespace, error) {
	return s.runtime.Authority.PreparationNamespaces(clock, environment)
}

func (r *Reporter) ErrorIf(err error) {
	if err != nil {
		r.mu.Lock()
		r.failures = append(r.failures, err)
		r.mu.Unlock()
	}
}

// SourcePreparation describes untouched original local inputs. Acquiring the
// lease and spending its SQLite record remain inside normal Connect/Controller.
func (r *Runtime) SourcePreparation(carrier fs.ConsumerCarrierFactory) *fs.ControllerPreparation {
	h := r.Authority
	return &fs.ControllerPreparation{Pool: h.Pool, Live: h.Live, Config: fs.SourceConnectConfig{Provider: &LeaseSource{runtime: r, lease: r.Leases[r.Role]}, Generation: h.Generation, Identity: r.Identities[r.Role], MaterialRuntimeBytes: 8192, LocalCapabilities: h.Hello.Offered,
		Requirements: fs.MaterialRequirements{ApplicationProfile: r.Reporter.AuthorityApplicationProfile(), RPCMaxGeneralOutstanding: h.Admission[r.Role].Core.Session.Contract.Limits().RPCMaxGeneralOutstanding, Connection: r.connectionRequirements()}, Carrier: carrier, Hello: h.Hello, Limits: h.Limits, Admission: h.Admission[r.Role], Root: h.Root, Owner: h.Owner(), Environment: h.Environment, Preauth: h.Preauth, Dependencies: h.Environment, Scope: h.Scope[r.Role], RuntimeBytes: 8192, CarrierRuntimeBytes: 8192, AddressAttempts: 1, AttemptBudget: fs.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}, LiveIssuance: h.LiveIssuance}}
}
