package sessionv4

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestSessionEstablishmentSourcesToAdmissionReadyAndDuplex(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) { sessionEstablishmentDuplex(t, source) })
	}
}

func sessionEstablishmentDuplex(t *testing.T, source string, acquireInEnvironment ...bool) {
	viaControl := source == "live_control"
	if viaControl {
		source = "live_authority"
	}
	viaSource := len(acquireInEnvironment) > 0 && acquireInEnvironment[0]
	viaIntake := len(acquireInEnvironment) > 1 && acquireInEnvironment[1]
	viaIngress := len(acquireInEnvironment) > 2 && acquireInEnvironment[2]
	viaServe := len(acquireInEnvironment) > 3 && acquireInEnvironment[3]
	viaApplication := len(acquireInEnvironment) > 4 && acquireInEnvironment[4]
	viaBytes := len(acquireInEnvironment) > 5 && acquireInEnvironment[5]
	viaStatic := len(acquireInEnvironment) > 6 && acquireInEnvironment[6]
	viaRegistry := len(acquireInEnvironment) > 7 && acquireInEnvironment[7]
	viaController := len(acquireInEnvironment) > 8 && acquireInEnvironment[8]
	failInitialize := len(acquireInEnvironment) > 9 && acquireInEnvironment[9]
	lateInitialize := len(acquireInEnvironment) > 10 && acquireInEnvironment[10]
	closeCandidate := len(acquireInEnvironment) > 11 && acquireInEnvironment[11]
	expireCandidate := len(acquireInEnvironment) > 12 && acquireInEnvironment[12]
	completionBlocked := len(acquireInEnvironment) > 13 && acquireInEnvironment[13]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connectContext, cancelConnect := context.WithCancel(ctx)
	defer cancelConnect()
	f := admissionIntegration(t, ctx, source)
	var verification *protocolv4.NamespaceRegistry
	if viaRegistry {
		verification = environmentVerificationRegistry(t, f)
	}
	var raw *materialBytesFixture
	if viaBytes {
		if verification != nil {
			raw = materialBytesFor(t, f, verification)
		} else {
			raw = materialBytesFor(t, f)
		}
	}
	// Replace the fixture's unused message provider with the actual byte pipe
	// before any admission or irreversible consume has occurred.
	f.prepared.Close()
	if err := f.prepared.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.prepared.Retire(); err != nil {
		t.Fatal(err)
	}
	reserve := func(n uint32, cost resourcev4.Vector) resourcev4.Reference {
		r, err := f.root.Reserve(admissionResourceKey(f.owner, n), cost)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Release)
		return r
	}
	f.config.Core.MessageCarrier = false
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	charge, _ := PreparedCarrierCharge(8192)
	var err error
	if !viaSource {
		f.prepared, err = NewPreparedStream(ctx, PreparedCarrierConfig{Candidate: f.trust.candidate, Attempt: f.trust.attempt, Session: f.trust.session, Role: protocolv4.ClientToServer, Deadline: f.config.Initial.Deadline, Reservation: reserve(250, charge), Environment: f.environment, RuntimeBytes: 8192}, &acceptedPipe{Conn: left, winner: f.trust.candidate, environment: f.environment})
		if err != nil {
			t.Fatal(err)
		}
	}
	var e *AcceptedEntrance
	if !viaIngress {
		e, err = NewAcceptedStream(ctx, acceptedTestConfig(f), &acceptedPipe{Conn: right, winner: f.trust.candidate, environment: f.environment}, f.root, admissionResourceKey(f.owner, 251), f.environment)
		if err != nil {
			t.Fatal(err)
		}
		cleanupAccepted(t, e)
	}
	limits := EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
	planCharge, err := EstablishmentCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	environmentConfig := EnvironmentConfig{Positions: 2, RuntimeBytes: 65536, Verification: verification}
	if viaStatic {
		environmentConfig.Materials, environmentConfig.MaterialCreateMS, environmentConfig.Clock = 1, 1000, f.trust.clock
	}
	environmentCharge, err := EnvironmentCharge(environmentConfig)
	if err != nil {
		t.Fatal(err)
	}
	host, err := NewEnvironment(environmentConfig, reserve(248, environmentCharge), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		host.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := host.WaitCleanup(cleanup); err != nil {
			t.Error(err)
			return
		}
		if err := host.Retire(); err != nil {
			t.Error(err)
		}
	})
	var group *ServeGroup
	if viaServe {
		config := ServeConfig{Positions: 2, RuntimeBytes: 8192, DrainTimeoutMS: 1000, Clock: f.trust.clock}
		cost, err := ServeCharge(config)
		if err != nil {
			t.Fatal(err)
		}
		group, err = host.NewServeGroup(ctx, config, reserve(316, cost))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			group.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := group.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if err := group.Retire(); err != nil {
				t.Error(err)
			}
		})
	}
	var plans [2]*SessionEstablishment
	var materials [2]*ConnectionMaterial
	var identities [2]*ApplicationIdentity
	var leases [2]*ArtifactLease
	for role := range 2 {
		f.trust.subscriptions[role].Close()
		if raw == nil {
			materials[role], identities[role], leases[role] = materialTestBundle(t, f, protocolv4.Direction(role), uint32(280+10*role))
		} else {
			leases[role], err = raw.lease(t)
			if err != nil {
				t.Fatal(err)
			}
			identities[role], err = raw.identity(t, protocolv4.Direction(role))
			if err != nil {
				t.Fatal(err)
			}
			cost, e := ConnectionMaterialCharge(8192)
			if e != nil {
				t.Fatal(e)
			}
			materials[role], err = NewConnectionMaterial(leases[role], identities[role], MaterialGeneration{Source: [16]byte{1}, Generation: 1}, 8192, raw.reserve(cost))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(materials[role].Close)
		}
		if viaStatic && role == 0 {
			original := materials[role]
			materials[role], err = host.CreateMaterial(ctx, func(context.Context) (*ConnectionMaterial, error) { return original, nil })
			if err != nil {
				t.Fatal(err)
			}
			identities[role].Close()
			leases[role].Close()
			continue
		}
		if viaIntake && role == 1 {
			identities[role].Close()
			leases[role].Close()
			continue
		}
		materials[role].Close()
		if viaSource && role == 0 {
			continue
		}
		acquireCharge, err := MaterialAcquisitionCharge(8192)
		if err != nil {
			t.Fatal(err)
		}
		materialCharge, err := ConnectionMaterialCharge(8192)
		if err != nil {
			t.Fatal(err)
		}
		acquisition, err := NewMaterialAcquisition(connectContext, identities[role], MaterialGeneration{Source: [16]byte{1}, Generation: 1}, source, MaterialRequirements{ApplicationProfile: "transport"}, f.config.Initial.Deadline, 8192, 8192, reserve(uint32(283+10*role), acquireCharge), reserve(uint32(284+10*role), materialCharge))
		if err != nil {
			t.Fatal(err)
		}
		materials[role], err = acquisition.Acquire(immediateMaterialProvider{leases[role]})
		if err != nil {
			t.Fatal(err)
		}
		plans[role], f.trust.subscriptions[role], err = materials[role].Establishment(InitialHello{Index: 0, Attempt: f.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}, limits, MaterialGeneration{Source: [16]byte{1}, Generation: 1}, reserve(uint32(252+role), planCharge), reserve(uint32(287+10*role), protocolv4.CredentialSubscriptionsCharge()))
		if err != nil {
			t.Fatal(role, err)
		}
		// Rotation stops future advertisement, preserving these captured owners.
		identities[role].Close()
		leases[role].Close()
	}
	var applicationPlans [2]*SessionPlan
	var executor *ApplicationExecutor
	var authorized, released [2]atomic.Uint32
	if viaApplication {
		completionReserved := uint32(2)
		if viaController {
			completionReserved++
		}
		if completionBlocked {
			completionReserved++
		}
		c := ApplicationExecutorConfig{Running: 4, ResidentRunning: 2, CompletionRunning: 1, CompletionReserved: completionReserved, RuntimeBytes: 8192, RuntimeBytesPerTask: 65536}
		cost, err := ApplicationExecutorCharge(c)
		if err != nil {
			t.Fatal(err)
		}
		executor, err = NewApplicationExecutor(c, reserve(340, cost))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { executor.Close(); <-executor.Done() })
		for role := range 2 {
			config := SessionPlanConfig{RuntimeBytes: 8192, AuthorizeApplication: func(ctx context.Context, request AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
				binding := request.Binding()
				if binding.Artifact != f.trust.session.ArtifactDigest || binding.Attempt != f.trust.attempt || binding.Role != protocolv4.Direction(role) || binding.Source != source {
					t.Error("wrong authenticated application binding")
				}
				authorized[role].Add(1)
				lease, err := request.ReserveLease(binding, "trusted local projection", func(context.Context) error { released[role].Add(1); return nil })
				return AuthorizeApplicationResult{Lease: lease}, err
			}}
			cost, err := SessionPlanCharge(config)
			if err != nil {
				t.Fatal(err)
			}
			borrow, err := f.environment.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			n := uint32(341 + role*3)
			applicationPlans[role], err = NewSessionPlan(config, executor, reserve(n, cost), reserve(n+1, executor.TaskCharge()), reserve(n+2, executor.CompletionCharge()), borrow)
			borrow.Release()
			if err != nil {
				t.Fatal(err)
			}
		}
		f.config.Application = applicationPlans[0]
	}
	var a *SessionAdmissionReservation
	var sourceConfig SourceConnectConfig
	if viaSource {
		sourceConfig = sourceConnectTestConfig(t, f, identities[0], immediateMaterialProvider{leases[0]}, carrierFactoryFunc(func(call context.Context, request CarrierPreparationRequest) (*PreparedCarrier, error) {
			return NewPreparedStream(call, request.Config, &acceptedPipe{Conn: left, winner: f.trust.candidate, environment: f.environment})
		}))
		sourceConfig.Requirements.Connection.LocalConsumerTls13Verification = true
		if viaStatic {
			sourceConfig.Acquisition.Release()
			sourceConfig.Material.Release()
			sourceConfig.Identity, sourceConfig.Provider = nil, nil
			sourceConfig.Acquisition, sourceConfig.Material = resourcev4.Reference{}, resourcev4.Reference{}
			sourceConfig.MaterialRuntimeBytes = 0
		}
	} else {
		a = f.reserve(t, ctx)
	}
	serverScope := corePlanTestScope(t, f.root, f.root.Snapshot().Limit, 2)
	serverConfig := f.config
	serverConfig.Initial.Role = protocolv4.ServerToClient
	serverConfig.Application = applicationPlans[1]
	recordBytes := uint32(4096)
	if source == "live_authority" {
		recordBytes = 16384
	}
	bufferCharge, invocationCharge, err := ledgerv4.SQLiteAdmissionCharges(recordBytes)
	if err != nil {
		t.Fatal(err)
	}
	buffers, invocation := reserve(254, bufferCharge), reserve(255, invocationCharge)
	type serverResult struct {
		admission *SessionAdmissionReservation
		core      *SessionCore
		session   *EnvironmentSession
		err       error
	}
	serverDone := make(chan serverResult, 1)
	serverAccepted := make(chan struct{})
	var server serverResult
	var client *SessionCore
	var clientSession *EnvironmentSession
	var controller *ConnectionController
	var initialized atomic.Uint32
	initializeFailure := errors.New("test application registration outcome unknown")
	controllerConnect := func(pool *PoolSessionInput, live *LiveSessionInput) (*EnvironmentSession, error) {
		var completionGate *CompletionTask
		var completionRelease chan struct{}
		if completionBlocked {
			completionRelease = make(chan struct{})
			entered := make(chan struct{})
			future, err := executor.ReserveCompletion(reserve(450, executor.CompletionCharge()), f.environment)
			if err != nil {
				t.Fatal(err)
			}
			completionGate, err = future.Submit(func() error { close(entered); <-completionRelease; return nil })
			if err != nil {
				t.Fatal(err)
			}
			<-entered
			defer func() { close(completionRelease); _ = completionGate.Wait(context.Background()) }()
		}
		controller = controllerForTest(t, f, host, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 65536,
			Executor: executor, InitializeClass: ApplicationResident,
			Source: controllerSourceFunc(func(_ context.Context, request ControllerRequest) (*ControllerPreparation, error) {
				if request.Attempt != 1 {
					return nil, cryptov4.ErrConfiguration
				}
				return &ControllerPreparation{Config: sourceConfig, Pool: pool, Live: live}, nil
			}),
			InitializeSession: func(initCtx context.Context, candidate *EnvironmentSession) error {
				initialized.Add(1)
				if _, err := candidate.Core(); err != nil {
					return err
				}
				if _, err := controller.CaptureSession(); !errors.Is(err, ErrControllerInitialization) {
					t.Error("initializer candidate published prematurely", err)
				}
				if _, err := checkApplicationContext(initCtx); err != nil {
					t.Error("initializer bypassed ordinary context", err)
				}
				if _, err := controller.WaitForSession(initCtx); !errors.Is(err, ErrApplicationDependency) {
					t.Error("initializer could wait on its own publication", err)
				}
				if err := controller.WaitCleanup(initCtx); !errors.Is(err, ErrApplicationDependency) {
					t.Error("initializer could wait on its own cleanup", err)
				}
				if _, err := controller.ReplaceSession(initCtx, ControllerReplaceOptions{}); !errors.Is(err, ErrApplicationDependency) {
					t.Error("initializer could acquire recursively", err)
				}
				if failInitialize {
					// Ensure the original peer has delivered before deliberately
					// failing initialization and closing the private candidate.
					select {
					case <-serverAccepted:
					case <-initCtx.Done():
						return context.Cause(initCtx)
					}
					return initializeFailure
				}
				if lateInitialize {
					cancelConnect()
					waitController(t, controller, func(s ControllerSnapshot) bool { return s.LastError != nil })
				}
				if closeCandidate || expireCandidate {
					if closeCandidate {
						candidate.Close()
					} else {
						f.trust.tick.Add(100000)
					}
					select {
					case <-initCtx.Done():
					case <-time.After(time.Second):
						t.Error("candidate lifetime did not cancel initializer")
					}
				}
				if completionBlocked {
					cancelConnect()
					waitController(t, controller, func(s ControllerSnapshot) bool { return s.LastError != nil })
				}
				return nil
			}})
		result, err := controller.ReplaceSession(connectContext, ControllerReplaceOptions{})
		if err == nil {
			if !result.CurrentSwitched || result.Previous != nil {
				t.Error("invalid first publication", result)
			}
			captured, captureErr := controller.CaptureSession()
			if captureErr != nil || captured != result.Current {
				t.Error("current changed identity", captureErr)
			}
		}
		return result.Current, err
	}
	run := func(store *ledgerv4.SQLiteStore, authority ledgerv4.SQLiteAdmissionAuthority, connect func() (*SessionCore, error)) error {
		t.Cleanup(func() {
			if server.session != nil {
				server.session.Close()
				if err := server.session.WaitPhysicalCleanup(context.Background()); err != nil {
					t.Error(err)
					return
				}
			}
			if server.admission != nil {
				server.admission.Close()
				if err := server.admission.WaitCleanup(context.Background()); err != nil {
					t.Error(err)
				}
				if err := server.admission.Retire(); err != nil {
					t.Error(err)
				}
			}
		})
		go func() {
			accepted := AcceptedSessionInput{Entrance: e, Config: serverConfig, Root: f.root, ResourceOwner: admissionResourceKey(f.owner, 256), Environment: f.environment, Preauth: f.preauth, Scope: serverScope, Store: store, Authority: authority, Owner: ledgerv4.AdmissionOwner{Acceptor: [16]byte{1}, Invocation: [16]byte{2}, Carrier: [16]byte{3}, Generation: 1}, Buffers: buffers, Invocation: invocation}
			var session *EnvironmentSession
			var err error
			if viaIntake {
				c := AcceptedIntakeConfig{Input: accepted, Limits: limits, RuntimeBytes: 8192, Dependencies: f.environment,
					Establishment: reserve(253, planCharge), Subscriptions: reserve(297, protocolv4.CredentialSubscriptionsCharge()),
					Resolver: acceptedResolverFunc(func(context.Context, []byte) (*ConnectionMaterial, InitialHello, error) {
						return materials[1], InitialHello{Index: 0, Attempt: f.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}, nil
					})}
				charge, chargeErr := AcceptedIntakeCharge(c)
				if chargeErr != nil {
					serverDone <- serverResult{err: chargeErr}
					return
				}
				c.Reservation = reserve(310, charge)
				if viaIngress {
					ingress := AcceptedIngressConfig{Intake: c, RuntimeBytes: 8192, Dependencies: f.environment,
						Factory: acceptedIngressFactoryFunc(func(call context.Context, deadline *timev4.Deadline) (*AcceptedEntrance, error) {
							config := acceptedTestConfig(f)
							config.Initial.Deadline = deadline
							return NewAcceptedStream(call, config, &acceptedPipe{Conn: right, winner: f.trust.candidate, environment: f.environment}, f.root, admissionResourceKey(f.owner, 251), f.environment)
						})}
					cost, chargeErr := AcceptedIngressCharge(ingress)
					if chargeErr != nil {
						serverDone <- serverResult{err: chargeErr}
						return
					}
					ingress.Reservation = reserve(315, cost)
					if viaServe {
						child, beginErr := group.BeginIngress()
						if beginErr != nil {
							serverDone <- serverResult{err: beginErr}
							return
						}
						defer child.Release()
						ingress.Intake.Input.Owner = ledgerv4.AdmissionOwner{}
						session, err = child.Accept(connectContext, ingress)
					} else {
						session, err = host.AcceptIngress(connectContext, ingress)
					}
				} else {
					session, err = host.AcceptIntake(connectContext, c)
				}
			} else {
				var input [16384]byte
				if _, err := e.ReadClientHello(input[:]); err != nil {
					e.Close()
					serverDone <- serverResult{err: err}
					return
				}
				accepted.Establishment, accepted.Subscriptions = plans[1], f.trust.subscriptions[1]
				session, err = host.Accept(connectContext, accepted)
			}
			if err != nil {
				serverDone <- serverResult{err: err}
				return
			}
			close(serverAccepted)
			if failInitialize {
				// Force the late peer observation that previously replaced the
				// client's original initialization error with Core's ErrClosed.
				_ = session.WaitTermination(ctx)
			}
			core, err := session.Core()
			session.mu.Lock()
			sa := session.admission
			session.mu.Unlock()
			serverDone <- serverResult{admission: sa, core: core, session: session, err: err}
		}()
		var err error
		client, err = connect()
		server = <-serverDone
		if failInitialize && !errors.Is(server.err, cryptov4.ErrClosed) {
			t.Error("late peer observation did not exercise candidate closure", server.err)
		}
		// Both original owners are collected before selecting the client's
		// result. A later peer observation cannot replace that operation error.
		if err != nil {
			return err
		}
		if server.err != nil {
			return server.err
		}
		if err == nil {
			info := clientSession.Info()
			if info.ApplicationProfile != protocolv4.V4ApplicationProfileTransport || info.SelectedFeatures != 0 || info.Guarantees.ReliableProgress != protocolv4.V4ReliableProgressSharedOrdered || info.Guarantees.BoundStreamInputIsolation != protocolv4.V4BoundStreamInputIsolationSharedFailureScope || info.Guarantees.Datagram || info.Guarantees.LocalConsumerTls13Verification != protocolv4.V4ConsumerTLS13VerificationConsumerEnforced {
				t.Errorf("incorrect delivered guarantee projection: %+v", info)
			}
		}
		return err
	}
	if source == "preauthorized_pool" {
		_, err = consumeSessionPool(t, f, a, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
			return nil, run(store, authority, func() (*SessionCore, error) {
				var err error
				if viaController {
					clientSession, err = controllerConnect(&PoolSessionInput{Store: store, Authority: authority, Consume: work}, nil)
				} else if viaStatic {
					clientSession, err = host.ConnectMaterialPool(connectContext, materials[0], MaterialConnectConfig(sourceConfig), PoolSessionInput{Store: store, Authority: authority, Consume: work})
				} else if viaSource {
					clientSession, err = host.ConnectSourcePool(connectContext, sourceConfig, PoolSessionInput{Store: store, Authority: authority, Consume: work})
				} else {
					clientSession, err = host.ConnectPool(connectContext, PoolSessionInput{Establishment: plans[0], Admission: a, Store: store, Authority: authority, Consume: work})
				}
				if err != nil {
					return nil, err
				}
				return clientSession.Core()
			})
		})
	} else {
		issuanceCharge, e := protocolv4.LiveActivationPlanCharge()
		if e != nil {
			t.Fatal(e)
		}
		issuance, e := protocolv4.NewLiveActivationPlan(f.trust.artifact, f.trust.rules, f.trust.delegation, f.trust.once, f.trust.issueSigner, protocolv4.LiveActivationConfig{Index: 0, Attempt: f.trust.attempt, IssuedAt: 1150, ActivationEnd: 1400, SessionEnd: 4000}, reserve(257, issuanceCharge), f.environment, f.preauth)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if e := issuance.Close(); e != nil {
				t.Error(e)
			}
		})
		fields, _, e := issuance.CopyProjection(make([]byte, 4096))
		if e != nil {
			t.Fatal(e)
		}
		authority := liveSQLiteAuthority{acceptedSQLiteAuthority: acceptedSQLiteAuthority{identity: ledgerv4.SQLiteIdentity{Authority: fields.Authority, StoreID: [32]byte{3}, Generation: 1}}, original: fields}
		credential, e := f.trust.artifact.DetachCredential()
		if e != nil {
			t.Fatal(e)
		}
		guard := func() error {
			now, e := f.trust.clock.Sample()
			if e != nil {
				return e
			}
			return issuance.CheckTrust(f.trust.namespace, credential, f.trust.trust.permissions[0], 5000, 59000, 4000, now.Interval)
		}
		callbacks := 0
		err = withSessionSQLite(t, f, a, authority.identity, authority, recordBytes, func(store *ledgerv4.SQLiteStore, reserve func(uint32, resourcev4.Vector) resourcev4.Reference) error {
			ownerCharge, invokeCharge, e := ledgerv4.SQLiteLiveSpendCharges(recordBytes)
			if e != nil {
				return e
			}
			ownerBuffer, invocation := reserve(242, ownerCharge), reserve(243, invokeCharge)
			return run(store, authority, func() (*SessionCore, error) {
				var err error
				input := LiveSessionInput{Store: store, Authority: authority, Issuance: issuance, Owner: ledgerv4.LiveSpendOwner{Invocation: [16]byte{1}, Generation: 1, RequestDigest: [32]byte{2}, ClientMaterialNotAfter: 1400}, Guard: guard, Policy: func(context.Context) (bool, error) { callbacks++; return true, nil }, Buffers: ownerBuffer, Invocation: invocation}
				if viaControl {
					original := input
					control := LiveControlConfig{RuntimeBytes: 65536, Provider: liveAuthorizationProviderFunc(func(call context.Context, request LiveAuthorizationRequest, dst []byte) (int, error) {
						if request.AttemptNo != 1 || request.Tenant != fields.Tenant || request.Issuer != fields.Issuer || request.Lease != fields.Lease || request.Attempt != fields.Attempt || request.Artifact != fields.Artifact || request.Winner != fields.Winner || request.ClientIdentity != fields.ClientIdentity || request.ServerIdentity != fields.ServerIdentity || request.Audience != fields.Audience || request.CryptoProfile != fields.Profile || request.ActivationNotAfterMS == 0 {
							return 0, ledgerv4.ErrConflict
						}
						durable, err := ledgerv4.NewSQLiteLiveSpend(call, store, authority, issuance, original.Owner, f.trust.clock, f.config.Initial.Deadline, guard, ownerBuffer, invocation, f.environment)
						if err != nil {
							return 0, err
						}
						defer func() {
							if err := durable.Cleanup(); err != nil {
								t.Error(err)
							}
						}()
						n := 0
						err = durable.Authorize(original.Policy, func(_ context.Context, proof []byte) error { n = copy(dst, proof); return nil })
						return n, err
					})}
					cost, costErr := LiveControlCharge(control)
					if costErr != nil {
						return nil, costErr
					}
					input = LiveSessionInput{Control: control, Buffers: reserve(259, cost)}
					var material *ConnectionMaterial
					if viaStatic {
						material = materials[0]
					}
					clientSession, _, err = host.ConnectPrepared(connectContext, sourceConfig, material, nil, &input)
				} else if viaSource {
					sourceConfig.LiveIssuance = SourceLiveIssuance{Signer: f.trust.issueSigner, IssuedAt: 1150, ActivationEnd: 1400, SessionEnd: 4000, Reservation: reserve(258, issuanceCharge)}
					input.Issuance = nil
					if viaController {
						clientSession, err = controllerConnect(nil, &input)
					} else if viaStatic {
						clientSession, err = host.ConnectMaterialLiveSQLite(connectContext, materials[0], MaterialConnectConfig(sourceConfig), input)
					} else {
						clientSession, err = host.ConnectSourceLiveSQLite(connectContext, sourceConfig, input)
					}
				} else {
					input.Establishment, input.Admission = plans[0], a
					clientSession, err = host.ConnectLiveSQLite(connectContext, input)
				}
				if err != nil {
					return nil, err
				}
				return clientSession.Core()
			})
		})
		if callbacks != 1 {
			t.Fatal("policy invocation count", callbacks, err)
		}
	}
	if viaController && (failInitialize || lateInitialize || closeCandidate || expireCandidate || completionBlocked) {
		if err == nil || initialized.Load() != 1 {
			t.Fatal("failed initializer published or was repeated", err, initialized.Load())
		}
		if failInitialize && !errors.Is(err, initializeFailure) {
			t.Fatal("original initialization error lost", err)
		}
		if _, captureErr := controller.CaptureSession(); !errors.Is(captureErr, ErrControllerInitialization) {
			t.Fatal("failure reopened publication", captureErr)
		}
		if retryErr := controller.RetryNow(context.Background()); !errors.Is(retryErr, ErrControllerInitialization) {
			t.Fatal("RetryNow replayed initialization", retryErr)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if viaController && initialized.Load() != 1 {
		t.Fatal("initializer count", initialized.Load())
	}
	cancelConnect()
	if client == nil || server.core == nil {
		t.Fatal("READY did not deliver both original Sessions")
	}

	if got := host.DiagnosticCounts(diagnosticv4.MetricConnectionAttempt).Total; got != 2 {
		t.Fatal("preparation handoffs changed the original attempt count", got)
	}
	if got := host.DiagnosticCounts(diagnosticv4.MetricConnectionFailure).Total; got != 0 {
		t.Fatal("successful READY reported a failure", got)
	}
	for _, established := range []*SessionCore{client, server.core} {
		engine := established.Engine()
		// Exercise the ordinary authenticated engine composition: the backing
		// is the same originally charged bank, not a copied counter value.
		if established.plan.diagnostics != &host.counters || engine == nil || established.Admission().diagnostics != &host.counters {
			t.Fatal("original Environment diagnostics not bound through READY")
		}
	}

	fixtures := [2]initialCoreFixture{{root: f.root, next: 70}, {root: f.root, next: 90}}
	l, r := client.Admission(), server.core.Admission()
	h, result, err := l.OpenLocal(ctx, BusinessStream, "example/raw", nil, &CarrierAssociation{shared: l.sharedIngress}, fixtures[0].streamReservation(t, client), streamTestDeadline(t, client.Engine()))
	if err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	peer := OpenHandle{r, h.scope}
	waitCoreOpen(t, r, peer, true)
	if _, err := r.Decide(ctx, peer, BusinessStream, "", fixtures[1].streamReservation(t, server.core), r.termination.writer); err != nil {
		t.Fatal(err)
	}
	waitCoreOpen(t, l, h, false)
	lf, err := l.Flow(h)
	if err != nil {
		t.Fatal(err)
	}
	rf, err := r.Flow(peer)
	if err != nil {
		t.Fatal(err)
	}
	var draining *DrainOperation
	if viaServe {
		draining, err = group.Drain(0, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, direction := range []struct {
		source, target *StreamFlow
		body           string
	}{{lf, rf, "consumer payload"}, {rf, lf, "accepted reply"}} {
		if n, err := direction.source.send.queueOwner.Write(ctx, []byte(direction.body)); err != nil || n != len(direction.body) {
			t.Fatal(n, err)
		}
		var dst [64]byte
		read, err := direction.target.receive.ReadInto(ctx, dst[:])
		if err != nil || string(dst[:read.Progress.Filled]) != direction.body {
			t.Fatal(read, err)
		}
	}
	if viaServe {
		for _, flow := range []*StreamFlow{lf, rf} {
			if err := flow.send.queueOwner.CloseWrite(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for _, flow := range []*StreamFlow{lf, rf} {
			if err := flow.send.queueOwner.Finish(ctx); err != nil {
				t.Fatal(err)
			}
		}
		result, err := draining.Wait(ctx)
		if err != nil || result.Outcome != Drained {
			t.Fatal(result, err)
		}
		if err := group.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
		host.mu.Lock()
		closed := host.closed
		host.mu.Unlock()
		if closed {
			t.Fatal("Serve closed borrowed Environment")
		}
	}
	clientSession.Close()
	host.Close()
	if err := host.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := clientSession.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if viaApplication {
		for role := range 2 {
			if authorized[role].Load() != 1 || released[role].Load() != 1 {
				t.Fatal("application lifecycle", role, authorized[role].Load(), released[role].Load())
			}
		}
	}
	for role := range 2 {
		identities[role].Close()
		if err := materials[role].WaitCleanup(ctx); err != nil {
			t.Fatal("material retained after physical Session cleanup", err)
		}
		if err := identities[role].WaitCleanup(ctx); err != nil {
			t.Fatal("identity retained after physical Session cleanup", err)
		}
		if err := leases[role].WaitCleanup(ctx); err != nil {
			t.Fatal("lease retained after physical Session cleanup", err)
		}
	}
	if err := f.environment.Check(); err != nil {
		t.Fatal("host closed a borrowed dependency", err)
	}
}

func TestSessionApplicationSourcesToAdmissionReadyAndDuplex(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) { sessionEstablishmentDuplex(t, source, true, true, true, true, true) })
	}
}
