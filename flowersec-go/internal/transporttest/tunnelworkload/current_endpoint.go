package tunnelworkload

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest/linuxnetlab"
)

const currentTunnelNamespace = "flowersec.engineering.tunnel"
const releaseRunnerOrigin = "https://release-runner.flowersec.invalid"
const poolRelayAddressRetryLimit = 4
const preparedCleanupTimeout = 10 * time.Second

// Endpoint has a finite table of original tunnel positions. Each Connect owns
// real PoolService issuance, independent consumer stores, two native carriers,
// authenticated server allowance, HOP_AUTH, Noise and READY. It publishes no
// reconstructed admission result and performs no reconnect or business replay.
type Endpoint struct {
	mu                                sync.Mutex
	topology                          Topology
	listenHost                        string
	operationDeadlineMS               uint64
	ctx                               context.Context
	cancel                            context.CancelCauseFunc
	endpointNamespace, relayNamespace string
	slots                             []*Pair
	building                          []bool
	construction                      sync.WaitGroup
	constructionDone                  chan struct{}
	closed                            bool
	preparedTunnels                   []*preparedTunnel
	pendingPreparedTunnels            []*preparedTunnel
	capacityPreparing                 bool
	capacityPrepared                  bool
}

// Only the original public Session owners implement this production projection.
// Application bulk tests can supply I/O without constructing a protocol engine.
type tunnelSession interface {
	OpenStream(context.Context, string, fs.StreamMetadata) (fs.Stream, error)
	AcceptStream(context.Context) (fs.AcceptedStream, error)
	UnreliableMessages() (fs.UnreliableMessageChannel, error)
	ProbeLiveness(context.Context, uint64) (fs.LivenessResult, error)
	WaitTermination(context.Context) error
	WaitCleanup(context.Context) error
	Close() error
}

type preparedTunnel struct {
	relay                          *interopharness.PoolRelay
	server                         *interopharness.TunnelServer
	client                         *interopharness.Client
	serverReporter, clientReporter *interopharness.Reporter
	relayReporter                  *interopharness.Reporter
	definition                     *interopharness.RPCDefinition
	call                           context.Context
	cancel                         context.CancelCauseFunc
	cleanupWaiters                 []func(context.Context) error
	mu                             sync.Mutex
	closing, cleaning, cleaned     bool
	cleanupDone                    chan struct{}
	closeErr                       error
}

func waitRelayOwners(relay *interopharness.PoolRelay) func(context.Context) error {
	return func(cleanup context.Context) error {
		if relay == nil {
			return nil
		}
		relay.CloseOwners()
		return relay.WaitOwners(cleanup)
	}
}

func waitReporterOwners(reporter *interopharness.Reporter) func(context.Context) error {
	return func(cleanup context.Context) error {
		if reporter == nil {
			return nil
		}
		reporter.CloseOwners()
		return reporter.WaitOwners(cleanup)
	}
}

func preparedCleanupContext() (context.Context, context.CancelFunc) {
	// Cleanup must outlive the construction caller's cancellation so physical
	// owners get a bounded chance to close. If that bound expires, the owner is
	// retained for a later retry instead of being refunded by reporter cleanup.
	return context.WithTimeout(context.Background(), preparedCleanupTimeout)
}

func (prepared *preparedTunnel) isCleaned() bool {
	if prepared == nil {
		return true
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	return prepared.cleaned
}

func (prepared *preparedTunnel) close(cleanup context.Context) error {
	if prepared == nil {
		return nil
	}
	if cleanup == nil {
		return errors.New("original prepared tunnel cleanup context is required")
	}
	for {
		prepared.mu.Lock()
		if prepared.cleaned {
			err := prepared.closeErr
			prepared.mu.Unlock()
			return err
		}
		if prepared.cleaning {
			done := prepared.cleanupDone
			prepared.mu.Unlock()
			select {
			case <-done:
				continue
			case <-cleanup.Done():
				return cleanup.Err()
			}
		}
		prepared.cleaning = true
		prepared.cleanupDone = make(chan struct{})
		if !prepared.closing {
			prepared.closing = true
			if prepared.cancel != nil {
				prepared.cancel(context.Canceled)
			}
		}
		prepared.mu.Unlock()
		break
	}
	var waitErr error
	for _, wait := range prepared.cleanupWaiters {
		if wait != nil {
			waitErr = errors.Join(waitErr, wait(cleanup))
		}
	}
	var reporterErr error
	// A bounded physical wait failure leaves the reporters and their owners
	// live. Closing a reporter here would run one-shot cleanup and release the
	// reservation while a carrier or callback tail still exists.
	if cleanup.Err() == nil {
		if prepared.serverReporter != nil {
			reporterErr = errors.Join(reporterErr, prepared.serverReporter.Close())
		}
		if prepared.clientReporter != nil {
			reporterErr = errors.Join(reporterErr, prepared.clientReporter.Close())
		}
		if prepared.relayReporter != nil {
			reporterErr = errors.Join(reporterErr, prepared.relayReporter.Close())
		}
	}
	prepared.mu.Lock()
	prepared.closeErr = errors.Join(prepared.closeErr, reporterErr)
	prepared.cleaning = false
	if waitErr == nil {
		prepared.cleaned = true
	}
	close(prepared.cleanupDone)
	result := errors.Join(waitErr, prepared.closeErr)
	prepared.mu.Unlock()
	return result
}

// retainPreparedCleanup moves a prepared deployment out of the connectable
// queue while any physical owner is still live. The original finite position
// remains occupied until a later close retry observes actual cleanup.
func (e *Endpoint) retainPreparedCleanup(prepared *preparedTunnel) {
	if e == nil || prepared == nil || prepared.isCleaned() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for index, current := range e.preparedTunnels {
		if current == prepared {
			e.preparedTunnels = append(e.preparedTunnels[:index], e.preparedTunnels[index+1:]...)
			break
		}
	}
	for _, current := range e.pendingPreparedTunnels {
		if current == prepared {
			return
		}
	}
	e.pendingPreparedTunnels = append(e.pendingPreparedTunnels, prepared)
}

func (e *Endpoint) removePrepared(prepared *preparedTunnel) {
	if e == nil || prepared == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for index, current := range e.preparedTunnels {
		if current == prepared {
			e.preparedTunnels = append(e.preparedTunnels[:index], e.preparedTunnels[index+1:]...)
			break
		}
	}
	for index, current := range e.pendingPreparedTunnels {
		if current == prepared {
			e.pendingPreparedTunnels = append(e.pendingPreparedTunnels[:index], e.pendingPreparedTunnels[index+1:]...)
			break
		}
	}
}

type Pair struct {
	Client, Server tunnelSession
	echo           *fs.ServiceClient
	endpoint       *Endpoint
	position       int
	reporters      []*interopharness.Reporter
	// Physical owners whose cleanup is normally registered on a Reporter. Keep
	// direct joiners as well so a bounded first cleanup can be retried against
	// the still-live owner instead of reducing a historical reporter error to a
	// false-clean slot.
	cleanupWaiters             []func(context.Context) error
	mu                         sync.Mutex
	closing, cleaning, cleaned bool
	cleanupDone                chan struct{}
	cancel                     context.CancelCauseFunc
	closeErr                   error
}

func OpenEndpointAt(ctx context.Context, topology Topology, listenHost string) (*Endpoint, error) {
	return openCurrentEndpoint(ctx, topology, listenHost, 128)
}
func OpenTestEndpointAt(ctx context.Context, topology Topology, listenHost string, plan transporttest.ProfilePlan) (*Endpoint, error) {
	if plan.Cold.OperationDeadlineSeconds < 1 || plan.Cold.PhaseDeadlineSeconds < plan.Cold.OperationDeadlineSeconds || plan.Cold.MaxInflight < 1 {
		return nil, errors.New("invalid original tunnel profile deadlines or positions")
	}
	if plan.Cold.OperationDeadlineSeconds > 90 {
		return nil, errors.New("tunnel operation exceeds the original supported preparation window")
	}
	endpoint, err := openCurrentEndpoint(ctx, topology, listenHost, plan.Cold.MaxInflight)
	if err != nil {
		return nil, err
	}
	endpoint.operationDeadlineMS = uint64(plan.Cold.OperationDeadlineSeconds) * 1000
	return endpoint, nil
}
func OpenCapacityEndpointAt(ctx context.Context, topology Topology, listenHost string, sessions int) (*Endpoint, error) {
	if sessions != 100 && sessions != 1000 {
		return nil, errors.New("tunnel capacity must be an exact supported session count")
	}
	return openCurrentEndpoint(ctx, topology, listenHost, sessions)
}
func openCurrentEndpoint(ctx context.Context, topology Topology, listenHost string, positions int) (*Endpoint, error) {
	if ctx == nil || positions < 1 || positions > 1000 {
		return nil, errors.New("original tunnel context and finite position count are required")
	}
	if _, _, err := topology.Carriers(); err != nil {
		return nil, err
	}
	host, err := netip.ParseAddr(listenHost)
	if err != nil || host.IsUnspecified() || host.IsMulticast() || host.Zone() != "" {
		return nil, errors.New("tunnel requires one explicit numeric unicast host")
	}
	owner, cancel := context.WithCancelCause(ctx)
	return &Endpoint{topology: topology, listenHost: host.String(), ctx: owner, cancel: cancel, slots: make([]*Pair, positions), building: make([]bool, positions), constructionDone: make(chan struct{})}, nil
}
func (e *Endpoint) SetEndpointDialNamespace(namespace string) error {
	return e.setNamespace(namespace, false)
}
func (e *Endpoint) SetRelayNamespace(namespace string) error { return e.setNamespace(namespace, true) }
func (e *Endpoint) setNamespace(namespace string, relay bool) error {
	if e == nil || namespace == "" {
		return errors.New("explicit network namespace is required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errEndpointClosed
	}
	if e.capacityPreparing || e.capacityPrepared {
		return errors.New("network scope is frozen before original tunnel preparation")
	}
	for i := range e.slots {
		if e.slots[i] != nil || e.building[i] {
			return errors.New("network scope is frozen before original tunnel construction")
		}
	}
	if relay {
		e.relayNamespace = namespace
	} else {
		e.endpointNamespace = namespace
	}
	return nil
}

// PrepareCapacity constructs independent original pool deployments and peer
// runtimes before a capacity ramp begins. Connect still performs the live
// carrier handshake, admission spend, HOP_AUTH, Noise, and READY steps.
func (e *Endpoint) PrepareCapacity(ctx context.Context, sessions int) error {
	if e == nil || ctx == nil || sessions < 1 {
		return errors.New("original tunnel capacity preparation is invalid")
	}
	carrierA, carrierB, err := e.topology.Carriers()
	if err != nil {
		return err
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errEndpointClosed
	}
	if sessions > len(e.slots) || e.capacityPreparing || e.capacityPrepared || len(e.pendingPreparedTunnels) != 0 {
		e.mu.Unlock()
		return errors.New("tunnel capacity preparation requires unused finite positions")
	}
	for i := range e.slots {
		if e.slots[i] != nil || e.building[i] {
			e.mu.Unlock()
			return errors.New("tunnel capacity preparation must precede original connections")
		}
	}
	need := sessions
	e.capacityPreparing = true
	listenHost := e.listenHost
	operationDeadlineMS := e.operationDeadlineMS
	endpointScope := namespaceSocketScope(e.endpointNamespace)
	relayScope := namespaceSocketScope(e.relayNamespace)
	e.construction.Add(1)
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.capacityPreparing = false
		e.mu.Unlock()
		e.construction.Done()
	}()

	carriers := [2]string{relayCarrier(carrierA), relayCarrier(carrierB)}
	type preparationResult struct {
		item *preparedTunnel
		err  error
	}
	jobs := make(chan struct{}, need)
	for range need {
		jobs <- struct{}{}
	}
	close(jobs)
	results := make(chan preparationResult, need)
	workerCount := min(4, need)
	var group sync.WaitGroup
	for range workerCount {
		group.Add(1)
		go func() {
			defer group.Done()
			for range jobs {
				if err := ctx.Err(); err != nil {
					results <- preparationResult{err: context.Cause(ctx)}
					return
				}
				prepared := &preparedTunnel{}
				prepared.call, prepared.cancel = context.WithCancelCause(e.ctx)
				callCancelDone := make(chan struct{})
				stopCallCancel := context.AfterFunc(ctx, func() {
					defer close(callCancelDone)
					prepared.cancel(context.Cause(ctx))
				})
				var buildErr error
				for attempt := 0; attempt < poolRelayAddressRetryLimit; attempt++ {
					if err := ctx.Err(); err != nil {
						buildErr = context.Cause(ctx)
						break
					}
					prepared.relayReporter, buildErr = interopharness.NewPeerReporter()
					if buildErr == nil {
						prepared.relayReporter.OperationDeadlineMS = operationDeadlineMS
						prepared.relay, buildErr = interopharness.NewPoolRelay(prepared.call, prepared.relayReporter, carriers, releaseRunnerOrigin, interopharness.PoolRelayOptions{EndpointListeners: [2]bool{false, false}, ListenHost: listenHost, SocketScope: relayScope})
						if prepared.relay != nil {
							prepared.cleanupWaiters = append(prepared.cleanupWaiters, waitRelayOwners(prepared.relay))
						}
					}
					if prepared.relayReporter != nil {
						// Keep every reporter acquired for an address attempt. A
						// retry may close the reporter's diagnostics, but its physical
						// owners still need the same bounded, retryable join. Register
						// it after the relay waiter so runtime shutdown cannot wait on
						// an owner whose carrier has not been closed yet.
						prepared.cleanupWaiters = append(prepared.cleanupWaiters, waitReporterOwners(prepared.relayReporter))
					}
					if buildErr == nil || !errors.Is(buildErr, syscall.EADDRINUSE) || attempt+1 == poolRelayAddressRetryLimit {
						break
					}
					closeErr := prepared.relayReporter.Close()
					prepared.relayReporter = nil
					if closeErr != nil {
						buildErr = errors.Join(buildErr, closeErr)
						break
					}
					select {
					case <-prepared.call.Done():
						buildErr = context.Cause(prepared.call)
					case <-time.After(time.Duration(attempt+1) * 25 * time.Millisecond):
					}
					if buildErr != nil && !errors.Is(buildErr, syscall.EADDRINUSE) {
						break
					}
				}
				if buildErr == nil {
					prepared.serverReporter, buildErr = interopharness.NewPeerReporter()
					if prepared.serverReporter != nil {
						prepared.cleanupWaiters = append(prepared.cleanupWaiters, waitReporterOwners(prepared.serverReporter))
					}
				}
				if buildErr == nil {
					prepared.serverReporter.OperationDeadlineMS = operationDeadlineMS
					serverWire, wireErr := prepared.relay.Material[1].JSON()
					if wireErr != nil {
						buildErr = wireErr
					} else {
						prepared.server, buildErr = interopharness.NewTunnelServer(prepared.call, prepared.serverReporter, serverWire, prepared.relay.TrustPEM, prepared.relay.Origin, currentTunnelHandlers(nil), interopharness.TunnelServerOptions{SocketScope: endpointScope})
						if prepared.server != nil {
							prepared.cleanupWaiters = append(prepared.cleanupWaiters, func(cleanup context.Context) error {
								prepared.server.CloseOwners()
								return prepared.server.WaitOwners(cleanup)
							})
						}
					}
				}
				if buildErr == nil {
					clientWire, wireErr := prepared.relay.Material[0].JSON()
					if wireErr != nil {
						buildErr = wireErr
					} else {
						installed, binding, configErr := prepared.server.LocalPoolClientConfiguration()
						buildErr = configErr
						if buildErr == nil {
							prepared.clientReporter, buildErr = interopharness.NewPeerReporter()
							if prepared.clientReporter != nil {
								prepared.cleanupWaiters = append(prepared.cleanupWaiters, waitReporterOwners(prepared.clientReporter))
							}
							if buildErr == nil {
								prepared.clientReporter.OperationDeadlineMS = operationDeadlineMS
								prepared.client, buildErr = interopharness.NewClient(prepared.call, prepared.clientReporter, clientWire, prepared.relay.TrustPEM, prepared.relay.Origin, currentTunnelHandlers(&prepared.definition), interopharness.ClientOptions{DialScope: endpointScope, PoolClientDeployment: installed, ServerAllowBinding: binding})
								if prepared.client != nil {
									prepared.cleanupWaiters = append(prepared.cleanupWaiters, func(cleanup context.Context) error {
										prepared.client.CloseOwners()
										return prepared.client.WaitOwners(cleanup)
									})
								}
							}
						}
					}
				}
				callCancelStopped := stopCallCancel()
				if !callCancelStopped {
					<-callCancelDone
					if buildErr == nil {
						buildErr = context.Cause(ctx)
					}
				}
				if buildErr != nil {
					cleanup, cancelCleanup := preparedCleanupContext()
					cleanupErr := prepared.close(cleanup)
					cancelCleanup()
					var retained *preparedTunnel
					if !prepared.isCleaned() {
						retained = prepared
					}
					results <- preparationResult{item: retained, err: errors.Join(buildErr, cleanupErr)}
					continue
				}
				results <- preparationResult{item: prepared}
			}
		}()
	}
	group.Wait()
	close(results)
	prepared := make([]*preparedTunnel, 0, need)
	var preparationErr error
	for result := range results {
		preparationErr = errors.Join(preparationErr, result.err)
		if result.item != nil {
			prepared = append(prepared, result.item)
		}
	}
	if preparationErr != nil {
		cleanup, cancelCleanup := preparedCleanupContext()
		defer cancelCleanup()
		var retained []*preparedTunnel
		for _, item := range prepared {
			itemErr := item.close(cleanup)
			preparationErr = errors.Join(preparationErr, itemErr)
			if !item.isCleaned() {
				retained = append(retained, item)
			}
		}
		if len(retained) != 0 {
			for _, item := range retained {
				e.retainPreparedCleanup(item)
			}
		}
		return preparationErr
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		cleanup, cancelCleanup := preparedCleanupContext()
		defer cancelCleanup()
		var retained []*preparedTunnel
		for _, item := range prepared {
			itemErr := item.close(cleanup)
			preparationErr = errors.Join(preparationErr, itemErr)
			if !item.isCleaned() {
				retained = append(retained, item)
			}
		}
		if len(retained) != 0 {
			for _, item := range retained {
				e.retainPreparedCleanup(item)
			}
		}
		return errors.Join(errEndpointClosed, preparationErr)
	}
	// Keep any cleanup-only entries separate and never replace them with a
	// newly successful queue. The entry check above normally makes this list
	// empty, but append preserves ownership if a close raced this call.
	e.preparedTunnels = append(e.preparedTunnels, prepared...)
	e.capacityPrepared = true
	e.mu.Unlock()
	return nil
}

func namespaceSocketScope(namespace string) assemblyv4.NativeDialScope {
	if namespace == "" {
		return nil
	}
	return func(ctx context.Context, dial func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return linuxnetlab.InNamespace(namespace, dial)
	}
}
func currentTunnelHandlers(definition **interopharness.RPCDefinition) interopharness.HandlerConfig {
	return func(r *interopharness.Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
		rpc := interopharness.ConfigureRPC(r, role, currentTunnelNamespace, []interopharness.RPCMethod{{Type: 1, MaxEncodedBytes: 1 << 20, Handle: func(ctx context.Context, input []byte) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return append([]byte(nil), input...), nil
		}}})
		if definition != nil {
			*definition = rpc
		}
		maximum := r.Authority.Admission[role].Core.Open.PerClass[0]
		return fs.StreamHandlerPlanConfig{RuntimeBytes: 65536, Handlers: []fs.RawStreamHandlerConfig{{
			Kind: "release-tunnel-bulk", Manual: true, Slots: maximum, NormalTerminationMS: 5000,
			WorkClass: fs.WorkResident, AuthorizeOpen: func(ctx context.Context, _ any, _ []byte) error { return ctx.Err() },
		}}}, nil
	}
}
func (e *Endpoint) Connect(ctx context.Context) (_ *Pair, resultErr error) {
	if e == nil || ctx == nil {
		return nil, errors.New("original tunnel endpoint and context are required")
	}
	if e.ctx == nil {
		return nil, errEndpointClosed
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errEndpointClosed
	}
	if e.capacityPreparing || (e.capacityPrepared && len(e.preparedTunnels) == 0) || (!e.capacityPrepared && len(e.pendingPreparedTunnels) != 0) {
		e.mu.Unlock()
		return nil, errors.New("original prepared tunnel positions are unavailable")
	}
	position := -1
	for i := range e.slots {
		if e.slots[i] == nil && !e.building[i] {
			position = i
			break
		}
	}
	if position < 0 {
		e.mu.Unlock()
		return nil, errors.New("original tunnel position capacity is exhausted")
	}
	e.building[position] = true
	e.construction.Add(1)
	endpointScope, relayScope := namespaceSocketScope(e.endpointNamespace), namespaceSocketScope(e.relayNamespace)
	var prepared *preparedTunnel
	if len(e.preparedTunnels) != 0 {
		prepared = e.preparedTunnels[0]
		e.preparedTunnels = e.preparedTunnels[1:]
	}
	e.mu.Unlock()
	timeline := &establishmentTimeline{}
	pair := &Pair{endpoint: e, position: position}
	committed := false
	preparedTransferred := false
	defer func() {
		if !committed && prepared != nil && !preparedTransferred {
			cleanup, cancelCleanup := preparedCleanupContext()
			preparedErr := prepared.close(cleanup)
			cancelCleanup()
			resultErr = errors.Join(resultErr, preparedErr)
			if !prepared.isCleaned() {
				e.retainPreparedCleanup(prepared)
			}
		}
		if !committed {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resultErr = errors.Join(resultErr, pair.Close(cleanup))
			cancel()
		}
		if resultErr != nil {
			resultErr = fmt.Errorf("%w; establishment_stages=%s", resultErr, timeline.compact())
		}
		pair.mu.Lock()
		cleaned := pair.cleaned
		pair.mu.Unlock()
		e.mu.Lock()
		if !committed && !cleaned {
			e.slots[position] = pair
		}
		e.building[position] = false
		e.mu.Unlock()
		e.construction.Done()
	}()
	call, cancel := context.WithCancelCause(e.ctx)
	if prepared != nil {
		call, cancel = prepared.call, prepared.cancel
	}
	pair.cancel = cancel
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(stopped); cancel(context.Cause(ctx)) })
	defer func() {
		if !committed {
			cancel(context.Canceled)
		}
		if !stop() {
			<-stopped
		}
	}()
	reporter := func() (*interopharness.Reporter, error) {
		r, err := interopharness.NewPeerReporter()
		if err == nil {
			r.OperationDeadlineMS = e.operationDeadlineMS
			pair.reporters = append(pair.reporters, r)
		}
		return r, err
	}
	var relayReporter *interopharness.Reporter
	var err error
	carrierA, carrierB, err := e.topology.Carriers()
	if err != nil {
		return nil, err
	}
	carriers := [2]string{relayCarrier(carrierA), relayCarrier(carrierB)}
	// Both endpoints dial from their explicitly selected namespace to the actual
	// relay listeners. Both original legs traverse the kernel's configured path.
	var relay *interopharness.PoolRelay
	if prepared != nil {
		relay = prepared.relay
		timeline.record(2, "", carrierA, "pool_issuance_prepared", time.Now(), time.Now(), nil)
	} else {
		for attempt := 0; attempt < poolRelayAddressRetryLimit; attempt++ {
			relayReporter, err = reporter()
			if err != nil {
				return nil, err
			}
			issuedAt := time.Now()
			relay, err = interopharness.NewPoolRelay(call, relayReporter, carriers, releaseRunnerOrigin, interopharness.PoolRelayOptions{EndpointListeners: [2]bool{false, false}, ListenHost: e.listenHost, SocketScope: relayScope})
			if relay != nil {
				pair.cleanupWaiters = append(pair.cleanupWaiters, waitRelayOwners(relay))
			}
			pair.cleanupWaiters = append(pair.cleanupWaiters, waitReporterOwners(relayReporter))
			timeline.record(2, "", carrierA, "pool_issuance", issuedAt, time.Now(), err)
			if err == nil {
				break
			}
			if !errors.Is(err, syscall.EADDRINUSE) || attempt+1 == poolRelayAddressRetryLimit {
				return nil, err
			}
			closeErr := relayReporter.Close()
			relayReporter = nil
			if closeErr != nil {
				return nil, errors.Join(err, closeErr)
			}
			wait := time.NewTimer(time.Duration(attempt+1) * 25 * time.Millisecond)
			select {
			case <-call.Done():
				if !wait.Stop() {
					<-wait.C
				}
				return nil, context.Cause(call)
			case <-wait.C:
			}
		}
	}
	clientWire, err := relay.Material[0].JSON()
	if err != nil {
		return nil, err
	}
	serverWire, err := relay.Material[1].JSON()
	if err != nil {
		return nil, err
	}
	var server *interopharness.TunnelServer
	var client *interopharness.Client
	var definition *interopharness.RPCDefinition
	if prepared != nil {
		server, client, definition = prepared.server, prepared.client, prepared.definition
		pair.reporters = append(pair.reporters, prepared.relayReporter, prepared.serverReporter, prepared.clientReporter)
		pair.cleanupWaiters = append(pair.cleanupWaiters, prepared.cleanupWaiters...)
		prepared.cleanupWaiters = nil
		preparedTransferred = true
	} else {
		serverReporter, reporterErr := reporter()
		if reporterErr != nil {
			return nil, reporterErr
		}
		pair.cleanupWaiters = append(pair.cleanupWaiters, waitReporterOwners(serverReporter))
		server, err = interopharness.NewTunnelServer(call, serverReporter, serverWire, relay.TrustPEM, relay.Origin, currentTunnelHandlers(nil), interopharness.TunnelServerOptions{SocketScope: endpointScope})
		if server != nil {
			pair.cleanupWaiters = append(pair.cleanupWaiters, func(cleanup context.Context) error {
				server.CloseOwners()
				return server.WaitOwners(cleanup)
			})
		}
		if err != nil {
			return nil, err
		}
		clientReporter, reporterErr := reporter()
		if reporterErr != nil {
			return nil, reporterErr
		}
		pair.cleanupWaiters = append(pair.cleanupWaiters, waitReporterOwners(clientReporter))
		installed, binding, configErr := server.LocalPoolClientConfiguration()
		if configErr != nil {
			return nil, configErr
		}
		client, err = interopharness.NewClient(call, clientReporter, clientWire, relay.TrustPEM, relay.Origin, currentTunnelHandlers(&definition), interopharness.ClientOptions{DialScope: endpointScope, PoolClientDeployment: installed, ServerAllowBinding: binding})
		if client != nil {
			pair.cleanupWaiters = append(pair.cleanupWaiters, func(cleanup context.Context) error {
				client.CloseOwners()
				return client.WaitOwners(cleanup)
			})
		}
		if err != nil {
			return nil, err
		}
	}
	relay.Start()
	type acceptance struct {
		session *fs.Session
		err     error
	}
	accepted := make(chan acceptance, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		session, err := server.Accept(call)
		accepted <- acceptance{session, err}
	}()
	connectedAt := time.Now()
	connected, connectErr := client.Connect(call)
	timeline.record(0, "", carrierA, "client_connect", connectedAt, time.Now(), connectErr)
	if connected != nil {
		pair.Client = connected
	}
	if connectErr != nil {
		cancel(connectErr)
	}
	result := <-accepted
	<-acceptDone
	if result.session != nil {
		pair.Server = result.session
	}
	if err = errors.Join(connectErr, result.err); err != nil {
		return nil, err
	}
	pair.echo, err = definition.Bind(call, connected)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errEndpointClosed
	}
	e.slots[position] = pair
	committed = true
	e.mu.Unlock()
	return pair, nil
}
func callTunnelEcho(ctx context.Context, echo *fs.ServiceClient, input []byte) ([]byte, error) {
	if echo == nil {
		return nil, errors.New("original tunnel service binding is required")
	}
	op, err := echo.PrepareMethod(ctx, fs.MethodSelector{Namespace: currentTunnelNamespace, Type: 1}, input, fs.OperationOptions{DefaultLifetimeMS: 30000})
	if err != nil {
		return nil, err
	}
	started := op.StartContext(ctx)
	if started.Err != nil {
		op.Close()
		return nil, started.Err
	}
	result, resultErr := op.TakeResultContext(ctx)
	op.Close()
	cleanupErr := op.WaitCleanup(ctx)
	return append([]byte(nil), result.Payload...), errors.Join(resultErr, result.Err, cleanupErr)
}

func (p *Pair) CallEcho(ctx context.Context, input []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("original tunnel service binding is required")
	}
	return callTunnelEcho(ctx, p.echo, input)
}
func (p *Pair) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("original cleanup context is required")
	}
	for {
		p.mu.Lock()
		if p.cleaned {
			err := p.closeErr
			p.mu.Unlock()
			return err
		}
		if p.cleaning {
			done := p.cleanupDone
			p.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		p.cleaning = true
		p.cleanupDone = make(chan struct{})
		if !p.closing {
			p.closing = true
			if p.cancel != nil {
				p.cancel(context.Canceled)
			}
			if p.echo != nil {
				p.echo.Close()
			}
			for _, session := range []tunnelSession{p.Client, p.Server} {
				if session != nil {
					p.closeErr = errors.Join(p.closeErr, transporttest.NormalizeCloseError(session.Close()))
				}
			}
		}
		p.mu.Unlock()
		err := p.join(ctx)
		p.mu.Lock()
		p.cleaning = false
		if err == nil {
			p.cleaned = true
			err = p.closeErr
		}
		close(p.cleanupDone)
		cleaned := p.cleaned
		p.mu.Unlock()
		if cleaned && p.endpoint != nil {
			p.endpoint.mu.Lock()
			if p.endpoint.slots[p.position] == p {
				p.endpoint.slots[p.position] = nil
			}
			p.endpoint.mu.Unlock()
		}
		return err
	}
}
func (p *Pair) join(ctx context.Context) error {
	for _, wait := range p.cleanupWaiters {
		if wait != nil {
			if err := wait(ctx); err != nil {
				return err
			}
		}
	}
	if p.echo != nil {
		if err := p.echo.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	for _, session := range []tunnelSession{p.Client, p.Server} {
		if session != nil {
			if err := session.WaitCleanup(ctx); err != nil {
				return err
			}
		}
	}
	var reporterErr error
	for i := len(p.reporters) - 1; i >= 0; i-- {
		reporter := p.reporters[i]
		if reporter == nil {
			continue
		}
		if err := reporter.Close(); err != nil {
			reporterErr = errors.Join(reporterErr, err)
		}
	}
	// Reporter failures are historical diagnostics. Physical ownership has
	// already been joined above through the direct cleanup waiters and Session
	// tails; do not turn a retained diagnostic into a second ownership path.
	p.reporters = nil
	if reporterErr != nil {
		p.closeErr = errors.Join(p.closeErr, fmt.Errorf("original tunnel owner cleanup: %w", reporterErr))
	}
	return nil
}
func (e *Endpoint) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("original endpoint cleanup context is required")
	}
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		e.cancel(errEndpointClosed)
		go func() { e.construction.Wait(); close(e.constructionDone) }()
	}
	done := e.constructionDone
	e.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	e.mu.Lock()
	pairs := append([]*Pair(nil), e.slots...)
	e.mu.Unlock()
	var err error
	for _, pair := range pairs {
		err = errors.Join(err, pair.Close(ctx))
	}
	e.mu.Lock()
	prepared := append([]*preparedTunnel(nil), e.preparedTunnels...)
	prepared = append(prepared, e.pendingPreparedTunnels...)
	e.mu.Unlock()
	for _, item := range prepared {
		itemErr := item.close(ctx)
		err = errors.Join(err, itemErr)
		// A prior bounded attempt may have recorded a timeout even though this
		// retry observed the owner reach its terminal state. Remove the item once
		// physical cleanup is complete; retaining a closed pointer would make a
		// later endpoint close retry a refunded position forever.
		if item.isCleaned() {
			e.removePrepared(item)
		} else {
			// A failed endpoint close must not leave a still-closing deployment
			// available to a later Connect call or be overwritten by preparation.
			e.retainPreparedCleanup(item)
		}
	}
	return err
}
