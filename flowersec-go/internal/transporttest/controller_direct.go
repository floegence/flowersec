package transporttest

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type ControllerArtifactPlan string

const (
	ControllerPlanCurrentPin      ControllerArtifactPlan = "current-pin"
	ControllerPlanExpiringPin     ControllerArtifactPlan = "expiring-pin"
	ControllerPlanStalePin        ControllerArtifactPlan = "stale-pin"
	ControllerPlanUnavailable     ControllerArtifactPlan = "unavailable"
	ControllerPlanTLSInterruption ControllerArtifactPlan = "tls-interruption"
)

type controllerArtifactRecord struct {
	material     interopharness.Material
	accepted     *interopharness.AcceptedRecord
	client       *interopharness.Client
	rpc          *interopharness.RPCDefinition
	acquiredAt   time.Time
	pinExpiresMS uint64
}

// ProductControllerArtifactSource prepares exclusively owned local recipes in
// one original Environment. All signed inputs are independently issued and
// installed before Start. Only the original acquisition callback records an
// acquisition; actual SQLite completion and original lease cleanup record spend
// and retirement. Preparation never issues, acquires, spends or dials.
type ProductControllerArtifactSource struct {
	endpoint       *ProductDirectEndpoint
	reporter       *interopharness.Reporter
	base           *interopharness.Client
	clientHandlers interopharness.HandlerConfig
	mu             sync.Mutex
	records        []*controllerArtifactRecord
	acquired       []*controllerArtifactRecord
	next           int
	closed         bool
	pause          *controllerPreparationPause
}

func NewProductControllerArtifactSource(endpoint *ProductDirectEndpoint, plans []ControllerArtifactPlan, handlers ...interopharness.HandlerConfig) (*ProductControllerArtifactSource, error) {
	return newProductControllerArtifactSource(endpoint, plans, nil, handlers...)
}
func NewProductControllerTLSInterruptionSource(endpoint *ProductDirectEndpoint, address netip.AddrPort, handlers ...interopharness.HandlerConfig) (*ProductControllerArtifactSource, error) {
	if !address.IsValid() || address.Port() == 0 || !address.Addr().IsLoopback() {
		return nil, errors.New("TLS interruption requires an explicitly owned numeric loopback endpoint")
	}
	return newProductControllerArtifactSource(endpoint, []ControllerArtifactPlan{ControllerPlanCurrentPin, ControllerPlanTLSInterruption, ControllerPlanCurrentPin}, map[ControllerArtifactPlan]netip.AddrPort{ControllerPlanTLSInterruption: address}, handlers...)
}
func newProductControllerArtifactSource(endpoint *ProductDirectEndpoint, plans []ControllerArtifactPlan, addresses map[ControllerArtifactPlan]netip.AddrPort, handlers ...interopharness.HandlerConfig) (result *ProductControllerArtifactSource, resultErr error) {
	if endpoint == nil || len(plans) == 0 || len(plans) > 32 {
		return nil, errors.New("original controller endpoint and finite plans are required")
	}
	if len(handlers) > 1 || len(handlers) == 1 && handlers[0] == nil {
		return nil, errors.New("one original client handler declaration is required")
	}
	source := &ProductControllerArtifactSource{endpoint: endpoint}
	if len(handlers) == 1 {
		source.clientHandlers = handlers[0]
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, source.Close())
		}
	}()
	// Current replacements are finite original materials, never a reusable lease.
	planned := append(append([]ControllerArtifactPlan(nil), plans...), make([]ControllerArtifactPlan, 16)...)
	source.records = make([]*controllerArtifactRecord, len(planned))
	order := make([]int, 0, len(planned))
	for index, plan := range planned {
		if plan != ControllerPlanExpiringPin {
			order = append(order, index)
		}
	}
	for index, plan := range planned {
		if plan == ControllerPlanExpiringPin {
			order = append(order, index)
		}
	}
	issueRecord := func(index int) error {
		plan := planned[index]
		if plan == "" {
			plan = ControllerPlanCurrentPin
		}
		now, err := endpoint.reporter.AuthorityClock().Sample()
		if err != nil {
			return err
		}
		leaf := endpoint.certificateDER
		expires := uint64(0)
		address := netip.AddrPort{}
		install := true
		switch plan {
		case ControllerPlanCurrentPin:
		case ControllerPlanExpiringPin:
			expires = now.Interval.UpperMS + 4000
		case ControllerPlanStalePin:
			previous, _, _, _, err := interopharness.TLSMaterial(endpoint.listenHost)
			if err != nil {
				return err
			}
			leaf = previous.Certificate[0]
			install = false
		case ControllerPlanUnavailable:
			address = netip.AddrPortFrom(endpoint.nativeServer().Address.Addr(), 1)
			install = false
		case ControllerPlanTLSInterruption:
			address = addresses[plan]
			if !address.IsValid() {
				return errors.New("TLS interruption destination was not independently installed")
			}
			install = false
		default:
			return errors.New("unknown current controller material plan")
		}
		policy, err := currentPinPolicy(leaf, expires, now.Interval, true)
		if err != nil {
			return err
		}
		material, accepted, err := endpoint.issue(policy, address, install)
		if err != nil {
			return err
		}
		source.records[index] = &controllerArtifactRecord{material: material, accepted: accepted, pinExpiresMS: expires}
		return nil
	}
	for _, index := range order {
		if planned[index] != ControllerPlanExpiringPin {
			if err := issueRecord(index); err != nil {
				return nil, err
			}
		}
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return nil, err
	}
	source.reporter = reporter
	reporter.ApplicationProfile = "services"
	reporter.OperationDeadlineMS = endpoint.reporter.OperationDeadlineMS
	reporter.ActivationWindowMS = endpoint.reporter.ActivationWindowMS
	// Bootstrap installs a fresh complete original namespace before any material
	// acquisition. This base owns the one Environment and its real consumer store.
	wire, err := source.records[len(plans)].material.JSON()
	if err != nil {
		return nil, err
	}
	source.base, err = interopharness.NewClient(endpoint.ctx, reporter, wire, endpoint.nativeServer().TrustPEM, endpoint.allowedOrigin, productHandlers(nil))
	if err != nil {
		return nil, err
	}
	// Expiring policies are issued after namespace/bootstrap construction so the
	// original trusted admission interval is available to the first attempt.
	for _, index := range order {
		if planned[index] == ControllerPlanExpiringPin {
			if err := issueRecord(index); err != nil {
				return nil, err
			}
		}
	}
	return source, nil
}
func (source *ProductControllerArtifactSource) PrepareConnection(ctx context.Context, _ flowersec.ControllerRequest) (*flowersec.ControllerPreparation, error) {
	if ctx == nil || source == nil {
		return nil, errors.New("original controller preparation context is required")
	}
	var record *controllerArtifactRecord
	for {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		source.mu.Lock()
		if source.closed || source.next == len(source.records) {
			source.mu.Unlock()
			return nil, errors.New("current controller local recipe capacity is exhausted")
		}
		if pause := source.pause; pause != nil {
			source.mu.Unlock()
			select {
			case <-pause.ready:
				continue
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
		}
		record = source.records[source.next]
		source.next++
		source.mu.Unlock()
		break
	}
	var definition *interopharness.RPCDefinition
	configured := productHandlers(&definition)
	if source.clientHandlers != nil {
		configured = source.clientHandlers
	}
	client, err := source.base.PrepareMaterial(ctx, record.material, source.endpoint.allowedOrigin, configured)
	if err != nil {
		return nil, err
	}
	source.mu.Lock()
	if source.closed {
		source.mu.Unlock()
		return nil, errors.Join(errors.New("original controller source closed during preparation"), client.Runtime.Reporter.Close())
	}
	record.client, record.rpc = client, definition
	source.mu.Unlock()
	preparation := client.Runtime.SourcePreparation(client.Carrier)
	original := preparation.Config.Provider
	preparation.Config.Provider = &controllerObservedSource{owner: source, record: record, original: original}
	return preparation, nil
}

type controllerObservedSource struct {
	owner    *ProductControllerArtifactSource
	record   *controllerArtifactRecord
	original flowersec.ConnectionMaterialSource
}

func (source *controllerObservedSource) PreparationNamespaces(clock *flowersec.Clock, environment flowersec.ResourceReference) ([3]*protocolv4.LiveNamespace, error) {
	return source.record.client.Runtime.Authority.PreparationNamespaces(clock, environment)
}
func (source *controllerObservedSource) AcquireLease(ctx context.Context, request flowersec.MaterialLeaseRequest) (*flowersec.ArtifactLease, error) {
	lease, err := source.original.AcquireLease(ctx, request)
	if lease != nil {
		source.owner.mu.Lock()
		source.record.acquiredAt = time.Now()
		source.owner.acquired = append(source.owner.acquired, source.record)
		source.owner.mu.Unlock()
	}
	return lease, err
}
func (source *ProductControllerArtifactSource) NewController(ctx context.Context) (*flowersec.ConnectionController, error) {
	if source == nil || source.base == nil {
		return nil, errors.New("original current controller source is required")
	}
	runtime := source.base.Runtime
	authority := runtime.Authority
	options := flowersec.ControllerOptions{Clock: authority.Clock, Source: source, SourceIncarnation: authority.Generation.Source, Executor: runtime.Executor, AttemptTimeoutMS: source.reporter.AuthorityOperationMS(), DrainTimeoutMS: 1000, RuntimeBytes: 65536, MaximumAttempts: uint64(len(source.records))}
	metadata, task, completion, err := flowersec.ControllerCharges(options)
	if err != nil {
		return nil, err
	}
	// A Controller spans Session generations within this trusted tenant.
	// Its observer roots must retain the same ancestry as their source Sessions.
	options.Reservation = authority.Reserve(metadata, authority.Scope[0].Tenant)
	if task != (flowersec.ResourceVector{}) {
		options.InitializeTask = authority.Reserve(task, authority.Scope[0].Tenant)
	}
	if completion != (flowersec.ResourceVector{}) {
		options.InitializeCompletion = authority.Reserve(completion, authority.Scope[0].Tenant)
	}
	return flowersec.NewConnectionController(ctx, flowersec.ConnectionControllerOptions{Environment: runtime.Environment, ControllerOptions: options})
}
func (source *ProductControllerArtifactSource) WaitServer(ctx context.Context, acquisition int) (*flowersec.Session, error) {
	source.mu.Lock()
	if acquisition < 0 || acquisition >= len(source.acquired) {
		source.mu.Unlock()
		return nil, errors.New("original controller acquisition is unavailable")
	}
	record := source.acquired[acquisition]
	source.mu.Unlock()
	return record.accepted.WaitSession(ctx)
}
func (source *ProductControllerArtifactSource) AcquisitionCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return len(source.acquired)
}
func (source *ProductControllerArtifactSource) AcquisitionTimes() []time.Time {
	source.mu.Lock()
	defer source.mu.Unlock()
	times := make([]time.Time, len(source.acquired))
	for index, record := range source.acquired {
		times[index] = record.acquiredAt
	}
	return times
}
func (source *ProductControllerArtifactSource) observation(index int) (*ledgerv4.PoolSpendObservation, *flowersec.ArtifactLease) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if index < 0 || index >= len(source.acquired) {
		return nil, nil
	}
	runtime := source.acquired[index].client.Runtime
	return runtime.PoolSpend, runtime.Leases[0]
}
func (source *ProductControllerArtifactSource) SpendCount(index int) int32 {
	observation, _ := source.observation(index)
	if observation != nil && observation.Snapshot().CommitKnown {
		return 1
	}
	return 0
}
func (source *ProductControllerArtifactSource) RetireCount(index int) int32 {
	observation, lease := source.observation(index)
	if observation != nil && !observation.Snapshot().CommitKnown && lease != nil && lease.CleanupComplete() {
		return 1
	}
	return 0
}
func (source *ProductControllerArtifactSource) NewPair(ctx context.Context, client, server *flowersec.Session) (*ProductDirectPair, error) {
	source.mu.Lock()
	var record *controllerArtifactRecord
	for index := len(source.acquired) - 1; index >= 0; index-- {
		candidate := source.acquired[index]
		if candidate.client != nil && candidate.accepted.IsSession(server) {
			record = candidate
			break
		}
	}
	source.mu.Unlock()
	if record == nil || record.rpc == nil {
		return nil, errors.New("original controller service registration is unavailable")
	}
	echo, err := record.rpc.Bind(ctx, client)
	if err != nil {
		return nil, err
	}
	return &ProductDirectPair{Client: client, Server: server, Profile: source.endpoint.profile, spend: record.client.Runtime.PoolSpend, echo: echo}, nil
}
func (source *ProductControllerArtifactSource) Close() error {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	if source.closed {
		source.mu.Unlock()
		return nil
	}
	source.closed = true
	if source.pause != nil {
		source.pause.once.Do(func() { close(source.pause.ready) })
	}
	records := append([]*controllerArtifactRecord(nil), source.records...)
	source.mu.Unlock()
	var err error
	for _, record := range records {
		if record != nil {
			err = errors.Join(err, record.accepted.Close())
		}
	}
	if source.reporter != nil {
		err = errors.Join(err, source.reporter.Close())
	}
	return err
}

var _ flowersec.ControllerSource = (*ProductControllerArtifactSource)(nil)

func (source *ProductControllerArtifactSource) ClientRuntime(index int) *interopharness.Runtime {
	source.mu.Lock()
	defer source.mu.Unlock()
	if index < 0 || index >= len(source.acquired) || source.acquired[index].client == nil {
		return nil
	}
	return source.acquired[index].client.Runtime
}
func (source *ProductControllerArtifactSource) ServerRuntime(index int) *interopharness.Runtime {
	source.mu.Lock()
	if index < 0 || index >= len(source.acquired) {
		source.mu.Unlock()
		return nil
	}
	accepted := source.acquired[index].accepted
	source.mu.Unlock()
	return accepted.Runtime()
}

type controllerPreparationPause struct {
	ready chan struct{}
	once  sync.Once
}

// PausePreparations holds only untouched local recipes during an explicitly
// owned listener restart. It neither acquires material nor masks transport
// failure, and the original preparation context cancels the wait normally.
func (source *ProductControllerArtifactSource) PausePreparations() (func(), error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed || source.pause != nil {
		return nil, errors.New("controller preparation pause is unavailable")
	}
	pause := &controllerPreparationPause{ready: make(chan struct{})}
	source.pause = pause
	return func() {
		source.mu.Lock()
		defer source.mu.Unlock()
		if source.pause == pause {
			source.pause = nil
		}
		pause.once.Do(func() { close(pause.ready) })
	}, nil
}
