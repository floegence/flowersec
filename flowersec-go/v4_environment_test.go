package flowersec_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

// This external-package test assembles only public types. It guards against
// exposing configuration aliases whose required constructors remain internal.
func TestPublicEnvironmentAssemblyAndIndependentCleanup(t *testing.T) {
	config := fs.ResourceConfig{ProfileRevision: [32]byte{1}, AccountSlots: 8, ReservationSlots: 64, ReferenceSlots: 256}
	for i := range config.Limit {
		config.Limit[i] = 1 << 20
	}
	config.Limit[fs.SDKBytes] = 64 << 20
	root, err := fs.NewResourceRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	serial := byte(0)
	owner := func() fs.ResourceOwnerKey {
		serial++
		return fs.ResourceOwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{serial}, Backing: [16]byte{serial}, Kind: 1}
	}
	reserve := func(charge fs.ResourceVector, err error) fs.ResourceReference {
		if err != nil {
			t.Fatal(err)
		}
		ref, err := root.Reserve(owner(), charge)
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	dependencies := reserve(fs.ResourceVector{fs.SDKBytes: 4096, fs.Items: 1}, nil)
	clock, err := fs.NewClock(fs.ClockProfile{Rate: fs.ClockRate{Numerator: 1, Denominator: 1000, QuantizationMS: 1}, MaxWidthMS: 1000, MaxAgeMS: 60000, MaxRoundTripMS: 1000}, func() (fs.ClockTick, error) { return fs.ClockTick{Milliseconds: 1, Incarnation: [16]byte{1}}, nil })
	if err != nil {
		t.Fatal(err)
	}
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.InstallTrusted(mark, fs.TimeInterval{LowerMS: 1000, UpperMS: 1001}); err != nil {
		t.Fatal(err)
	}
	verificationConfig := fs.VerificationNamespacesConfig{Continuity: fs.OnlineBootstrap, Entries: 2, RuntimeBytes: 4096}
	verification, err := fs.NewVerificationNamespaces(verificationConfig, reserve(fs.VerificationNamespacesCharge(verificationConfig)))
	if err != nil {
		t.Fatal(err)
	}
	executorConfig := fs.ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, CompletionRunning: 1, CompletionReserved: 4, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}
	executor, err := fs.NewApplicationExecutor(executorConfig, reserve(fs.ApplicationExecutorCharge(executorConfig)))
	if err != nil {
		t.Fatal(err)
	}
	envConfig := fs.EnvironmentConfig{Positions: 2, RuntimeBytes: 4096, Clock: clock, Verification: verification}
	environment, err := fs.NewTransportEnvironment(fs.EnvironmentOptions{Config: envConfig, Reservation: reserve(fs.EnvironmentCharge(envConfig)), Dependencies: dependencies})
	if err != nil {
		t.Fatal(err)
	}
	planConfig := fs.SessionPlanConfig{RuntimeBytes: 4096, AuthorizeApplication: func(context.Context, fs.AuthenticatedRequestContext) (fs.AuthorizeApplicationResult, error) {
		t.Fatal("factory invoked application callback")
		return fs.AuthorizeApplicationResult{}, nil
	}}
	factory := fs.SessionPlanFactory{Root: root, Executor: executor, Dependencies: dependencies}
	plan, err := factory.Create(planConfig, owner())
	if err != nil {
		t.Fatal(err)
	}
	plan.Close()
	if err := plan.Retire(); err != nil {
		t.Fatal(err)
	}
	// The external source returns a partially built recipe alongside failure.
	// Both its application plan and original spend reservation must retire.
	beforeController := root.Snapshot()
	plan, err = factory.Create(planConfig, owner())
	if err != nil {
		t.Fatal(err)
	}
	consume := reserve(fs.ResourceVector{fs.SDKBytes: 4096, fs.Items: 1}, nil)
	sourceErr := errors.New("source refused local preparation")
	var prepared atomic.Int32
	controllerOptions := fs.ControllerOptions{Clock: clock, SourceIncarnation: [16]byte{3}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 8192,
		Source: publicControllerSourceFunc(func(_ context.Context, request fs.ControllerRequest) (*fs.ControllerPreparation, error) {
			prepared.Add(1)
			if request.Attempt != 1 || request.SourceIncarnation != ([16]byte{3}) || request.Deadline == nil {
				t.Error("public Controller lost original attempt facts")
			}
			return &fs.ControllerPreparation{Config: fs.SourceConnectConfig{Admission: fs.SessionAdmissionConfig{Application: plan}}, Pool: &fs.PoolSessionInput{Consume: consume}, PoolSource: &fs.PreauthorizedPoolSource{}}, sourceErr
		})}
	metadata, task, completion, err := fs.ControllerCharges(controllerOptions)
	if err != nil || task != (fs.ResourceVector{}) || completion != (fs.ResourceVector{}) {
		t.Fatal("unexpected callback floor for unconfigured initializer", err)
	}
	controllerOptions.Reservation = reserve(metadata, nil)
	controller, err := environment.NewConnectionController(context.Background(), controllerOptions)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Load() != 0 {
		t.Fatal("Controller construction acquired material")
	}
	if err := controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	controllerWait, stopControllerWait := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopControllerWait()
	if _, err := controller.WaitForSession(controllerWait); err == nil {
		t.Fatal("source failure lost")
	} else {
		var failure *fs.SessionError
		if !errors.As(err, &failure) || failure.Code() != fs.SessionOperationFailed || errors.Is(err, sourceErr) {
			t.Fatal("source failure was not redacted", err)
		}
	}
	controller.Close()
	if err := controller.WaitCleanup(controllerWait); err != nil {
		t.Fatal(err)
	}
	if got := root.Snapshot(); got.Charged != beforeController.Charged || got.Reservations != beforeController.Reservations || got.References != beforeController.References || prepared.Load() != 1 {
		t.Fatal("failed public preparation leaked or replayed", got, beforeController, prepared.Load())
	}
	environment.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := environment.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Check(); err != nil {
		t.Fatal("environment closed caller dependency", err)
	}
	if _, err := clock.Sample(); err != nil {
		t.Fatal("environment closed caller clock", err)
	}
	plan, err = factory.Create(planConfig, owner())
	if err != nil {
		t.Fatal("environment closed shared executor", err)
	}
	plan.Close()
	if err := plan.Retire(); err != nil {
		t.Fatal(err)
	}
	executor.Close()
	select {
	case <-executor.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	verification.Close()
	root.Close()
	if err := verification.DestroyEnvironment(); err != nil {
		t.Fatal(err)
	}
	dependencies.Release()
	clock.Close()
	root.Close()
	if snapshot := root.Snapshot(); !snapshot.CleanupComplete {
		t.Fatal("public assembly leaked original resources", snapshot)
	}
}

type publicControllerSourceFunc func(context.Context, fs.ControllerRequest) (*fs.ControllerPreparation, error)

func (f publicControllerSourceFunc) PrepareConnection(ctx context.Context, request fs.ControllerRequest) (*fs.ControllerPreparation, error) {
	return f(ctx, request)
}

func TestPublicEnvironmentRejectsUnqualifiedConstruction(t *testing.T) {
	if _, err := fs.NewTransportEnvironment(fs.EnvironmentOptions{}); err == nil {
		t.Fatal("unqualified TransportEnvironment accepted")
	}
	if _, err := fs.NewConnectionMaterial(nil, nil, fs.MaterialGeneration{}, 0, fs.ResourceReference{}); err == nil {
		t.Fatal("material constructed without original credentials")
	}
}

type unqualifiedLiveSource struct{}

func (unqualifiedLiveSource) AcquireLease(context.Context, fs.MaterialLeaseRequest) (*fs.ArtifactLease, error) {
	return nil, errors.New("provider must not be called")
}

func TestLiveSourceRequiresNamespacePreflight(t *testing.T) {
	if _, err := fs.NewLiveAuthoritySource(unqualifiedLiveSource{}); err == nil {
		t.Fatal("live source accepted a provider without a fixed namespace snapshot")
	}
}

type blockingLiveSourceProvider struct {
	started   chan struct{}
	release   chan struct{}
	closed    chan struct{}
	waited    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	waitOnce  sync.Once
}

func (p *blockingLiveSourceProvider) AcquireLease(context.Context, fs.MaterialLeaseRequest) (*fs.ArtifactLease, error) {
	p.startOnce.Do(func() { close(p.started) })
	<-p.release
	return nil, errors.New("provider released")
}

func (*blockingLiveSourceProvider) PreparationNamespaceSet(*fs.Clock, fs.ResourceReference) (fs.MaterialNamespaceSet, error) {
	return fs.MaterialNamespaceSet{Count: 1}, nil
}

func (p *blockingLiveSourceProvider) Close() {
	p.closeOnce.Do(func() { close(p.closed) })
}

func (p *blockingLiveSourceProvider) WaitCleanup(context.Context) error {
	p.waitOnce.Do(func() { close(p.waited) })
	return nil
}

func TestLiveSourceCloseWaitsForActiveProviderCall(t *testing.T) {
	provider := &blockingLiveSourceProvider{started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), waited: make(chan struct{})}
	source, err := fs.NewLiveAuthoritySource(provider)
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan error, 1)
	go func() {
		_, callErr := source.AcquireLease(context.Background(), fs.MaterialLeaseRequest{})
		acquired <- callErr
	}()
	<-provider.started
	source.Close()
	select {
	case <-provider.closed:
		t.Fatal("provider closed while AcquireLease was still active")
	default:
	}
	waited := make(chan error, 1)
	go func() { waited <- source.WaitCleanup(context.Background()) }()
	select {
	case <-waited:
		t.Fatal("WaitCleanup returned before the active provider call exited")
	default:
	}
	close(provider.release)
	if callErr := <-acquired; callErr == nil {
		t.Fatal("released provider call unexpectedly succeeded")
	}
	select {
	case <-provider.closed:
	case <-time.After(time.Second):
		t.Fatal("provider Close was not forwarded after the active call exited")
	}
	if waitErr := <-waited; waitErr != nil {
		t.Fatal(waitErr)
	}
	select {
	case <-provider.waited:
	default:
		t.Fatal("WaitCleanup did not join provider cleanup")
	}
}
