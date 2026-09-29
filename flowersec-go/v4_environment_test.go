package flowersec_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

// This external-package test assembles only public types. It guards against
// exposing configuration aliases whose required constructors remain internal.
func TestV4PublicEnvironmentAssemblyAndIndependentCleanup(t *testing.T) {
	config := fs.V4ResourceConfig{ProfileRevision: [32]byte{1}, AccountSlots: 8, ReservationSlots: 64, ReferenceSlots: 256}
	for i := range config.Limit {
		config.Limit[i] = 1 << 20
	}
	config.Limit[fs.V4SDKBytes] = 64 << 20
	root, err := fs.NewV4ResourceRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	serial := byte(0)
	owner := func() fs.V4ResourceOwnerKey {
		serial++
		return fs.V4ResourceOwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{serial}, Backing: [16]byte{serial}, Kind: 1}
	}
	reserve := func(charge fs.V4ResourceVector, err error) fs.V4ResourceReference {
		if err != nil {
			t.Fatal(err)
		}
		ref, err := root.Reserve(owner(), charge)
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	dependencies := reserve(fs.V4ResourceVector{fs.V4SDKBytes: 4096, fs.V4Items: 1}, nil)
	clock, err := fs.NewV4Clock(fs.V4ClockProfile{Rate: fs.V4ClockRate{Numerator: 1, Denominator: 1000, QuantizationMS: 1}, MaxWidthMS: 1000, MaxAgeMS: 60000, MaxRoundTripMS: 1000}, func() (fs.V4ClockTick, error) { return fs.V4ClockTick{Milliseconds: 1, Incarnation: [16]byte{1}}, nil })
	if err != nil {
		t.Fatal(err)
	}
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.InstallTrusted(mark, fs.V4TimeInterval{LowerMS: 1000, UpperMS: 1001}); err != nil {
		t.Fatal(err)
	}
	verificationConfig := fs.V4VerificationNamespacesConfig{Continuity: fs.V4OnlineBootstrap, Entries: 2, RuntimeBytes: 4096}
	verification, err := fs.NewV4VerificationNamespaces(verificationConfig, reserve(fs.V4VerificationNamespacesCharge(verificationConfig)))
	if err != nil {
		t.Fatal(err)
	}
	executorConfig := fs.V4ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, CompletionRunning: 1, CompletionReserved: 4, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}
	executor, err := fs.NewV4ApplicationExecutor(executorConfig, reserve(fs.V4ApplicationExecutorCharge(executorConfig)))
	if err != nil {
		t.Fatal(err)
	}
	envConfig := fs.V4EnvironmentConfig{Positions: 2, RuntimeBytes: 4096, Clock: clock, Verification: verification}
	environment, err := fs.NewTransportEnvironment(fs.TransportEnvironmentOptions{Config: envConfig, Reservation: reserve(fs.V4EnvironmentCharge(envConfig)), Dependencies: dependencies})
	if err != nil {
		t.Fatal(err)
	}
	planConfig := fs.V4SessionPlanConfig{RuntimeBytes: 4096, AuthorizeApplication: func(context.Context, fs.V4AuthenticatedRequestContext) (fs.V4AuthorizeApplicationResult, error) {
		t.Fatal("factory invoked application callback")
		return fs.V4AuthorizeApplicationResult{}, nil
	}}
	factory := fs.V4SessionPlanFactory{Root: root, Executor: executor, Dependencies: dependencies}
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
	consume := reserve(fs.V4ResourceVector{fs.V4SDKBytes: 4096, fs.V4Items: 1}, nil)
	sourceErr := errors.New("source refused local preparation")
	var prepared atomic.Int32
	controllerOptions := fs.V4ControllerOptions{Clock: clock, SourceIncarnation: [16]byte{3}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 8192,
		Source: publicControllerSourceFunc(func(_ context.Context, request fs.V4ControllerRequest) (*fs.V4ControllerPreparation, error) {
			prepared.Add(1)
			if request.Attempt != 1 || request.SourceIncarnation != ([16]byte{3}) || request.Deadline == nil {
				t.Error("public Controller lost original attempt facts")
			}
			return &fs.V4ControllerPreparation{Config: fs.V4SourceConnectConfig{Admission: fs.V4SessionAdmissionConfig{Application: plan}}, Pool: &fs.V4PoolSessionInput{Consume: consume}, PoolSource: &fs.V4PreauthorizedPoolSource{}}, sourceErr
		})}
	metadata, task, completion, err := fs.V4ControllerCharges(controllerOptions)
	if err != nil || task != (fs.V4ResourceVector{}) || completion != (fs.V4ResourceVector{}) {
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

type publicControllerSourceFunc func(context.Context, fs.V4ControllerRequest) (*fs.V4ControllerPreparation, error)

func (f publicControllerSourceFunc) PrepareConnection(ctx context.Context, request fs.V4ControllerRequest) (*fs.V4ControllerPreparation, error) {
	return f(ctx, request)
}

func TestV4PublicEnvironmentRejectsUnqualifiedConstruction(t *testing.T) {
	if _, err := fs.NewTransportEnvironment(fs.TransportEnvironmentOptions{}); err == nil {
		t.Fatal("unqualified Environment accepted")
	}
	if _, err := fs.NewConnectionMaterial(nil, nil, fs.V4MaterialGeneration{}, 0, fs.V4ResourceReference{}); err == nil {
		t.Fatal("material constructed without original credentials")
	}
}

type unqualifiedLiveSource struct{}

func (unqualifiedLiveSource) AcquireLease(context.Context, fs.V4MaterialLeaseRequest) (*fs.V4ArtifactLease, error) {
	return nil, errors.New("provider must not be called")
}

func TestV4LiveSourceRequiresNamespacePreflight(t *testing.T) {
	if _, err := fs.NewV4LiveAuthoritySource(unqualifiedLiveSource{}); err == nil {
		t.Fatal("live source accepted a provider without a fixed namespace snapshot")
	}
}
