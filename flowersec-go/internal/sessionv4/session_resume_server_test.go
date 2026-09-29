package sessionv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// The fixture seeds an independently issued application checkpoint in the
// original store. The recovery request, result and following application bytes
// use real encrypted Sessions and the registered SDK server dispatcher.
type resumeLiveServerFixture struct {
	f                *executorFixture
	handlers         *StreamHandlerPlan
	plan             *SessionPlan
	storage          *durableServiceStorage
	token            protocolv4.ResumeToken
	reports          chan protocolv4.ResumeResult
	failures         chan error
	issueViaRPC      bool
	content          *retainedStreamFixture
	reopenPath       string
	deferTarget      bool
	stopPair         func()
	referencePath    string
	referenceBacking resourcev4.Reference
	businessWire     []byte
	businessPolicy   protocolv4.ServiceContractPolicy
	issuanceCalls    atomic.Uint32
	businessCalls    atomic.Uint32
	original         rpcv4.ExecutionTarget
	issuedReference  protocolv4.OperationReference
}

func (s *resumeLiveServerFixture) prepare(t *testing.T, fixture *initialCoreFixture, c *SessionCoreConfig, policy protocolv4.ServiceContractPolicy) {
	t.Helper()
	f := &executorFixture{root: fixture.root, serial: 100, config: ApplicationExecutorConfig{Running: 3, ResidentRunning: 1, Ready: 4, ResidentReady: 2, CompletionRunning: 1, CompletionReserved: 16, QueryOwners: 4, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}}
	charge, err := ApplicationExecutorCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.executor.Close(); awaitApplicationTask(t, f.executor.Done()) })
	s.f = f
	s.reports, s.failures = make(chan protocolv4.ResumeResult, 2), make(chan error, 2)
	binding := &ResumeStreamBinding{Kind: "example/raw", Namespace: policy.Namespace, Type: policy.Type, ContractDigest: policy.Digest}
	hc := StreamHandlerPlanConfig{RuntimeBytes: 8192, Handlers: []RawStreamHandlerConfig{{Kind: binding.Kind, Resume: binding, Slots: 2, WorkClass: ApplicationResident, Handler: func(ctx context.Context, _ any, _ []byte, owner *StreamOwnership) error {
		progress, present, err := owner.RecoveryProgress()
		if err == nil && !present {
			err = errors.New("recovery handler received no confirmed progress")
		}
		if err == nil {
			s.reports <- progress
			_, err = owner.WriteAll(ctx, []byte("after-resume"))
		}
		s.failures <- err
		// Retain the original handler until the caller closes the target.
		<-ctx.Done()
		return ctx.Err()
	}}}}
	charge, err = StreamHandlerPlanCharge(hc)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := fixture.environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	s.handlers, err = NewStreamHandlerPlan(hc, f.executor, f.reserve(t, 1, charge), dependencies)
	if err != nil {
		dependencies.Release()
		t.Fatal(err)
	}
	accounts := []resourcev4.Account{fixture.scope.Tenant, fixture.scope.Session}
	s.plan = applicationTestPlan(t, f, SessionPlanConfig{Services: true, ContractQueries: true, Handlers: s.handlers, ExecutionHistoryNamespaces: []string{policy.Namespace}, RuntimeBytes: 4096, AuthorizeApplication: func(context.Context, AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		return AuthorizeApplicationResult{}, ErrApplicationAuthorization
	}}, accounts...)
	c.Handlers = SessionStreamHandlerConfig{Plan: s.handlers, Concurrency: 2, TimeoutMS: 5000, RuntimeBytes: 8192, RuntimeBytesPerInvocation: 32768}
}

func (s *resumeLiveServerFixture) install(t *testing.T, fixture *initialCoreFixture, wire []byte, policy protocolv4.ServiceContractPolicy) *executorFixture {
	t.Helper()
	f, c := s.f, fixture.plan.config
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer contract.Release()
	var businessShape [32]byte
	if s.issueViaRPC {
		if bytes.Count(wire, []byte{1, 1, 2, 0}) != 1 {
			t.Fatal("business contract fixture changed")
		}
		s.businessWire = bytes.Replace(wire, []byte{1, 1, 2, 0}, []byte{1, 2, 2, 0}, 1)
		businessCodec, err := protocolv4.NewServiceContractCodec(256)
		if err != nil {
			t.Fatal(err)
		}
		business, err := businessCodec.Decode(s.businessWire)
		if err != nil {
			t.Fatal(err)
		}
		businessShape, err = business.MethodShapeDigest()
		if err != nil {
			t.Fatal(err)
		}
		s.businessPolicy, err = business.Policy()
		business.Release()
		if err != nil {
			t.Fatal(err)
		}
	}
	if s.content != nil {
		s.content.prepare(t)
	}
	configure := func(config *ledgerv4.SQLiteExecutionConfig) {
		config.RecoveryTokensPerOperation = 2
		config.RecoveryMaxIssuedDurationMS = 10000
		if s.issueViaRPC {
			config.Methods = append(config.Methods, ledgerv4.SQLiteExecutionMethod{Type: s.businessPolicy.Type, Shape: businessShape})
		}
		if s.content != nil {
			s.content.configure(config)
		}
	}
	if s.reopenPath == "" {
		s.storage = newDurableServiceStorage(t, f, c.Clock, fixture.environment, contract, wire, configure)
	} else {
		s.storage = durableServiceStorageAt(t, f, c.Clock, fixture.environment, contract, wire, s.reopenPath, false, configure)
	}
	key, err := cryptov4.ImportRecoveryMACKey([32]byte{7}, f.reserve(t, 1, cryptov4.RecoveryMACKeyCharge()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	vc := rpcv4.RecoveryVerifierConfig{Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}, Clock: c.Clock, Keys: []rpcv4.RecoveryKey{{ID: [16]byte{1}, Protection: 1, MAC: key}}, RuntimeBytes: 4096}
	charge, err := rpcv4.RecoveryVerifierCharge(vc)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := rpcv4.NewRecoveryVerifier(vc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(verifier.Close)
	if !s.issueViaRPC {
		s.seedCheckpoint(t, policy, key, c.Clock)
	}
	accounts := []resourcev4.Account{fixture.scope.Tenant, fixture.scope.Session}

	config := rpcServicesTestConfig(f, c.Clock, c.Session.Contract)
	config.Owner, config.Accounts, config.Bootstrap = fixture.plan.resourceOwner, accounts, c.Streams
	config.ReferenceDomain = "test-domain"
	if s.issueViaRPC {
		config.ResultRead = rpcv4.QueryBinding{Type: 3, Contract: [32]byte{9}}
	}
	var original [8192]byte
	registration, err := s.storage.store.ReadRegistration(context.Background(), policy.Digest, original[:], func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	config.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{wire}, OfferWindowMS: 1000, InitialOffers: registration.Offers[:registration.OfferCount], AdvertisedContract: policy.Digest}}
	config.Methods = []UnaryRegistration{{Method: 0, Namespace: policy.Namespace, Type: policy.Type, Resume: true}}
	if s.issueViaRPC {
		windows := []timev4.Interval{{LowerMS: registration.Offers[0].NotBeforeMS, UpperMS: registration.Offers[0].NotAfterMS}}
		if s.reopenPath == "" {
			if _, err := s.storage.store.InstallContract(context.Background(), registration.Revision, s.businessWire, windows, true, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
		config.Routes.Methods = append(config.Routes.Methods, rpcv4.MethodRoutes{Contracts: [][]byte{s.businessWire}, OfferWindowMS: 1000, InitialOffers: []protocolv4.AdmissionOfferBounds{{Digest: s.businessPolicy.Digest, NotBeforeMS: windows[0].LowerMS, NotAfterMS: windows[0].UpperMS}}, AdvertisedContract: s.businessPolicy.Digest})
		config.Methods = append(config.Methods, UnaryRegistration{Method: 1, Namespace: policy.Namespace, Type: s.businessPolicy.Type, Handler: func(ctx context.Context, request UnaryRequest, response *UnaryResponse) (uint32, error) {
			input, _, err := request.Input.Bytes()
			if err != nil {
				return 0, err
			}
			if len(input) == 0 {
				s.businessCalls.Add(1)
				_, err := response.Write([]byte("checkpoint source"))
				return 0, err
			}
			if len(input) != 96 {
				return 0, errors.New("invalid checkpoint source reference")
			}
			s.issuanceCalls.Add(1)
			original := rpcv4.ExecutionTarget{Service: vc.Service, Caller: rpcv4.ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}, Operation: [32]byte(input[:32]), RequestDigest: [32]byte(input[32:64]), ContractDigest: [32]byte(input[64:])}
			resumeCodec, err := protocolv4.NewResumeCodec()
			if err != nil {
				return 0, err
			}
			checkpoint, err := resumeCodec.CaptureCheckpoint(policy.CheckpointFormat, []byte{42})
			if err != nil {
				return 0, err
			}
			now, err := c.Clock.Sample()
			if err != nil {
				return 0, err
			}
			return 0, response.IssueCheckpoint(ctx, original, checkpoint, CheckpointIssuanceOptions{KeyID: [16]byte{1}, DurationMS: 9000, ApplicationDurationLimitMS: 10000, HistoryNotAfterMS: now.LowerMS + 10000})
		}})
	}
	if s.content != nil {
		s.content.install(t, s, &config, registration)
	}
	config.DurableProviderRuntimeBytes = 65536
	binding := rpcv4.ServiceBinding{Authority: rpcv4.ServiceAuthority{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}, DurableHistory: s.storage.history, Recovery: verifier}
	rc := rpcv4.ServiceRegistryConfig{Root: f.root, Owner: config.Owner, Entries: 4, RuntimeBytes: 4096}
	charge, err = rpcv4.ServiceRegistryCharge(rc)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := rpcv4.NewServiceRegistry(rc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.Close)
	if err = registry.Bind(binding); err != nil {
		t.Fatal(err)
	}
	config.ExecutionRegistry, config.ExecutionServices = registry, []rpcv4.ServiceBinding{binding}
	fixture.plan.rpc, err = s.plan.InstallRPCServices(config)
	if err != nil {
		t.Fatal("install real recovery service", err)
	}
	return f
}

func (s *resumeLiveServerFixture) seedCheckpoint(t *testing.T, policy protocolv4.ServiceContractPolicy, key *cryptov4.RecoveryMACKey, clock *timev4.Clock) {
	t.Helper()
	ctx, guard := context.Background(), func() error { return nil }
	now, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	request := ledgerv4.SQLiteExecutionRequest{Key: ledgerv4.SQLiteExecutionKey{CallerAuthority: [32]byte{8}, CallerSubject: "caller"}, RequestDigest: [32]byte{91}, ContractDigest: policy.Digest, RegistrationRevision: 1, DeadlineAtMS: now.LowerMS + 5000, ResponseLimitBytes: 1024}
	binary.BigEndian.PutUint64(request.Key.OperationID[:], now.LowerMS+500)
	request.Key.OperationID[31] = 91
	charge, err := s.storage.store.WorkCharge()
	if err != nil {
		t.Fatal(err)
	}
	_, work, err := s.storage.store.Register(ctx, request, s.f.reserve(t, 1, charge), guard)
	if err != nil {
		t.Fatal("seed original operation", err)
	}
	t.Cleanup(func() {
		if !work.CleanupComplete() {
			if err := work.Exit(ctx); err != nil {
				t.Error(err)
			}
		}
	})
	if err = work.Enter(ctx, guard); err != nil {
		t.Fatal(err)
	}
	if err = work.Finish(ctx, 0, []byte("checkpoint source"), guard); err != nil {
		t.Fatal(err)
	}
	if err = work.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	codec, err := protocolv4.NewResumeCodec()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := codec.CaptureCheckpoint(policy.CheckpointFormat, []byte{42})
	if err != nil {
		t.Fatal(err)
	}
	claims := protocolv4.ResumeClaims{Tenant: "tenant", Caller: "caller", Audience: "audience", Namespace: policy.Namespace, Operation: request.Key.OperationID, RequestDigest: request.RequestDigest, Nonce: [32]byte{43}, Checkpoint: checkpoint, IssuedAtMS: now.LowerMS, ExpiresAtMS: now.LowerMS + 9000}
	s.token, err = codec.ProtectMACToken(claims, [16]byte{1}, key, guard)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := codec.VerifyMACToken(s.token, [16]byte{1}, key, guard)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.storage.store.RecordRecoveryToken(ctx, request, proof, 10000, guard); err != nil {
		t.Fatal("seed application checkpoint", err)
	}
}

func TestResumeEncryptedSessionCommitsBeforeTargetHandler(t *testing.T) {
	runResumeEncryptedSession(t, false)
}

func TestCheckpointUnaryIssuanceAndEncryptedResume(t *testing.T) {
	runResumeEncryptedSession(t, true)
}

func runResumeEncryptedSession(t *testing.T, issueViaRPC bool) {
	t.Helper()
	live := &resumeLiveServerFixture{issueViaRPC: issueViaRPC}
	cores, streams, method, token, ctx := resumeSessionPair(t, live)
	op, err := cores[0].PrepareResume(ctx, method, streams[0], token, rpcv4.UnaryPreparation{DefaultLifetimeMS: 6000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	reference, err := op.Reference()
	if err != nil {
		t.Fatal(err)
	}
	if err = op.Start(ctx).Error; err != nil {
		t.Fatal(err)
	}
	value, status, err := op.TakeResult(ctx)
	want := protocolv4.ResumeResult{Status: 0, HasProgress: true, Checkpoint: token.Claims().Checkpoint, Generation: token.Claims().Generation + 1}
	if err != nil || value != want || !status.Delivered {
		t.Fatal("confirmed resume result", value, status, err)
	}
	select {
	case got := <-live.reports:
		if got != want {
			t.Fatal("handler checkpoint", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	access := executionDispatchAccess{live.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})}
	var saved [4248]byte
	target, err := cores[0].plan.rpc.referenceTarget(reference)
	if err != nil {
		t.Fatal(err)
	}
	_, n, err := live.storage.history.ReadResult(ctx, target, access, saved[:])
	if err != nil {
		t.Fatal("original recovery result missing", err)
	}
	codec, _ := protocolv4.NewResumeCodec()
	persisted, err := codec.DecodeResult(saved[:n])
	if err != nil || persisted != want {
		t.Fatal("persisted result differs from handler", persisted, err)
	}
	op.Close()
	var body [12]byte
	if err := readResumeBytes(ctx, streams[0], body[:]); err != nil || string(body[:]) != "after-resume" {
		t.Fatal("target application continuation", string(body[:]), err)
	}
	select {
	case err := <-live.failures:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cores[0].plan.rpc.AdvanceCalls()
	if err := op.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := streams[0].Cancel(); err != nil {
		t.Fatal(err)
	}
}

// Original business work and explicit issuance both pass through the same
// ordinary encrypted unary channel, durable store and publication owner.
func (s *resumeLiveServerFixture) issueCheckpointRPC(t *testing.T, core *SessionCore, ctx context.Context) {
	t.Helper()
	method := UnaryMethodDefinition{Contract: s.businessPolicy.Digest, DefaultResponseLimitBytes: 1024, RequireDurable: true, Decode: func(_ context.Context, body []byte) (any, error) { return string(body), nil }}
	call := func(input []byte) (*UnaryOperation, []byte) {
		op, err := core.PrepareUnary(ctx, method, input, rpcv4.UnaryPreparation{DefaultLifetimeMS: 6000})
		if err != nil {
			t.Fatal("prepare checkpoint business", err)
		}
		t.Cleanup(op.Close)
		if len(input) != 0 && s.referencePath != "" {
			saved, err := SavePreparedReference(ctx, op, ReferenceStoreBinding{Domain: "test-domain", Backing: s.referenceBacking,
				Store: referenceStoreFunc(func(ctx context.Context, ref protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
					return persistResumeReference(ctx, s.referencePath, ref)
				})})
			if err != nil || !saved.Attempted || saved.Outcome != ReferenceSaveConfirmed {
				t.Fatal("save checkpoint reference", saved, err)
			}
		}
		if err := op.Start(ctx).Error; err != nil {
			t.Fatal("start checkpoint business", err)
		}
		body, status, err := op.TakeEncodedResult(ctx)
		if err != nil || !status.Delivered {
			t.Fatal("checkpoint business result", status, err)
		}
		return op, body
	}
	business, reply := call(nil)
	if string(reply) != "checkpoint source" {
		t.Fatal("original business result", string(reply))
	}
	original, err := business.Reference()
	if err != nil {
		t.Fatal(err)
	}
	s.original, err = core.plan.rpc.referenceTarget(original)
	if err != nil {
		t.Fatal(err)
	}
	business.Close()
	core.plan.rpc.AdvanceCalls()
	if err := business.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	var input [96]byte
	copy(input[:32], s.original.Operation[:])
	copy(input[32:64], s.original.RequestDigest[:])
	copy(input[64:], s.original.ContractDigest[:])
	issued, wire := call(input[:])
	s.issuedReference, err = issued.Reference()
	if err != nil {
		t.Fatal(err)
	}
	codec, err := protocolv4.NewResumeCodec()
	if err != nil {
		t.Fatal(err)
	}
	s.token, err = codec.DecodeToken(wire, 1)
	if err != nil {
		t.Fatal("issued token", err)
	}
	claims := s.token.Claims()
	if claims.Operation != s.original.Operation || claims.RequestDigest != s.original.RequestDigest || claims.Generation != 0 {
		t.Fatal("issued token source changed")
	}
	issued.Close()
	core.plan.rpc.AdvanceCalls()
	if err := issued.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	// Reading the original result is an ordinary RPC, never a new issuance.
	now, err := core.plan.rpc.clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	read, err := core.plan.rpc.ReadOperationResult(ctx, s.issuedReference, now.LowerMS+6000, method.Decode)
	if err != nil {
		t.Fatal("read issued checkpoint", err)
	}
	tokenBytes, readStatus, err := read.TakeEncodedResult(ctx)
	if err != nil || !readStatus.Delivered || !bytes.Equal(tokenBytes, wire) {
		t.Fatal("original token read changed", readStatus, err)
	}
	read.Close()
	if s.businessCalls.Load() != 1 || s.issuanceCalls.Load() != 1 {
		t.Fatal("business/issuance entry counts", s.businessCalls.Load(), s.issuanceCalls.Load())
	}
}

// Application-owned create-or-compare storage confirms only after both the
// original canonical record and its directory entry have been synchronized.
func persistResumeReference(ctx context.Context, path string, ref protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
	if err := ctx.Err(); err != nil {
		return ReferenceSaveUnknown, err
	}
	codec, err := protocolv4.NewOperationReferenceCodec()
	if err != nil {
		return ReferenceSaveUnknown, err
	}
	var canonical [2048]byte
	n, err := codec.Export(canonical[:], ref)
	if err != nil {
		return ReferenceSaveUnknown, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		previous, readErr := os.ReadFile(path)
		if readErr != nil {
			return ReferenceSaveUnknown, readErr
		}
		if !bytes.Equal(previous, canonical[:n]) {
			return ReferenceSaveUnknown, errors.New("reference conflict")
		}
		return ReferenceSaveConfirmed, nil
	}
	if err != nil {
		return ReferenceSaveUnknown, err
	}
	defer file.Close()
	if _, err = file.Write(canonical[:n]); err != nil {
		return ReferenceSaveUnknown, err
	}
	if err = file.Sync(); err != nil {
		return ReferenceSaveUnknown, err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ReferenceSaveUnknown, err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return ReferenceSaveUnknown, err
	}
	return ReferenceSaveConfirmed, nil
}

func TestCheckpointReferenceReopensThroughNewSessionManagementAndResume(t *testing.T) {
	first := &resumeLiveServerFixture{issueViaRPC: true, deferTarget: true, referencePath: filepath.Join(t.TempDir(), "issued.reference")}
	oldCores, _, _, token, _ := resumeSessionPair(t, first)
	first.stopPair()
	first.storage.shutdown()
	second := &resumeLiveServerFixture{issueViaRPC: true, deferTarget: true, reopenPath: first.storage.path}
	cores, _, method, _, ctx := resumeSessionPair(t, second)
	wire, err := os.ReadFile(first.referencePath)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := protocolv4.NewOperationReferenceCodec()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := codec.Import(wire, "test-domain")
	if err != nil {
		t.Fatal(err)
	}
	query, err := cores[0].plan.rpc.referenceManagement(ctx, ref, false, 5000)
	if err != nil || query.Status != "ok" || query.Observation.State != rpcv4.ExecutionCompleted || !query.Observation.ResultAvailable || query.Observation.WorkActive {
		t.Fatal("new Session management history", query, err)
	}
	now, err := cores[0].plan.rpc.clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	read, err := cores[0].plan.rpc.ReadOperationResult(ctx, ref, now.LowerMS+6000, func(_ context.Context, p []byte) (any, error) { return string(p), nil })
	if err != nil {
		t.Fatal(err)
	}
	stored, status, err := read.TakeEncodedResult(ctx)
	if err != nil || !status.Delivered {
		t.Fatal("new Session original token", status, err)
	}
	resumeCodec, err := protocolv4.NewResumeCodec()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := resumeCodec.DecodeToken(stored, 1)
	if err != nil || restored != token {
		t.Fatal("token renewed or changed", err)
	}
	read.Close()
	target, err := cores[0].OpenStream(ctx, method.Kind, nil, streamTestDeadline(t, cores[0].Engine()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Cancel(); _ = target.Release() })
	if _, err := oldCores[0].PrepareResume(ctx, method, target, restored, rpcv4.UnaryPreparation{DefaultLifetimeMS: 6000}); err == nil {
		t.Fatal("closed original Session accepted replacement target")
	}
	op, err := cores[0].PrepareResume(ctx, method, target, restored, rpcv4.UnaryPreparation{DefaultLifetimeMS: 6000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if err := op.Start(ctx).Error; err != nil {
		t.Fatal(err)
	}
	value, status, err := op.TakeResult(ctx)
	want := protocolv4.ResumeResult{Status: 0, HasProgress: true, Checkpoint: token.Claims().Checkpoint, Generation: token.Claims().Generation + 1}
	if err != nil || !status.Delivered || value != want {
		t.Fatal("new target recovery", value, status, err)
	}
	op.Close()
	select {
	case progress := <-second.reports:
		if progress != want {
			t.Fatal("handler progress", progress)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var body [12]byte
	if err := readResumeBytes(ctx, target, body[:]); err != nil || string(body[:]) != "after-resume" {
		t.Fatal("same target bytes", string(body[:]), err)
	}
	select {
	case err := <-second.failures:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cores[0].plan.rpc.AdvanceCalls()
	if err := op.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if second.businessCalls.Load() != 0 || second.issuanceCalls.Load() != 0 || first.businessCalls.Load() != 1 || first.issuanceCalls.Load() != 1 {
		t.Fatal("reopen replayed business or issuance")
	}
	if err := target.Cancel(); err != nil {
		t.Fatal(err)
	}
}
