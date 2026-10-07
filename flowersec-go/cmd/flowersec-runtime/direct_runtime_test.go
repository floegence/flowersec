package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// The resolver receives an unauthenticated lookup hint. These regressions use
// real independently signed material and its normal public installation; they
// do not manufacture an admission decision, durable receipt or start guard.
func directSourceFixture(t *testing.T) (*sessionv4.PublicQUICTestHarness, *directRuntimeMaterial, *protocolv4.SignedMap) {
	t.Helper()
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reporter.Close(); err != nil {
			t.Error(err)
		}
	})
	_, _, _, policy, err := interopharness.TLSMaterial("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	h := sessionv4.NewPublicQUICTestHarness(reporter, "preauthorized_pool", protocolv4.DHProfileX25519, netip.MustParseAddrPort("127.0.0.1:45443"), policy)
	leaseCharge, err := fs.ArtifactLeaseCharge(h.Lease.MapBytes, h.Lease.MapNodes, h.Lease.RuntimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	leaseRef := h.Reserve(leaseCharge)
	lease, err := fs.NewArtifactLeaseFromBytes(h.Lease, leaseRef, h.Preauth)
	leaseRef.Release()
	if err != nil {
		t.Fatal(err)
	}
	identityConfig := h.Identity[1]
	identityCharge, err := fs.ApplicationIdentityCharge(identityConfig.MapNodes, identityConfig.RuntimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	identityRef := h.Reserve(identityCharge)
	identity, err := fs.NewApplicationIdentityFromBytes(identityConfig, identityRef, h.Preauth)
	identityRef.Release()
	if err != nil {
		t.Fatal(err)
	}
	materialCharge, err := fs.ConnectionMaterialCharge(65536)
	if err != nil {
		t.Fatal(err)
	}
	materialRef := h.Reserve(materialCharge)
	original, err := fs.NewConnectionMaterial(lease, identity, h.Generation, 65536, materialRef)
	materialRef.Release()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		original.Close()
		if err := original.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		identity.Close()
		if err := identity.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		lease.Close()
		if err := lease.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	codec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := codec.VerifyCredential(h.Lease.Artifact, h.Lease.Trust[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(artifact.Release)
	parameters, err := artifact.SessionParameters()
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := artifact.CopyCandidateRoute(h.Hello.Index, make([]byte, 16384))
	if err != nil {
		t.Fatal(err)
	}
	candidate, ok := artifact.Field("candidates").Index(int(h.Hello.Index)).Named("Candidate", "candidate_id").ByteString()
	if !ok || len(candidate) != 16 {
		t.Fatal("missing original candidate")
	}
	return h, &directRuntimeMaterial{spec: directMaterialSpec{Source: h.Lease.Source}, session: parameters, material: original, hello: h.Hello, features: h.Admission[1].Features, binding: sessionv4.ApplicationBinding{Artifact: parameters.ArtifactDigest, Route: digest, Candidate: [16]byte(candidate), Attempt: h.Hello.Attempt}}, artifact
}

func TestDirectAcceptedSourceMatchesCompleteOriginalHintBeforeTransfer(t *testing.T) {
	h, original, artifact := directSourceFixture(t)
	runtime := &directRuntime{materials: []*directRuntimeMaterial{original}}
	source := directRuntimeSource{runtime: runtime, profile: original.session.Profile, source: original.spec.Source, routes: map[[32]byte]bool{original.binding.Route: true}}
	workspace, err := protocolv4.NewHelloWorkspace(h.Limits.Hello)
	if err != nil {
		t.Fatal(err)
	}
	build := func(attempt [16]byte) []byte {
		wire, err := workspace.BuildClientHello(make([]byte, 16384), artifact, h.Hello.Index, attempt, h.Hello.Offered, h.Hello.BindingModes, nil)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	foreignAttempt := original.binding.Attempt
	foreignAttempt[0] ^= 1
	if material, _, err := source.ResolveAcceptedMaterial(context.Background(), build(foreignAttempt)); !errors.Is(err, ledgerv4.ErrDenied) || material != nil || original.claimed {
		t.Fatalf("foreign attempt consumed original material: %v", err)
	}
	wrongListener := source
	wrongListener.routes = map[[32]byte]bool{}
	if material, _, err := wrongListener.ResolveAcceptedMaterial(context.Background(), build(original.binding.Attempt)); !errors.Is(err, ledgerv4.ErrDenied) || material != nil || original.claimed {
		t.Fatalf("foreign listener consumed original material: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := source.ResolveAcceptedMaterial(canceled, build(original.binding.Attempt)); !errors.Is(err, context.Canceled) || original.claimed {
		t.Fatalf("canceled lookup consumed original material: %v", err)
	}
	material, hello, err := source.ResolveAcceptedMaterial(context.Background(), build(original.binding.Attempt))
	if err != nil {
		t.Fatal(err)
	}
	if material != original.material || hello.Attempt != original.binding.Attempt || hello.Index != h.Hello.Index || !original.claimed {
		t.Fatal("lookup changed original material or logical invocation")
	}
	if replay, _, err := source.ResolveAcceptedMaterial(context.Background(), build(original.binding.Attempt)); !errors.Is(err, ledgerv4.ErrDenied) || replay != nil {
		t.Fatalf("original transfer was repeated: %v", err)
	}
}

func TestDirectAcceptedPositionsOwnIndependentHandlerPlans(t *testing.T) {
	h, original, _ := directSourceFixture(t)
	environmentAccount, err := h.Root.Account(resourcev4.AccountKey{Kind: resourcev4.EnvironmentAccount, ID: h.Owner().Environment}, h.Root.Snapshot().Limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environmentAccount.Close)
	host := &deploymentRuntime{root: h.Root, owner: h.Owner(), clock: h.Clock, environment: h.Environment, accounts: []resourcev4.Account{h.Scope[1].Tenant, environmentAccount}}
	host.config.Resources.Limit = h.Root.Snapshot().Limit
	host.config.ShutdownMS = 5000
	host.stores[0] = h.Store
	config := &directRuntimeSpec{Core: h.Admission[1].Core, Limits: h.Limits, HandshakeMS: 10000, Streams: []directStreamSpec{{Kind: "original_stream_v1", Slots: 1, Network: "tcp", Address: "127.0.0.1:9", TimeoutMS: 1000}}}
	executorConfig := fs.ApplicationExecutorConfig{Running: 8, ResidentRunning: 4, CompletionRunning: 2, CompletionReserved: 4, RuntimeBytes: 16384, RuntimeBytesPerTask: 131072}
	cost, err := fs.ApplicationExecutorCharge(executorConfig)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := host.reserveApplicationExecutor(cost)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := fs.NewApplicationExecutor(executorConfig, ref)
	ref.Release()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		executor.Close()
		select {
		case <-executor.Done():
		case <-time.After(5 * time.Second):
			t.Error("executor retained original plan owners")
		}
	})
	runtime := &directRuntime{host: host, config: config, executor: executor, materials: []*directRuntimeMaterial{original}, context: context.Background(), positions: make(chan struct{}, 2)}
	first, _, err := runtime.newInput(original, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.retireInput(first, nil) })
	second, _, err := runtime.newInput(original, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.retireInput(second, nil) })
	if first.Config.Application == second.Config.Application || first.Config.Core.Handlers.Plan == second.Config.Core.Handlers.Plan || first.Scope.Session == second.Scope.Session {
		t.Fatal("accepted positions reused a once-only application, handler or session account")
	}
	if first.Config.Initial.Limits.MaxFrame != int(original.session.Contract.Limits().MaxFrame) {
		t.Fatal("Initial frame limit was reconstructed from an unrelated codec bound")
	}
	runtime.retireInput(first, nil)
	if len(runtime.admissions) != 1 || len(runtime.positions) != 1 {
		t.Fatal("retiring one original input released another position")
	}
	runtime.retireInput(second, nil)
	if len(runtime.admissions) != 0 || len(runtime.positions) != 0 {
		t.Fatal("original handler/input graph retained after retirement")
	}
}
