package flowersec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

type publicExecutionContinuity struct {
	identity V4SQLiteIdentity
	service  V4SQLiteExecutionService
}

func (p publicExecutionContinuity) CheckExecutionHistory(identity V4SQLiteIdentity, service V4SQLiteExecutionService, _ uint64, _ bool) error {
	if identity != p.identity || service != p.service {
		return ledgerv4.ErrFenced
	}
	return nil
}

func TestV4RecoveryServiceAssemblyKeepsOriginalAuthorityAndHistory(t *testing.T) {
	f := newPublicReferenceFixture(t)
	ctx := context.Background()
	canonical := publicResumeVector(t, "service_unary_restart")
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(canonical)
	if err != nil {
		t.Fatal(err)
	}
	defer contract.Release()
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	shape, err := contract.MethodShapeDigest()
	if err != nil {
		t.Fatal(err)
	}
	service := V4ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}
	dbService := V4SQLiteExecutionService(service)
	limits := V4SQLiteLimits{MaxPages: 1024, MaxRecords: 2, MaxRecordBytes: 1 << 20, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	path := filepath.Join(t.TempDir(), "execution.db")
	environment := f.reserve(t, V4ResourceVector{V4Items: 1}, nil)
	charge, err := V4SQLiteBackingCharge(limits)
	backing, err := NewV4SQLiteBacking(path, limits, f.reserve(t, charge, err), environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		backing.Close()
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		if err := backing.ReleaseRemoved(); err != nil {
			t.Error(err)
		}
	})
	identity := V4SQLiteIdentity{Authority: "recovery.test", StoreID: [32]byte{9}, Generation: 1}
	continuity := publicExecutionContinuity{identity, dbService}
	dbConfig := V4SQLiteExecutionConfig{Root: f.root, Clock: f.clock, Service: dbService, CallerAuthorities: [][32]byte{{8}}, Methods: []V4SQLiteExecutionMethod{{Type: policy.Type, Shape: shape}}, Active: 2, ContractNodes: 256, WorkRuntimeBytes: 4096, RecoveryTokensPerOperation: 2, RecoveryMaxIssuedDurationMS: 1000}
	charge, err = V4SQLiteExecutionsCharge(limits, dbConfig)
	if err != nil {
		t.Fatal(err)
	}
	dbConfig.Owner = f.owner()
	reservation, err := f.root.Reserve(dbConfig.Owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Release()
	store, err := CreateV4SQLiteExecutions(ctx, backing, identity, continuity, dbConfig, reservation, environment)
	if err != nil {
		t.Fatal(err)
	}
	closeStore := func() {
		if store == nil {
			return
		}
		store.Close()
		cleanup, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if err := store.WaitCleanup(cleanup); err != nil {
			t.Error(err)
		}
		if err := store.Retire(); err != nil {
			t.Error(err)
		}
		store = nil
	}
	defer closeStore()
	if _, err := store.InstallContract(ctx, 0, canonical, []V4TimeInterval{{LowerMS: 1000, UpperMS: 2000}}, true, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	historyConfig := V4DurableExecutionConfig{Root: f.root, Owner: f.owner(), Clock: f.clock, Service: service, Store: store, Active: 2, TaskCharge: V4ResourceVector{V4Tasks: 1, V4WorkSlots: 1, V4Items: 1}, RuntimeBytes: 4096, WorkRuntimeBytes: 4096}
	charge, err = V4DurableExecutionsCharge(historyConfig)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err = f.root.Reserve(historyConfig.Owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	history, err := NewV4DurableExecutions(historyConfig, reservation)
	reservation.Release()
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	key, err := ImportV4RecoveryMACKey([32]byte{7}, f.reserve(t, V4RecoveryMACKeyCharge(), nil))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	config := V4RecoveryVerifierConfig{Service: service, Clock: f.clock, Keys: []V4RecoveryKey{{ID: [16]byte{4}, Protection: V4ResumeMACToken, MAC: key}}, RuntimeBytes: 4096}
	charge, err = V4RecoveryVerifierCharge(config)
	recovery, err := NewV4RecoveryVerifier(config, f.reserve(t, charge, err))
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	clear(config.Keys)
	registryConfig := V4ServiceRegistryConfig{Root: f.root, Owner: f.owner(), Entries: 1, RuntimeBytes: 4096}
	charge, err = V4ServiceRegistryCharge(registryConfig)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err = f.root.Reserve(registryConfig.Owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewV4ServiceRegistry(registryConfig, reservation)
	reservation.Release()
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	authority := V4ServiceAuthority(service)
	binding := V4DurableServiceBinding(authority, history, recovery)
	if binding.DurableHistory != history || binding.Recovery != recovery.inner || binding.History != nil {
		t.Fatal("assembly substituted execution owners")
	}
	if err := registry.Bind(binding); err != nil {
		t.Fatal(err)
	}
	if err := registry.Bind(binding); !errors.Is(err, rpcv4.ErrServiceAlreadyBound) {
		t.Fatal("duplicate live authority accepted", err)
	}
	registered, err := registry.Lookup(authority)
	if err != nil || registered != binding {
		t.Fatal("registry lost original recovery binding", err)
	}
	for _, value := range []any{key, recovery, history} {
		encoded, err := json.Marshal(value)
		if err != nil || string(encoded) != "{}" || strings.Contains(fmt.Sprintf("%#v", value), service.Tenant) {
			t.Fatal("recovery diagnostics exposed authority", err)
		}
	}
	registration := NewV4ResumeRegistration(0, policy.Namespace, policy.Type)
	if !registration.Resume || registration.Handler != nil || registration.Namespace != policy.Namespace || registration.Type != policy.Type {
		t.Fatal("recovery registration changed method routing")
	}
	registry.Close()
	recovery.Close()
	history.Close()
	if !history.CleanupComplete() {
		t.Fatal("history did not finish original borrows")
	}
	closeStore()
	// Reopening the exact original file preserves its durable registration.
	charge, err = V4SQLiteExecutionsCharge(limits, dbConfig)
	if err != nil {
		t.Fatal(err)
	}
	dbConfig.Owner = f.owner()
	reservation, err = f.root.Reserve(dbConfig.Owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	store, err = OpenV4SQLiteExecutions(ctx, backing, identity, continuity, dbConfig, reservation, environment)
	reservation.Release()
	if err != nil {
		t.Fatal(err)
	}
	if revision, err := store.RegistrationRevision(ctx, policy.Digest, func() error { return nil }); err != nil || revision != 1 {
		t.Fatal("reopen lost original registration", revision, err)
	}
}

func TestV4RecoveryVerifierRejectsUnboundedAndMismatchedKeys(t *testing.T) {
	f := newPublicReferenceFixture(t)
	config := V4RecoveryVerifierConfig{Service: V4ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: "files"}, Clock: f.clock, RuntimeBytes: 4096}
	for _, keys := range [][]V4RecoveryKey{nil, make([]V4RecoveryKey, 17), {{Protection: V4ResumeMACToken}}, {{Protection: V4ResumeSignedToken, MAC: &V4RecoveryMACKey{}, Public: [32]byte{1}}}, {{Public: [32]byte{1}}, {Public: [32]byte{2}}}} {
		config.Keys = keys
		if _, err := V4RecoveryVerifierCharge(config); err == nil {
			t.Fatal("invalid recovery registration admitted")
		}
	}
	charge, err := V4ResumeCodecCharge()
	codec, err := NewV4ResumeCodec(f.reserve(t, charge, err))
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	position := []byte("offset=12")
	checkpoint, err := codec.CaptureCheckpoint("offset", position)
	if err != nil {
		t.Fatal(err)
	}
	clear(position)
	var copied [9]byte
	if n, err := checkpoint.CopyPosition(copied[:]); err != nil || n != 9 || string(copied[:]) != "offset=12" {
		t.Fatal("checkpoint retained mutable position", n, err)
	}
	if _, err := codec.CaptureCheckpoint("offset", make([]byte, 4097)); err == nil {
		t.Fatal("unbounded checkpoint accepted")
	}
}
