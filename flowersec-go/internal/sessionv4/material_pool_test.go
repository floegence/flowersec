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
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// The test adapter uses a fixed application material tag to select actual
// signed credentials. This exercises ownership and durable assembly, not an
// application material format or network interoperability qualification.
type materialPoolAdapter struct {
	f                 *materialBytesFixture
	t                 *testing.T
	decoded, restored atomic.Int32
	failAt            int32
	entered, release  chan struct{}
}

func (a *materialPoolAdapter) DecodePoolLease(ctx context.Context, wire []byte) (*ArtifactLease, error) {
	n := a.decoded.Add(1)
	if !bytes.Equal(wire, []byte{0xa1, 0, 1}) {
		return nil, ErrSourceContractInvalid
	}
	if a.entered != nil {
		close(a.entered)
		<-a.release
	}
	if n == a.failAt {
		return nil, ErrSourceContractInvalid
	}
	return a.f.lease(a.t)
}
func (a *materialPoolAdapter) RestorePoolIdentity(ctx context.Context, cert, key []byte) (*ApplicationIdentity, error) {
	a.restored.Add(1)
	if !bytes.Equal(cert, a.f.config.ClientCertificate) || string(key) != "original-key" {
		return nil, ErrSourceContractInvalid
	}
	return a.f.identity(a.t, protocolv4.ClientToServer)
}

type materialPoolAuthority struct {
	identity ledgerv4.SQLiteIdentity
	digest   [32]byte
}

func (a *materialPoolAuthority) Check(id ledgerv4.SQLiteIdentity, epoch uint64, create bool) error {
	if id != a.identity || create && epoch != 0 {
		return ledgerv4.ErrFenced
	}
	return nil
}
func (a *materialPoolAuthority) CheckTopUpOwner(id ledgerv4.SQLiteIdentity, tenant string, source [16]byte, generation uint64) error {
	if id != a.identity || tenant != "tenant-1" || source != ([16]byte{1}) || generation != 1 {
		return ledgerv4.ErrFenced
	}
	return nil
}
func (a *materialPoolAuthority) CheckTopUpIdentity(r protocolv4.TopUpRequestFacts) error {
	if r.Identity != a.digest {
		return ledgerv4.ErrFenced
	}
	return nil
}

type materialPoolFixture struct {
	*materialBytesFixture
	environment *Environment
	pool        *MaterialPool
	adapter     *materialPoolAdapter
	journal     *ledgerv4.SQLiteTopUpJournal
	config      MaterialPoolConfig
	request     protocolv4.TopUpRequestFacts
	batch       *protocolv4.TopUpBatch
	identity    *ApplicationIdentity
}

func newMaterialPoolFixture(t *testing.T, count uint32) *materialPoolFixture {
	t.Helper()
	f := &materialPoolFixture{materialBytesFixture: newMaterialBytesFixture(t, "preauthorized_pool")}
	ctx := context.Background()
	ec := EnvironmentConfig{Positions: 2, Materials: 8, MaterialPools: 1, MaterialCreateMS: 1000, Clock: f.admissionIntegrationFixture.trust.clock, RuntimeBytes: 65536}
	cost, err := EnvironmentCharge(ec)
	if err != nil {
		t.Fatal(err)
	}
	f.environment, err = NewEnvironment(ec, f.reserve(cost), f.admissionIntegrationFixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	limits := ledgerv4.SQLiteLimits{MaxPages: 128, MaxRecords: 9, MaxRecordBytes: 131072, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	path := filepath.Join(t.TempDir(), "topup.db")
	cost, err = ledgerv4.SQLiteBackingCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	backing, err := ledgerv4.NewSQLiteBacking(path, limits, f.reserve(cost), f.admissionIntegrationFixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	id := ledgerv4.SQLiteIdentity{Authority: "pool.test", StoreID: [32]byte{19}, Generation: 1}
	digest, err := protocolv4.TopUpIdentityDigest(f.configBytes().ClientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	authority := &materialPoolAuthority{identity: id, digest: digest}
	jc := ledgerv4.SQLiteTopUpConfig{Tenant: "tenant-1", Source: [16]byte{1}, BindingGeneration: 1, IdentityBytes: 4096, KeyReferenceBytes: 128, PoolBytes: 1 << 18, Clock: ec.Clock, Authority: authority}
	cost, err = ledgerv4.SQLiteTopUpJournalCharge(limits, jc)
	if err != nil {
		t.Fatal(err)
	}
	f.journal, err = ledgerv4.CreateSQLiteTopUpJournal(ctx, backing, id, authority, jc, f.reserve(cost), f.admissionIntegrationFixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.environment.Close()
		cleanup, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := f.environment.WaitCleanup(cleanup); err != nil {
			t.Error(err)
		}
		if err := f.environment.Retire(); err != nil {
			t.Error(err)
		}
		f.journal.Close()
		if err := f.journal.WaitCleanup(cleanup); err != nil {
			t.Error(err)
		}
		if err := f.journal.Retire(); err != nil {
			t.Error(err)
		}
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
	f.adapter = &materialPoolAdapter{f: f.materialBytesFixture, t: t}
	f.config = MaterialPoolConfig{Tenant: "tenant-1", Generation: MaterialGeneration{Source: [16]byte{1}, Generation: 1}, Capacity: 8, OperationMS: 1000, RuntimeBytes: 65536, MaterialRuntimeBytes: 8192, Journal: f.journal, Decoder: f.adapter, Identities: f.adapter, Root: f.root, Owner: f.owner}
	cost, err = MaterialPoolCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.pool, err = f.environment.NewMaterialPool(f.config, f.reserve(cost))
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.identityForPool(t)
	if err != nil {
		t.Fatal(err)
	}
	f.request = protocolv4.TopUpRequestFacts{Tenant: "tenant-1", Source: [16]byte{1}, Generation: 1, DeadlineMS: 1400, Pool: [32]byte{9}, Identity: digest, DesiredCount: count, MaxItemBytes: 65536}
	binary.BigEndian.PutUint64(f.request.Operation[:8], 1)
	f.request.Operation[8] = 7
	codec, err := protocolv4.NewTopUpCodec()
	if err != nil {
		t.Fatal(err)
	}
	f.request.Digest, err = codec.RequestDigest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.journal.Begin(ctx, f.request, f.configBytes().ClientCertificate, []byte("original-key")); err != nil {
		t.Fatal(err)
	}
	items := make([]protocolv4.TopUpIssueEntry, count)
	for i := range items {
		items[i] = protocolv4.TopUpIssueEntry{ExpiryMS: 1400, Material: []byte{0xa1, 0, 1}}
	}
	wire := make([]byte, 524288)
	n, err := codec.EncodeResponse(wire, f.request, 1, false, 0, items)
	if err != nil {
		t.Fatal(err)
	}
	f.batch, err = codec.ParseResponse(wire[:n], f.request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.batch.Release)
	return f
}
func (f *materialPoolFixture) configBytes() ArtifactLeaseBytesConfig {
	return f.materialBytesFixture.config
}
func (f *materialPoolFixture) identityForPool(t *testing.T) (*ApplicationIdentity, error) {
	return f.materialBytesFixture.identity(t, protocolv4.ClientToServer)
}

func TestMaterialPoolCompleteBatchAcquireAndHistoryOnlyReplay(t *testing.T) {
	f := newMaterialPoolFixture(t, 2)
	ctx := context.Background()
	if err := f.pool.Install(ctx, f.request, f.batch, f.identity); err != nil {
		t.Fatal(err)
	}
	installed, err := f.journal.Recover(ctx)
	if err != nil || installed.State != ledgerv4.TopUpJournalInstalled {
		t.Fatal(installed, err)
	}
	f.identity.Close()
	if err = f.pool.Install(ctx, f.request, f.batch, nil); err != nil || f.adapter.decoded.Load() != 2 {
		t.Fatal("Applied replay required old identity or decoded again", err)
	}
	for range 2 {
		m, e := f.pool.Acquire(ctx, MaterialRequirements{ApplicationProfile: "transport"})
		if e != nil {
			t.Fatal(e)
		}
		if m.identity.identity != f.identity {
			t.Fatal("material lost original key owner")
		}
		if e = m.check(); e != nil {
			t.Fatal(e)
		}
		m.Close()
	}
	_, err = f.pool.Acquire(ctx, MaterialRequirements{ApplicationProfile: "transport"})
	var failure ledgerv4.TopUpFailure
	if !errors.As(err, &failure) || failure.Fact.Code != protocolv4.V4TopUpErrorCodeSourceExhausted {
		t.Fatal("empty pool", err)
	}
	after, err := f.journal.Recover(ctx)
	if err != nil || after != installed {
		t.Fatal("Acquire changed operation history", after, err)
	}
	if err = f.pool.RestoreInstalled(ctx); err != nil || f.adapter.restored.Load() != 0 {
		t.Fatal("taken entries restored", err)
	}
	if err = f.journal.ConfirmAck(ctx, installed.Request, installed.Response); err != nil {
		t.Fatal(err)
	}
}
func TestMaterialPoolRejectsPartialBatchBeforeApplied(t *testing.T) {
	f := newMaterialPoolFixture(t, 2)
	f.adapter.failAt = 2
	if err := f.pool.Install(context.Background(), f.request, f.batch, f.identity); err == nil {
		t.Fatal("partial validation installed")
	}
	state, err := f.journal.Recover(context.Background())
	if err != nil || state.State != ledgerv4.TopUpJournalPending || state.ArtifactFrontier != 0 {
		t.Fatal(state, err)
	}
	_, err = f.pool.Acquire(context.Background(), MaterialRequirements{ApplicationProfile: "transport"})
	var failure ledgerv4.TopUpFailure
	if !errors.As(err, &failure) || failure.Fact.Code != protocolv4.V4TopUpErrorCodeSourceExhausted {
		t.Fatal("partial batch published", err)
	}
}
func TestMaterialPoolRestoreUsesOriginalCertificateAndKeyLocator(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	ctx := context.Background()
	if err := f.pool.Install(ctx, f.request, f.batch, f.identity); err != nil {
		t.Fatal(err)
	}
	f.pool.Close()
	cleanup, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := f.pool.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	// One registered position is released by the same Environment coordinator.
	f.environment.mu.Lock()
	active := f.environment.poolActive
	f.environment.mu.Unlock()
	if active != 0 {
		t.Fatal("pool tail still registered")
	}
	cost, err := MaterialPoolCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.pool, err = f.environment.NewMaterialPool(f.config, f.reserve(cost))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.pool.RestoreInstalled(ctx); err != nil {
		t.Fatal(err)
	}
	if f.adapter.restored.Load() != 1 {
		t.Fatal("original identity not restored")
	}
	m, err := f.pool.Acquire(ctx, MaterialRequirements{ApplicationProfile: "transport"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.identity.identity == f.identity || m.identity.identity.credential.Facts().Digest != f.request.Identity {
		t.Fatal("restoration did not create same-key original identity")
	}
}
func TestMaterialPoolCloseWaitsForRealDecoderTail(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	f.adapter.entered, f.adapter.release = make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- f.pool.Install(context.Background(), f.request, f.batch, f.identity) }()
	select {
	case <-f.adapter.entered:
	case err := <-result:
		t.Fatal("install exited before decoder", err)
	case <-time.After(time.Second):
		t.Fatal("decoder did not start")
	}
	f.environment.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.pool.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("unreturned provider refunded", err)
	}
	if _, err := f.pool.Acquire(context.Background(), MaterialRequirements{ApplicationProfile: "transport"}); err == nil {
		t.Fatal("closed pool admitted")
	}
	close(f.adapter.release)
	if err := <-result; err == nil {
		t.Fatal("late decoder published")
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := f.pool.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	state, err := f.journal.Recover(context.Background())
	if err != nil || state.State != ledgerv4.TopUpJournalPending {
		t.Fatal(state, err)
	}
}
func TestMaterialPoolAcquireCapacityFailureKeepsLocalMaterial(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	ctx := context.Background()
	if err := f.pool.Install(ctx, f.request, f.batch, f.identity); err != nil {
		t.Fatal(err)
	}
	f.pool.db.Lock()
	if _, err := f.pool.Acquire(ctx, MaterialRequirements{ApplicationProfile: "transport"}); err == nil {
		t.Fatal("store contention hidden")
	}
	f.pool.db.Unlock()
	m, err := f.pool.Acquire(ctx, MaterialRequirements{ApplicationProfile: "transport"})
	if err != nil {
		t.Fatal("transient contention discarded material", err)
	}
	defer m.Close()
	if err = m.check(); err != nil && !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal(err)
	}
}

func TestMaterialPoolPendingRecoveryAndRetiredAdvertisement(t *testing.T) {
	for _, mode := range []string{"restored", "original"} {
		t.Run(mode, func(t *testing.T) {
			f := newMaterialPoolFixture(t, 1)
			pin, err := f.identity.capture(f.pool.reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer pin.release()
			f.identity.Close()
			if mode == "restored" {
				err = f.pool.RecoverInstall(context.Background(), f.request, f.batch)
			} else {
				err = f.pool.installOriginal(context.Background(), f.request, f.batch, pin)
			}
			if err != nil {
				t.Fatal(err)
			}
			m, err := f.pool.Acquire(context.Background(), MaterialRequirements{ApplicationProfile: "transport"})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			if (m.identity.identity == f.identity) != (mode == "original") {
				t.Fatal("original identity binding changed")
			}
			restored := f.adapter.restored.Load()
			if err = f.pool.RecoverInstall(context.Background(), f.request, f.batch); err != nil || f.adapter.restored.Load() != restored {
				t.Fatal("Applied history recovered keys", err)
			}
		})
	}
}
