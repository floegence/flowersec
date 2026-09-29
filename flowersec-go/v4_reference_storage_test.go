package flowersec

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type referenceContinuityFunc func(V4SQLiteIdentity, uint64, bool) error

func (f referenceContinuityFunc) Check(identity V4SQLiteIdentity, epoch uint64, create bool) error {
	return f(identity, epoch, create)
}

type publicReferenceFixture struct {
	root   *V4ResourceRoot
	serial byte
	clock  *V4Clock
	tick   atomic.Uint64
}

func newPublicReferenceFixture(t *testing.T) *publicReferenceFixture {
	t.Helper()
	c := V4ResourceConfig{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 64, ReferenceSlots: 256}
	for i := range c.Limit {
		c.Limit[i] = 1 << 30
	}
	root, err := NewV4ResourceRoot(c)
	if err != nil {
		t.Fatal(err)
	}
	f := &publicReferenceFixture{root: root}
	f.clock, err = NewV4Clock(V4ClockProfile{Rate: V4ClockRate{Numerator: 1, Denominator: 1000000, QuantizationMS: 1}, MaxWidthMS: 1000, MaxAgeMS: 60000, MaxRoundTripMS: 1000}, func() (V4ClockTick, error) {
		return V4ClockTick{Milliseconds: f.tick.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mark, err := f.clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.clock.InstallTrusted(mark, V4TimeInterval{LowerMS: 1000, UpperMS: 1001}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("reference owner retained resources", root.Snapshot())
		}
	})
	return f
}

func (f *publicReferenceFixture) owner() V4ResourceOwnerKey {
	f.serial++
	return V4ResourceOwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{f.serial}, Backing: [16]byte{f.serial}, Kind: 1}
}
func (f *publicReferenceFixture) reserve(t *testing.T, charge V4ResourceVector, err error) V4ResourceReference {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(f.owner(), charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	return ref
}

func publicReference(t *testing.T, codec *OperationReferenceCodec, operation, request byte) OperationReference {
	t.Helper()
	var op [32]byte
	binary.BigEndian.PutUint64(op[:8], 2000)
	op[31] = operation
	authority, digest, contract := [32]byte{8}, [32]byte{request}, [32]byte{9}
	var target [1024]byte
	wire, err := protocolv4.EncodeMap(target[:], "ExecutionManagementTarget", []protocolv4.Field{
		{Name: "tenant_id", Kind: protocolv4.TextString, Text: "tenant"}, {Name: "audience", Kind: protocolv4.TextString, Text: "audience"},
		{Name: "service_namespace", Kind: protocolv4.TextString, Text: "example/service"}, {Name: "caller_subject", Kind: protocolv4.TextString, Text: "caller"},
		{Name: "caller_authority", Kind: protocolv4.ByteString, Bytes: authority[:]}, {Name: "operation_id", Kind: protocolv4.ByteString, Bytes: op[:]},
		{Name: "request_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}, {Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: contract[:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	var output [2048]byte
	wire, err = protocolv4.EncodeMap(output[:], "OperationReference", []protocolv4.Field{
		{Name: "format_version", Number: 1}, {Name: "target_domain", Kind: protocolv4.TextString, Text: "local-domain"},
		{Name: "target", Kind: protocolv4.EncodedMap, Bytes: wire}, {Name: "call_shape", Number: 0}, {Name: "execution_mode", Number: 0},
		{Name: "deadline_at_ms", Number: 3000}, {Name: "cancel_mode", Number: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := codec.Import(wire, "local-domain")
	if err != nil || !ref.Valid() {
		t.Fatal(ref, err)
	}
	return ref
}

func newPublicReferenceCodec(t *testing.T, f *publicReferenceFixture) *OperationReferenceCodec {
	t.Helper()
	charge, err := OperationReferenceCodecCharge()
	codec, err := NewOperationReferenceCodec(f.reserve(t, charge, err))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(codec.Close)
	return codec
}

func TestV4ReferenceCodecCanonicalDomainAndClosure(t *testing.T) {
	f := newPublicReferenceFixture(t)
	codec := newPublicReferenceCodec(t, f)
	ref := publicReference(t, codec, 1, 2)
	var wire [2048]byte
	n, err := codec.Export(wire[:], ref)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := codec.Import(wire[:n], "local-domain")
	if err != nil || copy != ref {
		t.Fatal(copy, err)
	}
	if _, err := codec.Import(wire[:n], "untrusted-domain"); err == nil {
		t.Fatal("import substituted trusted domain")
	}
	codec.Close()
	if _, err := codec.Export(wire[:], ref); !errors.Is(err, ErrOperationClosed) {
		t.Fatal(err)
	}
	if !ref.Valid() {
		t.Fatal("closing codec revoked immutable query locator")
	}
}

func TestV4SQLiteReferencePersistenceQuotaReopenAndExpiry(t *testing.T) {
	f := newPublicReferenceFixture(t)
	codec := newPublicReferenceCodec(t, f)
	first, conflicting, second := publicReference(t, codec, 1, 2), publicReference(t, codec, 1, 3), publicReference(t, codec, 2, 4)
	environment := f.reserve(t, V4ResourceVector{V4Items: 1}, nil)
	limits := V4SQLiteLimits{MaxPages: 32, MaxRecords: 1, MaxRecordBytes: 2048, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	charge, err := V4SQLiteBackingCharge(limits)
	path := filepath.Join(t.TempDir(), "references.db")
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
	identity := V4SQLiteIdentity{Authority: "local-references", StoreID: [32]byte{4}, Generation: 1}
	continuity := referenceContinuityFunc(func(got V4SQLiteIdentity, _ uint64, _ bool) error {
		if got != identity {
			return ledgerv4.ErrFenced
		}
		return nil
	})
	config := V4SQLiteReferenceConfig{Root: f.root, Clock: f.clock, Domain: "local-domain", MaxBytes: 2048, RetentionMS: 1000}
	open := func(create bool) *V4SQLiteReferences {
		config.Owner = f.owner()
		charge, err := V4SQLiteReferencesCharge(limits, config)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := f.root.Reserve(config.Owner, charge)
		if err != nil {
			t.Fatal(err)
		}
		defer reservation.Release()
		var store *V4SQLiteReferences
		if create {
			store, err = CreateV4SQLiteReferences(context.Background(), backing, identity, continuity, config, reservation, environment)
		} else {
			store, err = OpenV4SQLiteReferences(context.Background(), backing, identity, continuity, config, reservation, environment)
		}
		if store != nil {
			t.Cleanup(func() { retirePublicReferences(t, store) })
		}
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	store := open(true)
	adapter, err := NewV4SQLiteReferenceStore(store, "local-domain", f.reserve(t, V4SQLiteReferenceStoreCharge(), nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adapter.Close)
	if binding, err := adapter.Binding(); err != nil || binding.Store != adapter || binding.Domain != "local-domain" {
		t.Fatal(binding, err)
	}
	for range 2 {
		if outcome, err := adapter.SaveOperationReference(context.Background(), first); err != nil || outcome != V4ReferenceSaveConfirmed {
			t.Fatal(outcome, err)
		}
	}
	if err := store.Save(context.Background(), conflicting); !errors.Is(err, ledgerv4.ErrConflict) {
		t.Fatal("changed identity bytes were accepted", err)
	}
	if err := store.Save(context.Background(), second); !errors.Is(err, ledgerv4.ErrCapacity) {
		t.Fatal("reference quota bypassed", err)
	}
	adapter.Close()
	retirePublicReferences(t, store)
	store = open(false)
	loaded, found, err := store.Load(context.Background(), first)
	if err != nil || !found || loaded != first {
		t.Fatal(loaded, found, err)
	}
	var page [1]OperationReference
	n, next, err := store.List(context.Background(), [32]byte{}, page[:])
	if err != nil || n != 1 || page[0] != first || next == [32]byte{} {
		t.Fatal(n, next, err)
	}
	if n, _, err := store.List(context.Background(), next, page[:]); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	f.tick.Store(2000)
	if _, _, err := store.Load(context.Background(), first); !errors.Is(err, ErrOperationReferenceExpired) {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), first); !errors.Is(err, ErrOperationReferenceExpired) {
		t.Fatal("duplicate save renewed retention", err)
	}
	if err := store.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Load(context.Background(), first); err != nil || found {
		t.Fatal(found, err)
	}
	if err := store.Save(context.Background(), second); err != nil {
		t.Fatal("collected quota not reusable", err)
	}
}

func retirePublicReferences(t *testing.T, store *V4SQLiteReferences) {
	t.Helper()
	store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := store.WaitCleanup(ctx); err != nil {
		t.Error(err)
	}
	if err := store.Retire(); err != nil {
		t.Error(err)
	}
}

type publicReferenceStoreFunc func(context.Context, OperationReference) (V4ReferenceSaveOutcome, error)

func (f publicReferenceStoreFunc) SaveOperationReference(ctx context.Context, ref OperationReference) (V4ReferenceSaveOutcome, error) {
	return f(ctx, ref)
}

func TestV4PrepareAndSaveValidatesBindingBeforePreparation(t *testing.T) {
	f := newPublicReferenceFixture(t)
	validated, preparations := 0, 0
	want := errors.New("store binding refused")
	s := &V4Session{validateReferenceStore: func(context.Context, sessionv4.ReferenceStoreBinding) error { validated++; return want },
		prepareUnary: func(context.Context, sessionv4.UnaryMethodDefinition, []byte, rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error) {
			preparations++
			return nil, nil
		},
		prepareStreaming: func(context.Context, sessionv4.UnaryMethodDefinition, string, []byte, []byte, rpcv4.UnaryPreparation) (*sessionv4.StreamOperation, error) {
			preparations++
			return nil, nil
		},
		prepareNotify: func(context.Context, sessionv4.UnaryMethodDefinition, []byte, rpcv4.UnaryPreparation) (*sessionv4.NotifyOperation, error) {
			preparations++
			return nil, nil
		},
	}
	binding := V4ReferenceStoreBinding{Domain: "local-domain", Backing: f.reserve(t, V4ResourceVector{V4Items: 1}, nil), Store: publicReferenceStoreFunc(func(context.Context, OperationReference) (V4ReferenceSaveOutcome, error) {
		t.Error("invalid binding invoked store")
		return V4ReferenceSaveUnknown, nil
	})}
	if _, _, err := s.PrepareUnaryAndSave(context.Background(), V4UnaryMethod{}, nil, V4OperationOptions{}, binding); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if _, _, err := s.PrepareStreamingAndSave(context.Background(), V4StreamingMethod{}, nil, V4OperationOptions{}, binding); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if _, _, err := s.PrepareNotifyAndSave(context.Background(), V4NotifyMethod{}, nil, V4OperationOptions{}, binding); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if validated != 3 || preparations != 0 {
		t.Fatal(validated, preparations)
	}
}
