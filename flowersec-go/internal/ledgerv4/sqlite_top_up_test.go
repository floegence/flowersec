package ledgerv4

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type topUpInsertFailure struct {
	driver.ExecerContext
	count int
}

func (f *topUpInsertFailure) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(query, "INSERT INTO pool ") {
		f.count++
		if f.count == 2 {
			return nil, errors.New("second item failed")
		}
	}
	return f.ExecerContext.ExecContext(ctx, query, args)
}

type topUpOwner struct {
	generation          atomic.Uint64
	identityUnavailable atomic.Bool
}

func (a *topUpOwner) CheckTopUpIdentity(protocolv4.TopUpRequestFacts) error {
	if a.identityUnavailable.Load() {
		return ErrFenced
	}
	return nil
}

func (a *topUpOwner) CheckTopUpOwner(_ SQLiteIdentity, tenant string, source [16]byte, generation uint64) error {
	if tenant != "tenant-1" || source != ([16]byte{1}) || a.generation.Load() != generation {
		return ErrFenced
	}
	return nil
}

func topUpStoreBatch(t *testing.T, r protocolv4.TopUpRequestFacts) (*protocolv4.TopUpBatch, protocolv4.TopUpResponseFacts) {
	t.Helper()
	array := []byte{0x82}
	enc := func(schema string, fields []protocolv4.Field) []byte {
		v, e := protocolv4.EncodeMap(make([]byte, 8192), schema, fields)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	for i := uint64(1); i <= 2; i++ {
		material := []byte{0xa1, 0, byte(i)}
		digest := sha256.Sum256(material)
		array = append(array, enc("TopUpEntry", []protocolv4.Field{{Name: "artifact_sequence", Number: i}, {Name: "binding_generation", Number: r.Generation}, {Name: "expiry_ms", Number: 1000}, {Name: "material", Kind: protocolv4.ByteString, Bytes: material}, {Name: "material_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}, {Name: "client_identity_digest", Kind: protocolv4.ByteString, Bytes: r.Identity[:]}})...)
	}
	var digest [32]byte
	fields := []protocolv4.Field{{Name: "operation_id", Kind: protocolv4.ByteString, Bytes: r.Operation[:]}, {Name: "tenant_id", Kind: protocolv4.TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: protocolv4.ByteString, Bytes: r.Source[:]}, {Name: "binding_generation", Number: r.Generation}, {Name: "entries", Kind: protocolv4.EncodedArray, Bytes: array}, {Name: "server_highest_artifact_sequence", Number: 2}, {Name: "gap_authorized", Kind: protocolv4.Boolean}, {Name: "server_committed", Kind: protocolv4.Boolean, Number: 1}, {Name: "response_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}}
	wire := enc("TopUpResponse", fields)
	// This fixed fixture independently hashes the complete eight-field map,
	// omitting the final key 9 and its 32-byte bstr (35 encoded bytes).
	unsigned := append([]byte(nil), wire[:len(wire)-35]...)
	unsigned[0] = 0xa8
	// A no-gap response has keys 0..6,8,9: removing key 9 leaves eight fields.
	digest = sha256.Sum256(unsigned)
	fields[len(fields)-1].Bytes = digest[:]
	wire = enc("TopUpResponse", fields)
	codec, err := protocolv4.NewTopUpCodec()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := codec.ParseResponse(wire, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(batch.Release)
	facts, err := batch.Facts()
	if err != nil {
		t.Fatal(err)
	}
	return batch, facts
}

func TestSQLiteTopUpPendingAppliedAndAckSurviveOwnerRestart(t *testing.T) {
	f := newSQLiteFixtureWithLimits(t, "", SQLiteLimits{MaxPages: 128, MaxRecords: 16, MaxRecordBytes: 131072, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})
	var tick atomic.Uint64
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 100, MaxAgeMS: 1 << 40, MaxRoundTripMS: 100}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: tick.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, _ := clock.Monotonic()
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 25, UpperMS: 25}); err != nil {
		t.Fatal(err)
	}
	owner := &topUpOwner{}
	owner.generation.Store(1)
	c := SQLiteTopUpConfig{Tenant: "tenant-1", Source: [16]byte{1}, BindingGeneration: 1, IdentityBytes: 1024, KeyReferenceBytes: 128, PoolBytes: 1 << 18, Clock: clock, Authority: owner}
	open := func(create bool) *SQLiteTopUpJournal {
		charge, e := SQLiteTopUpJournalCharge(f.backing.limits, c)
		if e != nil {
			t.Fatal(e)
		}
		var j *SQLiteTopUpJournal
		if create {
			j, e = CreateSQLiteTopUpJournal(context.Background(), f.backing, f.identity, f.continuity, c, f.reserve(charge, 1), f.environment)
		} else {
			j, e = OpenSQLiteTopUpJournal(context.Background(), f.backing, f.identity, f.continuity, c, f.reserve(charge, 1), f.environment)
		}
		if j != nil {
			f.stores = append(f.stores, j.store)
		}
		if e != nil {
			t.Fatal(e)
		}
		return j
	}
	j := open(true)
	ctx := context.Background()
	// The fixture exercises storage, not credential authorization; the source
	// supplies its already-validated complete certificate and key locator.
	certificate := []byte{0xa0}
	identity, err := protocolv4.TopUpIdentityDigest(certificate)
	if err != nil {
		t.Fatal(err)
	}
	r := protocolv4.TopUpRequestFacts{Tenant: c.Tenant, Source: c.Source, Pool: [32]byte{2}, Identity: identity, Digest: [32]byte{3}, Generation: 1, DeadlineMS: 500, DesiredCount: 2, MaxItemBytes: 64}
	binary.BigEndian.PutUint64(r.Operation[:8], 1)
	r.Operation[8] = 7
	r.Digest, err = protocolv4.ComputeTopUpRequestDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Begin(ctx, r, certificate, []byte("key-original")); err != nil {
		t.Fatal(err)
	}
	if err = j.Begin(ctx, r, certificate, []byte("key-replacement")); !errors.Is(err, ErrConflict) {
		t.Fatal("identity locator changed", err)
	}
	old, err := j.Recover(ctx)
	if err != nil || old.State != TopUpJournalPending || old.Request != r || old.NextSequence != 2 {
		t.Fatal("pending facts", old, err)
	}
	closeSQLite(t, j.store)
	owner.generation.Store(2)
	c.BindingGeneration = 2
	j = open(false)
	recovered, err := j.Recover(ctx)
	if err != nil || recovered.Request != r || recovered.BindingGeneration != 2 {
		t.Fatal("original pending not restored", recovered, err)
	}
	certBuffer, keyBuffer := make([]byte, c.IdentityBytes), make([]byte, c.KeyReferenceBytes)
	certN, keyN, err := j.ReadPendingIdentity(ctx, r, certBuffer, keyBuffer)
	if err != nil || string(certBuffer[:certN]) != string(certificate) || string(keyBuffer[:keyN]) != "key-original" {
		t.Fatal("original key recovery", err)
	}
	batch, response := topUpStoreBatch(t, r)
	original := j.store.execer
	j.store.execer = &topUpInsertFailure{ExecerContext: original}
	if err = j.Install(ctx, r, batch); err == nil {
		t.Fatal("partial batch failure hidden")
	}
	j.store.execer = original
	partial, err := j.Recover(ctx)
	if err != nil || partial.State != TopUpJournalPending || partial.ArtifactFrontier != 0 {
		t.Fatal("partial batch advanced Applied", err)
	}
	rows, err := j.store.scalar("SELECT count(*) FROM pool")
	if err != nil || rows != int64(0) {
		t.Fatal("partial batch escaped rollback", rows, err)
	}
	fault := &sqliteExecFault{ExecerContext: original, afterCommit: func() error { return errors.New("lost commit response") }}
	fault.commits.Store(1)
	j.store.execer = fault
	if err = j.Install(ctx, r, batch); !errors.Is(err, ErrUnknown) {
		t.Fatal("lost commit was not unknown", err)
	}
	j.store.execer = original
	installed, err := j.Recover(ctx)
	if err != nil || installed.State != TopUpJournalInstalled || installed.Response != response || installed.ArtifactFrontier != 2 {
		t.Fatal("Applied did not survive lost confirmation", installed, err)
	}
	count, err := j.store.scalar("SELECT count(*) FROM pool")
	if err != nil || count != int64(2) {
		t.Fatal("batch not atomic", count, err)
	}
	if err = j.Install(ctx, r, batch); err != nil {
		t.Fatal("Applied replay", err)
	}
	count, _ = j.store.scalar("SELECT count(*) FROM pool")
	if count != int64(2) {
		t.Fatal("replay appended material")
	}
	closeSQLite(t, j.store)
	tick.Store(2000)
	owner.identityUnavailable.Store(true)
	j = open(false)
	installed, err = j.Recover(ctx)
	if err != nil || installed.State != TopUpJournalInstalled {
		t.Fatal("expired material blocked Applied recovery", err)
	}
	// History-only Ack does not parse material or require its keys to remain usable.
	if err = j.ConfirmAck(ctx, installed.Request, installed.Response); err != nil {
		t.Fatal(err)
	}
	acked, err := j.Recover(ctx)
	if err != nil || acked.State != TopUpJournalAcked || acked.RetiredSequence != 1 || acked.NextSequence != 2 {
		t.Fatal("Ack frontier", acked, err)
	}
	owner.generation.Store(3)
	if _, err = j.Recover(ctx); !errors.Is(err, ErrFenced) {
		t.Fatal("stale owner queried material history", err)
	}
}
