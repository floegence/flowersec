package ledgerv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type topUpServerAuthority struct {
	commitGate                                      sync.Mutex
	generation                                      atomic.Uint64
	permanent, unavailable, denied, invalidMaterial atomic.Bool
}

type topUpServerCommit struct {
	authority *topUpServerAuthority
	released  atomic.Bool
}

func (c *topUpServerCommit) Check() error {
	if c.released.Load() {
		return ErrOwner
	}
	return nil
}
func (c *topUpServerCommit) Release() {
	if c.released.CompareAndSwap(false, true) {
		c.authority.commitGate.Unlock()
	}
}
func (a *topUpServerAuthority) AcquireTopUpCommit(SQLiteIdentity, string, [16]byte) (SQLiteTopUpCommit, error) {
	if !a.commitGate.TryLock() {
		return nil, ErrCapacity
	}
	return &topUpServerCommit{authority: a}, nil
}

func (a *topUpServerAuthority) CheckTopUpAccess(string, [16]byte) error {
	if a.denied.Load() {
		return ErrOwner
	}
	return nil
}
func (a *topUpServerAuthority) TopUpAuditPrincipal(tenant string, source [16]byte) (AuditPrincipal, error) {
	if err := a.CheckTopUpAccess(tenant, source); err != nil {
		return AuditPrincipal{}, err
	}
	return AuditPrincipal{Actor: [32]byte{5}, Role: 1}, nil
}
func (a *topUpServerAuthority) CheckTopUpSource(SQLiteIdentity, string, [16]byte) (TopUpSourceFence, error) {
	if a.unavailable.Load() {
		return TopUpSourceFence{}, ErrOwner
	}
	return TopUpSourceFence{Generation: a.generation.Load(), LeaseUntilMS: 10000, Permanent: a.permanent.Load()}, nil
}
func (a *topUpServerAuthority) CheckTopUpIssuedBatch(_ protocolv4.TopUpRequestFacts, b *protocolv4.TopUpBatch) error {
	if a.invalidMaterial.Load() {
		return topUpFailure(protocolv4.V4TopUpErrorCodeSourceContractInvalid)
	}
	// These tests exercise storage with trusted issuer fixtures. Actual
	// credential verification is an independently composed authority contract.
	_, err := b.Material(0)
	return err
}

type topUpServerFixture struct {
	*sqliteFixture
	clock     *timev4.Clock
	tick      atomic.Uint64
	authority *topUpServerAuthority
	config    SQLiteTopUpServerConfig
	server    *SQLiteTopUpServer
	dst       []byte
}

func newTopUpServerFixture(t *testing.T) *topUpServerFixture {
	return newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{})
}

func newTopUpServerFixtureWithAudit(t *testing.T, audit SQLiteAuditPolicy) *topUpServerFixture {
	t.Helper()
	f := &topUpServerFixture{sqliteFixture: newSQLiteFixtureWithLimits(t, "", SQLiteLimits{MaxPages: 384, MaxRecords: 1, MaxRecordBytes: 524288, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}), authority: &topUpServerAuthority{}, dst: make([]byte, 524288)}
	f.authority.generation.Store(1)
	var err error
	f.clock, err = timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 100, MaxAgeMS: 1 << 40, MaxRoundTripMS: 100}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: f.tick.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.clock.Close)
	mark, _ := f.clock.Monotonic()
	if err = f.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 100, UpperMS: 100}); err != nil {
		t.Fatal(err)
	}
	seed := [32]byte{7}
	key := ed25519.NewKeyFromSeed(seed[:])
	f.config = SQLiteTopUpServerConfig{Tenant: "tenant-1", Source: [16]byte{1}, FenceKey: protocolv4.TopUpFenceAuthority{KeyID: [16]byte{8}, PublicKey: [32]byte(key.Public().(ed25519.PublicKey))}, RetirementSkewMS: 10, Clock: f.clock, Authority: f.authority}
	f.config.Audit = audit
	f.openServer(true)
	return f
}
func (f *topUpServerFixture) openServer(create bool) {
	f.t.Helper()
	charge, err := SQLiteTopUpServerCharge(f.backing.limits, f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	reservation := f.reserve(charge, 1)
	if create {
		f.server, err = CreateSQLiteTopUpServer(context.Background(), f.backing, f.identity, f.continuity, f.config, reservation, f.environment)
	} else {
		f.server, err = OpenSQLiteTopUpServer(context.Background(), f.backing, f.identity, f.continuity, f.config, reservation, f.environment)
	}
	if f.server != nil {
		f.stores = append(f.stores, f.server.store)
	}
	if err != nil {
		f.t.Fatal(err)
	}
}
func serverTopUpEncode(t *testing.T, schema string, fields []protocolv4.Field) []byte {
	t.Helper()
	b, e := protocolv4.EncodeMap(make([]byte, 524288), schema, fields)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func serverTopUpProof(t *testing.T, r protocolv4.TopUpRequestFacts, generation, expiry uint64) []byte {
	t.Helper()
	codec, e := protocolv4.NewSignedMapCodec("OwnerFenceProof", 512, 64)
	if e != nil {
		t.Fatal(e)
	}
	seed := [32]byte{7}
	id := [16]byte{8}
	signed, e := codec.Sign([]protocolv4.Field{{Name: "tenant_id", Kind: protocolv4.TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: protocolv4.ByteString, Bytes: r.Source[:]}, {Name: "operation_id", Kind: protocolv4.ByteString, Bytes: r.Operation[:]}, {Name: "request_digest", Kind: protocolv4.ByteString, Bytes: r.Digest[:]}, {Name: "current_generation", Number: generation}, {Name: "issued_at_ms", Number: 50}, {Name: "expires_at_ms", Number: expiry}, {Name: "authority_key_id", Kind: protocolv4.ByteString, Bytes: id[:]}}, seed, protocolv4.DecodeContext{})
	if e != nil {
		t.Fatal(e)
	}
	defer signed.Release()
	b, e := signed.Bytes()
	if e != nil {
		t.Fatal(e)
	}
	return bytes.Clone(b)
}
func serverTopUpRequest(t *testing.T, r protocolv4.TopUpRequestFacts, expiry uint64) (protocolv4.TopUpRequestFacts, []byte) {
	t.Helper()
	fields := []protocolv4.Field{{Name: "operation_id", Kind: protocolv4.ByteString, Bytes: r.Operation[:]}, {Name: "tenant_id", Kind: protocolv4.TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: protocolv4.ByteString, Bytes: r.Source[:]}, {Name: "desired_count", Number: uint64(r.DesiredCount)}, {Name: "max_item_bytes", Number: uint64(r.MaxItemBytes)}, {Name: "pool_digest", Kind: protocolv4.ByteString, Bytes: r.Pool[:]}, {Name: "binding_generation", Number: r.Generation}, {Name: "owner_fence_proof", Kind: protocolv4.ByteString, Bytes: serverTopUpProof(t, r, r.Generation, expiry)}, {Name: "request_deadline_ms", Number: r.DeadlineMS}, {Name: "client_identity_digest", Kind: protocolv4.ByteString, Bytes: r.Identity[:]}}
	codec, e := protocolv4.NewTopUpCodec()
	if e != nil {
		t.Fatal(e)
	}
	r, e = codec.InspectRequest(serverTopUpEncode(t, "TopUpRequest", fields))
	if e != nil {
		t.Fatal(e)
	}
	fields[7].Bytes = serverTopUpProof(t, r, r.Generation, expiry)
	return r, serverTopUpEncode(t, "TopUpRequest", fields)
}
func (f *topUpServerFixture) request(sequence, generation uint64) (protocolv4.TopUpRequestFacts, []byte) {
	r := protocolv4.TopUpRequestFacts{Tenant: f.config.Tenant, Source: f.config.Source, Pool: [32]byte{2}, Identity: [32]byte{3}, Generation: generation, DeadlineMS: 500, DesiredCount: 2, MaxItemBytes: 64}
	binary.BigEndian.PutUint64(r.Operation[:8], sequence)
	r.Operation[8] = 9
	return serverTopUpRequest(f.t, r, 9000)
}
func serverTopUpResponse(t *testing.T, r protocolv4.TopUpRequestFacts, first uint64, gap bool, retired uint64) ([]byte, protocolv4.TopUpResponseFacts) {
	t.Helper()
	array := []byte{0x82}
	for i := uint64(0); i < 2; i++ {
		material := []byte{0xa1, 0, byte(i)}
		digest := sha256.Sum256(material)
		array = append(array, serverTopUpEncode(t, "TopUpEntry", []protocolv4.Field{{Name: "artifact_sequence", Number: first + i}, {Name: "binding_generation", Number: r.Generation}, {Name: "expiry_ms", Number: 1000 + (first-1)*1000 + i*100}, {Name: "material", Kind: protocolv4.ByteString, Bytes: material}, {Name: "material_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}, {Name: "client_identity_digest", Kind: protocolv4.ByteString, Bytes: r.Identity[:]}})...)
	}
	var digest [32]byte
	fields := []protocolv4.Field{{Name: "operation_id", Kind: protocolv4.ByteString, Bytes: r.Operation[:]}, {Name: "tenant_id", Kind: protocolv4.TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: protocolv4.ByteString, Bytes: r.Source[:]}, {Name: "binding_generation", Number: r.Generation}, {Name: "entries", Kind: protocolv4.EncodedArray, Bytes: array}, {Name: "server_highest_artifact_sequence", Number: first + 1}, {Name: "gap_authorized", Kind: protocolv4.Boolean}, {Name: "server_committed", Kind: protocolv4.Boolean, Number: 1}, {Name: "response_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}}
	if gap {
		fields[6].Number = 1
		fields = append(fields, protocolv4.Field{Name: "retired_artifact_through", Number: retired})
	}
	b := serverTopUpEncode(t, "TopUpResponse", fields)
	unsigned := bytes.Clone(b[:len(b)-35])
	unsigned[0]--
	digest = sha256.Sum256(unsigned)
	fields[8].Bytes = digest[:]
	b = serverTopUpEncode(t, "TopUpResponse", fields)
	codec, e := protocolv4.NewTopUpCodec()
	if e != nil {
		t.Fatal(e)
	}
	batch, e := codec.ParseResponse(b, r)
	if e != nil {
		t.Fatal(e)
	}
	defer batch.Release()
	facts, e := batch.Facts()
	if e != nil {
		t.Fatal(e)
	}
	return b, facts
}
func serverTopUpAck(t *testing.T, r protocolv4.TopUpRequestFacts, response protocolv4.TopUpResponseFacts, generation uint64) []byte {
	fields := []protocolv4.Field{{Name: "operation_id", Kind: protocolv4.ByteString, Bytes: r.Operation[:]}, {Name: "pool_digest", Kind: protocolv4.ByteString, Bytes: r.Pool[:]}, {Name: "response_digest", Kind: protocolv4.ByteString, Bytes: response.Digest[:]}, {Name: "server_highest_artifact_sequence", Number: response.Highest}, {Name: "gap_authorized", Kind: protocolv4.Boolean}, {Name: "applied", Kind: protocolv4.Boolean, Number: 1}, {Name: "request_digest", Kind: protocolv4.ByteString, Bytes: r.Digest[:]}, {Name: "binding_generation", Number: generation}, {Name: "owner_fence_proof", Kind: protocolv4.ByteString, Bytes: serverTopUpProof(t, r, generation, 9000)}}
	if response.Gap {
		fields[4].Number = 1
		fields = append(fields, protocolv4.Field{Name: "retired_artifact_through", Number: response.RetiredThrough})
	}
	return serverTopUpEncode(t, "TopUpAck", fields)
}
func (f *topUpServerFixture) prepare(wire []byte) (TopUpServerResult, error) {
	return f.server.Prepare(context.Background(), f.authority, wire, f.dst)
}
func (f *topUpServerFixture) state() TopUpServerSnapshot {
	f.t.Helper()
	s, e := f.server.Recover(context.Background(), f.authority)
	if e != nil {
		f.t.Fatal(e)
	}
	return s
}

func TestSQLiteTopUpServerCommitReplayTakeoverAndHistoricalAck(t *testing.T) {
	f := newTopUpServerFixture(t)
	ctx := context.Background()
	r, wire := f.request(1, 1)
	result, e := f.prepare(wire)
	if e != nil || result.Snapshot.State != TopUpServerPending || result.Snapshot.Request != r {
		t.Fatal(result, e)
	}
	next, nextWire := f.request(2, 1)
	if _, e = f.prepare(nextWire); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodeCapacityExhausted) {
		t.Fatal("parallel append", e)
	}
	response, facts := serverTopUpResponse(t, r, 1, false, 0)
	// Unknown commit confirmation must not issue another batch on recovery.
	original := f.server.store.execer
	fault := &sqliteExecFault{ExecerContext: original, afterCommit: func() error { return errors.New("lost commit confirmation") }}
	fault.commits.Store(1)
	f.server.store.execer = fault
	if _, e = f.server.Commit(ctx, f.authority, wire, response); !errors.Is(e, ErrUnknown) {
		t.Fatal("unknown confirmation", e)
	}
	f.server.store.execer = original
	if f.state().Response != facts {
		t.Fatal("durable response lost")
	}
	closeSQLite(t, f.server.store)
	f.authority.generation.Store(2)
	f.openServer(false)
	if _, e = f.prepare(wire); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodeStaleGeneration) {
		t.Fatal("old owner replay", e)
	}
	current := r
	current.Generation = 2
	_, renewed := serverTopUpRequest(t, current, 9000)
	result, e = f.prepare(renewed)
	if e != nil || !result.Replay || !bytes.Equal(f.dst[:result.ResponseBytes], response) || result.Snapshot.Request != r {
		t.Fatal("changed replay", result, e)
	}
	// A current proof can confirm an already-installed original batch after
	// material expiry, without an issuer/identity check or reinstatement.
	f.tick.Store(1200)
	f.authority.invalidMaterial.Store(true)
	ack := serverTopUpAck(t, r, facts, 2)
	state, e := f.server.Ack(ctx, f.authority, ack)
	if e != nil || state.State != TopUpServerRetired || state.RetiredSequence != 1 || state.Response != facts {
		t.Fatal("history Ack", state, e)
	}
	if _, e = f.server.Ack(ctx, f.authority, ack); e != nil {
		t.Fatal("duplicate Ack", e)
	}
	if _, e = f.prepare(wire); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodeStaleOperation) {
		t.Fatal("retired needs no proof", e)
	}
	n, e := f.server.readWire()
	if e != nil || n != 0 {
		t.Fatal("retired material retained", n, e)
	}
	next.Generation = 2
	next.DeadlineMS = 3000
	_, nextWire = serverTopUpRequest(t, next, 9000)
	result, e = f.prepare(nextWire)
	if e != nil || result.Snapshot.State != TopUpServerPending || result.Snapshot.RetiredSequence != 1 || result.Snapshot.HighestArtifact != 2 || result.Snapshot.Response.Count != 0 {
		t.Fatal("next sequence reset artifact history", result, e)
	}
}

func TestSQLiteTopUpServerPendingTakeoverDoesNotChangeOriginalIntent(t *testing.T) {
	f := newTopUpServerFixture(t)
	r, wire := f.request(1, 1)
	if _, e := f.prepare(wire); e != nil {
		t.Fatal(e)
	}
	f.authority.generation.Store(2)
	current := r
	current.Generation = 2
	_, renewed := serverTopUpRequest(t, current, 9000)
	result, e := f.prepare(renewed)
	if e != nil || result.Snapshot.Request != r || result.Snapshot.BindingGeneration != 2 {
		t.Fatal(result, e)
	}
	response, _ := serverTopUpResponse(t, r, 1, false, 0)
	if _, e = f.server.Commit(context.Background(), f.authority, wire, response); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodeStaleGeneration) {
		t.Fatal("late old writer", e)
	}
	if _, e = f.server.Commit(context.Background(), f.authority, renewed, response); e != nil {
		t.Fatal("new owner original batch", e)
	}
	changed := current
	changed.Identity[0]++
	_, conflicting := serverTopUpRequest(t, changed, 9000)
	if _, e = f.prepare(conflicting); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodeOperationConflict) {
		t.Fatal("intent replaced", e)
	}
	if f.state().Request != r {
		t.Fatal("original intent mutated")
	}
}

func TestSQLiteTopUpServerPermissionProofAndSequenceRejectionsDoNotConsume(t *testing.T) {
	f := newTopUpServerFixture(t)
	r, wire := f.request(1, 1)
	initial := f.state()
	f.authority.denied.Store(true)
	f.authority.unavailable.Store(true)
	if _, e := f.prepare(nil); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodePermissionDenied) {
		t.Fatal("permission precedence", e)
	}
	f.authority.denied.Store(false)
	if _, e := f.prepare(wire); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodeSourceUnavailable) {
		t.Fatal(e)
	}
	f.authority.unavailable.Store(false)
	_, badProof := serverTopUpRequest(t, r, 90)
	if _, e := f.prepare(badProof); e == nil {
		t.Fatal("expired proof")
	}
	future := r
	future.Generation = 2
	_, futureWire := serverTopUpRequest(t, future, 9000)
	if _, e := f.prepare(futureWire); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodeFutureGeneration) {
		t.Fatal(e)
	}
	_, skipped := f.request(2, 1)
	if _, e := f.prepare(skipped); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodeFutureOperation) {
		t.Fatal(e)
	}
	if got := f.state(); got != initial {
		t.Fatal("rejection wrote state", got)
	}
	if _, e := f.prepare(wire); e != nil {
		t.Fatal("same sequence retry failed", e)
	}
}

func TestSQLiteTopUpServerExpiryRetiresWithoutUnboundedHistory(t *testing.T) {
	f := newTopUpServerFixture(t)
	ctx := context.Background()
	r, wire := f.request(1, 1)
	if _, e := f.prepare(wire); e != nil {
		t.Fatal(e)
	}
	response, _ := serverTopUpResponse(t, r, 1, false, 0)
	if _, e := f.server.Commit(ctx, f.authority, wire, response); e != nil {
		t.Fatal(e)
	}
	f.tick.Store(900) // First item is expired, second is still retained.
	result, e := f.prepare(wire)
	if e != nil || result.Snapshot.State != TopUpServerTerminal || result.Snapshot.Terminal != protocolv4.V4TopUpErrorCodeSourceResetRequired || result.ResponseBytes != 0 {
		t.Fatal(result, e)
	}
	if n, e := f.server.readWire(); e != nil || n == 0 {
		t.Fatal("unexpired second item GC", n, e)
	}
	state, e := f.server.AdvanceRetirement(ctx, f.authority)
	if e != nil || state.State != TopUpServerTerminal {
		t.Fatal("premature retirement", state, e)
	}
	closeSQLite(t, f.server.store)
	f.openServer(false)
	f.tick.Store(1010)
	state, e = f.server.AdvanceRetirement(ctx, f.authority)
	if e != nil || state.State != TopUpServerRetired || state.RetiredArtifact != 2 || state.RetiredSequence != 1 {
		t.Fatal(state, e)
	}
	r, wire = f.request(2, 1)
	r.DeadlineMS = 2000
	r, wire = serverTopUpRequest(t, r, 9000)
	if _, e = f.prepare(wire); e != nil {
		t.Fatal(e)
	}
	// The sequence space stays global and the gap is backed by the tombstone.
	response, _ = serverTopUpResponse(t, r, 3, true, 2)
	if _, e = f.server.Commit(ctx, f.authority, wire, response); e != nil {
		t.Fatal("authorized forward gap", e)
	}
	if f.state().HighestArtifact != 4 {
		t.Fatal("artifact sequence was reset by a new operation")
	}
	f.authority.permanent.Store(true)
	state, e = f.server.AdvanceRetirement(ctx, f.authority)
	if e != nil || !state.Permanent || state.RetiredSequence != 2 {
		t.Fatal("permanent fence", state, e)
	}
	if _, e = f.prepare(wire); !topUpIsFailure(e, protocolv4.V4TopUpErrorCodeSourceResetRequired) {
		t.Fatal("fenced source reused", e)
	}
}

func TestSQLiteTopUpServerExpiredUnallocatedRequestAndCallErrors(t *testing.T) {
	f := newTopUpServerFixture(t)
	ctx := context.Background()
	_, wire := f.request(1, 1)
	f.tick.Store(410)
	result, e := f.prepare(wire)
	if e != nil || result.Snapshot.State != TopUpServerTerminal || result.Snapshot.Terminal != protocolv4.V4TopUpErrorCodeTopUpRequestExpired {
		t.Fatal(result, e)
	}
	state, e := f.server.AdvanceRetirement(ctx, f.authority)
	if e != nil || state.State != TopUpServerRetired || state.HighestArtifact != 0 {
		t.Fatal(state, e)
	}
	r, wire := f.request(2, 1)
	r.DeadlineMS = 2000
	_, wire = serverTopUpRequest(t, r, 9000)
	if _, e = f.prepare(wire); e != nil {
		t.Fatal(e)
	}
	before := f.state()
	for _, code := range []protocolv4.V4TopUpErrorCode{protocolv4.V4TopUpErrorCodePermissionDenied, protocolv4.V4TopUpErrorCodeSourceUnavailable, protocolv4.V4TopUpErrorCodeSourceExhausted, protocolv4.V4TopUpErrorCodeSourceContractInvalid} {
		if _, e = f.server.Deny(ctx, f.authority, wire, code); e == nil {
			t.Fatal("call error became terminal", code)
		}
	}
	if f.state() != before {
		t.Fatal("call errors changed operation")
	}
	state, e = f.server.Deny(ctx, f.authority, wire, protocolv4.V4TopUpErrorCodeCapacityExhausted)
	if e != nil || state.State != TopUpServerTerminal {
		t.Fatal(state, e)
	}
}

// Mutation at the provider boundary simulates an independent fence or clock
// update after SQL writes and before the transaction's final authority check.
type topUpServerBoundaryFault struct {
	driver.ExecerContext
	fired  bool
	mutate func()
}

func (f *topUpServerBoundaryFault) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, e := f.ExecerContext.ExecContext(ctx, query, args)
	if !f.fired && e == nil && strings.HasPrefix(query, "UPDATE manifest SET binding=") {
		f.fired = true
		f.mutate()
	}
	return result, e
}
func TestSQLiteTopUpServerLateCommitGuardsRollback(t *testing.T) {
	for _, name := range []string{"fence", "proof", "deadline", "permission", "issuer"} {
		t.Run(name, func(t *testing.T) {
			f := newTopUpServerFixture(t)
			r, wire := f.request(1, 1)
			if _, e := f.prepare(wire); e != nil {
				t.Fatal(e)
			}
			before := f.state()
			response, _ := serverTopUpResponse(t, r, 1, false, 0)
			original := f.server.store.execer
			f.server.store.execer = &topUpServerBoundaryFault{ExecerContext: original, mutate: func() {
				switch name {
				case "fence":
					f.authority.generation.Store(2)
				case "proof":
					f.tick.Store(8950)
				case "deadline":
					f.tick.Store(450)
				case "permission":
					f.authority.denied.Store(true)
				case "issuer":
					f.authority.invalidMaterial.Store(true)
				}
			}}
			if _, e := f.server.Commit(context.Background(), f.authority, wire, response); e == nil {
				t.Fatal("late authorization change committed")
			}
			f.server.store.execer = original
			f.authority.denied.Store(false)
			after, e := f.server.readState()
			if e != nil || after != before {
				t.Fatal("failed guard did not roll back", after, e)
			}
		})
	}
}

type topUpServerCommitTail struct {
	driver.ExecerContext
	entered, release chan struct{}
}

func (f *topUpServerCommitTail) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, e := f.ExecerContext.ExecContext(ctx, query, args)
	if query == "COMMIT" && e == nil {
		close(f.entered)
		<-f.release
		return result, errors.New("lost commit acknowledgement")
	}
	return result, e
}
func TestSQLiteTopUpServerPinsAuthorityThroughActualCommitReturn(t *testing.T) {
	f := newTopUpServerFixture(t)
	r, wire := f.request(1, 1)
	if _, e := f.prepare(wire); e != nil {
		t.Fatal(e)
	}
	response, _ := serverTopUpResponse(t, r, 1, false, 0)
	original := f.server.store.execer
	fault := &topUpServerCommitTail{ExecerContext: original, entered: make(chan struct{}), release: make(chan struct{})}
	f.server.store.execer = fault
	done := make(chan error, 1)
	go func() { _, e := f.server.Commit(context.Background(), f.authority, wire, response); done <- e }()
	<-fault.entered
	// An authority update uses this same nonblocking gate. The SQL provider's
	// real tail retains it even after the bytes have reached durable storage.
	acquired := f.authority.commitGate.TryLock()
	if acquired {
		f.authority.commitGate.Unlock()
	}
	close(fault.release)
	err := <-done
	f.server.store.execer = original
	if acquired {
		t.Fatal("owner fence was free during physical COMMIT tail")
	}
	if !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	if !f.authority.commitGate.TryLock() {
		t.Fatal("completed transaction retained authority permit")
	}
	f.authority.generation.Store(2)
	f.authority.commitGate.Unlock()
	current := r
	current.Generation = 2
	_, renewed := serverTopUpRequest(t, current, 9000)
	result, err := f.prepare(renewed)
	if err != nil || !result.Replay || !bytes.Equal(f.dst[:result.ResponseBytes], response) {
		t.Fatal("replacement reissued original batch", result, err)
	}
}

func topUpIsFailure(err error, code protocolv4.V4TopUpErrorCode) bool {
	var f TopUpFailure
	return errors.As(err, &f) && f.Fact.Code == code
}
