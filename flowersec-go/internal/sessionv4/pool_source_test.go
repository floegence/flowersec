package sessionv4

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// This independently configured test control adapter signs real owner proofs
// and parses real request/Ack bytes. It uses actual signed material and a real
// client SQLite store, but is not the network control-service qualification.
type poolSourceControl struct {
	afterTopUpError                                          error
	f                                                        *materialPoolFixture
	t                                                        *testing.T
	key                                                      protocolv4.TopUpFenceAuthority
	denied, unavailable, ackUnavailable, identityUnavailable atomic.Bool
	topUps, acks, snapshots                                  atomic.Int32
	entered, release                                         chan struct{}
	response                                                 protocolv4.TopUpResponseFacts
	request                                                  protocolv4.TopUpRequestFacts
}

func (a *poolSourceControl) CheckTopUpAccess(tenant string, source [16]byte) error {
	if a.denied.Load() || tenant != "tenant-1" || source != ([16]byte{1}) {
		return errors.New("permission denied")
	}
	return nil
}
func (a *poolSourceControl) SnapshotPoolIdentity(ctx context.Context, key []byte) (*ApplicationIdentity, int, error) {
	a.snapshots.Add(1)
	if a.identityUnavailable.Load() {
		return nil, 0, ErrSourceContractInvalid
	}
	identity, err := a.f.identityForPool(a.t)
	return identity, copy(key, []byte("original-key")), err
}
func (a *poolSourceControl) GetTopUpOwnerProof(ctx context.Context, r protocolv4.TopUpRequestFacts, generation uint64, dst []byte) (int, error) {
	if a.unavailable.Load() {
		return 0, poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	fields := []protocolv4.Field{{Name: "tenant_id", Kind: protocolv4.TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: protocolv4.ByteString, Bytes: r.Source[:]}, {Name: "operation_id", Kind: protocolv4.ByteString, Bytes: r.Operation[:]}, {Name: "request_digest", Kind: protocolv4.ByteString, Bytes: r.Digest[:]}, {Name: "current_generation", Number: generation}, {Name: "issued_at_ms", Number: 1100}, {Name: "expires_at_ms", Number: 9000}, {Name: "authority_key_id", Kind: protocolv4.ByteString, Bytes: a.key.KeyID[:]}, {Name: "signature", Kind: protocolv4.ByteString, Bytes: make([]byte, 64)}}
	wire, err := protocolv4.EncodeMap(make([]byte, 512), "OwnerFenceProof", fields)
	if err != nil {
		return 0, err
	}
	signed := initialSignTemplate(a.t, "OwnerFenceProof", wire, nil, [32]byte{7})
	defer signed.Release()
	wire, err = signed.Bytes()
	if err != nil {
		return 0, err
	}
	return copy(dst, wire), nil
}
func (a *poolSourceControl) TopUp(ctx context.Context, wire, dst []byte) (TopUpExchangeResult, error) {
	a.topUps.Add(1)
	codec, err := protocolv4.NewTopUpCodec()
	if err != nil {
		return TopUpExchangeResult{}, err
	}
	now, err := a.f.authorityFixture.trust.clock.Sample()
	if err != nil {
		return TopUpExchangeResult{}, err
	}
	r, err := codec.ParseRequest(wire, a.key, now.Interval)
	if err != nil {
		return TopUpExchangeResult{}, err
	}
	stored, err := a.f.journal.Recover(context.Background())
	if err != nil {
		return TopUpExchangeResult{}, err
	}
	if stored.State != ledgerv4.TopUpJournalPending || stored.Request.Operation != r.Operation || stored.Request.Digest != r.Digest {
		a.t.Error("control send preceded durable exact pending")
		return TopUpExchangeResult{}, ErrSourceContractInvalid
	}
	if a.entered != nil {
		close(a.entered)
		<-a.release
	}
	if a.afterTopUpError != nil {
		return TopUpExchangeResult{}, a.afterTopUpError
	}
	original := stored.Request
	var items [4]protocolv4.TopUpIssueEntry
	for i := range int(original.DesiredCount) {
		items[i] = protocolv4.TopUpIssueEntry{ExpiryMS: 1400, Material: []byte{0xa1, 0, 1}}
	}
	n, err := codec.EncodeResponse(dst, original, stored.ArtifactFrontier+1, false, 0, items[:original.DesiredCount])
	if err != nil {
		return TopUpExchangeResult{}, err
	}
	batch, err := codec.ParseResponse(dst[:n], original)
	if err != nil {
		return TopUpExchangeResult{}, err
	}
	a.response, err = batch.Facts()
	a.request = original
	batch.Release()
	return TopUpExchangeResult{ResponseBytes: n}, err
}
func (a *poolSourceControl) Ack(ctx context.Context, wire []byte) (TopUpExchangeResult, error) {
	a.acks.Add(1)
	if a.ackUnavailable.Load() {
		return TopUpExchangeResult{Code: protocolv4.V4TopUpErrorCodeSourceUnavailable}, nil
	}
	codec, err := protocolv4.NewTopUpCodec()
	if err != nil {
		return TopUpExchangeResult{}, err
	}
	now, err := a.f.authorityFixture.trust.clock.Sample()
	if err != nil {
		return TopUpExchangeResult{}, err
	}
	if _, err = codec.VerifyAck(wire, a.request, a.response, a.key, now.Interval); err != nil {
		return TopUpExchangeResult{}, err
	}
	return TopUpExchangeResult{}, nil
}
func newPoolSource(t *testing.T, f *materialPoolFixture) (*PreauthorizedPoolSource, *poolSourceControl) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(makeSeed(7))
	a := &poolSourceControl{f: f, t: t, key: protocolv4.TopUpFenceAuthority{KeyID: [16]byte{8}, PublicKey: [32]byte(key.Public().(ed25519.PublicKey))}, request: f.request}
	a.response, _ = f.batch.Facts()
	c := PoolSourceConfig{Pool: f.pool, Access: a, Identities: a, Proofs: a, Transport: a, FenceKey: a.key, Clock: f.authorityFixture.trust.clock, RequestLifetimeMS: 100, RecoveryWindowMS: 5000, CallMS: 2000, RuntimeBytes: 65536, MaxWaiters: 8}
	cost, err := PoolSourceCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewPreauthorizedPoolSource(c, f.reserve(cost))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	return s, a
}
func makeSeed(v byte) []byte { var seed [32]byte; seed[0] = v; return seed[:] }
func topUpCode(err error) protocolv4.V4TopUpErrorCode {
	var e ledgerv4.TopUpFailure
	if errors.As(err, &e) {
		return e.Fact.Code
	}
	return ""
}

func TestPoolSourceConcurrentJoinAndWaitingCancellation(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	s, a := newPoolSource(t, f)
	a.entered, a.release = make(chan struct{}), make(chan struct{})
	first, second := make(chan TopUpResult, 1), make(chan TopUpResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { first <- s.TopUp(ctx, TopUpOptions{4, 12}) }()
	select {
	case <-a.entered:
	case r := <-first:
		t.Fatal("early TopUp", r)
	case <-time.After(time.Second):
		t.Fatal("no original send")
	}
	cancel()
	r := <-first
	if r.State != TopUpPending || r.Handle == nil || !errors.Is(r.CallError, context.Canceled) || r.Options != (TopUpOptions{1, 65536}) {
		t.Fatal("waiting cancellation changed original intent", r)
	}
	go func() { second <- s.TopUp(context.Background(), TopUpOptions{0, 0}) }()
	// Join is observed at the local gate, without depending on wall-clock sleep.
	until := time.NewTimer(time.Second)
	defer until.Stop()
	for {
		s.mu.Lock()
		joined := s.waiters == 1
		s.mu.Unlock()
		if joined {
			break
		}
		select {
		case <-until.C:
			t.Fatal("second observer not admitted")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(a.release)
	result := <-second
	if result.CallError != nil || result.State != TopUpAcked || result.Handle != nil || result.Options != (TopUpOptions{1, 65536}) || a.topUps.Load() != 1 || a.acks.Load() != 1 {
		t.Fatal("concurrent join", result, a.topUps.Load(), a.acks.Load())
	}
	if status := s.TopUpStatus(context.Background(), r.Handle); status.State != TopUpAcked || status.CallError != nil {
		t.Fatal("original handle changed operation", status)
	}
	if err := r.Handle.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestPoolSourceReadOnlyRecoveryAndInstalledAck(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	s, a := newPoolSource(t, f)
	ctx := context.Background()
	recovered := s.RecoverPendingTopUps(ctx, "tenant-1", [16]byte{1})
	if recovered.CallError != nil || recovered.Count != 1 || recovered.Operations[0].State != TopUpPending || a.topUps.Load() != 0 || f.adapter.restored.Load() != 0 {
		t.Fatal("read-only recovery did work", recovered)
	}
	a.ackUnavailable.Store(true)
	installed := s.TopUp(ctx, TopUpOptions{2, 123})
	if installed.State != TopUpInstalled || installed.Handle == nil || topUpCode(installed.CallError) != protocolv4.V4TopUpErrorCodeSourceUnavailable {
		t.Fatal(installed)
	}
	restored := f.adapter.restored.Load()
	decoded := f.adapter.decoded.Load()
	a.identityUnavailable.Store(true)
	a.ackUnavailable.Store(false)
	result := s.TopUp(ctx, TopUpOptions{})
	if result.State != TopUpAcked || result.CallError != nil || a.topUps.Load() != 1 || a.snapshots.Load() != 0 || f.adapter.restored.Load() != restored || f.adapter.decoded.Load() != decoded {
		t.Fatal("Ack restored or issued material", result)
	}
	m, err := s.Acquire(ctx, MaterialRequirements{ApplicationProfile: "transport"})
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
}
func TestPoolSourceCreatesNextIntentOnlyAfterAuthoritativeAck(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	s, a := newPoolSource(t, f)
	ctx := context.Background()
	first := s.TopUp(ctx, TopUpOptions{})
	if first.State != TopUpAcked || first.CallError != nil {
		t.Fatal(first)
	}
	old, err := f.journal.Recover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second := s.TopUp(ctx, TopUpOptions{2, 65536})
	if second.State != TopUpAcked || second.CallError != nil || second.Options != (TopUpOptions{2, 65536}) || a.snapshots.Load() != 1 || a.topUps.Load() != 2 {
		t.Fatal(second)
	}
	state, err := f.journal.Recover(ctx)
	if err != nil || state.Request.Sequence() != 2 || state.Request.Operation == old.Request.Operation || state.Request.Pool == old.Request.Pool || state.ArtifactFrontier != 3 {
		t.Fatal("new intent or frontier", state, err)
	}
}
func TestPoolSourceCloseJoinsActualTransportTail(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	s, a := newPoolSource(t, f)
	a.entered, a.release = make(chan struct{}), make(chan struct{})
	returned := make(chan TopUpResult, 1)
	go func() { returned <- s.TopUp(context.Background(), TopUpOptions{}) }()
	select {
	case <-a.entered:
	case r := <-returned:
		t.Fatal("early return", r)
	case <-time.After(time.Second):
		t.Fatal("send did not start")
	}
	s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("unreturned I/O refunded", err)
	}
	close(a.release)
	r := <-returned
	if r.State != TopUpPending || r.Handle == nil || r.CallError == nil {
		t.Fatal("late provider published after Close", r)
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := s.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := r.Handle.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	state, err := f.journal.Recover(context.Background())
	if err != nil || state.State != ledgerv4.TopUpJournalPending {
		t.Fatal(state, err)
	}
}
func TestPoolSourcePermissionErrorPrecedesUnavailable(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	s, a := newPoolSource(t, f)
	a.denied.Store(true)
	a.unavailable.Store(true)
	if r := s.TopUp(context.Background(), TopUpOptions{}); topUpCode(r.CallError) != protocolv4.V4TopUpErrorCodePermissionDenied || r.State != "" {
		t.Fatal(r)
	}
	r := s.RecoverPendingTopUps(context.Background(), "tenant-1", [16]byte{1})
	if topUpCode(r.CallError) != protocolv4.V4TopUpErrorCodePermissionDenied || r.Count != 0 {
		t.Fatal(r)
	}
	if a.topUps.Load() != 0 || a.snapshots.Load() != 0 || f.adapter.restored.Load() != 0 {
		t.Fatal("permission failure performed work")
	}
}

func TestPoolSourcePermissionRevokedDuringControlIO(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	s, a := newPoolSource(t, f)
	pending := s.RecoverPendingTopUps(context.Background(), "tenant-1", [16]byte{1})
	if pending.Count != 1 || pending.Operations[0].Handle == nil {
		t.Fatal(pending)
	}
	a.entered, a.release = make(chan struct{}), make(chan struct{})
	a.afterTopUpError = context.Canceled
	var released atomic.Bool
	defer func() {
		if released.CompareAndSwap(false, true) {
			close(a.release)
		}
	}()
	returned := make(chan TopUpResult, 1)
	go func() { returned <- s.TopUp(context.Background(), TopUpOptions{}) }()
	select {
	case <-a.entered:
	case r := <-returned:
		t.Fatal("control call returned early", r)
	case <-time.After(time.Second):
		t.Fatal("control call did not start")
	}
	a.denied.Store(true)
	released.Store(true)
	close(a.release)
	r := <-returned
	if topUpCode(r.CallError) != protocolv4.V4TopUpErrorCodePermissionDenied || r.State != "" || r.Handle != nil {
		t.Fatal("I/O cancellation hid permission failure or disclosed history", r)
	}
	r = s.TopUpStatus(context.Background(), pending.Operations[0].Handle)
	if topUpCode(r.CallError) != protocolv4.V4TopUpErrorCodePermissionDenied || r.State != "" || r.Handle != nil {
		t.Fatal("status disclosed revoked history", r)
	}
	state, err := f.journal.Recover(context.Background())
	if err != nil || state.State != ledgerv4.TopUpJournalPending || a.acks.Load() != 0 {
		t.Fatal("permission failure changed pending", state, err)
	}
}

func TestTopUpStatusPreservesKnownOperationAfterSourceCleanup(t *testing.T) {
	fixture := newMaterialPoolFixture(t, 1)
	source, _ := newPoolSource(t, fixture)
	recovered := source.RecoverPendingTopUps(context.Background(), "tenant-1", [16]byte{1})
	if recovered.Count != 1 || recovered.Operations[0].Handle == nil {
		t.Fatal(recovered)
	}
	original := recovered.Operations[0]
	source.Close()
	if err := source.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := source.TopUpStatus(context.Background(), original.Handle)
	if status.State != original.State || status.Handle != original.Handle || status.Options != original.Options || topUpCode(status.CallError) != protocolv4.V4TopUpErrorCodeSourceUnavailable {
		t.Fatal("unavailable status erased previously established facts", status)
	}
}
