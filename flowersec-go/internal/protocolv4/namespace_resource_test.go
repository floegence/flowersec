package protocolv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func (f *namespaceFixture) reserve(t *testing.T, charge resourcev4.Vector) resourcev4.Reference {
	t.Helper()
	f.initializeResources(t)
	ref, err := f.resources.Reserve(f.resourceOwner(), charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	return ref
}

func (f *namespaceFixture) initializeResources(t *testing.T) {
	t.Helper()
	if f.resources == nil {
		limit := resourcev4.Vector{}
		for i := range limit {
			limit[i] = 1 << 30
		}
		var err error
		f.resources, err = resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 128, ReferenceSlots: 1024})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.resources.Close)
	}
}

func (f *namespaceFixture) resourceOwner() resourcev4.OwnerKey {
	f.resourceSequence++
	var id [16]byte
	binary.BigEndian.PutUint64(id[:8], f.resourceSequence)
	return resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: id, Backing: id, Kind: 1}
}

func (f *namespaceFixture) namespaceAllocation(t *testing.T) NamespaceAllocation {
	t.Helper()
	f.initializeResources(t)
	return NamespaceAllocation{Root: f.resources, Owners: [3]resourcev4.OwnerKey{f.resourceOwner(), f.resourceOwner(), f.resourceOwner()}}
}

func TestNamespaceResourceConstructorOwnership(t *testing.T) {
	f := newNamespaceFixture(t)
	charge, _ := f.rules.StateCharge()
	if _, err := NewRevocationWorkspace(f.rules, resourcev4.Reference{}); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("unreserved State decoder allocated", err)
	}
	ref := f.reserve(t, charge)
	w, err := NewRevocationWorkspace(f.rules, ref)
	if err != nil {
		t.Fatal(err)
	}
	ref.Release()
	if _, err := NewRevocationWorkspace(f.rules, ref); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("constructor reused original reservation", err)
	}
	if err := w.reservation.Check(); err != nil {
		t.Fatal("stale constructor released original backing", err)
	}
	h, bytes := f.bindHead(t, 1, [2]uint64{})
	s, err := w.Bind(h, bytes)
	if err != nil {
		t.Fatal(err)
	}
	before := f.resources.Snapshot().Charged
	s.Release()
	if f.resources.Snapshot().Charged != before {
		t.Fatal("State release returned still-allocated decoder backing")
	}
	if err := w.Close(); err != nil || f.resources.Snapshot().Reservations != 0 {
		t.Fatal("uninstalled workspace cleanup leaked reservation", err)
	}
	if _, err := w.Bind(h, bytes); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("closed workspace reused", err)
	}
}

func TestNamespaceResourceRetainsHistoryAndActualFetchTail(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, _ := liveNamespaceFixture(t, f, 4000, false)
	wake := make(chan struct{}, 1)
	ref, err := n.subscribe(wake)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.release()
	if f.resources.Snapshot().References != 4 || f.resources.Snapshot().Reservations != 3 {
		t.Fatal("subscription failed to borrow the same backing", f.resources.Snapshot())
	}
	h, input := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(h); err != nil {
		t.Fatal(err)
	}
	pin, _ := n.Pending()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- pin.Fetch(func(_ context.Context, _ NamespaceContent, out []byte) (int, error) {
			close(entered)
			<-release
			return copy(out, input), nil
		})
	}()
	<-entered
	before := f.resources.Snapshot().Charged
	n.Close(nil)
	f.resources.Close()
	if n.CleanupComplete() || n.DestroyEnvironment() == nil || f.resources.Snapshot().Charged != before {
		t.Fatal("closed owner refunded a running fetch")
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("late fetch published after close", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := n.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if n.DestroyEnvironment() == nil || f.resources.Snapshot().Charged != before {
		t.Fatal("task cleanup discarded referenced history")
	}
	ref.release()
	if err := n.DestroyEnvironment(); err != nil || f.resources.Snapshot().Reservations != 0 {
		t.Fatal("closed Environment retained unreferenced history", err)
	}
	ref.release() // Stale release after the slot slab is gone must remain inert.
	if err := n.DestroyEnvironment(); err != nil {
		t.Fatal(err)
	}
}

func TestNamespaceCloseIsNotHistoryRetirement(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, _ := liveNamespaceFixture(t, f, 4000, false)
	before := f.resources.Snapshot().Charged
	workspace := n.active.workspace
	if err := workspace.Close(); err == nil {
		t.Fatal("stale constructor destroyed installed State")
	}
	n.Close(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := n.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if n.DestroyEnvironment() == nil || f.resources.Snapshot().Charged != before || workspace.current == nil {
		t.Fatal("ordinary close discarded required history or charge")
	}
}

func TestNamespaceResourcesRejectPrivateBudgetRoot(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, trust := liveNamespaceFixture(t, f, 4000, false)
	other := newNamespaceFixture(t)
	charge, _ := f.rules.StateCharge()
	spare, err := NewRevocationWorkspace(f.rules, other.reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	defer spare.Close()
	charge, _ = f.rules.LiveNamespaceCharge(8)
	ref := f.reserve(t, charge)
	if _, err := NewLiveNamespace(context.Background(), n.clock, trust, n.active, spare, 4000, 2, 8, ref); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("namespace privately recreated shared budget authority", err)
	}
	if err := ref.Check(); err != nil {
		t.Fatal("failed preflight consumed caller reservation", err)
	}
}

func TestCredentialSubscriptionResourceSurvivesOriginalTransfer(t *testing.T) {
	x := newEndpointCredentialFixture(t, false, false)
	x.f.now.LowerMS, x.f.now.UpperMS = 1200, 1250
	closure, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	n, _, trust := liveNamespaceFixture(t, x.f, 4000, false)
	p := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
	bindings := make([]CredentialValidation, closure.count)
	for i, c := range closure.credentials[:closure.count] {
		bindings[i] = CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: c.scope.Schema, Issuer: c.scope.Issuer, Key: c.key, SigningStart: 1000, SigningEnd: 1100}, Policy: p}
	}
	baseline := x.f.resources.Snapshot()
	other := newNamespaceFixture(t)
	if _, err := closure.Subscribe(bindings, 10000, other.reserve(t, CredentialSubscriptionsCharge())); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("private budget root authorized shared namespace reference", err)
	}
	short := CredentialSubscriptionsCharge()
	short[resourcev4.SDKBytes]--
	shortRef := x.f.reserve(t, short)
	if _, err := closure.Subscribe(bindings, 10000, shortRef); !errors.Is(err, resourcev4.ErrCapacity) || n.SubscriptionCount() != 0 {
		t.Fatal("under-reserved authorization acquired a namespace", err)
	}
	shortRef.Release()
	ref := x.f.reserve(t, CredentialSubscriptionsCharge())
	s, err := closure.Subscribe(bindings, 10000, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ref.Release()
	if _, err := closure.Subscribe(bindings, 10000, ref); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("subscription reservation was consumed twice", err)
	}
	_, activation, _ := x.f.activationOriginal(t, "live_authority", x.originals[0])
	trust.activation = activation.trust
	reserved := x.f.resources.Snapshot()
	a, err := NewEndpointAuthorization(s, activation)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(nil)
	s.Close()
	if a != &s.authorization || x.f.resources.Snapshot() != reserved || n.SubscriptionCount() != 1 {
		t.Fatal("activation reacquired or prematurely returned a pre-spend resource")
	}
	x.f.resources.Close()
	if err := a.Check(); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("closed budget authority allowed publication", err)
	}
	a.Close(nil)
	a.Close(nil)
	after := x.f.resources.Snapshot()
	if after.Charged != baseline.Charged || after.Reservations != baseline.Reservations || after.References != baseline.References || n.SubscriptionCount() != 0 {
		t.Fatal("authorization cleanup failed to release exactly its resources", baseline, after)
	}
}

func TestBootstrappedNamespaceAtomicAdmissionAndUnpublishedCleanup(t *testing.T) {
	f := newNamespaceFixture(t)
	clock, _ := namespaceClockFixture(t, f, false)
	head, input := f.bindHead(t, 1, [2]uint64{})
	bootstrap := NamespaceBootstrap{Rules: f.rules, Head: head, State: input}
	allocation := f.namespaceAllocation(t)
	state, _ := f.rules.StateCharge()
	live, _ := f.rules.LiveNamespaceCharge(8)
	combined, _ := state.Add(state)
	combined, _ = combined.Add(live)
	combined[resourcev4.SDKBytes]--
	pool, err := f.resources.Account(resourcev4.AccountKey{Kind: resourcev4.PoolAccount, ID: [16]byte{7}}, combined)
	if err != nil {
		t.Fatal(err)
	}
	allocation.Accounts = []resourcev4.Account{pool}
	before := f.resources.Snapshot()
	if _, err := NewBootstrappedNamespace(context.Background(), clock, &testNamespaceTrust{}, bootstrap, 4000, 2, 8, allocation); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("partial active/candidate/live capacity accepted", err)
	}
	usage, _ := pool.Usage()
	if f.resources.Snapshot() != before || usage != (resourcev4.Vector{}) {
		t.Fatal("failed composite admission retained quota")
	}
	allocation = f.namespaceAllocation(t)
	bad := bytes.Clone(input)
	bad[len(bad)-1] ^= 1
	bootstrap.State = bad
	if _, err := NewBootstrappedNamespace(context.Background(), clock, &testNamespaceTrust{}, bootstrap, 4000, 2, 8, allocation); err == nil {
		t.Fatal("unauthenticated State installed")
	}
	if f.resources.Snapshot() != before {
		t.Fatal("failed decode retained unpublished complete namespace allocations")
	}
	bootstrap.State = input
	rejected := &testNamespaceTrust{}
	rejected.rejected.Store(true)
	if _, err := NewBootstrappedNamespace(context.Background(), clock, rejected, bootstrap, 4000, 2, 8, allocation); err != CBORFailure("independent_trust_rejected") || f.resources.Snapshot() != before {
		t.Fatal("failed independent trust retained unpublished owners", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewBootstrappedNamespace(ctx, clock, &testNamespaceTrust{}, bootstrap, 4000, 2, 8, allocation); !errors.Is(err, context.Canceled) || f.resources.Snapshot() != before {
		t.Fatal("cancelled bootstrap acquired work", err)
	}
	n, err := NewBootstrappedNamespace(context.Background(), clock, &testNamespaceTrust{}, bootstrap, 4000, 2, 8, allocation)
	if err != nil {
		t.Fatal(err)
	}
	if f.resources.Snapshot().Reservations != 3 || n.active.head != head {
		t.Fatal("original complete pair or reservations lost")
	}
	n.Close(nil)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := n.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	f.resources.Close()
	if err := n.DestroyEnvironment(); err != nil || f.resources.Snapshot().Reservations != 0 {
		t.Fatal("complete initializer ownership did not return", err)
	}
}
