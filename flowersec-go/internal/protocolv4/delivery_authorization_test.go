package protocolv4

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func deliveryFixture(t *testing.T) (*endpointCredentialFixture, *EndpointAuthorization, *LiveNamespace, *testNamespaceTrust) {
	t.Helper()
	x := newEndpointCredentialFixture(t, false, false)
	x.f.now = timev4.Interval{LowerMS: 1200, UpperMS: 1250}
	closure, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	n, _, trust := liveNamespaceFixture(t, x.f, 4000, false)
	p := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
	bindings := make([]CredentialValidation, closure.count)
	for i, credential := range closure.credentials[:closure.count] {
		bindings[i] = CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: credential.scope.Schema, Issuer: credential.scope.Issuer, Key: credential.key, SigningStart: 1000, SigningEnd: 1100}, Policy: p}
	}
	s, err := closure.Subscribe(bindings, 10000, x.f.reserve(t, CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	_, activation, _ := x.f.activationOriginal(t, "live_authority", x.originals[0])
	trust.activation = activation.trust
	a, err := NewEndpointAuthorization(s, activation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(nil) })
	return x, a, n, trust
}

func TestDeliveryAuthorizationSurvivesIOCloseWithoutResettingTime(t *testing.T) {
	x, a, n, trust := deliveryFixture(t)
	before, err := a.RemainingMS()
	if err != nil {
		t.Fatal(err)
	}
	mark, _ := n.clock.Monotonic()
	if err := n.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1200, UpperMS: 1201}); err != nil {
		t.Fatal(err)
	}
	d, err := a.ForkDelivery(x.f.reserve(t, CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(nil)
	copied := *d
	if _, err := copied.Take(); err == nil {
		t.Fatal("copied creator attached to original ownership slot")
	}
	copied.Close(nil)
	if remaining, err := d.RemainingMS(); err != nil || remaining != before || n.SubscriptionCount() != 2 {
		t.Fatal("new result reference extended time or failed to retain namespace", remaining, before, err)
	}
	owned, err := d.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close(nil)
	copiedOwner := *owned
	copiedOwner.Close(nil)
	if err := copiedOwner.Check(); err == nil || copiedOwner.Wake() != nil {
		t.Fatal("copied delivery owner retained live authority", err)
	}
	d.Close(nil)
	a.Close(nil)
	if err := owned.Check(); err != nil || n.SubscriptionCount() != 1 {
		t.Fatal("normal I/O close revoked separately admitted result", err)
	}
	if _, err := d.Take(); err == nil {
		t.Fatal("original result reference attached twice")
	}
	if _, err := owned.Take(); err == nil {
		t.Fatal("attached reference manufactured another owner")
	}
	trust.rejected.Store(true)
	n.NotifyTrust()
	if err := owned.Check(); err != CBORFailure("independent_trust_rejected") {
		t.Fatal("retained result bypassed independent current trust", err)
	}
	trust.rejected.Store(false)
	if err := owned.Check(); err != CBORFailure("independent_trust_rejected") {
		t.Fatal("new trust revived an already rejected result", err)
	}
	owned.Close(nil)
	if n.SubscriptionCount() != 0 {
		t.Fatal("completed result kept namespace subscribed")
	}
}

type deliveryTimeTrust struct {
	*testNamespaceTrust
	status atomic.Uint32
}

func (t *deliveryTimeTrust) Head(binding NamespaceHeadTrust) error {
	switch t.status.Load() {
	case 1:
		return timev4.ErrPending
	case 2:
		return timev4.ErrUnavailable
	case 3:
		return timev4.ErrExpired
	}
	return t.testNamespaceTrust.Head(binding)
}

func TestDeliveryAuthorizationTimePauseDoesNotDestroyCandidate(t *testing.T) {
	x, a, n, _ := deliveryFixture(t)
	d, err := a.ForkDelivery(x.f.reserve(t, CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(nil)
	n.mu.Lock()
	trust := &deliveryTimeTrust{testNamespaceTrust: n.trust.(*testNamespaceTrust)}
	n.trust = trust
	n.mu.Unlock()
	a.Close(nil)
	for _, pause := range []struct {
		status uint32
		err    error
	}{{1, timev4.ErrPending}, {2, timev4.ErrUnavailable}} {
		trust.status.Store(pause.status)
		if err := d.Check(); !errors.Is(err, pause.err) {
			t.Fatal("unproven time allowed a new payload handoff", err)
		}
		if _, err := d.RemainingMS(); !errors.Is(err, pause.err) {
			t.Fatal("time pause was lost in the wakeup projection", err)
		}
		trust.status.Store(0)
		if err := d.Check(); err != nil {
			t.Fatal("temporary time failure permanently erased the candidate", err)
		}
	}
	trust.status.Store(3)
	if err := d.Check(); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal(err)
	}
	trust.status.Store(0)
	if err := d.Check(); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("expired delivery gate revived", err)
	}
}

func TestDeliveryAuthorizationPayloadUsesOriginalEnvironment(t *testing.T) {
	x, a, n, _ := deliveryFixture(t)
	d, err := a.ForkDelivery(x.f.reserve(t, CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(nil)
	foreign := newNamespaceFixture(t)
	if _, err := d.TakeFor(foreign.reserve(t, CredentialSubscriptionsCharge())); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("private budget root substituted for original Environment", err)
	}
	if _, err := d.TakeFor(resourcev4.Reference{}); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("unreserved payload attached", err)
	}
	payload := x.f.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 16, resourcev4.Items: 1})
	owned, err := d.TakeFor(payload)
	if err != nil {
		t.Fatal("rejected attachment consumed original reference", err)
	}
	defer owned.Close(nil)
	if _, err := d.RemainingMS(); err == nil {
		t.Fatal("stale creator kept time authority after attachment")
	}
	a.Close(nil)
	if n.SubscriptionCount() != 1 {
		t.Fatal("result lost independent namespace reference")
	}
	x.f.resources.Close()
	if err := owned.Check(); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("Environment close failed to fence private result", err)
	}
	owned.Close(nil)
	if n.SubscriptionCount() != 0 {
		t.Fatal("closed delivery authority leaked original namespace reference")
	}
}

func TestDeliveryAuthorizationOrdersActualOwnershipTransfer(t *testing.T) {
	x, authority, _, _ := deliveryFixture(t)
	delivery, err := authority.ForkDelivery(x.f.reserve(t, CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer delivery.Close(nil)
	owner, err := delivery.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(nil)
	authority.Close(nil)
	calls := 0
	transfer := func() error { calls++; return nil }
	if err := owner.WithCurrentAuthorization(transfer); err != nil || calls != 1 {
		t.Fatal(calls, err)
	}
	copy := *owner
	if err := copy.WithCurrentAuthorization(transfer); err == nil || calls != 1 {
		t.Fatal("copied owner transferred input", calls, err)
	}
	owner.Close(nil)
	if err := owner.WithCurrentAuthorization(transfer); err == nil || calls != 1 {
		t.Fatal("closed owner transferred input", calls, err)
	}
}
