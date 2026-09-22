package protocolv4

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func TestNamespaceSubscriptionsBoundCoalesceAndFenceReleasedSlot(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, _ := liveNamespaceFixture(t, f, 4000, false)
	var refs [8]namespaceSubscription
	var wakes [8]chan struct{}
	for i := range refs {
		wakes[i] = make(chan struct{}, 1)
		var err error
		refs[i], err = n.subscribe(wakes[i])
		if err != nil {
			t.Fatal(err)
		}
		defer refs[i].release()
	}
	if _, err := n.subscribe(make(chan struct{}, 1)); err != CBORFailure("revocation_subscription_capacity") {
		t.Fatal("unbounded subscriber", err)
	}
	for range 100 {
		n.NotifyTrust()
	}
	for _, wake := range wakes {
		if len(wake) != 1 {
			t.Fatal("missing or queued notification history")
		}
		<-wake
	}
	refs[0].release()
	replacementWake := make(chan struct{}, 1)
	replacement, err := n.subscribe(replacementWake)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.release()
	refs[0].release()
	n.NotifyTrust()
	if len(wakes[0]) != 0 || len(replacementWake) != 1 || n.SubscriptionCount() != 8 {
		t.Fatal("stale subscription displaced replacement")
	}
	for _, ref := range refs {
		ref.release()
	}
	replacement.release()
	if n.SubscriptionCount() != 0 {
		t.Fatal("subscriptions retained")
	}
}

func TestNamespaceSubscriptionsObserveFloorContentAndClose(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, _ := liveNamespaceFixture(t, f, 4000, false)
	wake := make(chan struct{}, 1)
	ref, err := n.subscribe(wake)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.release()
	head, content := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(head); err != nil {
		t.Fatal(err)
	}
	if len(wake) != 1 {
		t.Fatal("observed frontier not announced")
	}
	<-wake
	pin, err := n.Pending()
	if err != nil || pin == nil {
		t.Fatal(err)
	}
	if err := pin.Fetch(namespaceRead(content)); err != nil {
		t.Fatal(err)
	}
	if len(wake) != 1 {
		t.Fatal("complete State installation not announced")
	}
	<-wake
	n.Close(context.Canceled)
	if len(wake) != 1 {
		t.Fatal("namespace destruction not announced")
	}
}

func TestCredentialSubscriptionsReserveBeforeActivationAndTransferOnce(t *testing.T) {
	x := newEndpointCredentialFixture(t, false, false)
	x.f.now = timev4.Interval{LowerMS: 1200, UpperMS: 1250}
	closure, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	n, _, trust := liveNamespaceFixture(t, x.f, 4000, false)
	p := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
	var bindings [3]CredentialValidation
	for i, credential := range closure.credentials[:closure.count] {
		bindings[i] = CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: credential.scope.Schema, Issuer: credential.scope.Issuer, Key: credential.key, SigningStart: 1000, SigningEnd: 1100}, Policy: p}
	}
	var reservations [8]*CredentialSubscriptions
	for i := range reservations {
		reservations[i], err = closure.Subscribe(bindings[:], 10000, x.f.reserve(t, CredentialSubscriptionsCharge()))
		if err != nil {
			t.Fatal(err)
		}
		defer reservations[i].Close()
		if n.SubscriptionCount() != i+1 {
			t.Fatal("duplicate credential charged another complete subscription")
		}
	}
	if _, err := closure.Subscribe(bindings[:], 10000, x.f.reserve(t, CredentialSubscriptionsCharge())); err != CBORFailure("revocation_subscription_capacity") {
		t.Fatal("spent despite unavailable subscription", err)
	}
	// Only now obtain the actual original activation proof and current authority.
	_, activation, _ := x.f.activationOriginal(t, "live_authority", x.originals[0])
	trust.activation = activation.trust
	mark, _ := n.clock.Monotonic()
	if err := n.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1200, UpperMS: 1210}); err != nil {
		t.Fatal(err)
	}
	a, err := NewEndpointAuthorization(reservations[0], activation)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(nil)
	if a.hard != reservations[0].hard {
		t.Fatal("original pre-spend deadline was replaced")
	}
	if remaining, err := a.RemainingMS(); err != nil || remaining != 750 {
		t.Fatal("post-spend clock refinement extended original time", remaining, err)
	}
	if _, err := reservations[0].CheckPreparation(); err != CBORFailure("credential_authorization_owner") {
		t.Fatal("transferred Prepare owner remained usable", err)
	}
	reservations[0].Close()
	if n.SubscriptionCount() != 8 {
		t.Fatal("stale Prepare owner released Session references")
	}
	if _, err := NewEndpointAuthorization(reservations[0], activation); err != CBORFailure("credential_authorization_owner") {
		t.Fatal("reservation transferred twice", err)
	}
	trust.rejected.Store(true)
	n.NotifyTrust()
	select {
	case <-a.Wake():
	case <-time.After(time.Second):
		t.Fatal("idle authorization was not woken")
	}
	if err := a.Check(); err != CBORFailure("independent_trust_rejected") {
		t.Fatal(err)
	}
	a.Close(nil)
	if n.SubscriptionCount() != 7 {
		t.Fatal("original Session reference not released")
	}
	for _, reservation := range reservations {
		reservation.Close()
	}
	if n.SubscriptionCount() != 0 {
		t.Fatal("closed reservations retained")
	}
}

func TestCredentialSubscriptionFailedActivationCannotRetry(t *testing.T) {
	x := newEndpointCredentialFixture(t, false, false)
	closure, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	n, _, _ := liveNamespaceFixture(t, x.f, 4000, false)
	p := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
	bindings := make([]CredentialValidation, closure.count)
	for i, credential := range closure.credentials[:closure.count] {
		bindings[i] = CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: credential.scope.Schema, Issuer: credential.scope.Issuer, Key: credential.key, SigningStart: 1000, SigningEnd: 1100}, Policy: p}
	}
	s, err := closure.Subscribe(bindings, 10000, x.f.reserve(t, CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEndpointAuthorization(s, nil); err == nil {
		t.Fatal("missing activation accepted")
	}
	if n.SubscriptionCount() != 0 {
		t.Fatal("failed activation retained references")
	}
	if _, err := NewEndpointAuthorization(s, nil); err != CBORFailure("credential_authorization_owner") {
		t.Fatal("failed transfer retried", err)
	}
}
