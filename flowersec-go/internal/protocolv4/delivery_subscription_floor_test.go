package protocolv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestDeliverySubscriptionFloorReusesOriginalNamespaceReferences(t *testing.T) {
	x, authority, namespace, _ := deliveryFixture(t)
	floor, err := authority.ReserveDeliveryFloor(x.f.reserve(t, DeliverySubscriptionFloorCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer floor.Close()
	count := namespace.SubscriptionCount()
	var refs [3]resourcev4.Reference
	for j := range refs {
		refs[j] = x.f.reserve(t, CredentialSubscriptionsCharge())
	}
	// Exhaust actual root references after every needed future was admitted.
	var held []resourcev4.Reference
	for {
		ref, err := floor.reservation.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, ref)
	}
	defer func() {
		for _, ref := range held {
			ref.Release()
		}
	}()
	for _, ref := range refs {
		d, err := authority.ForkDeliveryWithFloor(ref, floor)
		if err != nil {
			t.Fatal("short result allocated an unreserved namespace reference", err)
		}
		if namespace.SubscriptionCount() != count {
			t.Fatal("duplicated namespace subscription")
		}
		if err := d.Check(); err != nil {
			t.Fatal(err)
		}
		d.Close(nil)
		if namespace.SubscriptionCount() != count {
			t.Fatal("return erased the promised future namespace slot")
		}
	}
}

func TestDeliverySubscriptionFloorCloseTransfersItsLiveResult(t *testing.T) {
	x, authority, namespace, trust := deliveryFixture(t)
	floor, err := authority.ReserveDeliveryFloor(x.f.reserve(t, DeliverySubscriptionFloorCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer floor.Close()
	d, err := authority.ForkDeliveryWithFloor(x.f.reserve(t, CredentialSubscriptionsCharge()), floor)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(nil)
	if _, err := authority.ForkDeliveryWithFloor(x.f.reserve(t, CredentialSubscriptionsCharge()), floor); err == nil {
		t.Fatal("two results used one protected namespace promise")
	}
	floor.Close()
	authority.Close(nil)
	if err := d.Check(); err != nil {
		t.Fatal("Session close revoked independent result", err)
	}
	if namespace.SubscriptionCount() != 1 {
		t.Fatal(namespace.SubscriptionCount())
	}
	trust.rejected.Store(true)
	namespace.NotifyTrust()
	if err := d.Check(); err == nil {
		t.Fatal("detached protected result ignored current trust")
	}
	d.Close(nil)
	if namespace.SubscriptionCount() != 0 {
		t.Fatal("late result retained namespace after real release")
	}
}

func TestDeliverySubscriptionFloorSurvivesOriginalLiveGrantCompletion(t *testing.T) {
	for _, role := range []Direction{ClientToServer, ServerToClient} {
		t.Run(map[Direction]string{ClientToServer: "client", ServerToClient: "server"}[role], func(t *testing.T) {
			x := newEndpointCredentialFixture(t, true, false)
			x.f.now = timev4.Interval{LowerMS: 1200, UpperMS: 1250}
			// This fixture's Grant uses cohort zero, whose issuance window ends
			// at 1100. Sign an original within that window before preparing it.
			grantIndex := 3 + 2*int(role)
			wire, err := x.originals[grantIndex].Bytes()
			if err != nil {
				t.Fatal(err)
			}
			grant, _, err := x.f.r.decode(wire, "Grant", nil, 1<<16)
			if err != nil {
				t.Fatal(err)
			}
			x.f.set(t, "Grant", grant, "issued_at_ms", namespaceNumber(1050))
			x.originals[grantIndex] = signRuntimeFixture(t, "Grant", grant.encode(nil), DecodeContext{})
			complete, err := x.bind(role)
			if err != nil {
				t.Fatal(err)
			}
			namespace, _, trust := liveNamespaceFixture(t, x.f, 4000, false)
			policy := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
			bindings := make([]CredentialValidation, complete.count)
			for i, credential := range complete.credentials[:complete.count] {
				bindings[i] = CredentialValidation{Namespace: namespace, Issuer: IssuerPermission{Schema: credential.scope.Schema, Issuer: credential.scope.Issuer, Key: credential.key, SigningStart: 1000, SigningEnd: 1200}, Policy: policy}
			}
			pending, err := BindLiveEndpointPreparation(role, x.originals[0], 0, x.originals[1], x.originals[2], x.originals[4+2*int(role)], LiveGrantPreparation{Scope: complete.credentials[3].scope, Validation: bindings[3]})
			if err != nil {
				t.Fatal(err)
			}
			subscriptions, err := pending.Subscribe(bindings, 2000, x.f.reserve(t, CredentialSubscriptionsCharge()))
			if err != nil {
				t.Fatal(err)
			}
			defer subscriptions.Close()
			floor, err := subscriptions.ReserveDeliveryFloor(x.f.reserve(t, DeliverySubscriptionFloorCharge()))
			if err != nil {
				t.Fatal(err)
			}
			defer floor.Close()
			// Exhaust all remaining physical slots before the live Grant arrives.
			var occupied []namespaceSubscription
			defer func() {
				for _, slot := range occupied {
					slot.release()
				}
			}()
			for {
				slot, err := namespace.subscribe(make(chan struct{}, 1))
				if err == CBORFailure("revocation_subscription_capacity") {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				occupied = append(occupied, slot)
			}
			count := namespace.SubscriptionCount()
			if err = subscriptions.CompleteLiveGrant(complete); err != nil {
				t.Fatal(err)
			}
			if err = subscriptions.CompleteLiveGrant(complete); err == nil {
				t.Fatal("completed a second live Grant")
			}
			_, activation, _ := x.f.activationOriginal(t, "live_authority", x.originals[0])
			trust.activation = activation.trust
			authority, err := NewEndpointAuthorization(subscriptions, activation)
			if err != nil {
				t.Fatal(err)
			}
			defer authority.Close(nil)
			remaining, err := authority.RemainingMS()
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				delivery, err := authority.ForkDeliveryWithFloor(x.f.reserve(t, CredentialSubscriptionsCharge()), floor)
				if err != nil {
					t.Fatal("original live result lost its preadmitted namespace slots", err)
				}
				if err = delivery.Check(); err != nil {
					t.Fatal(err)
				}
				if namespace.SubscriptionCount() != count {
					t.Fatal("live completion acquired extra namespace slots")
				}
				if value, err := delivery.RemainingMS(); err != nil || value > remaining {
					t.Fatal("live completion extended the original deadline", value, err)
				}
				if i == 2 {
					authority.Close(nil)
					if err = delivery.Check(); err != nil {
						t.Fatal("Session close revoked the independently held result", err)
					}
				}
				delivery.Close(nil)
			}
			// A fresh admission with identical signed facts cannot redeem this floor.
			unrelated, err := x.bind(role)
			if err != nil {
				t.Fatal(err)
			}
			otherSubscriptions, err := unrelated.Subscribe(bindings, 2000, x.f.reserve(t, CredentialSubscriptionsCharge()))
			if err != nil {
				t.Fatal(err)
			}
			defer otherSubscriptions.Close()
			other, err := NewEndpointAuthorization(otherSubscriptions, activation)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close(nil)
			if delivery, err := other.ForkDeliveryWithFloor(x.f.reserve(t, CredentialSubscriptionsCharge()), floor); err == nil {
				delivery.Close(nil)
				t.Fatal("a fresh admission adopted the original live result floor")
			}
			other.Close(nil)
			floor.Close()
			for _, slot := range occupied {
				slot.release()
			}
			if namespace.SubscriptionCount() != 0 {
				t.Fatal("retired live delivery retained namespace slots")
			}
		})
	}
}
