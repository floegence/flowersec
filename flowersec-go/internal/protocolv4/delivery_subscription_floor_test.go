package protocolv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
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
