package rpcv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestQuerySnapshotInstallationKeepsOriginalWindowsAndRollsBackFailure(t *testing.T) {
	f := newOfferFixture(t, true, timev4.Interval{LowerMS: 25, UpperMS: 25})
	charge, _ := ContractRouteCharge(4096)
	route, err := f.registry.Capture(f.digest, f.rpc.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer route.Release()
	_, policy, err := route.Policy()
	if err != nil {
		t.Fatal(err)
	}
	var body [8192]byte
	n, err := route.CopyCanonical(body[:])
	if err != nil {
		t.Fatal(err)
	}
	original := protocolv4.AdmissionOfferBounds{Digest: f.digest, NotBeforeMS: 0, NotAfterMS: 100}
	if err = f.registry.RegisterOffer(f.digest, offerBytes(t, f.digest, 0, 100)); err != nil {
		t.Fatal(err)
	}
	next := protocolv4.AdmissionOfferBounds{Digest: f.digest, NotBeforeMS: 75, NotAfterMS: 200}
	info := protocolv4.ContractSnapshotInfo{Status: "available_full", Policy: policy, HasOffer: true, Offer: next, ContractBytes: uint16(n)}
	now, err := f.clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	canceled := errors.New("installation canceled")
	if err = f.registry.WithQuerySnapshot(info, body[:n], now, func() error { return canceled }); err != canceled {
		t.Fatal(err)
	}
	if _, err = f.registry.CapturePreparationOffer(f.digest, next); err != ErrAdmissionOfferUnavailable {
		t.Fatal("failed install retained new Offer", err)
	}
	if _, err = f.registry.CapturePreparationOffer(f.digest, original); err != nil {
		t.Fatal("failed install removed old Offer", err)
	}
	if err = f.registry.WithQuerySnapshot(info, body[:n], now, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = f.registry.CapturePreparationOffer(f.digest, next); err != nil {
		t.Fatal("future Offer not retained", err)
	}
	if err = f.registry.WithQueryBindings([][32]byte{f.digest}, []protocolv4.AdmissionOfferBounds{next}, now, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), body[:n]...)
	wrong[len(wrong)-1] ^= 1
	if err = f.registry.WithQuerySnapshot(info, wrong, now, func() error { t.Fatal("mismatched body installed"); return nil }); err != ErrAssociation {
		t.Fatal(err)
	}
}
