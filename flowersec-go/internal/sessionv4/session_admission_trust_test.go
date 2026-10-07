package sessionv4

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestSessionAdmissionTrustFixtureChecksOriginalMaterials(t *testing.T) {
	limit := resourcev4.Vector{}
	for i := range limit {
		limit[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 128, ReferenceSlots: 512})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{83}, Backing: [16]byte{1}, Kind: 83}
	environment, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 1, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environment.Release)
	f := newSessionAdmissionTrustFixture(t, root, environment, owner)
	if err := f.authority.MatchOriginal(f.session, f.attempt, f.candidate); err != nil {
		t.Fatal(err)
	}
	var authorization [2]*protocolv4.EndpointAuthorization
	for role := range 2 {
		a, err := protocolv4.NewEndpointAuthorization(f.subscriptions[role], f.authority)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Close(nil) })
		if err := a.Check(); err != nil {
			t.Fatal(err)
		}
		authorization[role] = a
	}
	f.trust.rejected.Store(true)
	f.namespace.NotifyTrust()
	for _, a := range authorization {
		if err := a.Check(); err == nil {
			t.Fatal("independent trust rejection did not close the live gate")
		}
	}
}
