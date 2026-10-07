package sessionv4

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestMixedCarrierChargesCaptureBothOriginalOwnerGeometries(t *testing.T) {
	c := corePlanUnitConfig(t, true)
	c.Streams = factoryStreamConfig()
	c.MessageRuntimeBytes = 8192
	c.MixedCarrier = true
	native, shared := coreCarrierMode(c, false), coreCarrierMode(c, true)
	native.MixedCarrier, shared.MixedCarrier = false, false
	nc, _, _, err := sessionCoreCharges(native)
	if err != nil {
		t.Fatal(err)
	}
	sc, _, _, err := sessionCoreCharges(shared)
	if err != nil {
		t.Fatal(err)
	}
	c = coreCarrierMode(c, true)
	union, total, count, err := sessionCoreCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	var wantTotal resourcev4.Vector
	var wantCount uint32
	for owner := range union {
		var want resourcev4.Vector
		for dimension := range want {
			want[dimension] = max(nc[owner][dimension], sc[owner][dimension])
		}
		if union[owner] != want {
			t.Fatalf("original owner %d union = %v, native=%v, shared=%v", owner, union[owner], nc[owner], sc[owner])
		}
		if want != (resourcev4.Vector{}) {
			wantCount++
			wantTotal, err = wantTotal.Add(want)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if count != wantCount || total != wantTotal {
		t.Fatal("captured carrier union lost an original owner")
	}
	nativeChoice := coreCarrierMode(c, false)
	again, againTotal, againCount, err := sessionCoreCharges(nativeChoice)
	if err != nil {
		t.Fatal(err)
	}
	if again != union || againTotal != total || againCount != count {
		t.Fatal("actual native selection changed the captured owner union")
	}
	if callerStreamGeometry(c) != callerStreamGeometry(nativeChoice) {
		t.Fatal("one captured mixed stream floor cannot follow its actual selected carrier")
	}
	nativeOnly := nativeChoice
	nativeOnly.MixedCarrier = false
	if callerStreamGeometry(nativeOnly) == callerStreamGeometry(c) {
		t.Fatal("unrelated native-only floor was accepted as a captured mixed floor")
	}
}
func TestMixedCarrierGeometryRejectsUnqualifiedSharedMode(t *testing.T) {
	c := corePlanUnitConfig(t, true)
	c.MixedCarrier = true
	c.MessageRuntimeBytes = 0
	if _, _, _, err := sessionCoreCharges(c); err == nil {
		t.Fatal("mixed geometry omitted the original shared message decoder")
	}
}

func TestMixedCarrierCapturesOptionalNativeDatagramOwners(t *testing.T) {
	c := corePlanUnitConfig(t, true)
	c.Streams = factoryStreamConfig()
	c.MessageRuntimeBytes = 8192
	c.MixedCarrier = true
	c.Datagrams = true
	c.WorkSlots = 6
	native, shared := coreCarrierMode(c, false), coreCarrierMode(c, true)
	native.MixedCarrier, shared.MixedCarrier = false, false
	shared.Datagrams = false
	nc, _, _, err := sessionCoreCharges(native)
	if err != nil {
		t.Fatal(err)
	}
	sc, _, _, err := sessionCoreCharges(shared)
	if err != nil {
		t.Fatal(err)
	}
	union, total, count, err := sessionCoreCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	if union[coreUnreliableOwner] != (nc[coreUnreliableOwner]) || sc[coreUnreliableOwner] != (resourcev4.Vector{}) {
		t.Fatal("captured native datagram owner was lost or assigned to the shared carrier")
	}
	selected := coreCarrierMode(c, true)
	again, againTotal, againCount, err := sessionCoreCharges(selected)
	if err != nil {
		t.Fatal(err)
	}
	if again != union || againTotal != total || againCount != count {
		t.Fatal("shared selection changed original optional datagram backing")
	}
}

func TestMixedRPCFutureOwnersRetainTheirOriginalPositions(t *testing.T) {
	_, _, c := rpcServicesPlanFixture(t)
	native := c
	native.Native = true
	nc, nt, err := rpcServicesCharges(native)
	if err != nil {
		t.Fatal(err)
	}
	c.MixedCarrier = true
	captured, total, err := rpcServicesCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	if captured != nc || total != nt {
		t.Fatal("mixed fixed channels did not capture complete original native receive owners")
	}
	sharedStart, err := executionChargeStart(c)
	if err != nil {
		t.Fatal(err)
	}
	nativeStart, err := executionChargeStart(native)
	if err != nil {
		t.Fatal(err)
	}
	if sharedStart != nativeStart {
		t.Fatal("shared selection shifted the original execution owner positions")
	}
	c.Native = true
	again, againTotal, err := rpcServicesCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	if again != captured || againTotal != total {
		t.Fatal("native selection changed the original fixed channel vector")
	}
	for position := uint32(0); position < 10; position++ {
		v, count, err := futureChannelCharges(c, position)
		if err != nil {
			t.Fatal(err)
		}
		if count != internalChannelOwners || v[internalChannelNativeOwner] == (resourcev4.Vector{}) {
			t.Fatalf("original future %d omitted its native receive owner", position)
		}
	}
}
