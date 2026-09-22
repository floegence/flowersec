package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func TestSessionCoreScopeRequiresExactTenantAndSession(t *testing.T) {
	for _, failure := range []string{"missing tenant", "missing session", "swapped", "foreign tenant", "closed tenant"} {
		t.Run(failure, func(t *testing.T) {
			c := corePlanUnitConfig(t, false)
			root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
			_, _, _, foreign := corePlanUnitRoot(t, c, -1, false)
			switch failure {
			case "missing tenant":
				scope.Tenant = resourcev4.Account{}
			case "missing session":
				scope.Session = resourcev4.Account{}
			case "swapped":
				scope.Tenant, scope.Session = scope.Session, scope.Tenant
			case "foreign tenant":
				scope.Tenant = foreign.Tenant
			case "closed tenant":
				scope.Tenant.Close()
			}
			before := root.Snapshot()
			p, err := NewSessionCorePlan(c, root, owner, environment, scope)
			if p != nil || err == nil {
				t.Fatal("unbound Session capacity admitted", err)
			}
			if root.Snapshot() != before {
				t.Fatal("invalid scope retained a partial core")
			}
		})
	}
}

func TestSessionCoreScopeChargesFullGraphUntilRetirement(t *testing.T) {
	c := corePlanUnitConfig(t, false)
	root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
	want, _, err := SessionCoreRequirements(c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewSessionCorePlan(c, root, owner, environment, scope)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCorePlanUnit(t, p)
	for _, account := range []resourcev4.Account{scope.Tenant, scope.Session} {
		got, err := account.Usage()
		if err != nil || got != want || got[resourcev4.Sessions] != 1 {
			t.Fatal("scope omits core charge", got, want, err)
		}
	}
	// Logical close and even completed cleanup retain the pending/active slot;
	// only the original explicit retirement drops the last core owner.
	p.Close()
	if err := p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, account := range []resourcev4.Account{scope.Tenant, scope.Session} {
		got, err := account.Usage()
		if err != nil || got != want {
			t.Fatal("cleanup refunded unretired core", got, err)
		}
	}
	if err := p.Retire(); err != nil {
		t.Fatal(err)
	}
	for _, account := range []resourcev4.Account{scope.Tenant, scope.Session} {
		got, err := account.Usage()
		if err != nil || got != (resourcev4.Vector{}) {
			t.Fatal("retirement retained core", got, err)
		}
	}
}

func TestSessionCoreScopeTenantSlotExhaustionIsAtomic(t *testing.T) {
	c := corePlanUnitConfig(t, false)
	charge, _, err := SessionCoreRequirements(c)
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 512, ReferenceSlots: 1024}
	for i, v := range charge {
		config.Limit[i] = v*3 + 1
	}
	backing, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit[resourcev4.SDKBytes] += backing
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	owner := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := root.Reserve(owner, resourcev4.Vector{resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer environment.Release()
	limit := config.Limit
	limit[resourcev4.Sessions] = 1
	firstScope := corePlanTestScope(t, root, limit, 1)
	secondScope := corePlanTestScope(t, root, limit, 2)
	owner.Instance, owner.Kind = [16]byte{2}, 2
	first, err := NewSessionCorePlan(c, root, owner, environment, firstScope)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCorePlanUnit(t, first)
	owner.Instance = [16]byte{3}
	before := root.Snapshot()
	for _, closed := range []bool{false, true} {
		if closed {
			first.Close()
		}
		second, err := NewSessionCorePlan(c, root, owner, environment, secondScope)
		if second != nil || !errors.Is(err, resourcev4.ErrCapacity) {
			t.Fatal("tenant slot exhaustion admitted a second core", err)
		}
		if root.Snapshot() != before {
			t.Fatal("failed admission changed original accounting")
		}
	}
	if err := first.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := NewSessionCorePlan(c, root, owner, environment, secondScope)
	if err != nil {
		t.Fatal("actual retirement did not return slot", err)
	}
	cleanupCorePlanUnit(t, second)
}

func TestSessionCorePreparationGateRejectsClosedMandatoryOwners(t *testing.T) {
	for _, failure := range []string{"plan", "tenant", "session", "engine reservation"} {
		t.Run(failure, func(t *testing.T) {
			c := corePlanUnitConfig(t, false)
			root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
			p, err := NewSessionCorePlan(c, root, owner, environment, scope)
			if err != nil {
				t.Fatal(err)
			}
			cleanupCorePlanUnit(t, p)
			if err := p.checkAdmissionPreparation(environment); err != nil {
				t.Fatal(err)
			}
			before := root.Snapshot()
			switch failure {
			case "plan":
				p.Close()
			case "tenant":
				scope.Tenant.Close()
			case "session":
				scope.Session.Close()
			case "engine reservation":
				p.refs[coreEngineOwner].Seal()
			}
			if err := p.checkAdmissionPreparation(environment); err == nil {
				t.Fatal("closed mandatory owner passed consumption gate")
			}
			if root.Snapshot() != before {
				t.Fatal("closed preparation refunded original graph")
			}
		})
	}
}
