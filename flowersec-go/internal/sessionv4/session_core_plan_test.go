package sessionv4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func corePlanUnitConfig(t *testing.T, native bool) SessionCoreConfig {
	t.Helper()
	clock := sessionTestClock(t)
	now, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	c := SessionCoreConfig{
		Session: testSessionContract(t, protocolv4.DHProfileX25519, "transport", 4096, 4, 0, now.LowerMS+3600000), Clock: clock,
		Open: openResourceLimits(), MaxScopes: 4, PendingScopes: 2, WorkSlots: 4,
		Maintenance:     cryptov4.MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024},
		EngineResources: cryptov4.EngineResourceOptions{RuntimeBytes: 4096}, RuntimeBytes: 65536,
		Native: native, DecoderNodes: 128, MaxDataPayloadBytes: 1024, SendWorkers: [3]uint32{1},
		ProbeSlots: 2, PongSlots: 2, RekeyWaitSlots: 2,
		Automatic: AutomaticLivenessPolicy{1000000, 1000, 1000, 3}, Messages: MaintenanceMessagePolicy{8, 1000, 10000},
		Termination: StreamTerminationPolicy{10000, 1000, 8}, Rekey: RekeyPhaseBudgets{5000, 10000, 30000},
		SharedDiscard: SharedDiscardPolicy{16, 65536, 10000}, NativeIngress: MaintenanceIngressPolicy{10000, 1000, 8},
		DispatchTimeoutMS: 10000, RetirementTimeoutMS: 10000,
	}
	if native {
		c.NativeAuthWorkers = 1
	}
	return c
}

// These isolated values exercise accounting; no runtime/provider qualification
// is inferred from the synthetic overhead allowance or ordinary test clock.
func corePlanUnitRoot(t *testing.T, c SessionCoreConfig, shortage int, missingOwner bool) (*resourcev4.Root, resourcev4.Reference, resourcev4.OwnerKey, SessionResourceScope) {
	t.Helper()
	charge, owners, err := SessionCoreRequirements(c)
	if err != nil {
		t.Fatal(err)
	}
	limit, err := charge.Add(resourcev4.Vector{resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	if shortage >= 0 {
		limit[shortage]--
	}
	borrowed := uint32(2)
	if c.MessageCarrier {
		borrowed++
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 4, ReservationSlots: owners + 1, ReferenceSlots: owners + borrowed + 1}
	if missingOwner {
		config.ReservationSlots--
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
	t.Cleanup(root.Close)
	owner := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := root.Reserve(owner, resourcev4.Vector{resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environment.Release)
	owner.Instance, owner.Backing, owner.Kind = [16]byte{2}, [16]byte{2}, 2
	return root, environment, owner, corePlanTestScope(t, root, config.Limit, 1)
}

func cleanupCorePlanUnit(t *testing.T, p *SessionCorePlan) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.Abort(ctx); err != nil {
			t.Error(err)
		}
	})
}

func TestSessionCorePlanReservesAllOrNothing(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, dimension := range []int{resourcev4.SDKBytes, resourcev4.Items, resourcev4.Tasks, resourcev4.WorkSlots, resourcev4.Timers, resourcev4.Sessions, -1} {
			t.Run(fmt.Sprintf("native=%v/dimension=%d", native, dimension), func(t *testing.T) {
				c := corePlanUnitConfig(t, native)
				root, environment, owner, scope := corePlanUnitRoot(t, c, dimension, dimension < 0)
				before := root.Snapshot()
				if p, err := NewSessionCorePlan(c, root, owner, environment, scope); p != nil || !errors.Is(err, resourcev4.ErrCapacity) {
					t.Fatal("partial core admitted", err)
				}
				if after := root.Snapshot(); after != before {
					t.Fatal("failed batch changed original charges", before, after)
				}
				if err := environment.Check(); err != nil {
					t.Fatal("failed batch consumed Environment", err)
				}
			})
		}
	}
}

func TestSessionCorePlanReservesPositiveAndZeroGraphs(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, positive := range []bool{false, true} {
			t.Run(fmt.Sprintf("native=%v/positive=%v", native, positive), func(t *testing.T) {
				c := corePlanUnitConfig(t, native)
				if !positive {
					c.MaxScopes, c.Open.Active, c.Open.Opening = 0, 0, 0
					c.Open.PerClass, c.Open.PerOpener = [3]uint32{}, [2][3]uint32{}
					c.SendWorkers, c.NativeAuthWorkers = [3]uint32{}, 0
				}
				root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
				before := root.Snapshot()
				charge, owners, err := SessionCoreRequirements(c)
				if err != nil {
					t.Fatal(err)
				}
				p, err := NewSessionCorePlan(c, root, owner, environment, scope)
				if err != nil {
					t.Fatal(err)
				}
				cleanupCorePlanUnit(t, p)
				expected, _ := before.Charged.Add(charge)
				if got := root.Snapshot(); got.Charged != expected || got.Reservations != before.Reservations+owners || got.References != before.References+owners+2 {
					t.Fatal("incomplete core reservation", got, owners, charge)
				}
				if positive != (p.refs[coreSendOwner] != (resourcev4.Reference{})) || (native && positive) != (p.refs[coreNativeReceiverStart] != (resourcev4.Reference{})) {
					t.Fatal("positive DATA service positions missing or invented")
				}
				p.Close()
				if got := root.Snapshot(); got.Charged != expected {
					t.Fatal("logical close refunded core", got)
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := p.Abort(ctx); !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled cleanup observer completed", err)
				}
				if root.Snapshot().Charged != expected {
					t.Fatal("cancelled observation refunded core")
				}
				if err := p.Abort(context.Background()); err != nil {
					t.Fatal(err)
				}
				if got := root.Snapshot(); got != before {
					t.Fatal("unused plan did not return exact original graph", got, before)
				}
				if err := p.Abort(context.Background()); err != nil || root.Snapshot() != before {
					t.Fatal("duplicate abort changed accounting", err)
				}
			})
		}
	}
}

func TestSessionCorePlanRejectsInsufficientReferenceSlotsBeforeClaim(t *testing.T) {
	for _, messages := range []bool{false, true} {
		t.Run(fmt.Sprint(messages), func(t *testing.T) {
			config := corePlanUnitConfig(t, false)
			config.MessageCarrier = messages
			config.MessageRuntimeBytes = 4096
			root, environment, owner, scope := corePlanUnitRoot(t, config, -1, false)
			held, err := environment.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			defer held.Release()
			before := root.Snapshot()
			if plan, err := NewSessionCorePlan(config, root, owner, environment, scope); plan != nil || !errors.Is(err, resourcev4.ErrCapacity) {
				t.Fatal("plan admitted without all original reference positions", err)
			}
			if root.Snapshot() != before || held.Check() != nil || environment.Check() != nil {
				t.Fatal("failed reference admission changed another owner or retained a partial plan")
			}
		})
	}
}

func TestSessionCorePlanClaimIsImmutableAndOnceOnly(t *testing.T) {
	c := corePlanUnitConfig(t, false)
	original := c
	root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
	p, err := NewSessionCorePlan(c, root, owner, environment, scope)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCorePlanUnit(t, p)
	c.Open.Active, c.SendWorkers[0], c.WorkSlots = 1, 4, 128
	c.Session.ArtifactDigest[0]++
	if err := p.Claim(c.Session, protocolv4.ClientToServer); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("different original session claimed", err)
	}
	if err := p.Claim(original.Session, protocolv4.ServerToClient); err != nil {
		t.Fatal(err)
	}
	if err := p.Claim(original.Session, protocolv4.ClientToServer); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("one plan claimed twice", err)
	}
	if got := p.records(); got.MaxScopes != original.MaxScopes || got.WorkSlots != original.WorkSlots || got.SendDirection != protocolv4.ServerToClient || got.Clock != original.Clock {
		t.Fatal("caller changed captured core geometry")
	}
	if p.config.Open != original.Open || p.config.SendWorkers != original.SendWorkers {
		t.Fatal("caller changed captured OPEN allocation")
	}
	if err := p.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("claimed plan retired without cleanup", err)
	}
}

func TestSessionCorePlanRejectsInvalidPoliciesBeforeReservation(t *testing.T) {
	for name, change := range map[string]func(*SessionCoreConfig){
		"missing clock":                         func(c *SessionCoreConfig) { c.Clock = nil },
		"missing runtime bound":                 func(c *SessionCoreConfig) { c.RuntimeBytes = 0 },
		"clock width exceeds rekey phase":       func(c *SessionCoreConfig) { c.Rekey.ProtocolPrepareMS = 1 },
		"unrepresentable liveness interval":     func(c *SessionCoreConfig) { c.Automatic.IntervalMS = ^uint64(0) },
		"class has no worker":                   func(c *SessionCoreConfig) { c.SendWorkers[0] = 0 },
		"shared input has no crypto lane":       func(c *SessionCoreConfig) { c.SendWorkers[0] = c.WorkSlots },
		"missing native worker":                 func(c *SessionCoreConfig) { c.Native, c.NativeAuthWorkers = true, 0 },
		"positive bound exceeds engine":         func(c *SessionCoreConfig) { c.MaxScopes = 1 },
		"maintenance reserve exceeds key bound": func(c *SessionCoreConfig) { c.Maintenance.Calls = ^uint64(0) },
		"missing signed service span":           func(c *SessionCoreConfig) { c.Session.SessionNotAfterMS = c.Session.IssuedAtMS },
	} {
		t.Run(name, func(t *testing.T) {
			c := corePlanUnitConfig(t, false)
			root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
			before := root.Snapshot()
			change(&c)
			if p, err := NewSessionCorePlan(c, root, owner, environment, scope); err == nil || p != nil {
				t.Fatal("invalid core policy admitted")
			}
			if after := root.Snapshot(); after != before {
				t.Fatal("invalid policy changed original budget", before, after)
			}
		})
	}
}

func TestSessionCorePlanRejectsForeignEnvironmentAndRetainsOriginalBorrow(t *testing.T) {
	c := corePlanUnitConfig(t, false)
	root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
	_, foreign, _, _ := corePlanUnitRoot(t, c, -1, false)
	before := root.Snapshot()
	if _, err := NewSessionCorePlan(c, root, owner, foreign, scope); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("foreign budget root composed", err)
	}
	if root.Snapshot() != before {
		t.Fatal("foreign composition retained a partial batch")
	}
	foreignOwner := owner
	foreignOwner.Environment = [16]byte{2}
	if _, err := NewSessionCorePlan(c, root, foreignOwner, environment, scope); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("foreign Environment composed", err)
	}
	if root.Snapshot() != before {
		t.Fatal("foreign Environment retained a partial batch")
	}
	p, err := NewSessionCorePlan(c, root, owner, environment, scope)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCorePlanUnit(t, p)
	if err := p.CheckEnvironment(foreign); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("foreign InitialExchange accepted", err)
	}
	retained := root.Snapshot().Charged
	environment.Release()
	if root.Snapshot().Charged != retained {
		t.Fatal("plan did not retain original Environment backing")
	}
	if err := p.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := root.Snapshot(); got.Reservations != 0 || got.References != 0 {
		t.Fatal("retired plan retained Environment borrow", got)
	}
}

func TestSessionCorePlanAbortAfterPrivateEnginePreparation(t *testing.T) {
	_, configs := initialTestPairThrough(t, protocolv4.DHProfileX25519, "stream", 0)
	var handshakes [2]*cryptov4.Handshake
	for role := range 2 {
		var err error
		handshakes[role], err = cryptov4.NewHandshake(configs[role])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(handshakes[role].Close)
	}
	for sender := range 2 {
		wire, err := handshakes[sender].WriteMessage()
		if err != nil {
			t.Fatal(err)
		}
		err = handshakes[1-sender].ReadMessage(wire)
		clear(wire)
		if err != nil {
			t.Fatal(err)
		}
	}
	for role := range 2 {
		finished, err := handshakes[role].Finish()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(finished.Close)
		c := corePlanUnitConfig(t, role != 0)
		c.Session, c.Clock = configs[role].Session, configs[role].Clock
		root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
		before := root.Snapshot()
		p, err := NewSessionCorePlan(c, root, owner, environment, scope)
		if err != nil {
			t.Fatal(err)
		}
		cleanupCorePlanUnit(t, p)
		if err = p.Claim(c.Session, protocolv4.Direction(role)); err != nil {
			t.Fatal(err)
		}
		engine, err := p.PrepareRecords(finished, p.records())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := engine.ScopeFrontier(0, protocolv4.Direction(role)); !errors.Is(err, cryptov4.ErrNotReady) {
			t.Fatal("private core activated before READY", err)
		}
		retained := root.Snapshot().Charged
		if _, err := p.Install(engine, nil, io.Discard); !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal("missing provider accepted", err)
		}
		if root.Snapshot().Charged != retained || p.engine != engine {
			t.Fatal("failed installation lost original Engine owner")
		}
		p.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := p.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled observer completed", err)
		}
		if root.Snapshot().Charged != retained {
			t.Fatal("cancelled observer refunded prepared Engine")
		}
		finished.Close()
		if err := p.Abort(context.Background()); err != nil {
			t.Fatal(err)
		}
		if root.Snapshot() != before {
			t.Fatal("partial preparation leaked original claims", root.Snapshot(), before)
		}
		if err := p.Claim(c.Session, protocolv4.Direction(role)); !errors.Is(err, cryptov4.ErrClosed) {
			t.Fatal("aborted plan reused", err)
		}
	}
}

func TestSessionCorePlanRetainsManualRekeyOwnerUntilRelease(t *testing.T) {
	var fixtures [2]initialCoreFixture
	pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, "stream", 4, initialCorePrepare(t, &fixtures))
	var cores [2]*SessionCore
	results := make(chan error, 2)
	for role := range 2 {
		go func() {
			var err error
			cores[role], err = pair[role].AuthenticateCore(configs[role], fixtures[role].plan)
			results <- err
		}()
	}
	for range 2 {
		if err := waitRuntime(t, results); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, original := range pair {
		if err := original.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	p := fixtures[0].plan
	charge, _, err := SessionCoreRequirements(p.config)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := cores[0].Admission().rekeyCauses.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			_ = ref.Release()
		}
	}()
	before := fixtures[0].root.Snapshot().Charged
	p.Close()
	if err := p.WaitCleanup(ctx); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("live manual intent lost its original graph", err)
	}
	if err := p.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("manual intent refunded before Release", err)
	}
	if fixtures[0].root.Snapshot().Charged != before {
		t.Fatal("manual alias did not retain complete graph charge")
	}
	if err := ref.Release(); err != nil {
		t.Fatal(err)
	}
	released = true
	if err := p.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	expected := before
	for dimension, value := range charge {
		expected[dimension] -= value
	}
	if got := fixtures[0].root.Snapshot().Charged; got != expected {
		t.Fatal("released manual owner leaked original graph", got, expected)
	}
}

func corePlanTestScope(t *testing.T, root *resourcev4.Root, limit resourcev4.Vector, sessionID byte) SessionResourceScope {
	t.Helper()
	tenant, err := root.Account(resourcev4.AccountKey{Kind: resourcev4.TenantAccount, ID: [16]byte{1}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	sessionLimit := limit
	sessionLimit[resourcev4.Sessions] = 1
	session, err := root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: [16]byte{sessionID}}, sessionLimit)
	if err != nil {
		t.Fatal(err)
	}
	return SessionResourceScope{Tenant: tenant, Session: session}
}
