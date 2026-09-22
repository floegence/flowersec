package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func applicationCoreFixture(t *testing.T) SessionAdmissionConfig {
	t.Helper()
	_, plan, rpc := rpcServicesPlanFixture(t)
	core := corePlanUnitConfig(t, false)
	now, err := rpc.Clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	core.Session = testSessionContract(t, protocolv4.DHProfileX25519, "services", 65536, 16, 0, now.LowerMS+3600000, 1<<20)
	core.Clock = rpc.Clock
	core.MaxScopes = 16
	core.Open.Active, core.Open.Terminal = 12, 32
	core.Open.PerClass = [3]uint32{2, 10, 0}
	core.Open.PerOpener = [2][3]uint32{{2, 5, 0}, {2, 5, 0}}
	core.Open.Protected = [2][3]uint32{{0, 5, 0}, {0, 5, 0}}
	core.Open.Lifetime = [2][3]uint64{{1024, 1024, 0}, {1024, 1024, 0}}
	core.SendWorkers = [3]uint32{1, 1, 0}
	core.Streams = rpc.Bootstrap
	rpc.Session = core.Session.Contract
	return SessionAdmissionConfig{Core: core, Application: plan, RPC: &rpc}
}

func TestApplicationProfileCoreRequiresOriginalAssembly(t *testing.T) {
	c := applicationCoreFixture(t)
	if _, _, err := SessionCoreRequirements(c.Core); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("bare core advertised services", err)
	}
	core, err := admissionCoreConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if !core.applicationServices || !core.Handlers.internal || core.Handlers.RuntimeBytes != core.RuntimeBytes {
		t.Fatal("missing original dispatcher projection")
	}
	charges, total, _, err := sessionCoreCharges(core)
	if err != nil {
		t.Fatal(err)
	}
	if charges[coreHandlersOwner][resourcev4.Tasks] != 1 || total[resourcev4.Tasks] == 0 {
		t.Fatal("dispatcher task omitted from pre-spend requirements")
	}
	if c.Core.applicationServices || c.Core.Handlers.internal {
		t.Fatal("requirements mutated caller configuration")
	}
}

func TestApplicationCoreRejectsUnprotectedMandatoryServices(t *testing.T) {
	for _, kind := range []string{"missing_rpc", "missing_plan", "internal_cap", "opener_protection", "pool", "send", "server_management", "mismatched_session"} {
		t.Run(kind, func(t *testing.T) {
			c := applicationCoreFixture(t)
			switch kind {
			case "missing_rpc":
				c.RPC = nil
			case "missing_plan":
				c.Application = nil
			case "internal_cap":
				c.Core.Open.PerClass[InternalStream] = 9
			case "opener_protection":
				c.Core.Open.Protected[1][InternalStream] = 4
			case "pool":
				c.Core.Streams.ReceivePoolBytes = 16384
				c.RPC.Bootstrap.ReceivePoolBytes = 16384
			case "send":
				c.Core.SendWorkers[InternalStream] = 0
			case "server_management":
				c.Core.Open.Lifetime[1][ManagementStream] = 1
			case "mismatched_session":
				c.RPC.Session = corePlanUnitConfig(t, false).Session.Contract
			}
			if _, err := admissionCoreConfig(c); !errors.Is(err, cryptov4.ErrConfiguration) {
				t.Fatal("incomplete admission accepted", err)
			}
		})
	}
}
