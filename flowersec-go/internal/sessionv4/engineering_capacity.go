package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// EngineeringHostCapacity declares one independently installed capacity host.
// Sessions includes retained/candidate positions and the listener's base plan.
// Materials, parent publications and physical legs retain their own owners.
// These local bounds neither change signed limits nor promise that every legal
// dynamic request can run simultaneously. Ordinary engineering peers omit it.
type EngineeringHostCapacity struct {
	Sessions, Materials, Parents, Legs uint32
	BusinessStreams                    uint32
}

type EngineeringResourceCapacity interface {
	AuthorityHostCapacity() *EngineeringHostCapacity
}

func (c EngineeringHostCapacity) Validate() error {
	if c.Sessions > 64 || c.Materials == 0 || c.Materials > 64 || c.Parents > 1 || c.Legs > 2 || c.BusinessStreams > 128 || c.Sessions == 0 && c.Parents == 0 && c.Legs != 0 {
		return resourcev4.ErrConfiguration
	}
	return nil
}

func engineeringSessionLimit() (limit resourcev4.Vector) {
	for i := range limit {
		limit[i] = 1 << 30
	}
	return limit
}

func engineeringHostCapacity(t AuthorityReporter) *EngineeringHostCapacity {
	declaration, ok := t.(EngineeringResourceCapacity)
	if !ok || declaration.AuthorityHostCapacity() == nil {
		return nil
	}
	capacity := *declaration.AuthorityHostCapacity()
	if err := capacity.Validate(); err != nil {
		t.Fatal(err)
	}
	return &capacity
}

// The root is allocated before any trust or runtime owner exists. This uses
// the same unsigned authority/Core recipes as construction, then retains the
// full fixed RPC floor and finite original workload overlap. It does not size
// slabs from a sampled idle heap or enlarge any production scheduler cap.
func engineeringCapacityRoot(t AuthorityReporter, source, profile, carrier string, datagrams bool) *resourcev4.Config {
	host := engineeringHostCapacity(t)
	if host == nil {
		return nil
	}
	application := "transport"
	if policy, ok := t.(EngineeringApplicationProfile); ok {
		application = policy.AuthorityApplicationProfile()
	}
	parent := admissionOwnedDocument(t, "Artifact", initialFixture(t, "artifact_transport_fields"))
	defer parent.Release()
	wire := engineeringSessionContract(t, parent.Root().Named("Artifact", "session_contract").Encoded(), application)
	issued := uint64(1050)
	if engineeringOriginalLive(t) {
		issued = 1200
		wire = admissionMap(t, "SessionContract", wire, map[string]protocolv4.Field{"max_frame": {Number: 65528}})
	}
	decoder, err := protocolv4.NewDecoder(len(wire), len(wire))
	if err != nil {
		t.Fatal(err)
	}
	document, err := decoder.DecodeMap(wire, "SessionContract", protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	contract, err := document.SessionContract()
	document.Release()
	if err != nil {
		t.Fatal(err)
	}
	parameters := protocolv4.ArtifactSessionParameters{Contract: contract, ArtifactDigest: [32]byte{1}, Profile: profile, IssuedAtMS: authorityTime(t, issued), SessionNotAfterMS: authorityTime(t, 5000)}
	clock := t.(EngineeringAuthorityTime).AuthorityClock()
	core := engineeringNativeCore(t, engineeringBaseCore(parameters, clock), parameters, carrier, datagrams)
	core.applicationServices = application != "transport"
	if core.applicationServices {
		core.Handlers.internal, core.Handlers.RuntimeBytes = true, core.RuntimeBytes
	}
	coreGeometry, err := sessionCoreChargeGeometry(core)
	if err != nil {
		t.Fatal("engineering SessionCore geometry: ", err)
	}
	coreOwners, coreReferences := coreGeometry.owners, coreGeometry.references
	channels, _, err := internalChannelGeometry(application)
	if err != nil {
		t.Fatal(err)
	}
	internal := channels.RPC + channels.Notify + channels.Management
	rpcOwners := uint32(0)
	if internal != 0 {
		// Pure charge geometry: no root/executor is constructed or claimed.
		executor := &ApplicationExecutor{config: ApplicationExecutorConfig{RuntimeBytesPerTask: 131072}}
		rpc := RPCServicesConfig{Native: core.Native, NotifyReceivePending: 16, NotifyPublishPending: 16, NotificationWaitMS: 30000, NotificationCleanupMS: 5000, CompletionGraceMS: 5000,
			ShortRequestBytes: 1 << 20, ShortResponseBytes: 1 << 20, ShortTaskCharge: executor.TaskCharge(), ShortCompletionCharge: executor.CompletionFloorCharge(), CryptoProfile: profile,
			Bootstrap: core.Streams, MaxDataPayloadBytes: core.MaxDataPayloadBytes, Root: &resourcev4.Root{}, Session: contract, Clock: clock,
			Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}}, Routes: rpcv4.ContractRoutesConfig{ContractNodes: 256, RuntimeBytes: 16384, Clock: clock}, Slots: 8, ResidentSlots: 4,
			MaxCaptureBytes: 1 << 20, RuntimeBytes: 65536, InputRuntimeBytes: 65536, HashRuntimeBytes: 4096, InvocationRuntimeBytes: 65536}
		_, rpcOwners, err = RPCServicesRequirements(rpc)
		if err != nil {
			t.Fatal("engineering RPCServices geometry: ", err)
		}
	}
	streams := host.BusinessStreams
	if streams == 0 {
		streams = min(core.Open.PerClass[BusinessStream], 8)
	}
	if streams > core.Open.PerClass[BusinessStream] {
		t.Fatal("declared engineering business workload exceeds its original signed stream limit")
	}
	// The original capacity flow has eight service dispatch slots, one finite
	// prepared/caller vector per slot, and retained completion/cancellation tails.
	// Each raw Stream keeps all eight possible factory owners and their aliases.
	const serviceSlots = 8
	const operationOwners = 5 + 7
	const operationReferences = operationOwners + 8
	const sourceReferences = 48
	const rpcFixedAliases = 24
	const channelAliases = 5
	const streamAliases = 8
	perSessionOwners := coreOwners + 2 + rpcOwners + serviceSlots*operationOwners + streams*streamFactoryOwners
	perSessionReferences := coreReferences + 2 + rpcOwners + rpcFixedAliases + internal*channelAliases + sourceReferences + serviceSlots*operationReferences + streams*(streamFactoryOwners+streamAliases)
	// Authority startup owns one trust/namespace/SQLite graph. Per-material
	// owners include each accepted Environment, application/handler plans,
	// artifact/identity/material and original transport preparation.
	const authorityOwners, authorityReferences = 64, 128
	const materialOwners, materialReferences = 24, 48
	const parentOwners, parentReferences = 64, 128
	const legOwners, legReferences = 32, 64
	subscribers := uint32(64) * max(host.Sessions, 1)
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 3 + host.Sessions + 2*host.Parents + host.Legs,
		ReservationSlots: authorityOwners + host.Materials*materialOwners + host.Sessions*perSessionOwners + host.Parents*parentOwners + host.Legs*legOwners,
		ReferenceSlots:   authorityReferences + subscribers + host.Materials*materialReferences + host.Sessions*perSessionReferences + host.Parents*parentReferences + host.Legs*legReferences}
	// Every constituent keeps its original per-Session/account limit. The root
	// is the explicit aggregate of these independent local positions.
	positions := max(host.Sessions+host.Parents+host.Legs, 1)
	for range positions {
		config.Limit, err = config.Limit.Add(engineeringSessionLimit())
		if err != nil {
			t.Fatal(err)
		}
	}
	return &config
}
