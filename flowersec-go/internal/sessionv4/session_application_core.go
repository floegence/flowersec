package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// admissionCoreConfig is the single projection used by both the pre-spend
// requirements calculation and the actual aggregate reservation. Only this
// complete assembly may admit a services/execution transport core; a bare
// SessionCoreConfig cannot promise application service from its profile name.
func admissionCoreConfig(c SessionAdmissionConfig) (SessionCoreConfig, error) {
	core := c.Core
	core.applicationServices = false
	profile := core.Session.Contract.Limits().ApplicationProfile
	if profile == "transport" {
		if c.RPC != nil {
			return core, cryptov4.ErrConfiguration
		}
		return core, nil
	}
	// Both profiles use the same aggregate admission. Execution's retained
	// history, durable capacity and management channel are included by the RPC
	// batch before the one-time credential claim can commit.
	if profile != "services" && profile != "execution" || c.RPC == nil || c.Application == nil {
		return core, cryptov4.ErrConfiguration
	}
	rpc := c.RPC
	if rpc.Session != core.Session.Contract || rpc.Clock != core.Clock || rpc.CryptoProfile != core.Session.Profile || rpc.MaxDataPayloadBytes != core.MaxDataPayloadBytes || core.Native || core.Datagrams || core.Streams.ReceivePoolBytes == 0 || rpc.Bootstrap.ReceivePoolBytes != core.Streams.ReceivePoolBytes {
		return core, cryptov4.ErrConfiguration
	}
	geometry, minimum, err := internalChannelGeometry(profile)
	if err != nil {
		return core, err
	}
	internal := geometry.RPC + geometry.Notify
	total := internal + geometry.Management
	if total == 0 || internal%2 != 0 || core.Open.Active < total || core.Open.PerClass[InternalStream] < internal || core.Open.PerClass[ManagementStream] < geometry.Management || core.MaxScopes < total || core.PendingScopes == 0 || core.Streams.ReceivePoolBytes < uint64(total-1)*minimum+rpc.Bootstrap.ReceiveBytes || core.SendWorkers[InternalStream] == 0 || geometry.Management != 0 && core.SendWorkers[ManagementStream] == 0 {
		return core, cryptov4.ErrConfiguration
	}
	for role := range 2 {
		if core.Open.PerOpener[role][InternalStream] < internal/2 || core.Open.Protected[role][InternalStream] < internal/2 || core.Open.Lifetime[role][InternalStream] < uint64(internal/2) {
			return core, cryptov4.ErrConfiguration
		}
	}
	if core.Open.Protected[0][ManagementStream] < geometry.Management || core.Open.PerOpener[0][ManagementStream] < geometry.Management || core.Open.PerOpener[1][ManagementStream] != 0 || core.Open.Lifetime[1][ManagementStream] != 0 || geometry.Management != 0 && core.Open.Lifetime[0][ManagementStream] != 16 {
		return core, cryptov4.ErrConfiguration
	}
	p := c.Application
	p.mu.Lock()
	valid := !p.closed && !p.claimed && p.config.Services && p.config.ContractQueries && p.config.Handlers == core.Handlers.Plan && p.executor != nil
	p.mu.Unlock()
	if !valid {
		return core, cryptov4.ErrConfiguration
	}
	core.Handlers.internal = true
	if core.Handlers.RuntimeBytes == 0 {
		core.Handlers.RuntimeBytes = core.RuntimeBytes
	}
	core.applicationServices = true
	return core, nil
}
