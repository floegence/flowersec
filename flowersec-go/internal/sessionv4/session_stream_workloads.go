package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// RPC requirements cover request/result work. Only the original Session
// factory has the transport geometry needed to qualify the remaining vector.
func sessionStreamWorkloadRequirements(core SessionCoreConfig, rpc RPCServicesConfig, role protocolv4.Direction, additional ...[]SessionMethodWorkload) (total resourcev4.Vector, owners uint32, err error) {
	if len(additional) > 1 {
		return total, 0, cryptov4.ErrConfiguration
	}
	groups := [2][]SessionMethodWorkload{rpc.Workloads}
	if len(additional) == 1 {
		groups[1] = additional[0]
	}
	var calls uint64
	for _, group := range groups {
		for _, target := range group {
			if target.Method.Shape != 1 {
				continue
			}
			if role > protocolv4.ServerToClient || !serviceStreamGeometry(core.Streams) || core.Native != rpc.Native || core.MixedCarrier != rpc.MixedCarrier {
				return total, 0, cryptov4.ErrConfiguration
			}
			charges, metadata, e := streamCallerFloorCharges(core, len(target.Method.StreamKind)+len(target.Method.StreamMetadata))
			if e != nil {
				return total, 0, e
			}
			vector, count := metadata, uint32(1)
			for _, charge := range charges {
				if charge == (resourcev4.Vector{}) {
					continue
				}
				charge, err = resourcev4.ProtectedCharge(charge)
				if err == nil {
					vector, err = vector.Add(charge)
				}
				if err != nil {
					return total, 0, err
				}
				count++
			}
			for j := uint16(0); j < target.Workload.Calls; j++ {
				total, err = total.Add(vector)
				if err != nil {
					return total, 0, err
				}
				owners += count
			}
			calls += uint64(target.Workload.Calls)
		}
	}
	if calls == 0 {
		return
	}
	limits := core.Open
	// Leave the original bootstrap an opening opportunity while every declared
	// business target is dormant. The fixed class floors still belong to I/M.
	if calls >= uint64(limits.Opening) || calls > uint64(limits.PerClass[BusinessStream]) || calls > uint64(limits.PerOpener[role][BusinessStream]) || calls > limits.Lifetime[role][BusinessStream] {
		return total, 0, cryptov4.ErrCapacity
	}
	var protected uint64
	for r := range 2 {
		for class, n := range limits.Protected[r] {
			v := uint64(n)
			if r == int(role) && class == int(BusinessStream) {
				v = max(v, calls)
			}
			protected += v
		}
	}
	if protected > uint64(limits.Active) || uint64(limits.Terminal) < protected+uint64(limits.RejectionReserve) {
		return total, 0, cryptov4.ErrCapacity
	}
	services, _, err := streamServiceFloorCharges(core)
	if err != nil {
		return total, 0, err
	}
	geometry, quantum, err := internalChannelGeometry(rpc.Session.Limits().ApplicationProfile)
	if err != nil {
		return total, 0, err
	}
	channels := uint64(geometry.RPC) + uint64(geometry.Notify) + uint64(geometry.Management)
	streams := calls + uint64(services)
	if channels == 0 || streams+channels > uint64(limits.Active) {
		return total, 0, cryptov4.ErrCapacity
	}
	// These terms are bounded by validated factory fields; subtraction also
	// avoids overflowing an untrusted combination before original admission.
	backing, credit := core.Streams.ReceivePoolBytes, min(core.Streams.ReceivePoolBytes, core.Session.Contract.Limits().MaxCredit)
	for i := uint64(0); i < channels; i++ {
		capacity := quantum
		if i == 0 {
			capacity = rpc.Bootstrap.ReceiveBytes
		}
		if capacity > backing || quantum > credit {
			return total, 0, cryptov4.ErrCapacity
		}
		backing, credit = backing-capacity, credit-quantum
	}
	if streams > backing/core.Streams.ReceiveBytes || streams > credit/core.Streams.InitialReceiveLimit {
		return total, 0, cryptov4.ErrCapacity
	}
	return
}

// Provider reservations are made on the actual prepared connection before
// credential adoption/TxA. They are attached to the original workload slots;
// failure uses the same RPC cleanup path and never creates a replacement pool.
func (r *RPCServices) prepareWorkloadProviders(connection native.Connection) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired {
		return cryptov4.ErrClosed
	}
	for _, w := range r.initialWorkloads {
		if w == nil || w.stream == nil {
			continue
		}
		for i := range w.slots {
			f := w.slots[i].transport
			if f == nil || f.closed || f.plan != nil {
				return cryptov4.ErrConfiguration
			}
			if !f.geometry.native {
				continue
			}
			if connection == nil || f.provider != nil {
				return cryptov4.ErrConfiguration
			}
			var positions [1]native.StreamProtection
			if err := connection.ProtectNativeStreams(positions[:]); err != nil {
				return err
			}
			f.provider, f.connection = positions[0], connection
		}
	}
	return nil
}

// Install runs before bootstrap or application publication. There is no root
// reservation here: every floor adopts its original pool and provider position.
func (p *SessionCorePlan) installStreamWorkloads() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.rpc
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired || p.closed {
		return cryptov4.ErrClosed
	}
	for _, w := range r.initialWorkloads {
		if w == nil || w.stream == nil {
			continue
		}
		if w.closed || w.cleaned || w.stream.core != nil {
			return cryptov4.ErrConfiguration
		}
		for i := range w.slots {
			s := &w.slots[i]
			if s.closing || s.closed || s.used || s.building {
				return cryptov4.ErrClosed
			}
			if err := p.adoptStreamCallerFloorLocked(s.transport); err != nil {
				return err
			}
		}
		w.stream.core = &p.core
	}
	return nil
}
