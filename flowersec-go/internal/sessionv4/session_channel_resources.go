package sessionv4

import (
	"encoding/json"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type applicationChannelGeometry struct {
	RPC        uint32 `json:"rpc_channels"`
	Notify     uint32 `json:"notify_channels"`
	Management uint32 `json:"management_channels"`
}

var applicationChannelRegistry = sync.OnceValues(func() (struct {
	Profiles       map[string]applicationChannelGeometry `json:"profiles"`
	DirectionBytes uint64                                `json:"channel_direction_bytes"`
}, error) {
	var registry struct {
		Application struct {
			Profiles       map[string]applicationChannelGeometry `json:"profiles"`
			DirectionBytes uint64                                `json:"channel_direction_bytes"`
		} `json:"application"`
	}
	err := json.Unmarshal([]byte(protocolv4.ResourceFormulaRegistryJSON), &registry)
	return registry.Application, err
})

func internalChannelGeometry(profile string) (applicationChannelGeometry, uint64, error) {
	r, err := applicationChannelRegistry()
	geometry, ok := r.Profiles[profile]
	if err != nil || !ok || r.DirectionBytes == 0 || uint64(geometry.RPC)+uint64(geometry.Notify)+uint64(geometry.Management) > 11 {
		return applicationChannelGeometry{}, 0, cryptov4.ErrConfiguration
	}
	return geometry, r.DirectionBytes, nil
}

// prepareReceive protects all signed future I/M receive responsibilities in
// the original Session pool. Only the bootstrap later takes a real scope;
// every other position stays reserved for its original internal channel kind.
func (r *RPCServices) prepareReceive(pool *ReceivePool) error {
	if r == nil || pool == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prepareReceiveLocked(pool)
}

func (r *RPCServices) prepareReceiveLocked(pool *ReceivePool) error {
	if r.closed {
		return cryptov4.ErrClosed
	}
	if r.receivePool != nil {
		if r.receivePool != pool {
			return cryptov4.ErrConfiguration
		}
		return nil
	}
	guards, err := reserveInternalChannelReceive(pool, RPCServicesConfig{Session: r.session, Root: r.root, Owner: r.owner, Accounts: r.accounts[:r.accountCount], Bootstrap: r.firstFuture.config})
	if err != nil {
		return err
	}
	r.receivePool, r.receiveProtection = pool, guards
	return nil
}

// Original admission and component assembly use the same finite channel
// positions. No channel scope, wire credit or reader starts at this boundary.
func reserveInternalChannelReceive(pool *ReceivePool, c RPCServicesConfig) (guards [11]*ReceiveProtection, err error) {
	if pool == nil {
		return guards, cryptov4.ErrConfiguration
	}
	geometry, minimum, err := internalChannelGeometry(c.Session.Limits().ApplicationProfile)
	if err != nil {
		return guards, err
	}
	if err := pool.reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return guards, err
	}
	defer func() {
		if err != nil {
			for _, guard := range guards {
				guard.Close()
			}
			clear(guards[:])
		}
	}()
	count := int(geometry.RPC + geometry.Notify + geometry.Management)
	for i := 0; i < count; i++ {
		capacity := minimum
		if i == 0 {
			capacity = c.Bootstrap.ReceiveBytes
		}
		guards[i], err = pool.Protect(capacity, minimum)
		if err != nil {
			return guards, err
		}
	}
	return guards, nil
}

func checkInternalChannelReceive(pool *ReceivePool, c RPCServicesConfig, guards [11]*ReceiveProtection) error {
	if pool == nil {
		return cryptov4.ErrConfiguration
	}
	geometry, minimum, err := internalChannelGeometry(c.Session.Limits().ApplicationProfile)
	if err != nil {
		return err
	}
	if err := pool.reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return err
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.closed {
		return ErrFlowClosed
	}
	count := int(geometry.RPC + geometry.Notify + geometry.Management)
	for i, guard := range guards {
		if i >= count {
			if guard != nil {
				return cryptov4.ErrConfiguration
			}
			continue
		}
		capacity := minimum
		if i == 0 {
			capacity = c.Bootstrap.ReceiveBytes
		}
		if guard == nil || guard.pool != pool || guard.closed || guard.flow != nil || guard.retireWithFlow || guard.capacity != capacity || guard.promise != minimum {
			return resourcev4.ErrOwner
		}
		if err := guard.borrow.Check(); err != nil {
			return err
		}
	}
	return nil
}
