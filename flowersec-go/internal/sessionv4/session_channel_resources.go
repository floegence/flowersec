package sessionv4

import (
	"encoding/json"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
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
	geometry, minimum, err := internalChannelGeometry(r.session.Limits().ApplicationProfile)
	if err != nil {
		return err
	}
	if err := pool.reservation.CheckAllocationScope(r.root, r.owner, r.accounts[:r.accountCount]); err != nil {
		return err
	}
	r.receivePool = pool
	count := int(geometry.RPC + geometry.Notify + geometry.Management)
	for i := 0; i < count; i++ {
		capacity := minimum
		if i == 0 {
			capacity = r.firstFuture.config.ReceiveBytes
		}
		r.receiveProtection[i], err = pool.Protect(capacity, minimum)
		if err != nil {
			r.closed = true
			for _, guard := range r.receiveProtection {
				guard.Close()
			}
			return err
		}
	}
	return nil
}
