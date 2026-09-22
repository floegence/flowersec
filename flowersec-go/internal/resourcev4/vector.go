// Package resourcev4 owns local admission charges. It carries no credentials,
// wire messages, durable commit facts or authority to start an application job.
package resourcev4

import "errors"

var (
	ErrConfiguration = errors.New("resourcev4: configuration capacity")
	ErrCapacity      = errors.New("resourcev4: resource exhausted")
	ErrClosed        = errors.New("resourcev4: admission closed")
	ErrOwner         = errors.New("resourcev4: invalid resource owner")
)

// Dimensions describe local charges, not peer-advertised fields. Pool accounts
// constrain particular work/queue classes using the same root gate. External
// provider bytes never enter the SDK-owned byte bound. Rates and actual CPU
// service guarantees require their separately admitted scheduler/provider.
const (
	SDKBytes = iota
	ProviderBytes
	DiskBytes
	Items
	WorkSlots
	Tasks
	Timers
	Connections
	TLSHandshakes
	Sessions
	NativeHandles
	Dimensions
)

type Vector [Dimensions]uint64

func (v Vector) Contains(other Vector) bool {
	for i, value := range other {
		if value > v[i] {
			return false
		}
	}
	return true
}

func (v Vector) Add(other Vector) (Vector, error) {
	for i, value := range other {
		if value > ^uint64(0)-v[i] {
			return Vector{}, ErrConfiguration
		}
		v[i] += value
	}
	return v, nil
}

func (v Vector) subtract(other Vector) Vector {
	for i, value := range other {
		v[i] -= value
	}
	return v
}

func fits(used, limit, extra Vector) bool {
	return limit.subtract(used).Contains(extra)
}
