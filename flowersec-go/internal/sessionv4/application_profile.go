package sessionv4

import (
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// ApplicationResourceProfile changes only trusted local admission. It is not
// an application protocol profile, peer priority or a signed authorization.
type ApplicationResourceProfile string

const (
	ApplicationProfileCustom      ApplicationResourceProfile = ""
	ApplicationProfileClient      ApplicationResourceProfile = "client"
	ApplicationProfileServer      ApplicationResourceProfile = "server"
	ApplicationProfileConstrained ApplicationResourceProfile = "constrained"
)

// ApplicationExecutorPreset uses one root service for all participating
// Environments. Runtime allowances remain explicit qualified host inputs.
// execution enables the protected management lane; services can omit it.
func ApplicationExecutorPreset(profile ApplicationResourceProfile, runtimeBytes, runtimeBytesPerTask uint64, execution, diagnostics bool) (ApplicationExecutorConfig, error) {
	c := ApplicationExecutorConfig{Profile: profile, Diagnostics: diagnostics, DisableManagement: !execution,
		CompletionRunning: 2, CompletionReserved: 4096, QueryOwners: 12,
		RuntimeBytes: runtimeBytes, RuntimeBytesPerTask: runtimeBytesPerTask}
	switch profile {
	case ApplicationProfileClient, ApplicationProfileServer:
		c.Running, c.Ready, c.ResidentRunning, c.ResidentReady = 26, 52, 18, 36
	case ApplicationProfileConstrained:
		c.Running, c.Ready, c.ResidentRunning, c.ResidentReady = 8, 16, 6, 12
		c.QueryOwners = 6
	default:
		return ApplicationExecutorConfig{}, cryptov4.ErrConfiguration
	}
	if _, err := ApplicationExecutorCharge(c); err != nil {
		return ApplicationExecutorConfig{}, err
	}
	return c, nil
}

func (c ApplicationExecutorConfig) profileServiceBytes() (ordinary, resident uint64, err error) {
	switch c.Profile {
	case ApplicationProfileCustom:
		return 0, 0, nil
	case ApplicationProfileClient, ApplicationProfileServer:
		if c.Running != 26 || c.Ready != 52 || c.ResidentRunning != 18 || c.ResidentReady != 36 {
			return 0, 0, cryptov4.ErrConfiguration
		}
		ordinary, resident = 7*1048576, 6*1048576
	case ApplicationProfileConstrained:
		if c.Running != 8 || c.Ready != 16 || c.ResidentRunning != 6 || c.ResidentReady != 12 {
			return 0, 0, cryptov4.ErrConfiguration
		}
		ordinary, resident = 3*1048576, 5*1048576/2
	default:
		return 0, 0, cryptov4.ErrConfiguration
	}
	if c.CompletionRunning != 2 || c.CompletionReserved == 0 || c.CompletionReserved > 4096 || c.QueryOwners > 128 {
		return 0, 0, cryptov4.ErrConfiguration
	}
	return ordinary, resident, nil
}

func applicationProfileCharge(c ApplicationExecutorConfig) (resourcev4.Vector, error) {
	ordinary, resident, err := c.profileServiceBytes()
	if err != nil || ordinary == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	// The real running stacks and all admitted handles/queue links fit the
	// single reserved service. Payloads, contexts and application allocations
	// keep their separate original owners and are never paid from this reserve.
	if c.RuntimeBytes > ordinary {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	handle := max(uint64(unsafe.Sizeof(ApplicationPermit{})), uint64(unsafe.Sizeof(QueuedApplicationTask{}))) + uint64(unsafe.Sizeof(ApplicationTask{}))
	fixed := uint64(unsafe.Sizeof(ApplicationExecutor{})) + c.RuntimeBytes + uint64(c.Running)*uint64(unsafe.Sizeof(applicationTaskSlot{})) + uint64(c.Ready)*uint64(unsafe.Sizeof(applicationReadySlot{}))
	if c.RuntimeBytesPerTask > ordinary/uint64(c.Running) || fixed > ordinary || uint64(c.Running)*c.RuntimeBytesPerTask > ordinary-fixed || handle*uint64(c.Running+c.Ready) > ordinary-fixed-uint64(c.Running)*c.RuntimeBytesPerTask {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if c.RuntimeBytesPerTask > resident/uint64(c.ResidentRunning) || handle*uint64(c.ResidentRunning+c.ResidentReady) > resident-uint64(c.ResidentRunning)*c.RuntimeBytesPerTask {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	completionBytes := uint64(c.CompletionRunning)*c.RuntimeBytesPerTask + 4*uint64(unsafe.Sizeof(CompletionTask{}))
	if completionBytes > 256*1024 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	// Dormant result index storage is finite owner metadata, independent of
	// the protected Completion worker reserve and not multiplied per waiter.
	charge := resourcev4.Vector{resourcev4.SDKBytes: ordinary + 256*1024 + uint64(c.CompletionReserved)*uint64(unsafe.Sizeof(completionSlot{})),
		resourcev4.Items: uint64(c.Running+c.Ready+c.CompletionReserved) + 1, resourcev4.Tasks: uint64(c.Running + c.CompletionRunning), resourcev4.WorkSlots: uint64(c.Running + c.CompletionRunning)}
	for _, lane := range []func(ApplicationExecutorConfig) (resourcev4.Vector, error){sdkQueryLaneCharge, diagnosticLaneCharge, managementLaneCharge} {
		part, failure := lane(c)
		if failure != nil {
			return resourcev4.Vector{}, failure
		}
		charge, err = charge.Add(part)
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	return charge, nil
}
