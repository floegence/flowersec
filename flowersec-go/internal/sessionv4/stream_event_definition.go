package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// StreamEventSourceDefinition selects the SDK's closed byte-input source and
// pump. Setup subscribes exactly once; Codec maps one owned input into the
// existing bounded item writer. Neither an arbitrary generator nor an iterator
// can be substituted for this SDK-controlled queue and publication capability.
type StreamEventSourceDefinition struct {
	Pending           uint8
	InputBytes        uint64
	MaxInputBytes     uint32
	MaxInputCharge    resourcev4.Vector
	InputRuntimeBytes uint64
	CleanupMS         uint64
	Codec             SynchronousStreamCodec
	Setup             func(context.Context, StreamRequest, EventSubscription) error
}

func (d *StreamEventSourceDefinition) validate() error {
	if d == nil || d.Setup == nil || d.Pending == 0 || d.Pending > 8 || d.Codec.Encode == nil || d.Codec.MaxInputBytes < d.MaxInputBytes || d.Codec.ScratchBytes > 1048576 {
		return cryptov4.ErrConfiguration
	}
	maximum, err := EventInputCharge(d.MaxInputBytes, d.InputRuntimeBytes)
	if err != nil || !d.MaxInputCharge.Contains(maximum) || d.InputBytes < d.MaxInputCharge[resourcev4.SDKBytes] {
		return cryptov4.ErrConfiguration
	}
	_, err = streamSourceCleanupCharge(d.InputRuntimeBytes, d.CleanupMS)
	return err
}

func (d *StreamEventSourceDefinition) config(job *serviceStreamCall) streamEventSourceConfig {
	owner := job.dispatcher
	encoding, _ := StreamItemEncodingCharge(0, d.Codec, owner.runtimeBytes)
	return streamEventSourceConfig{Root: owner.root, Owner: owner.owner, Accounts: owner.accounts[:owner.accountCount], Identity: job.allocation.identity, Encoding: encoding, Task: owner.plan.executor.TaskCharge(), Pending: d.Pending, InputBytes: d.InputBytes, MaxInputBytes: d.MaxInputBytes, MaxInputCharge: d.MaxInputCharge, InputRuntimeBytes: d.InputRuntimeBytes, RuntimeBytes: owner.runtimeBytes}
}
