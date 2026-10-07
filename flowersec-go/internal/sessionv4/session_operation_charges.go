package sessionv4

import (
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// preparedOperationCharges is shared by actual Prepare and local workload
// qualification. Encoded request backing and codec input/scratch are distinct
// owners; the original invocation supplies its own execution reference when
// encoding synchronously inside an already admitted callback.
func preparedOperationCharges(runtimeBytes uint64, payloadBytes, inputBytes uint32, codec *SynchronousUnaryCodec, stream *streamPreparationPlan, executor *ApplicationExecutor, encoderTask bool) (charges [5]resourcev4.Vector, count int, err error) {
	var task resourcev4.Vector
	if executor != nil {
		task = executor.TaskCharge()
	}
	return preparedOperationChargesWithTask(runtimeBytes, payloadBytes, inputBytes, codec, stream, task, encoderTask)
}

func preparedOperationChargesWithTask(runtimeBytes uint64, payloadBytes, inputBytes uint32, codec *SynchronousUnaryCodec, stream *streamPreparationPlan, task resourcev4.Vector, encoderTask bool) (charges [5]resourcev4.Vector, count int, err error) {
	if runtimeBytes == 0 || payloadBytes > 1048576 || inputBytes > 1048576 || codec != nil && (codec.Encode == nil || codec.MaxEncodedBytes > 1048576 || codec.ScratchBytes > 1048576 || payloadBytes != codec.MaxEncodedBytes) {
		return charges, 0, cryptov4.ErrConfiguration
	}
	notify := stream != nil && stream.notify
	streaming := stream != nil && !notify
	resume := streaming && stream.resume != nil
	if resume && codec != nil || codec != nil && encoderTask && task == (resourcev4.Vector{}) {
		return charges, 0, cryptov4.ErrConfiguration
	}
	count = 3
	charges[0], err = rpcv4.PreparedRequestCharge(payloadBytes, runtimeBytes)
	if err == nil {
		charges[1], err = rpcv4.ContractRouteCharge(runtimeBytes)
	}
	if err == nil {
		charges[2], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(UnaryOperation{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	}
	if err == nil && !streaming && !notify {
		// The convenience caller may await the admitted first channel under its
		// original prepared lifetime with one bounded host timer.
		charges[2], err = charges[2].Add(resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Timers: 1})
	}
	if err == nil && streaming {
		charges[2], err = charges[2].Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(streamOperationState{})) + uint64(unsafe.Sizeof(StreamOperation{})) + uint64(len(stream.kind)) + uint64(len(stream.metadata)), resourcev4.Items: 2})
	}
	if err == nil && notify {
		if runtimeBytes > math.MaxUint64/4 {
			return charges, 0, cryptov4.ErrConfiguration
		}
		charges[2], err = charges[2].Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(notifyOperationState{})) + uint64(unsafe.Sizeof(NotifyOperation{})), resourcev4.Items: 6})
		if err == nil {
			charges[2], err = charges[2].Add(resourcev4.Vector{resourcev4.SDKBytes: 4 * runtimeBytes})
		}
	}
	if err == nil && resume {
		charges[2], err = charges[2].Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(resumeTarget{}))})
		if err == nil {
			charges[3], err = resumePreparationCharge(runtimeBytes)
		}
		count = 4
	}
	if err == nil && codec != nil {
		charges[3], err = synchronousUnaryCharge(inputBytes, *codec, runtimeBytes)
		count = 4
		if encoderTask {
			charges[4] = task
			count = 5
		}
	}
	return
}
