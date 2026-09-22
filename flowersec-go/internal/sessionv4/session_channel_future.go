package sessionv4

import (
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

const (
	internalChannelStreamOwners = 4
	internalChannelRPCOwners    = 4
	internalChannelOwners       = internalChannelStreamOwners + internalChannelRPCOwners
	maxFutureChannels           = 10 // The fixed bootstrap already owns position zero.
	rpcServicesOwnerCapacity    = rpcServicesOwners + maxFutureChannels*internalChannelOwners + 5 + 4*maxSessionExecutionServices
)

var firstChannelOwners = [internalChannelOwners]int{
	rpcServicesStreamMetadata, rpcServicesStreamSend, rpcServicesStreamQueue, rpcServicesStreamOwnership,
	rpcServicesChannel, rpcServicesBatchWriter, rpcServicesPublisher, rpcServicesReceiver,
}

// internalChannelFuture protects the original send ring, queue, Stream owner
// and constructor metadata. Ordinary RPC positions also own their complete
// reader/publisher assembly. Receive backing stays in the same Session pool;
// notification and management message engines have separate responsibilities.
// An unused future creates no Stream, ordinal, wire promise or running task.
type internalChannelFuture struct {
	config SessionStreamConfig
	owners [internalChannelOwners]*resourcev4.ProtectedReservation
	count  int
}

type internalChannelAllocation struct {
	stream     sessionStreamAllocation
	rpc        [internalChannelRPCOwners]resourcev4.Reference
	notify     [internalChannelRPCOwners]resourcev4.Reference
	management [internalChannelRPCOwners]resourcev4.Reference
}

// futureChannelCharges keeps each independently transferred backing distinct.
// Its order is stable for the original admission batch and later checkouts.
func futureChannelCharges(c RPCServicesConfig, position uint32) (v [internalChannelOwners]resourcev4.Vector, count int, err error) {
	stream, err := sessionStreamCharges(c.Bootstrap, c.CryptoProfile, uint64(c.Session.Limits().MaxFrame), c.MaxDataPayloadBytes, 256)
	if err != nil {
		return v, 0, err
	}
	copy(v[:internalChannelStreamOwners], stream[:internalChannelStreamOwners])
	v[0], err = v[0].Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(internalChannelAllocation{})) - uint64(unsafe.Sizeof(sessionStreamAllocation{})) + uint64(max(unsafe.Sizeof(rpcChannelOpening{}), unsafe.Sizeof(notifyChannelOpening{}), unsafe.Sizeof(managementChannelOpening{}))) + uint64(unsafe.Sizeof(timev4.Deadline{}))})
	if err != nil {
		return v, 0, err
	}
	count = internalChannelStreamOwners
	if position == 10 {
		v[4], err = ManagementChannelCharge(c.RuntimeBytes)
		if err != nil {
			return
		}
		v[5], err = RPCBatchWriterCharge(c.RuntimeBytes)
		if err != nil {
			return
		}
		v[6], err = rpcv4.ExecutionManagementWireCharge(c.RuntimeBytes)
		if err != nil {
			return
		}
		v[7], err = ManagementParserCharge(c.RuntimeBytes)
		count = internalChannelOwners
		return
	}
	if position >= 8 {
		v[4], err = NotifyChannelCharge(c.RuntimeBytes)
		if err != nil {
			return
		}
		v[5], err = RPCBatchWriterCharge(c.RuntimeBytes)
		if err != nil {
			return
		}
		v[6], err = rpcv4.NotifyPublisherCharge(c.notifyOutputConfig())
		if err != nil {
			return
		}
		v[7], err = rpcv4.NotifyReceiverCharge(c.notifyInputConfig())
		count = internalChannelOwners
		return
	}
	v[4], err = RPCChannelCharge(c.RuntimeBytes)
	if err != nil {
		return
	}
	v[5], err = RPCBatchWriterCharge(c.RuntimeBytes)
	if err != nil {
		return
	}
	v[6], err = rpcv4.PublisherCharge(c.RuntimeBytes)
	if err != nil {
		return
	}
	v[7], err = rpcv4.ReceiverCharge(c.RuntimeBytes)
	count = internalChannelOwners
	return
}

func (c RPCServicesConfig) futureConfig() (RPCServicesConfig, applicationChannelGeometry, error) {
	g, minimum, err := internalChannelGeometry(c.Session.Limits().ApplicationProfile)
	if err != nil || g.RPC == 0 || g.RPC > 8 {
		return c, g, cryptov4.ErrConfiguration
	}
	c.Bootstrap.ReceiveBytes = minimum
	c.Bootstrap.InitialReceiveLimit = minimum
	return c, g, nil
}

func appendFutureChannelCharges(c RPCServicesConfig, charges *[rpcServicesOwnerCapacity]resourcev4.Vector) (int, error) {
	c, g, err := c.futureConfig()
	if err != nil {
		return 0, err
	}
	count := rpcServicesOwners
	for channel := uint32(1); channel < g.RPC+g.Notify+g.Management; channel++ {
		v, n, err := futureChannelCharges(c, channel)
		if err != nil {
			return 0, err
		}
		for _, minimum := range v[:n] {
			charges[count], err = resourcev4.ProtectedCharge(minimum)
			if err != nil {
				return 0, err
			}
			count++
		}
	}
	return count, nil
}

func (r *RPCServices) adoptFutureChannels(c RPCServicesConfig) error {
	first, n, err := futureChannelCharges(c, 0)
	if err != nil {
		return err
	}
	r.firstFuture.config, r.firstFuture.count = c.Bootstrap, n
	for i, position := range firstChannelOwners {
		r.firstFuture.owners[i], err = resourcev4.NewProtectedReservation(r.refs[position], first[i])
		if err != nil {
			return err
		}
	}
	c, g, err := c.futureConfig()
	if err != nil {
		return err
	}
	position := rpcServicesOwners
	for channel := uint32(1); channel < g.RPC+g.Notify+g.Management; channel++ {
		v, n, err := futureChannelCharges(c, channel)
		if err != nil {
			return err
		}
		f := &r.futureChannels[channel-1]
		f.config, f.count = c.Bootstrap, n
		for i, minimum := range v[:n] {
			f.owners[i], err = resourcev4.NewProtectedReservation(r.refs[position], minimum)
			if err != nil {
				return err
			}
			position++
		}
	}
	return nil
}

// checkoutInternalChannel moves a whole original future vector. An earlier
// provider/reader/Stream alias prevents reuse of that position. Failure never
// consumes another channel's backing or a business Stream's dynamic budget.
// Actual role/kind admission and OPEN remain the original admission's job.
func (r *RPCServices) checkoutInternalChannel(position int) (*internalChannelAllocation, error) {
	if r == nil || position < 1 || position > maxFutureChannels {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkoutInternalChannelLocked(position)
}

func (r *RPCServices) checkoutInternalChannelLocked(position int) (*internalChannelAllocation, error) {
	if r.closed || r.retired {
		return nil, cryptov4.ErrClosed
	}
	f := &r.futureChannels[position-1]
	return r.checkoutChannelAllocationLocked(f, position)
}

func (r *RPCServices) checkoutChannelAllocationLocked(f *internalChannelFuture, position int) (*internalChannelAllocation, error) {
	if f.count == 0 || r.receivePool == nil || r.receiveProtection[position] == nil {
		return nil, cryptov4.ErrNotReady
	}
	var refs [internalChannelOwners]resourcev4.Reference
	if err := resourcev4.CheckoutProtectedBatch(f.owners[:f.count], refs[:f.count]); err != nil {
		return nil, err
	}
	a := &internalChannelAllocation{}
	copy(a.stream.refs[:internalChannelStreamOwners], refs[:internalChannelStreamOwners])
	if position == 10 {
		copy(a.management[:], refs[internalChannelStreamOwners:])
	} else if position >= 8 && position < 10 {
		copy(a.notify[:], refs[internalChannelStreamOwners:])
	} else {
		copy(a.rpc[:], refs[internalChannelStreamOwners:])
	}
	c := f.config
	a.stream.queue = SendQueueReservation{Capacity: c.QueueBytes, Waiters: c.WriteWaiters, Chunk: c.Chunk, Reservation: a.stream.refs[streamFactoryQueue]}
	a.stream.reservation = StreamReservation{Pool: r.receivePool, ReceiveProtection: r.receiveProtection[position], ReceiveCapacity: c.ReceiveBytes, InitialReceiveLimit: c.InitialReceiveLimit,
		SendCapacity: c.SendBytes, SendReservation: a.stream.refs[streamFactorySend], SendQueue: &a.stream.queue, MaxPlaintext: c.MaxPlaintext, OpenStorage: make([]byte, 256)}
	return a, nil
}

func (a *internalChannelAllocation) release() {
	if a == nil {
		return
	}
	if a.stream.candidate != nil {
		a.stream.candidate.reservation.Release()
	}
	for _, ref := range a.stream.refs {
		ref.Release()
	}
	for _, ref := range a.rpc {
		ref.Release()
	}
	for _, ref := range a.notify {
		ref.Release()
	}
	for _, ref := range a.management {
		ref.Release()
	}
	clear(a.stream.reservation.OpenStorage)
	*a = internalChannelAllocation{}
}
