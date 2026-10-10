package sessionv4

import (
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

const (
	streamServiceExternal = streamFactoryOwners + iota
	streamServiceConnection
	streamServiceMetadata
	streamServiceCallback
	streamServiceOwners
	maxStreamServices = 128
)

// Each position is part of the original Session plan, not a new budget root.
// It holds complete reusable backing and the original receive promise. A use
// returns only when every actual transport, callback and metadata alias exits.
type streamServiceFloor struct {
	owners  [streamServiceOwners]*resourcev4.ProtectedReservation
	receive *ReceiveProtection
	used    bool // Original Session plan gate.
}

func streamServiceFloorCharges(c SessionCoreConfig) (count uint32, vectors [streamServiceOwners]resourcev4.Vector, err error) {
	p := c.Handlers.Plan
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		err = resourcev4.ErrClosed
		return
	}
	var declared uint64
	for _, r := range p.registrations {
		var external, connection resourcev4.Vector
		if r.config.ControlledHTTP != nil {
			external, err = controlledHTTPStreamCharge(r.config.ControlledHTTP.Options, r.config.ControlledHTTP.Upgrade)
			if err == nil {
				connection, err = StreamConnCharge(r.config.ControlledHTTP.Options.Connection)
			}
			vectors[streamServiceCallback] = p.executor.TaskCharge()
		} else if r.config.HTTP != nil {
			external, err = HTTPStreamCharge(r.config.HTTP.Options)
			if err == nil {
				connection, err = StreamConnCharge(r.config.HTTP.Options.Connection)
			}
		} else if r.config.Delegated != nil {
			external, err = DelegatedStreamCharge(r.config.Delegated.Options)
			if err == nil {
				connection, err = StreamConnCharge(r.config.Delegated.Options.Connection)
			}
		} else {
			continue
		}
		if err != nil {
			return
		}
		declared += uint64(r.config.Slots)
		for dim := range resourcev4.Dimensions {
			vectors[streamServiceExternal][dim] = max(vectors[streamServiceExternal][dim], external[dim])
			vectors[streamServiceConnection][dim] = max(vectors[streamServiceConnection][dim], connection[dim])
		}
	}
	if declared == 0 {
		return
	}
	target := c.Handlers.ServiceTarget
	if target == 0 {
		target = 64
	}
	if target > maxStreamServices {
		err = cryptov4.ErrConfiguration
		return
	}
	count = uint32(min(declared, uint64(target)))
	// The selected envelope is uniform and covers any registered service at
	// each available position. It includes every external dimension; neither
	// sparse bytes nor a smaller native task declaration implies a free slot.
	if c.Streams.ReceiveBytes == 0 || c.Streams.InitialReceiveLimit == 0 || uint64(count) > c.Streams.ReceivePoolBytes/c.Streams.ReceiveBytes || uint64(count) > c.Session.Contract.Limits().MaxCredit/c.Streams.InitialReceiveLimit || count > c.Open.Active || count > c.Open.PerClass[BusinessStream] {
		err = cryptov4.ErrConfiguration
		return
	}
	kind, e := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if e != nil {
		err = e
		return
	}
	metadata, e := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
	if e != nil || metadata > math.MaxInt-kind {
		err = cryptov4.ErrConfiguration
		return
	}
	stream, e := sessionStreamCharges(c.Streams, c.Session.Profile, uint64(c.Session.Contract.Limits().MaxFrame), c.MaxDataPayloadBytes, kind+metadata)
	if e != nil {
		err = e
		return
	}
	copy(vectors[:], stream[:])
	if c.Native || c.MixedCarrier {
		vectors[streamFactoryNativeReceive], err = NativeDataAssemblyCharge(math.MaxInt64, protocolv4.ServerToClient, c.Session.Profile, c.Session.Contract.Limits().MaxFrame)
		if err != nil {
			return
		}
	}
	vectors[streamFactoryInvocation], err = streamHandlerInvocationCharge(c.Handlers)
	if err != nil {
		return
	}
	vectors[streamFactoryAuthorizeTask] = p.executor.TaskCharge()
	// Delegated service execution never needs an ordinary Handler task.
	vectors[streamServiceMetadata] = resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(preparedStreamService{})) + uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 1}
	return
}

func protectedStreamServiceFloorCharges(c SessionCoreConfig) (count uint32, charges [streamServiceOwners]resourcev4.Vector, err error) {
	count, vectors, err := streamServiceFloorCharges(c)
	if err != nil || count == 0 {
		return count, charges, err
	}
	for component, vector := range vectors {
		if vector == (resourcev4.Vector{}) {
			continue
		}
		charges[component], err = resourcev4.ProtectedCharge(vector)
		if err != nil {
			return 0, charges, err
		}
	}
	return count, charges, nil
}

func streamServiceBorrows(position int) int {
	switch position {
	case streamFactoryMetadata:
		return 1
	case streamFactoryInvocation, streamServiceExternal:
		return 2
	case streamServiceConnection:
		return 4
	default:
		return 0
	}
}

func (b *sessionCoreBatch) prepareStreamServiceFloor(refs []resourcev4.Reference) (err error) {
	if b.serviceFloors != nil {
		return nil
	}
	count, vectors, err := streamServiceFloorCharges(b.config)
	if err != nil || count == 0 {
		return err
	}
	b.serviceFloors = make([]streamServiceFloor, count)
	for i, position := range b.positions[:b.count] {
		if position < coreStreamServiceStart {
			continue
		}
		index := position - coreStreamServiceStart
		slot, component := index/streamServiceOwners, index%streamServiceOwners
		ref := refs[i]
		if err := ref.CheckAllocationScope(b.root, b.owner, b.accounts[:b.accountCount]); err != nil {
			return err
		}
		var aliases [4]resourcev4.Reference
		n := streamServiceBorrows(component)
		for k := 0; k < n; k++ {
			aliases[k], err = ref.Borrow()
			if err != nil {
				break
			}
		}
		if err == nil {
			b.serviceFloors[slot].owners[component], err = resourcev4.NewProtectedReservation(ref, vectors[component], aliases[:n]...)
		}
		for _, alias := range aliases {
			alias.Release()
		} // Successful protection invalidated these generations.
		if err != nil {
			return err
		}
	}
	for i := range b.serviceFloors {
		b.serviceFloors[i].receive, err = b.receivePool.Protect(b.config.Streams.ReceiveBytes, b.config.Streams.InitialReceiveLimit)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *streamServiceFloor) close() {
	f.receive.Close()
	for _, owner := range f.owners {
		owner.CloseAfterUse()
	}
}

func (f *streamServiceFloor) checkout() (refs [streamServiceOwners]resourcev4.Reference, err error) {
	f.receive.pool.mu.Lock()
	available := !f.receive.closed && !f.receive.pool.closed && f.receive.flow == nil
	f.receive.pool.mu.Unlock()
	if !available {
		return refs, resourcev4.ErrCapacity
	}
	var owners [streamServiceOwners]*resourcev4.ProtectedReservation
	var positions [streamServiceOwners]int
	var output [streamServiceOwners]resourcev4.Reference
	n := 0
	for i, owner := range f.owners {
		// A native HTTP callback checks out this original task per request;
		// an idle keep-alive never holds an ordinary execution permit.
		if owner != nil && i != streamServiceCallback {
			owners[n], positions[n] = owner, i
			n++
		}
	}
	if err = resourcev4.CheckoutProtectedBatch(owners[:n], output[:n]); err != nil {
		return
	}
	for i := range n {
		refs[positions[i]] = output[i]
	}
	return
}

// Internal routing reads only the already authenticated kind. It creates no
// application snapshot, capture, callback authority or OPEN outcome. Original
// PreparePeerOpen and CopyRequest still precede every application disclosure.
func (a *OpenAdmission) pendingDelegatedKind(h OpenHandle, plan *StreamHandlerPlan) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return false, nil
	}
	if a.closed {
		return false, cryptov4.ErrClosed
	}
	if s.phase != openPending || s.local || s.cancelled {
		return false, nil
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	for _, r := range plan.registrations {
		if a.metadata.equals(s.metadataStart, s.metadataStart+s.kindSize, r.config.Kind) {
			return r.config.HTTP != nil || r.config.Delegated != nil || r.config.ControlledHTTP != nil, nil
		}
	}
	return false, nil
}
