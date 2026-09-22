package sessionv4

import (
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// OwnedEventInput contains only an SDK-owned immutable byte snapshot. It cannot
// hide an application object graph, getter, generator or escaped producer
// buffer. Publication moves its one original backing; stale producer handles
// cannot release a queued or running event.
type OwnedEventInput struct {
	processingBorrow resourcev4.Reference
	processing       [2]resourcev4.Reference
	mu               sync.Mutex
	reservation      resourcev4.Reference
	charge           resourcev4.Vector
	bytes            []byte
	source           *streamEventSource
	transferred      bool
	closed           bool
}

func EventInputCharge(length uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if length > 1048576 || runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(OwnedEventInput{})) + uint64(length), resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// NewOwnedEventInput reserves the complete copy before allocation. Application
// encoding, when needed, runs in the producer's existing ordinary invocation;
// TryPublish itself never calls a codec or follows arbitrary object aliases.
func NewOwnedEventInput(input []byte, runtimeBytes uint64, reservation resourcev4.Reference) (*OwnedEventInput, error) {
	if len(input) > 1048576 {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := EventInputCharge(uint32(len(input)), runtimeBytes)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	return &OwnedEventInput{reservation: owned, charge: charge, bytes: append([]byte(nil), input...)}, nil
}

func (i *OwnedEventInput) Close() {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.transferred {
		return
	}
	i.releaseLocked()
}

func (i *OwnedEventInput) releaseLocked() {
	if i.closed {
		return
	}
	i.closed = true
	clear(i.bytes)
	i.bytes, i.source = nil, nil
	i.processingBorrow.Release()
	i.processingBorrow = resourcev4.Reference{}
	for _, ref := range i.processing {
		ref.Release()
	}
	i.processing = [2]resourcev4.Reference{}
	i.reservation.Release()
	i.reservation = resourcev4.Reference{}
}

func (*OwnedEventInput) String() string               { return "Flowersec.OwnedEventInput" }
func (*OwnedEventInput) GoString() string             { return "Flowersec.OwnedEventInput" }
func (*OwnedEventInput) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
