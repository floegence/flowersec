package sessionv4

import (
	"encoding/json"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type openAdmissionRegistryData struct {
	Streams struct {
		Client     uint64 `json:"client_ordinals"`
		Server     uint64 `json:"server_ordinals"`
		Pending    uint32 `json:"pending_per_role"`
		Terminal   uint32 `json:"terminal_capacity"`
		Reject     uint32 `json:"rejection_reserve"`
		Business   uint64 `json:"business_lifetime"`
		Internal   uint64 `json:"internal_lifetime"`
		Management uint64 `json:"management_lifetime"`
	}
	Records struct {
		Caps struct {
			Ingress struct{ Items, Bytes uint64 } `json:"ingress_staging"`
		} `json:"resource_caps"`
	}
}

// Shared immutable registry backing belongs to Environment initialization,
// rather than a transient decoder graph for every OPEN constructor.
var openAdmissionRegistry = sync.OnceValues(func() (*openAdmissionRegistryData, error) {
	r := new(openAdmissionRegistryData)
	if json.Unmarshal([]byte(protocolv4.StreamStateRegistryJSON), &r.Streams) != nil || json.Unmarshal([]byte(protocolv4.RecordRegistryJSON), &r.Records) != nil {
		return nil, cryptov4.ErrConfiguration
	}
	return r, nil
})

// OpenAdmissionCharge covers the fixed OPEN ownership graph, including both
// complete lifetime bitmaps. IngressBytes determines the metadata arena after
// its descriptor allowance; it is not an additional allocation. The admitted
// runtime profile separately accounts for allocator and channel overhead.
// One dispatcher and one outcome observer per fixed slot have fixed notification
// positions; they use their caller's original task and timer admission. Each
// slot also admits its once-only application preparation capability. Captured
// metadata storage belongs to the caller's original admitted callback owner.
// Each fixed slot also covers one SDK-owned logical carrier association; native
// provider handles have separate reservations. Service, Stream, barrier and
// retirement backing have their own reservations. Cleanup uses the original
// coordinator without another task.
func OpenAdmissionCharge(limits OpenLimits) (resourcev4.Vector, error) {
	r, err := openAdmissionRegistry()
	if err != nil {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	streams, records := r.Streams, r.Records
	if limits.Opening > min(limits.Active, streams.Pending) || limits.Terminal > streams.Terminal ||
		limits.RejectionReserve == 0 || limits.RejectionReserve > streams.Reject || uint64(limits.Active)+uint64(limits.RejectionReserve) > uint64(limits.Terminal) ||
		limits.IngressItems == 0 || uint64(limits.IngressItems) > records.Caps.Ingress.Items || limits.IngressBytes > records.Caps.Ingress.Bytes {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	for _, cap := range limits.PerClass {
		if cap > limits.Active {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
	}
	var protected uint64
	for role := range 2 {
		for class, cap := range [3]uint64{streams.Business, streams.Internal, streams.Management} {
			if limits.Lifetime[role][class] > cap || limits.PerOpener[role][class] > limits.PerClass[class] || limits.Protected[role][class] > limits.PerOpener[role][class] {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
			protected += uint64(limits.Protected[role][class])
		}
	}
	if protected > uint64(limits.Active) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}

	maxInt := uint64(^uint(0) >> 1)
	slots := uint64(limits.Terminal) + uint64(limits.IngressItems)
	if slots > uint64(^uint32(0)) || slots > maxInt/2 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	index := uint64(1)
	for index < 2*slots {
		if index > maxInt/2 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		index *= 2
	}
	slotBytes, indexBytes := uint64(unsafe.Sizeof(openSlot{})), uint64(unsafe.Sizeof(int(0)))
	ingressItemBytes := slotBytes + 4*indexBytes
	if uint64(limits.IngressItems) > ^uint64(0)/ingressItemBytes {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	ingressOverhead := uint64(limits.IngressItems) * ingressItemBytes
	if limits.IngressBytes <= ingressOverhead {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	arena := (limits.IngressBytes - ingressOverhead) / 2
	kind, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	metadata, err := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if kind <= 0 || metadata < 0 || uint64(kind) > maxInt-256 || uint64(metadata) > maxInt-256-uint64(kind) || arena > maxInt || arena < uint64(kind)+uint64(metadata) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	encode := uint64(kind) + uint64(metadata) + 256
	decoder, err := protocolv4.RecordDecoderBackingBytes(int(encode), 64)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if streams.Client > ^uint64(0)-63 || streams.Server > ^uint64(0)-63 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}

	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(OpenAdmission{})), resourcev4.Items: 2 + 3*slots}
	if limits.PerClass[InternalStream] != 0 {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(Bootstrap{})) + uint64(unsafe.Sizeof(bootstrapWriter{})), resourcev4.Items: 2})
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	for _, allocation := range [][2]uint64{
		{slots, slotBytes}, {index, indexBytes}, {arena, 1}, {arena, uint64(unsafe.Sizeof(bool(false)))},
		{slots, uint64(unsafe.Sizeof(CarrierAssociation{}))}, {slots, uint64(unsafe.Sizeof((chan struct{})(nil)))},
		{(streams.Client + 63) / 64, 8}, {(streams.Server + 63) / 64, 8}, {encode, 1}, {decoder, 1},
	} {
		count, width := allocation[0], allocation[1]
		if count > maxInt/width {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: count * width})
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	return charge, nil
}

// NewReservedOpenAdmission consumes one complete reservation from the original
// Environment before allocating the OPEN graph. Engine-specific configuration
// failures release that claimed reservation; a successful owner retains it
// until Retire has joined its actual cleanup.
func NewReservedOpenAdmission(engine *cryptov4.Engine, direction protocolv4.Direction, limits OpenLimits, reservation, environment resourcev4.Reference) (*OpenAdmission, error) {
	charge, err := OpenAdmissionCharge(limits)
	if err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if err := engine.CheckEnvironment(reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	a, err := NewOpenAdmission(engine, direction, limits)
	if err != nil {
		owned.Release()
		return nil, err
	}
	a.reservation = owned
	return a, nil
}
