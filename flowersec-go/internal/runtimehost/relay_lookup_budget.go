package runtimehost

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

const relayActivePairs = 1

// RelayAuthorityParallelLookups derives the table's prepaid lookup positions
// from the same two signed Grant limits used to admit the actual pair. Parent
// retention capacity is independent of simultaneous native forwarding work.
func RelayAuthorityParallelLookups(limits [2]protocolv4.RelayGrantLimits, activePairs uint32) (uint32, error) {
	if activePairs == 0 {
		return 0, resourcev4.ErrConfiguration
	}
	if limits[0].EnvelopeBytes != limits[1].EnvelopeBytes {
		return 0, resourcev4.ErrConfiguration
	}
	envelope := limits[0].EnvelopeBytes
	pending := min(limits[0].PendingMappings, limits[1].PendingMappings)
	resident := min(limits[0].ResidentMappings, limits[1].ResidentMappings)
	datagrams := min(limits[0].DatagramBytes, limits[1].DatagramBytes)
	for _, value := range []uint64{envelope, pending, resident, datagrams} {
		if value > uint64(^uint32(0)) {
			return 0, resourcev4.ErrConfiguration
		}
	}
	pair := sessionv4.RelayMessagePairConfig{MaxEnvelopeBytes: uint32(envelope), MaxPendingNativeMappings: uint32(pending), MaxResidentNativeMappings: uint32(resident), MaxTotalNativeMappings: min(limits[0].TotalMappings, limits[1].TotalMappings), MaxDatagramBytes: uint32(datagrams)}
	perPair, err := sessionv4.RelayMessagePairAuthorityLookups(pair)
	if err != nil {
		return 0, err
	}
	total := uint64(perPair) * uint64(activePairs)
	if total > 65536 {
		return 0, resourcev4.ErrConfiguration
	}
	return uint32(total), nil
}
