package interopharness

import "github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"

// The parity application uses the services profile's ten fixed channels and
// eight ordinary stream positions, matching the TypeScript peer's admission.
const nativeParityMaxStreams = 18

// nativeParityRelayLimits covers both mapping directions, both bounded
// provider input queues and the fixed forwarding tail across the native peers.
// It is signed by the original engineering issuer before any Grant is sent.
func nativeParityRelayLimits(carriers [2]string) protocolv4.RelayGrantLimits {
	limits := protocolv4.RelayGrantLimits{EnvelopeBytes: 65544, TotalBytes: 1 << 30, RateBytesPerSecond: 64 << 20, QueueBytes: 4 << 20, QueueItems: 256}
	if carriers[0] == "websocket" && carriers[1] == "websocket" {
		return limits
	}
	if carriers[0] != "websocket" && carriers[1] != "websocket" {
		limits.DatagramBytes = 1024
	}
	// Admit a full wave of pending streams while retaining both directions of
	// every active stream. Provider receive windows include these positions and
	// must also fit the native transport's fixed 16 MiB connection envelope.
	limits.PendingMappings = nativeParityMaxStreams
	limits.ResidentMappings = 2 * nativeParityMaxStreams
	limits.TotalMappings = 10000
	const providerQueueItems = 16
	limits.QueueItems = 2*(limits.PendingMappings+limits.ResidentMappings) + 2*providerQueueItems + 4
	limits.QueueBytes = limits.QueueItems*limits.EnvelopeBytes + 2*limits.DatagramBytes
	return limits
}
