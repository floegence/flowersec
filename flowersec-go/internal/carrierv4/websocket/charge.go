// Package websocket owns a bounded, message-oriented Gorilla WebSocket
// carrier. It adds no Flowersec credentials to the HTTP upgrade.
package websocket

import (
	"bufio"
	"math"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/gorilla/websocket"
)

const (
	SubprotocolDirect = "flowersec.direct.v4"
	SubprotocolTunnel = "flowersec.tunnel.v4"
	SubprotocolLocal  = "flowersec.local.v4"
)

// Options declares the entrance message capacity, not an authenticated frame
// limit. SessionMessageInput and InitialExchange apply their own smaller phase
// limits. Fixed provider I/O buffers can read ahead; there is no separately
// allocated complete-message buffer or asynchronous message queue.
//
// RuntimeBytes covers channels, allocator overhead and the sole cancellation
// worker. ProviderRuntimeBytes and ProviderTasks admit the qualified Go/Gorilla
// socket and TLS runtime overhead in addition to the fixed buffers below.
// Resolving/selecting the required numeric endpoint belongs to its original
// external prepare owner and is never an implicit task of these factories.
// Two native handles cover the synchronous FileConn duplication during numeric
// connect handoff; they represent one physical connection, never two attempts.
// HTTP server request/TLS buffers already created by the host, kernel buffers,
// caller policy callbacks and caller-owned message slices remain external.
type Options struct {
	MaxMessageBytes, ReadBufferBytes, WriteBufferBytes uint32
	HandshakeBytes, MaxControlsPerSecond               uint32
	HandshakeTimeout, MessageTimeout                   time.Duration
	RuntimeBytes, ProviderRuntimeBytes                 uint64
	ProviderTasks                                      uint32
}

// Charge is required in full before either factory allocates provider state
// or attempts a connection. HTTP header parsing has a separate wire-byte cap;
// its strings, map entries and temporary copies are conservatively charged at
// 64 bytes per admitted wire byte. Runtime qualification must cover the
// explicitly supplied remaining provider allowance; this is not a process
// memory or TLS/pin/exporter certification.
func Charge(o Options) (resourcev4.Vector, error) {
	if o.MaxMessageBytes < protocolv4.EnvelopePrefixSize || o.MaxMessageBytes > protocolv4.MaxPayloadLength+protocolv4.EnvelopePrefixSize ||
		o.ReadBufferBytes < 125 || o.ReadBufferBytes > 65536 || o.WriteBufferBytes < 125 || o.WriteBufferBytes > 65536 ||
		o.HandshakeBytes < 1024 || o.HandshakeBytes > 65536 || o.MaxControlsPerSecond == 0 || o.MaxControlsPerSecond > 1024 ||
		o.HandshakeTimeout <= 0 || o.MessageTimeout <= 0 || o.RuntimeBytes == 0 || o.ProviderRuntimeBytes == 0 || o.ProviderTasks == 0 || o.ProviderTasks > 32 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	sdk := uint64(unsafe.Sizeof(Messages{})) + uint64(unsafe.Sizeof(owner{})) + uint64(unsafe.Sizeof(ownedConn{})) + uint64(unsafe.Sizeof(handshakeConn{})) + uint64(unsafe.Sizeof(upgradeWriter{})) + uint64(unsafe.Sizeof(callContext{}))
	provider := uint64(unsafe.Sizeof(websocket.Conn{})) + uint64(unsafe.Sizeof(bufio.Reader{})) + uint64(o.ReadBufferBytes) + uint64(o.WriteBufferBytes) + 14 + 64*uint64(o.HandshakeBytes)
	if o.RuntimeBytes > math.MaxUint64-sdk || o.ProviderRuntimeBytes > math.MaxUint64-provider {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: sdk + o.RuntimeBytes, resourcev4.ProviderBytes: provider + o.ProviderRuntimeBytes,
		resourcev4.Items: 1, resourcev4.WorkSlots: 3, resourcev4.Tasks: 1 + uint64(o.ProviderTasks), resourcev4.Timers: 3,
		resourcev4.Connections: 1, resourcev4.NativeHandles: 2, resourcev4.TLSHandshakes: 1}, nil
}
