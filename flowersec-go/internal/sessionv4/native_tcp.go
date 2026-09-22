package sessionv4

import (
	"errors"
	"math"
	"net"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrNativeTCPClosing = errors.New("sessionv4: native TCP endpoint closing")
var ErrNativeTCPClosed = errors.New("sessionv4: native TCP endpoint closed")
var ErrNativeTCPFailure = errors.New("sessionv4: native TCP operation failed")

// NativeTCPOptions admits native runtime/provider overhead separately from
// SDK metadata. ProviderBytes is a qualified deployment allowance, not a claim
// that Go Close proves all kernel queues or OS RSS have disappeared.
type NativeTCPOptions struct {
	RuntimeBytes, ProviderBytes uint64
}

func NativeTCPCharge(options NativeTCPOptions) (resourcev4.Vector, error) {
	fixed := uint64(unsafe.Sizeof(NativeTCP{})) + uint64(unsafe.Sizeof(nativeTCPCore{}))
	if options.RuntimeBytes == 0 || options.ProviderBytes == 0 || options.RuntimeBytes > math.MaxUint64-fixed {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: fixed + options.RuntimeBytes, resourcev4.ProviderBytes: options.ProviderBytes, resourcev4.Items: 1, resourcev4.Connections: 1, resourcev4.NativeHandles: 1}, nil
}

// NativeTCP is created only by the sealed SDK factory. There is no adoption of
// arbitrary sockets and no File, SyscallConn, NetConn or raw-pointer accessor.
// Thus copied opaque handles still identify exactly one endpoint owner.
type NativeTCP struct{ *nativeTCPCore }

// All value-copy aliases share this private canonical owner and native handle.
type nativeTCPCore struct {
	mu                   sync.Mutex
	owner                *nativeTCPOwnership
	conn                 *net.TCPConn
	clock                *timev4.Clock
	reservation          resourcev4.Reference
	closed               bool
	complete, doneClosed bool
	failure              error
	done                 chan struct{}
}

// Close owns a synchronous native close outside the SDK gate. Default linger
// preserves the platform's normal queued-send behavior. Only actual close
// return releases the native handle; this is not remote acknowledgement.
func (n *NativeTCP) Close() error { return n.closeOwned(nil) }

func (n *NativeTCP) closeOwned(owner *nativeTCPOwnership) error {
	if n == nil || n.nativeTCPCore == nil {
		return ErrNativeTCPClosed
	}
	n.mu.Lock()
	if n.owner != owner {
		n.mu.Unlock()
		return ErrStreamOwned
	}
	if n.closed {
		err := n.failure
		if !n.complete {
			err = ErrNativeTCPClosing
		}
		n.mu.Unlock()
		return err
	}
	n.closed = true
	if owner != nil {
		owner.revoke()
	}
	conn := n.conn
	n.mu.Unlock()
	err := conn.Close()
	n.mu.Lock()
	defer n.mu.Unlock()
	if err != nil {
		n.failure = ErrNativeTCPFailure
	}
	n.conn, n.clock = nil, nil
	n.reservation.Release()
	n.reservation = resourcev4.Reference{}
	n.complete = true
	n.closeDoneLocked()
	return n.failure
}

func (n *NativeTCP) CleanupStatus() protocolv4.V4CleanupStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if n.complete && (n.owner == nil || n.owner.users == 0) {
		c.Status, c.CoreCleanup = protocolv4.V4CleanupStateComplete, protocolv4.V4CoreCleanupComplete
	}
	return c
}

func (n *nativeTCPCore) closeDoneLocked() {
	if n.complete && (n.owner == nil || n.owner.users == 0) && !n.doneClosed {
		n.doneClosed = true
		close(n.done)
	}
}

func (n *NativeTCP) Done() <-chan struct{} { return n.done }
