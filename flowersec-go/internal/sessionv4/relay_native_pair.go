package sessionv4

import (
	"context"
	"hash/maphash"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// The table and its two direction buffers per position are allocated before
// HOP_AUTH. Pending native handles, creation tasks and cleanup tails occupy
// these same positions. Used scopes and ended direction bits survive retirement.
// No slot is an endpoint OPEN acceptance or an authenticated record result.
type relayNativePair struct {
	mu                sync.Mutex
	pair              *RelayMessagePair
	slots             []relayNativeSlot
	queued            [2][]relayQueuedFrame
	used              []uint64
	retired           []uint8
	seed              maphash.Seed
	total, generation uint64
	pending, resident uint32
	hops              [2]*RelayHop
	connections       [2]native.Connection
	write             [2]sync.Mutex
	datagrams         [2][]byte
	ctx               context.Context
	cancel            context.CancelFunc
	workers           sync.WaitGroup
	errors            chan error
	wake              chan struct{}
	closed            bool
}

type relayNativeSlot struct {
	generation, scope                       uint64
	openEpoch                               uint32
	opener                                  int
	active, pending, live, closing, counted bool
	streams                                 [2]native.DirectionalStream
	protections                             [2]native.StreamProtection
	buffers                                 [2][]byte
	frames                                  [2]chan int
	queueHead, queueTail                    [2]int
	stop                                    [2]chan struct{}
	stopped                                 [2]bool
	done                                    chan int
}

func relayNativeCharge(c RelayMessagePairConfig) (resourcev4.Vector, error) {
	if c.MaxPendingNativeMappings == 0 && c.MaxResidentNativeMappings == 0 && c.MaxTotalNativeMappings == 0 && c.MaxDatagramBytes == 0 {
		return resourcev4.Vector{}, nil
	}
	if c.MaxPendingNativeMappings == 0 || c.MaxPendingNativeMappings > 128 || c.MaxResidentNativeMappings == 0 || c.MaxResidentNativeMappings > 2048 || c.MaxTotalNativeMappings < uint64(c.MaxResidentNativeMappings) || c.MaxTotalNativeMappings > 1<<20 || c.MaxDatagramBytes > 1200 || c.MaxDatagramBytes != 0 && c.MaxDatagramBytes < 44 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	count := uint64(c.MaxPendingNativeMappings) + uint64(c.MaxResidentNativeMappings)
	table := relayScopeTableSize(c.MaxTotalNativeMappings)
	return resourcev4.Vector{
		resourcev4.SDKBytes: uint64(unsafe.Sizeof(relayNativePair{})) + count*(uint64(unsafe.Sizeof(relayNativeSlot{}))+2*uint64(unsafe.Sizeof(relayQueuedFrame{}))+2*uint64(c.MaxEnvelopeBytes)+2048) + table*9 + 2*uint64(c.MaxDatagramBytes) + 2048,
		resourcev4.Items:    count*3 + 3, resourcev4.WorkSlots: count*3 + 6, resourcev4.Tasks: count*3 + 6,
	}, nil
}

func relayScopeTableSize(maximum uint64) uint64 {
	n := uint64(1)
	for n < 2*maximum {
		n <<= 1
	}
	return n
}

func newRelayNativePair(p *RelayMessagePair) *relayNativePair {
	c := p.c
	if c.MaxPendingNativeMappings == 0 {
		return nil
	}
	n := &relayNativePair{pair: p, seed: maphash.MakeSeed(), slots: make([]relayNativeSlot, c.MaxPendingNativeMappings+c.MaxResidentNativeMappings), used: make([]uint64, relayScopeTableSize(c.MaxTotalNativeMappings)), retired: make([]uint8, relayScopeTableSize(c.MaxTotalNativeMappings)), errors: make(chan error, 1), wake: make(chan struct{}, 2)}
	for d := 0; d < 2; d++ {
		n.queued[d] = make([]relayQueuedFrame, len(n.slots))
	}
	for i := range n.slots {
		s := &n.slots[i]
		for d := 0; d < 2; d++ {
			s.buffers[d] = make([]byte, c.MaxEnvelopeBytes)
			s.frames[d] = make(chan int, 1)
			n.queued[d][i] = relayQueuedFrame{buffer: s.buffers[d], next: -1}
		}
	}
	if c.MaxDatagramBytes != 0 {
		for d := 0; d < 2; d++ {
			n.datagrams[d] = make([]byte, c.MaxDatagramBytes)
		}
	}
	return n
}

func (p *RelayMessagePair) meterSlots() uint32 {
	if p == nil || p.native == nil {
		return 2
	}
	return 4 + 2*(p.c.MaxPendingNativeMappings+p.c.MaxResidentNativeMappings)
}

func (p *RelayMessagePair) validateCarriers(r *RelayHop) error {
	route := r.maps[0].Field("route_descriptor")
	ws, _ := protocolv4.EnumValue("Leg", "carrier", "websocket")
	raw, _ := protocolv4.EnumValue("Leg", "carrier", "raw_quic")
	wt, _ := protocolv4.EnumValue("Leg", "carrier", "webtransport")
	var types [2]uint64
	for side, name := range []string{"client_leg", "server_leg"} {
		types[side], _ = route.Named("Route", name).Named("Leg", "carrier").Uint()
	}
	nativeRoute := types[0] != ws || types[1] != ws
	if nativeRoute != (p.native != nil) {
		return protocolv4.ErrRequiredGuaranteeUnavailable
	}
	side := int(r.prepared.binding.Role)
	connection := r.prepared.native
	if types[side] == ws {
		if !r.prepared.binding.MessageCarrier || connection != nil {
			return protocolv4.ErrHopAuthContext
		}
	} else {
		if connection == nil || r.prepared.binding.MessageCarrier {
			return protocolv4.ErrHopAuthContext
		}
		switch connection.(type) {
		case *rawquic.OwnedConnection:
			if types[side] != raw {
				return protocolv4.ErrHopAuthContext
			}
		case *webtransport.OwnedConnection:
			if types[side] != wt {
				return protocolv4.ErrHopAuthContext
			}
		default:
			return protocolv4.ErrRequiredGuaranteeUnavailable
		}
	}
	if p.native == nil {
		maximum, _ := r.maps[0].Field("limits").Named("GrantLimits", "max_datagram_bytes").Uint()
		if maximum != 0 {
			return protocolv4.ErrRequiredGuaranteeUnavailable
		}
		return nil
	}
	limits := r.maps[0].Field("limits")
	get := func(name string) uint64 { v, _ := limits.Named("GrantLimits", name).Uint(); return v }
	c := p.c
	count := uint64(c.MaxPendingNativeMappings) + uint64(c.MaxResidentNativeMappings)
	queueItems := 2 + 2*count
	queueBytes := queueItems * uint64(c.MaxEnvelopeBytes)
	if c.MaxDatagramBytes != 0 {
		queueItems += 2
		queueBytes += 2 * uint64(c.MaxDatagramBytes)
	}
	if get("max_pending_native_mappings") < uint64(c.MaxPendingNativeMappings) || get("max_resident_native_mappings") < uint64(c.MaxResidentNativeMappings) || get("max_total_native_mappings") < c.MaxTotalNativeMappings || get("max_queue_items") < queueItems || get("max_queue_bytes") < queueBytes || get("max_datagram_bytes") != uint64(c.MaxDatagramBytes) {
		return cryptov4.ErrCapacity
	}
	// Datagram delivery requires native support on the complete route. It does
	// not become a reliable WebSocket message when one leg lacks datagrams.
	nativeLegs := uint32(0)
	for _, t := range types {
		if t != ws {
			nativeLegs++
		}
	}
	if c.MaxPendingNativeMappings < nativeLegs+1 {
		return cryptov4.ErrCapacity
	}
	if c.MaxDatagramBytes != 0 && (types[0] == ws || types[1] == ws) {
		return protocolv4.ErrRequiredGuaranteeUnavailable
	}
	if connection != nil {
		if err := connection.CheckStreamCapacity(uint32(count) + 3); err != nil {
			return err
		}
		if c.MaxDatagramBytes != 0 && connection.MaxDatagramBytes() < int(c.MaxDatagramBytes) {
			return cryptov4.ErrCapacity
		}
	}
	return nil
}

func (n *relayNativePair) bind(r *RelayHop) error {
	connection := r.prepared.native
	if connection == nil {
		return nil
	}
	if err := connection.ClaimSession(n.pair.reservation); err != nil {
		return err
	}
	n.connections[int(r.prepared.binding.Role)] = connection
	return nil
}

// The scope hash table never deletes entries. Its maximum load is one half;
// no peer input grows it, and no tombstone can authorize a new native handle.
func (n *relayNativePair) usedIndex(scope uint64) (int, bool) {
	mask := uint64(len(n.used) - 1)
	index := maphash.Comparable(n.seed, scope) & mask
	for scanned := 0; scanned < len(n.used); scanned++ {
		value := n.used[index]
		if value == 0 || value == scope {
			return int(index), value == scope
		}
		index = (index + 1) & mask
	}
	return -1, true
}

func (n *relayNativePair) claimLocked(opener int) (*relayNativeSlot, error) {
	if n.closed {
		return nil, cryptov4.ErrClosed
	}
	if n.pending >= n.pair.c.MaxPendingNativeMappings || n.generation == ^uint64(0) {
		return nil, cryptov4.ErrCapacity
	}
	for i := range n.slots {
		s := &n.slots[i]
		if s.active {
			continue
		}
		n.generation++
		s.generation, s.opener, s.active, s.pending = n.generation, opener, true, true
		s.done = make(chan int, 2)
		for d := 0; d < 2; d++ {
			s.stop[d] = make(chan struct{})
			s.queueHead[d], s.queueTail[d] = -1, -1
		}
		n.pending++
		return s, nil
	}
	return nil, cryptov4.ErrCapacity
}

func (n *relayNativePair) bindScopeLocked(s *relayNativeSlot, h protocolv4.RecordHeader, direction int) error {
	if n.closed || !s.active || !s.pending || s.scope != 0 || direction != s.opener {
		return resourcev4.ErrOwner
	}
	index, used := n.usedIndex(h.Scope)
	if used || index < 0 {
		return ErrOpenAssociation
	}
	if !s.counted || n.resident >= n.pair.c.MaxResidentNativeMappings {
		return cryptov4.ErrCapacity
	}
	// Peer scope parity and authenticated epoch/sequence checks remain endpoint
	// duties. This opaque binding records only the first visible OPEN identity.
	n.used[index] = h.Scope
	n.retired[index] = 0
	n.resident++
	s.scope, s.openEpoch, s.live = h.Scope, h.Epoch, true
	return nil
}

func (n *relayNativePair) fail(err error) {
	if err == nil {
		err = cryptov4.ErrClosed
	}
	select {
	case n.errors <- err:
	default:
	}
}

func (n *relayNativePair) launch(work func()) {
	n.workers.Add(1)
	go func() {
		returned := false
		defer func() {
			if recover() != nil || !returned {
				n.fail(ErrEnvironmentTaskExit)
			}
			n.workers.Done()
		}()
		work()
		returned = true
	}()
}

func (n *relayNativePair) run(ctx context.Context, hops [2]*RelayHop) error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return cryptov4.ErrClosed
	}
	n.ctx, n.cancel = context.WithCancel(ctx)
	n.hops = hops
	n.mu.Unlock()
	defer func() { n.pair.Close(); n.workers.Wait() }()
	for side := 0; side < 2; side++ {
		side := side
		n.launch(func() { n.readLane(side) })
		if n.connections[side] != nil {
			n.launch(func() { n.accept(side) })
			if len(n.datagrams[side]) != 0 {
				n.launch(func() { n.forwardDatagrams(side) })
			}
		}
	}
	var err error
	select {
	case err = <-n.errors:
	case <-ctx.Done():
		err = ctx.Err()
	}
	return err
}

func (n *relayNativePair) close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return
	}
	n.closed = true
	if n.cancel != nil {
		n.cancel()
	}
	for i := range n.slots {
		s := &n.slots[i]
		if !s.active {
			continue
		}
		for d := 0; d < 2; d++ {
			if !s.stopped[d] {
				s.stopped[d] = true
				n.discardQueueLocked(s, d)
				close(s.stop[d])
			}
		}
	}
}

func (n *relayNativePair) destroy() {
	if n == nil {
		return
	}
	for i := range n.slots {
		for _, b := range n.slots[i].buffers {
			clear(b)
		}
	}
	for _, b := range n.datagrams {
		clear(b)
	}
	clear(n.used)
	clear(n.retired)
	n.retired = nil
	n.slots, n.used, n.hops, n.connections = nil, nil, [2]*RelayHop{}, [2]native.Connection{}
	n.datagrams = [2][]byte{}
	n.queued = [2][]relayQueuedFrame{}
}
