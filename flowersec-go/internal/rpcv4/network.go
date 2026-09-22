// Package rpcv4 owns bounded application RPC resources. Authentication,
// service authorization and Stream publication remain with their original owners.
package rpcv4

import (
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var (
	ErrConfiguration = errors.New("rpcv4: configuration capacity")
	ErrCapacity      = errors.New("rpcv4: network positions exhausted")
	ErrOwner         = errors.New("rpcv4: original network owner unavailable")
	ErrClosed        = errors.New("rpcv4: network admission closed")
	ErrAssociation   = errors.New("rpcv4: conflicting request association")
	ErrMethod        = errors.New("rpcv4: request method unavailable")
)

// QueryBinding is trusted SDK registration, captured before Session admission.
// Only this exact canonical kind/type/contract tuple may use the Q2 reserve.
// It is never filled from an incoming header, namespace or refresh claim.
type QueryBinding struct {
	Type     uint32
	Contract [32]byte
}

type NetworkConfig struct {
	ProtectShortCall bool
	Session          protocolv4.SessionContract
	Query            QueryBinding
	// ResultRead is the trusted fixed result-read tuple. A zero tuple leaves
	// the route disabled; wire headers never install or replace this binding.
	ResultRead   QueryBinding
	RuntimeBytes uint64
}

// Association identifies the original local channel generation or exclusive
// typed Stream. It is supplied by trusted Stream assembly, never by wire input.
// Serial is zero only for a not-yet-published ordinary outgoing request or for
// a dedicated streaming request. A typed Stream may host only one request.
type Association struct {
	Channel [16]byte
	Serial  uint64
}

type networkClass uint8

const (
	generalUnary networkClass = iota
	generalStreaming
	contractQuery
)

type networkState uint8

const (
	networkFree networkState = iota
	networkReserved
	networkFull
	networkLate
	networkStreaming
	networkReply
)
const (
	outgoing       = 0
	incoming       = 1
	queryPositions = 2
)

type networkSlot struct {
	short          bool
	generation     uint64
	state          networkState
	class          networkClass
	header         protocolv4.ApplicationHeader
	path           Association
	inputState     InputState
	inputAttached  bool
	resultAdmitted bool
	message        sendMessage
	completion     *Completion
	received       receiveMessage
	observation    *outputInterestState
}

// Network reserves one Session's shared outgoing completions and incoming
// ReplySlots. All channels, dedicated typed Streams and old live generations
// share these same tables. It reserves compact associations, not request/result
// payloads, continuous reader/credit, dispatch or publication capacity.
//
// Methods are synchronous and invoke no provider, application callback or I/O.
// The caller performs the complete Start/input/publication gate around these
// local transitions. A Ticket is capacity responsibility, never proof that a
// request was authenticated, submitted, executed or completed.
type Network struct {
	serviceConsumer *ServiceConsumer
	mu              sync.Mutex
	config          NetworkConfig
	reservation     resourcev4.Reference
	slots           [2][]networkSlot
	count           [2][2]uint16
	shortOutgoing   uint16
	closed, retired bool
	publishers      [8]*Publisher
	receivers       [8]*Receiver
	inputs          *ServiceInputs
	queries         *ContractQueryService
	queryClient     *ContractQueryClient
}

type Ticket struct {
	network    *Network
	generation uint64
	index      uint16
	direction  uint8
}

func (Ticket) String() string                 { return "Flowersec.RPCNetworkTicket" }
func (Ticket) GoString() string               { return "Flowersec.RPCNetworkTicket" }
func (Ticket) MarshalJSON() ([]byte, error)   { return []byte("{}"), nil }
func (*Network) String() string               { return "Flowersec.RPCNetwork" }
func (*Network) GoString() string             { return "Flowersec.RPCNetwork" }
func (*Network) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func NetworkCharge(c NetworkConfig) (resourcev4.Vector, error) {
	limits := c.Session.Limits()
	if !c.Session.Valid() || (limits.ApplicationProfile != "services" && limits.ApplicationProfile != "execution") || limits.RPCMaxGeneralOutstanding == 0 || limits.RPCMaxGeneralOutstanding > 1024 || c.Query.Type == 0 || c.Query.Contract == ([32]byte{}) || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	if (c.ResultRead.Type == 0) != (c.ResultRead.Contract == ([32]byte{})) {
		return resourcev4.Vector{}, ErrConfiguration
	}
	if c.ResultRead.Type != 0 && limits.ApplicationProfile != "execution" {
		return resourcev4.Vector{}, ErrConfiguration
	}
	count := uint64(limits.RPCMaxGeneralOutstanding) + queryPositions
	metadata := uint64(unsafe.Sizeof(Network{})) + uint64(unsafe.Sizeof(ServiceConsumer{})) + 2*count*(uint64(unsafe.Sizeof(networkSlot{}))+uint64(unsafe.Sizeof(Ticket{})))
	return (resourcev4.Vector{resourcev4.SDKBytes: metadata, resourcev4.Items: 2*count + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// NewNetwork consumes the Session's one pre-reserved aggregate. It does not
// narrow the peer's signed K to a smaller local handler target. SessionPlan
// assembly must install this owner once and share it with every response path.
func NewNetwork(c NetworkConfig, reservation resourcev4.Reference) (*Network, error) {
	charge, err := NetworkCharge(c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	n := &Network{config: c, reservation: owned}
	size := int(c.Session.Limits().RPCMaxGeneralOutstanding) + queryPositions
	for i := range n.slots {
		n.slots[i] = make([]networkSlot, size)
	}
	return n, nil
}

func (n *Network) classify(h protocolv4.ApplicationHeader, dir int) (networkClass, error) {
	if h.IsResponse() || h.Kind() == "" {
		return 0, ErrMethod
	}
	if dir == outgoing && n.config.Session.Limits().ApplicationProfile != "execution" && (h.HasExecutionIdentity() || h.Kind() == "read_result_request") {
		return 0, ErrMethod
	}
	switch h.Kind() {
	case "query_contracts_request":
		f := h.Fields()
		if f.Type != n.config.Query.Type || f.ServiceContractDigest != n.config.Query.Contract {
			if dir == incoming {
				// A canonical but unknown fixed-method tuple still needs bounded
				// rejection/discard ownership. It cannot take protected Q space.
				return generalUnary, nil
			}
			return 0, ErrMethod
		}
		return contractQuery, nil
	case "read_result_request":
		if dir == outgoing && !n.resultReadMatches(h) {
			return 0, ErrMethod
		}
		return generalUnary, nil
	case "execution_unary_request", "transient_unary_request":
		return generalUnary, nil
	case "execution_stream_request", "transient_stream_request", "resume_request":
		return generalStreaming, nil
	default:
		return 0, ErrMethod
	}
}

func (n *Network) resultReadMatches(h protocolv4.ApplicationHeader) bool {
	return n != nil && n.config.ResultRead.Type != 0 && h.Kind() == "read_result_request" &&
		h.Fields().Type == n.config.ResultRead.Type && h.Fields().ServiceContractDigest == n.config.ResultRead.Contract
}
func (n *Network) liveLocked() error {
	if n.closed || n.retired {
		return ErrClosed
	}
	return n.reservation.Check()
}
func (n *Network) bounds(class networkClass) (int, int, int) {
	k := int(n.config.Session.Limits().RPCMaxGeneralOutstanding)
	if class == contractQuery {
		return k, k + queryPositions, 1
	}
	return 0, k, 0
}
func (n *Network) slotLocked(t Ticket) (*networkSlot, error) {
	if t.network != n || t.direction > 1 || int(t.index) >= len(n.slots[t.direction]) {
		return nil, ErrOwner
	}
	s := &n.slots[t.direction][t.index]
	if s.state == networkFree || s.generation != t.generation {
		return nil, ErrOwner
	}
	return s, nil
}
func (n *Network) conflictLocked(dir int, path Association, class networkClass, except int) bool {
	for direction := range n.slots {
		for i := range n.slots[direction] {
			s := &n.slots[direction][i]
			if direction == dir && i == except || s.state == networkFree || s.path.Channel != path.Channel {
				continue
			}
			// A dedicated typed Stream has only one initial request in either
			// direction. Ordinary channel serials are direction-local.
			if class == generalStreaming || s.class == generalStreaming {
				return true
			}
			if direction == dir && path.Serial != 0 && s.path.Serial == path.Serial {
				return true
			}
		}
	}
	return false
}
func (n *Network) acquire(dir int, h protocolv4.ApplicationHeader, path Association) (Ticket, error) {
	if n == nil {
		return Ticket{}, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if dir == outgoing && n.queryClient != nil && h.Kind() == "query_contracts_request" {
		return Ticket{}, ErrOwner
	}
	return n.acquireLocked(dir, h, path)
}

func (n *Network) acquireLocked(dir int, h protocolv4.ApplicationHeader, path Association) (Ticket, error) {
	return n.acquireClassLocked(dir, h, path, false)
}

func (n *Network) acquireClassLocked(dir int, h protocolv4.ApplicationHeader, path Association, short bool) (Ticket, error) {
	if err := n.liveLocked(); err != nil {
		return Ticket{}, err
	}
	class, err := n.classify(h, dir)
	if err != nil {
		return Ticket{}, err
	}
	if short && (dir != outgoing || class != generalUnary) {
		return Ticket{}, ErrMethod
	}
	if dir == outgoing && class != contractQuery && n.config.ProtectShortCall && !short && n.shortOutgoing == 0 && n.count[outgoing][0] >= n.config.Session.Limits().RPCMaxGeneralOutstanding-1 {
		return Ticket{}, ErrCapacity
	}
	if path.Channel == ([16]byte{}) || class == generalStreaming && path.Serial != 0 || dir == incoming && class != generalStreaming && path.Serial == 0 || dir == outgoing && path.Serial != 0 {
		return Ticket{}, ErrAssociation
	}
	if n.conflictLocked(dir, path, class, -1) {
		return Ticket{}, ErrAssociation
	}
	start, end, bucket := n.bounds(class)
	for i := start; i < end; i++ {
		s := &n.slots[dir][i]
		if s.state != networkFree || s.generation == math.MaxUint64 {
			continue
		}
		state := networkReserved
		if dir == incoming {
			state = networkReply
		}
		*s = networkSlot{generation: s.generation + 1, state: state, class: class, header: h, path: path, short: short}
		n.count[dir][bucket]++
		if short {
			n.shortOutgoing++
		}
		return Ticket{n, s.generation, uint16(i), uint8(dir)}, nil
	}
	return Ticket{}, ErrCapacity
}

// ReserveOutgoing precedes BEGIN first-byte acceptance (or the dedicated
// Stream's initial-header gate). Complete payload/result and executor promises
// must also exist before the caller publishes; this reserves only network state.
func (n *Network) ReserveOutgoing(h protocolv4.ApplicationHeader, path Association) (Ticket, error) {
	return n.acquire(outgoing, h, path)
}

// ReserveOutgoingShort is available only to trusted local method composition.
// The class is not a header field, peer priority, or authority to publish. It
// uses the same signed K table and requires the full original call vector.
func (n *Network) ReserveOutgoingShort(h protocolv4.ApplicationHeader, path Association) (Ticket, error) {
	if n == nil {
		return Ticket{}, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.acquireClassLocked(outgoing, h, path, true)
}

// AcceptIncoming follows canonical authenticated header validation and takes
// a real shared ReplySlot before attempting request payload allocation. The
// caller retains it during partial input, discard, ABORT and output cleanup.
// Inapplicable execution methods on services and unknown fixed-method tuples
// retain general rejection responsibility; a slot never permits dispatch.
func (n *Network) AcceptIncoming(h protocolv4.ApplicationHeader, path Association) (Ticket, error) {
	return n.acquire(incoming, h, path)
}

// BindOutgoing is called in the original publisher's first-byte acceptance
// gate. Serial allocation/continuity and irreversible Stream acceptance belong
// to that publisher. This method cannot allocate a serial or certify a write.
func (n *Network) BindOutgoing(t Ticket, serial uint64) error {
	if n == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return err
	}
	s, err := n.slotLocked(t)
	if err != nil {
		return err
	}
	if t.direction != outgoing || s.state != networkReserved {
		return ErrOwner
	}
	if (s.class == generalStreaming) != (serial == 0) {
		return ErrAssociation
	}
	path := s.path
	path.Serial = serial
	if n.conflictLocked(outgoing, path, s.class, int(t.index)) {
		return ErrAssociation
	}
	s.path = path
	s.state = networkFull
	if s.class == generalStreaming {
		s.state = networkStreaming
	}
	return nil
}

// Abandon retains the same header, path, class and network position. It cannot
// turn a submitted call back into a retryable reservation. Dedicated streaming
// retains its original streaming position through real termination.
func (n *Network) Abandon(t Ticket) error {
	if n == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return err
	}
	if t.direction != outgoing || s.state == networkReserved {
		return ErrOwner
	}
	if s.completion != nil {
		s.completion.abandon()
	}
	if s.state == networkFull {
		s.state = networkLate
	}
	return nil
}

// Original returns detached binding facts. It grants no payload access and is
// usable during cleanup even after new network admission closes.
func (n *Network) Original(t Ticket) (protocolv4.ApplicationHeader, Association, error) {
	if n == nil {
		return protocolv4.ApplicationHeader{}, Association{}, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return protocolv4.ApplicationHeader{}, Association{}, err
	}
	return s.header, s.path, nil
}

// Lookup finds only a live original association in the requested local role.
// The finite table is shared by all paths, including late-only completions.
// No per-serial history is created. The channel separately checks its BEGIN
// highwater, response/request kind, complete-input and STOP/ABORT eligibility.
func (n *Network) LookupOutgoing(path Association) (Ticket, error) {
	return n.lookup(outgoing, path)
}
func (n *Network) LookupIncoming(path Association) (Ticket, error) {
	return n.lookup(incoming, path)
}
func (n *Network) lookup(dir int, path Association) (Ticket, error) {
	if n == nil || path.Channel == ([16]byte{}) {
		return Ticket{}, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := range n.slots[dir] {
		s := &n.slots[dir][i]
		if s.state != networkFree && s.state != networkReserved && s.path == path {
			return Ticket{n, s.generation, uint16(i), uint8(dir)}, nil
		}
	}
	return Ticket{}, ErrOwner
}

// MatchResponse checks the exact original request before another component can
// use its result reserve. Fixed-read payload limits, response serial/offset,
// SDK error code and complete message boundaries remain the channel's gates.
func (n *Network) MatchResponse(t Ticket, h protocolv4.ApplicationHeader, path Association) error {
	if n == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return err
	}
	if t.direction != outgoing || s.state == networkReserved || s.path != path {
		return ErrAssociation
	}
	return s.header.MatchResponse(h)
}

// Release relinquishes only this local capacity ticket. Before submission the
// original Start may unwind it; afterward only the original authenticated
// terminal-input or irrevocable terminal-output/channel-cleanup gate may do so.
// It does not return a submission, execution or remote-completion result. Old
// aliases cannot release a reused slot or change the new request's metadata.
func (n *Network) Release(t Ticket) error {
	if n == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return err
	}
	n.releaseLocked(t, s)
	return nil
}

func (n *Network) releaseLocked(t Ticket, s *networkSlot) {
	if t.direction == incoming {
		n.queries.cancelOutputLocked(t)
	}
	s.observation.lose("owner_unavailable", true)
	s.message.requestCleanup.requestEnded()
	if s.completion != nil {
		s.completion.finish("owner_unavailable")
	}
	if s.received.input != nil {
		s.received.input.Close()
	}
	if s.message.publisher != nil {
		s.message.publisher.unlinkLocked(t)
		s.message.publication.update(false, false, false, true, "owner_unavailable")
		s.message.releaseSource()
	}
	_, _, bucket := n.bounds(s.class)
	n.count[t.direction][bucket]--
	if s.short {
		n.shortOutgoing--
	}
	generation := s.generation
	*s = networkSlot{generation: generation}
	n.cleanupLocked()
}
func (n *Network) Close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	if n.inputs != nil {
		n.inputs.Close()
	}
	if n.queries != nil {
		n.queries.Close()
	}
	if n.queryClient != nil {
		n.queryClient.closeInputs()
	}
	n.cleanupLocked()
}
func (n *Network) cleanupLocked() {
	if n.retired || !n.closed || n.count != ([2][2]uint16{}) {
		return
	}
	for _, p := range n.publishers {
		if p != nil {
			return
		}
	}
	for _, r := range n.receivers {
		if r != nil {
			return
		}
	}
	clear(n.slots[0])
	clear(n.slots[1])
	n.slots = [2][]networkSlot{}
	n.config = NetworkConfig{}
	n.inputs = nil
	n.queries = nil
	n.queryClient = nil
	n.reservation.Release()
	n.reservation = resourcev4.Reference{}
	n.retired = true
}

type NetworkSnapshot struct {
	OutgoingFull, OutgoingLate, OutgoingStreaming, OutgoingReserved, IncomingReplies uint16
	OutgoingGeneral, OutgoingQueries, IncomingGeneral, IncomingQueries               uint16
	Closed, CleanupComplete                                                          bool
}

func (n *Network) Snapshot() NetworkSnapshot {
	if n == nil {
		return NetworkSnapshot{Closed: true, CleanupComplete: true}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	v := NetworkSnapshot{OutgoingGeneral: n.count[0][0], OutgoingQueries: n.count[0][1], IncomingGeneral: n.count[1][0], IncomingQueries: n.count[1][1], Closed: n.closed, CleanupComplete: n.retired}
	for _, s := range n.slots[outgoing] {
		switch s.state {
		case networkReserved:
			v.OutgoingReserved++
		case networkFull:
			v.OutgoingFull++
		case networkLate:
			v.OutgoingLate++
		case networkStreaming:
			v.OutgoingStreaming++
		}
	}
	v.IncomingReplies = n.count[1][0] + n.count[1][1]
	return v
}
