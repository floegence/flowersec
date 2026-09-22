package rpcv4

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// Completion owns the whole legal result before its request can enter the
// Stream. It has no back-reference to a Session; actual input completion moves
// it out of the network slot, independently of application observation.
type Completion struct {
	mu                                          sync.Mutex
	reservation                                 resourcev4.Reference
	payload                                     []byte
	header                                      protocolv4.ApplicationHeader
	limit                                       uint32
	next                                        uint32
	started, terminal, abandoned, taken, closed bool
	reason                                      string
	refusalCode                                 uint64
	done                                        chan struct{}
	query                                       ContractQueryCall
	queryReleased                               ContractQueryCall
	deadline                                    *timev4.Deadline
	failure                                     error
}

type CompletionProgress struct {
	Header              protocolv4.ApplicationHeader
	Complete, Abandoned bool
	Reason              string
	SDKErrorCode        uint64
	Error               error
}

func CompletionCharge(limit uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if limit > 1048576 || runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	n := uint64(unsafe.Sizeof(Completion{})) + uint64(unsafe.Sizeof(VerifiedInput{})) + uint64(unsafe.Sizeof(InputBorrow{})) + uint64(unsafe.Sizeof(ApplicationInput{})) + uint64(max(limit, 256))
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 3}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// fixedLimit is the trusted fixed-read response bound. Ordinary unary requests
// must instead use their exact original signed-contract per-call limit.
func (n *Network) NewCompletion(t Ticket, fixedLimit uint32, reservation resourcev4.Reference, runtimeBytes uint64) (*Completion, error) {
	return n.newCompletion(t, fixedLimit, reservation, runtimeBytes, nil)
}

// NewTimedCompletion fixes the original local receive deadline before BEGIN.
// It includes the trusted finite receive grace and never changes the wire
// business deadline. Complete input and expiration share the result gate.
func (n *Network) NewTimedCompletion(t Ticket, fixedLimit uint32, reservation resourcev4.Reference, runtimeBytes uint64, deadline *timev4.Deadline) (*Completion, error) {
	if deadline == nil {
		return nil, ErrConfiguration
	}
	if err := deadline.Check(); err != nil {
		return nil, err
	}
	return n.newCompletion(t, fixedLimit, reservation, runtimeBytes, deadline)
}

func (n *Network) newCompletion(t Ticket, fixedLimit uint32, reservation resourcev4.Reference, runtimeBytes uint64, deadline *timev4.Deadline) (*Completion, error) {
	return n.newOwnedCompletion(t, fixedLimit, reservation, reservation, runtimeBytes, deadline)
}

// NewOwnedTimedCompletion binds payload to the original separately charged
// local result owner. Its one root result position survives typed input
// delivery and network retirement until that local owner is actually released.
func (n *Network) NewOwnedTimedCompletion(t Ticket, fixedLimit uint32, reservation, resultOwner resourcev4.Reference, runtimeBytes uint64, deadline *timev4.Deadline) (*Completion, error) {
	if deadline == nil {
		return nil, ErrConfiguration
	}
	if err := deadline.Check(); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(resultOwner); err != nil {
		return nil, err
	}
	return n.newOwnedCompletion(t, fixedLimit, reservation, resultOwner, runtimeBytes, deadline)
}

func (n *Network) newOwnedCompletion(t Ticket, fixedLimit uint32, reservation, resultOwner resourcev4.Reference, runtimeBytes uint64, deadline *timev4.Deadline) (*Completion, error) {
	if n == nil {
		return nil, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return nil, err
	}
	if t.direction != outgoing || s.state != networkReserved || s.completion != nil || !s.header.OrdinaryRPC() {
		return nil, ErrOwner
	}
	if s.class == contractQuery && n.queryClient != nil {
		return nil, ErrOwner
	}
	limit := fixedLimit
	if s.header.HasResponseLimit() {
		limit = s.header.Fields().ResponseLimitBytes
		if fixedLimit != limit {
			return nil, ErrConfiguration
		}
	}
	charge, err := CompletionCharge(limit, runtimeBytes)
	if err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	if s.class != contractQuery {
		if err := resultOwner.CheckResultOwner(); err != nil {
			return nil, err
		}
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	c := &Completion{reservation: owned, payload: make([]byte, max(limit, 256)), limit: limit, done: make(chan struct{}), deadline: deadline}
	s.completion = c
	return c, nil
}
func (c *Completion) Done() <-chan struct{} { return c.done }
func (c *Completion) Progress() CompletionProgress {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CompletionProgress{Header: c.header, Complete: c.terminal, Abandoned: c.abandoned, Reason: c.reason, SDKErrorCode: c.refusalCode, Error: c.failure}
}

// Expire observes only an incomplete original result. Complete input disarms
// this deadline permanently; delayed decoding or observation is not a TTL.
// The caller sends the original cancellation marker outside this gate, while
// the Network retains its late-response position until actual wire cleanup.
func (c *Completion) Expire() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expireLocked()
}

func (c *Completion) expireLocked() error {
	if c.terminal {
		return nil
	}
	if c.abandoned {
		return c.failure
	}
	if c.deadline == nil {
		return nil
	}
	err := c.deadline.Check()
	if err == nil || errors.Is(err, timev4.ErrPending) || errors.Is(err, timev4.ErrUnavailable) {
		return nil
	}
	c.abandoned, c.failure = true, err
	if !c.header.IsSDKError() {
		clear(c.payload)
	}
	return err
}
func (c *Completion) begin(h protocolv4.ApplicationHeader) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started || c.terminal {
		return ErrAssociation
	}
	limit := c.limit
	if h.IsSDKError() {
		limit = 256
	}
	if h.Fields().PayloadBytes > limit {
		return protocolv4.CBORFailure("application_response_limit")
	}
	if err := c.reservation.Check(); err != nil {
		return err
	}
	c.header = h
	c.started = true
	return nil
}
func (c *Completion) write(offset uint32, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started || c.terminal || offset != c.next || len(payload) == 0 || uint64(len(payload)) > uint64(c.header.Fields().PayloadBytes-c.next) {
		return protocolv4.CBORFailure("application_payload_length")
	}
	// Late SDK errors still need bounded payload schema and marker validation.
	if !c.abandoned || c.header.IsSDKError() {
		copy(c.payload[c.next:], payload)
	}
	c.next += uint32(len(payload))
	return nil
}
func (c *Completion) abandon() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.abandoned = true
	if !c.header.IsSDKError() {
		clear(c.payload)
	}
}
func (c *Completion) finish(reason string) {
	c.mu.Lock()
	defer c.unlockQueryCompletion()
	if c.terminal {
		return
	}
	if reason == "" {
		_ = c.expireLocked()
	}
	c.terminal = true
	c.deadline = nil
	c.reason = reason
	if c.abandoned {
		c.reason = "result_abandoned"
	}
	if c.reason != "" && !c.header.IsSDKError() {
		clear(c.payload)
	}
	close(c.done)
	if c.closed {
		c.cleanupLocked()
	}
}
func (c *Completion) cleanupLocked() {
	clear(c.payload)
	c.payload = nil
	if c.query.client != nil {
		c.queryReleased, c.query = c.query, ContractQueryCall{}
	} else {
		c.reservation.Release()
	}
	c.reservation = resourcev4.Reference{}
}

// Query notifications run only after the completion gate is released. The
// original Network may still be held, preserving Network -> query-pool order.
func (c *Completion) unlockQueryCompletion() {
	released, query := c.queryReleased, c.query
	c.queryReleased = ContractQueryCall{}
	c.mu.Unlock()
	released.releaseResponse()
	query.notify()
}

// Take moves complete immutable bytes once. No application decoder runs on the
// reader. A pre-reserved executor completion job may borrow these bytes later.
func (c *Completion) Take() (*VerifiedInput, error) {
	if c == nil {
		return nil, ErrOwner
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.terminal || c.abandoned || c.taken || c.closed || c.reason != "" || c.query.client != nil {
		return nil, ErrOwner
	}
	if err := c.reservation.Check(); err != nil {
		return nil, err
	}
	v := &VerifiedInput{header: c.header, payload: c.payload[:c.next], reservation: c.reservation}
	c.payload = nil
	c.reservation = resourcev4.Reference{}
	c.taken = true
	return v, nil
}

// Close discards local result delivery. It does not free an outstanding network
// position or send a marker; the original publisher's cancellation gate owns
// that action. Until real input termination this backing remains charged.
func (c *Completion) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.unlockQueryCompletion()
	if c.taken {
		return
	}
	c.closed = true
	c.abandoned = true
	if !c.header.IsSDKError() {
		clear(c.payload)
	}
	if c.terminal {
		c.cleanupLocked()
	}
}
