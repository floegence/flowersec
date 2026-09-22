package rpcv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type NotifyReceiverConfig struct {
	Root                                              *resourcev4.Root
	Owner                                             resourcev4.OwnerKey
	Accounts                                          []resourcev4.Account
	Clock                                             *timev4.Clock
	Pending, MaxCaptureBytes                          uint32
	RuntimeBytes, InputRuntimeBytes, HashRuntimeBytes uint64
}

// NotifyReceiveStatus is finite local evidence only. No outcome produces a
// response, remote acknowledgment, execution result or retry permission.
type NotifyReceiveStatus struct {
	Complete, Rejected uint64
	LastRejection      string
}

// NotifyReceiver consumes authenticated, ordered bytes from one admitted
// NOTIFY Stream. It has no Network/ReplySlot/Completion dependency. Refused
// messages are discarded up to their exact boundary in the same reader.
type NotifyReceiver struct {
	mu           sync.Mutex
	parser       *protocolv4.NotifyParser
	routes       *ContractRoutes
	root         *resourcev4.Root
	owner        resourcev4.OwnerKey
	accounts     [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount int
	config       InputConfig
	maxCapture   uint32
	runtimeBytes uint64
	reservation  resourcev4.Reference
	queue        []*NotifyMessage
	head, count  int
	serial       uint64
	current      *NotifyMessage
	collector    *RequestInput
	status       NotifyReceiveStatus
	failure      error
	closed       bool
}

// NotifyMessage is one complete physical message, not a business event ID.
// Independent identical messages have independent fanout guards. Its original
// route, input and deadline stay live until the finite SDK fanout returns.
type NotifyMessage struct {
	busy        bool
	mu          sync.Mutex
	input       *VerifiedInput
	route       ContractRoute
	reservation resourcev4.Reference
	fanout      bool
	closed      bool
}

func NotifyReceiverCharge(c NotifyReceiverConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || c.Pending == 0 || c.Pending > 128 || c.MaxCaptureBytes > 1048576 || c.RuntimeBytes == 0 || c.InputRuntimeBytes == 0 || c.HashRuntimeBytes == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge {
		return resourcev4.Vector{}, ErrConfiguration
	}
	n, err := protocolv4.NotifyParserBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	n += uint64(unsafe.Sizeof(NotifyReceiver{})) + uint64(c.Pending)*uint64(unsafe.Sizeof((*NotifyMessage)(nil)))
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewNotifyReceiver(routes *ContractRoutes, c NotifyReceiverConfig, reservation resourcev4.Reference) (*NotifyReceiver, error) {
	charge, err := NotifyReceiverCharge(c)
	if err != nil || routes == nil {
		return nil, ErrConfiguration
	}
	if err := reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	routes.mu.Lock()
	defer routes.mu.Unlock()
	if routes.closed || routes.clock != c.Clock || routes.captures == math.MaxUint32 {
		return nil, ErrOwner
	}
	if err := reservation.CheckSameEnvironment(routes.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	parser, err := protocolv4.NewNotifyParser()
	if err != nil {
		owned.Release()
		return nil, err
	}
	r := &NotifyReceiver{parser: parser, routes: routes, root: c.Root, owner: c.Owner, reservation: owned,
		maxCapture: c.MaxCaptureBytes, runtimeBytes: c.RuntimeBytes, accountCount: len(c.Accounts), queue: make([]*NotifyMessage, c.Pending),
		config: InputConfig{Clock: c.Clock, Capture: true, RuntimeBytes: c.InputRuntimeBytes, HashRuntimeBytes: c.HashRuntimeBytes}}
	copy(r.accounts[:], c.Accounts)
	routes.captures++
	return r, nil
}

func notifyMessageCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NotifyMessage{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func (r *NotifyReceiver) openLocked(h protocolv4.ApplicationHeader) (err error) {
	if r.count == len(r.queue) || h.Fields().PayloadBytes > r.maxCapture || r.serial == math.MaxUint64 {
		return ErrCapacity
	}
	var requests [3]resourcev4.Request
	var refs [3]resourcev4.Reference
	requests[0].Charge, err = ContractRouteCharge(r.runtimeBytes)
	if err != nil {
		return err
	}
	requests[1].Charge, err = RequestInputCharge(h, r.config)
	if err != nil {
		return err
	}
	requests[2].Charge, err = notifyMessageCharge(r.runtimeBytes)
	if err != nil {
		return err
	}
	r.serial++
	var identity [73]byte
	copy(identity[:32], "flowersec.notify.input")
	copy(identity[32:48], r.owner.Instance[:])
	copy(identity[48:64], r.owner.Backing[:])
	binary.BigEndian.PutUint64(identity[64:72], r.serial)
	for i := range requests {
		identity[72] = byte(i)
		digest := sha256.Sum256(identity[:])
		requests[i].Owner = r.owner
		copy(requests[i].Owner.Instance[:], digest[:16])
		copy(requests[i].Owner.Backing[:], digest[16:])
		requests[i].Accounts = r.accounts[:r.accountCount]
	}
	if err = r.root.ReserveBatch(requests[:], refs[:]); err != nil {
		return err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	route, err := r.routes.Capture(h.Fields().ServiceContractDigest, refs[0], r.runtimeBytes)
	if err != nil {
		return err
	}
	input, err := route.NewNotifyInput(h, r.config, refs[1])
	if err != nil {
		route.Release()
		return err
	}
	owned, err := refs[2].Take(requests[2].Charge)
	if err != nil {
		input.Close()
		route.Release()
		return err
	}
	r.current, r.collector = &NotifyMessage{route: route, reservation: owned}, input
	return nil
}

func (r *NotifyReceiver) rejectLocked(err error) {
	if r.status.Rejected < math.MaxUint64 {
		r.status.Rejected++
	}
	r.status.LastRejection = "service_contract_mismatch"
	switch {
	case errors.Is(err, resourcev4.ErrCapacity), errors.Is(err, ErrCapacity):
		r.status.LastRejection = "resource_exhausted"
	case errors.Is(err, timev4.ErrExpired):
		r.status.LastRejection = "deadline_exceeded"
	case errors.Is(err, ErrClosed), errors.Is(err, ErrMethod):
		r.status.LastRejection = "method_unavailable"
	}
}

func (r *NotifyReceiver) failLocked(err error) error {
	r.failure = err
	if r.collector != nil {
		r.collector.Close()
		r.collector = nil
	}
	if r.current != nil {
		r.current.Close()
		r.current = nil
	}
	return err
}

// Feed makes bounded progress without waiting for an application callback.
// Input bytes are not retained, even when the notification is discarded.
func (r *NotifyReceiver) Feed(data []byte) error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.failure != nil {
		return r.failure
	}
	if err := r.reservation.Check(); err != nil {
		return r.failLocked(err)
	}
	for len(data) != 0 {
		n, part, err := r.parser.Next(data)
		if err != nil {
			return r.failLocked(err)
		}
		if n == 0 {
			return r.failLocked(ErrOwner)
		}
		data = data[n:]
		if part.Header.Kind() == "" {
			continue
		}
		if part.First {
			if err := r.openLocked(part.Header); err != nil {
				r.rejectLocked(err)
			}
		}
		if r.collector != nil && len(part.Payload) != 0 {
			if err := r.collector.WriteAt(part.Offset, part.Payload); err != nil {
				return r.failLocked(err)
			}
		}
		if part.Last {
			if r.status.Complete < math.MaxUint64 {
				r.status.Complete++
			}
			if r.collector == nil {
				continue
			}
			if err := r.collector.Finish(); err != nil {
				return r.failLocked(err)
			}
			input, err := r.collector.Take()
			if err != nil {
				return r.failLocked(err)
			}
			r.collector.Close()
			r.collector = nil
			r.current.input = input
			r.queue[(r.head+r.count)%len(r.queue)] = r.current
			r.current = nil
			r.count++
		}
	}
	return nil
}

func (r *NotifyReceiver) Take() (*NotifyMessage, error) {
	if r == nil {
		return nil, ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
	}
	if r.failure != nil {
		return nil, r.failure
	}
	if r.count == 0 {
		return nil, ErrCapacity
	}
	m := r.queue[r.head]
	r.queue[r.head] = nil
	r.head = (r.head + 1) % len(r.queue)
	r.count--
	return m, nil
}

// OriginalMethod projects the complete input's immutable route before the
// Session enters its authorization gate. FanoutObservation rechecks that same
// route under authorization, preserving authority-before-registry lock order.
func (m *NotifyMessage) OriginalMethod() (uint32, protocolv4.ServiceContractPolicy, error) {
	if m == nil {
		return 0, protocolv4.ServiceContractPolicy{}, ErrOwner
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.input == nil {
		return 0, protocolv4.ServiceContractPolicy{}, ErrClosed
	}
	return m.input.OriginalMethod()
}

// AdmitExecution consumes this physical message through its original history
// authority. Only a new operation reserves an executor position; a duplicate
// has no dispatch/fanout right. The finite reserve callback runs under current
// authorization and history admission and must not start application code.
// No response join, result backing or completion slot is acquired for NOTIFY.
func (m *NotifyMessage) AdmitExecution(ctx context.Context, history *VolatileExecutions, caller ExecutionPrincipal, access ExecutionAccess, reserve func(resourcev4.Reference, resourcev4.Reference, *timev4.Deadline) error) (ExecutionObservation, *ExecutionWork, error) {
	if m == nil || history == nil || reserve == nil {
		return ExecutionObservation{}, nil, ErrConfiguration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.fanout || m.input == nil || m.route.capture == nil {
		return ExecutionObservation{}, nil, ErrOwner
	}
	_, policy, err := m.input.OriginalMethod()
	if err != nil {
		return ExecutionObservation{}, nil, err
	}
	if policy.Shape != 2 || policy.Semantics != 1 {
		return ExecutionObservation{}, nil, ErrMethod
	}
	capture := m.route.capture
	capture.mu.Lock()
	routes := capture.registry
	capture.mu.Unlock()
	m.fanout = true
	observation, work, err := history.admit(ctx, routes, m.input, caller, access, func(task, backing resourcev4.Reference) error {
		return reserve(task, backing, m.input.deadline)
	}, nil, nil)
	if work != nil {
		// The original work owns this exact input until its real task exits.
		// Closing the physical message must not close it before task entry.
		m.input = nil
	}
	return observation, work, err
}

// FanoutObservation consumes the complete message's guard once under its
// original registered route. The trusted SDK action must only admit/copy into
// bounded subscriber queues, never run application code or retain this slice.
// Current Session/target authority is an additional gate inside that action.
func (m *NotifyMessage) FanoutObservation(action func(uint32, protocolv4.ServiceContractPolicy, *timev4.Deadline, []byte) error) error {
	if m == nil || action == nil {
		return ErrOwner
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.fanout || m.input == nil {
		return ErrOwner
	}
	method, policy, err := m.input.OriginalMethod()
	if err != nil {
		return err
	}
	if policy.Shape != 2 || policy.Semantics != 0 {
		return ErrMethod
	}
	borrow, err := m.input.Borrow()
	if err != nil {
		return err
	}
	defer borrow.Release()
	bytes, header, err := borrow.Bytes()
	if err != nil {
		return err
	}
	if header.Kind() != "observation_notify" {
		return ErrMethod
	}
	deadline := m.input.deadline
	if deadline == nil {
		return ErrOwner
	}
	if err := deadline.Check(); err != nil {
		return err
	}
	m.fanout = true
	return m.route.WithRegistered(func() error { return action(method, policy, deadline, bytes) })
}

func (m *NotifyMessage) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	m.cleanupLocked()
}
func (m *NotifyMessage) cleanupLocked() {
	if !m.closed || m.busy {
		return
	}
	if m.input != nil {
		m.input.Close()
		m.input = nil
	}
	m.route.Release()
	m.route = ContractRoute{}
	m.reservation.Release()
	m.reservation = resourcev4.Reference{}
}

func (r *NotifyReceiver) End() error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.failure != nil {
		return r.failure
	}
	if err := r.parser.End(); err != nil {
		return r.failLocked(err)
	}
	return nil
}

func (r *NotifyReceiver) Status() NotifyReceiveStatus {
	if r == nil {
		return NotifyReceiveStatus{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// RecordAdmissionRejection records only a bounded local reason after the
// original dispatcher consumes a complete message. It has no output path.
func (r *NotifyReceiver) RecordAdmissionRejection(reason string) {
	if r == nil {
		return
	}
	switch reason {
	case "resource_exhausted", "deadline_exceeded", "method_unavailable", "service_unavailable", "permission_denied", "service_contract_mismatch", "operation_conflict", "operation_admission_expired":
	default:
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status.Rejected < math.MaxUint64 {
		r.status.Rejected++
	}
	r.status.LastRejection = reason
}

// UsesRoutes binds an internal consumer to the original Session's exact route
// owner. Equal namespace/type/digest values in another receiver do not suffice.
func (r *NotifyReceiver) UsesRoutes(routes *ContractRoutes) bool {
	if r == nil || routes == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && r.routes == routes && r.reservation.Check() == nil
}

func (r *NotifyReceiver) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.failLocked(ErrClosed)
	for _, message := range r.queue {
		message.Close()
	}
	r.queue = nil
	r.parser.Close()
	r.parser = nil
	routes := r.routes
	routes.mu.Lock()
	routes.captures--
	routes.cleanupLocked()
	routes.mu.Unlock()
	r.routes, r.root = nil, nil
	r.config = InputConfig{}
	clear(r.accounts[:])
	r.reservation.Release()
	r.reservation = resourcev4.Reference{}
}

// MessageDeadline captures the same original input deadline before an admitted
// provider task can wait on storage. It never renews the notification lifetime.
func (m *NotifyMessage) MessageDeadline(clock *timev4.Clock) (*timev4.Deadline, error) {
	if m == nil {
		return nil, ErrOwner
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.input == nil {
		return nil, ErrClosed
	}
	return m.input.MessageDeadline(clock)
}

func (m *NotifyMessage) AdmitDurableExecution(ctx context.Context, history *DurableExecutions, caller ExecutionPrincipal, access ExecutionAccess, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *DurableExecutionWork, error) {
	if m == nil || history == nil || reserve == nil {
		return ExecutionObservation{}, nil, ErrConfiguration
	}
	m.mu.Lock()
	if m.closed || m.fanout || m.busy || m.input == nil || m.route.capture == nil {
		m.mu.Unlock()
		return ExecutionObservation{}, nil, ErrOwner
	}
	_, policy, err := m.input.OriginalMethod()
	if err != nil || policy.Shape != 2 || policy.Semantics != 1 || policy.ExecutionMode != 1 {
		m.mu.Unlock()
		if err == nil {
			err = ErrMethod
		}
		return ExecutionObservation{}, nil, err
	}
	capture := m.route.capture
	capture.mu.Lock()
	routes := capture.registry
	capture.mu.Unlock()
	m.fanout, m.busy = true, true
	input := m.input
	m.mu.Unlock()
	o, work, err := history.Admit(ctx, routes, input, caller, access, reserve)
	m.mu.Lock()
	if work != nil {
		m.input = nil
	}
	m.busy = false
	m.cleanupLocked()
	m.mu.Unlock()
	return o, work, durableExecutionError(err)
}
