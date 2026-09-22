package sessionv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// StreamRegistration fixes the local OPEN binding and exact method before
// Session adoption. The initial request must independently match that contract.
// Arbitrary generators retain one resident application permit until real exit.
type StreamRegistration struct {
	EventSource    *StreamEventSourceDefinition
	Method         uint32
	Namespace      string
	Type           uint32
	ContractDigest [32]byte
	Kind           string
	Metadata       []byte
	Handler        func(context.Context, StreamRequest, *StreamMessages) (uint32, error)
}

type StreamRequest struct {
	Binding            ApplicationBinding
	ApplicationContext any
	Input              rpcv4.InputBorrow
}

type serviceStreamMethod struct {
	registration StreamRegistration
	allowed      bool
}

// This owner retains the original Stream factory task through input capture,
// dispatch and physical cleanup. The message lifetime supervisor and actual
// application callback each have their own preadmitted task, never a fallback.
type serviceStreamCall struct {
	source                      *streamEventOperation
	dispatcher                  *ServiceDispatch
	transport                   *sessionStreamDispatcher
	registration                StreamRegistration
	methodIndex, index          int
	allocation                  *sessionStreamAllocation
	handle                      OpenHandle
	messages                    *StreamMessages
	context                     context.Context
	cancel                      context.CancelFunc
	refs                        [10]resourcev4.Reference
	messageHold, dispatcherHold resourcev4.Reference
}

func streamRegistrationsCharge(c ServiceDispatchConfig) (resourcev4.Vector, error) {
	if len(c.Streams) == 0 {
		if c.StreamSlots != 0 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		return resourcev4.Vector{}, nil
	}
	if len(c.Streams)+len(c.Methods) > 128 || c.StreamSlots == 0 || c.StreamSlots > c.ResidentSlots {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	bootstrap, _, err := protocolv4.Bootstrap("services")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	notify, err := protocolv4.Notify()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	management, err := protocolv4.Management()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(c.StreamSlots) * (uint64(unsafe.Sizeof((*serviceStreamCall)(nil))) + uint64(unsafe.Sizeof(serviceStreamCall{})) + c.InvocationRuntimeBytes), resourcev4.Items: uint64(c.StreamSlots) + uint64(len(c.Streams))}
	for index, m := range c.Streams {
		if m.Kind == bootstrap.Kind || m.Kind == notify.Kind || m.Kind == management.Kind {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		if (m.Handler == nil) == (m.EventSource == nil) || m.Type == 0 || m.ContractDigest == ([32]byte{}) || !canonicalStreamHandlerKind(m.Kind) || len(m.Metadata) > 4096 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		if m.EventSource != nil {
			if err := m.EventSource.validate(); err != nil {
				return resourcev4.Vector{}, err
			}
			charge[resourcev4.SDKBytes] += uint64(unsafe.Sizeof(StreamEventSourceDefinition{}))
		}
		var wire [512]byte
		if _, err := protocolv4.EncodeMap(wire[:], "ContractTarget", []protocolv4.Field{{Name: "service_namespace", Kind: protocolv4.TextString, Text: m.Namespace}, {Name: "method_type_id", Number: uint64(m.Type)}}); err != nil {
			return resourcev4.Vector{}, err
		}
		for _, other := range c.Methods {
			if other.Method == m.Method || other.Namespace == m.Namespace && other.Type == m.Type {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
		for _, other := range c.Streams[:index] {
			if other.Method == m.Method || other.Namespace == m.Namespace && other.Type == m.Type || other.Kind == m.Kind && bytes.Equal(other.Metadata, m.Metadata) {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
		charge[resourcev4.SDKBytes] += uint64(unsafe.Sizeof(serviceStreamMethod{})) + uint64(len(m.Namespace)+len(m.Kind)+len(m.Metadata))
	}
	return charge, nil
}

// The sole pending-OPEN dispatcher calls this finite selector. Peer text can
// only match an installed binding; it cannot supply a contract or work class.
func (d *ServiceDispatch) dispatchStreamOpen(transport *sessionStreamDispatcher, h OpenHandle) (handled bool, err error) {
	a := h.owner
	if transport == nil || a == nil || a != transport.core.plan.admission {
		return false, ErrOpenAssociation
	}
	var snapshot [4224]byte
	a.mu.Lock()
	s, err := a.slot(h)
	kindSize, metadataSize := 0, 0
	if err == nil {
		kindSize, metadataSize = s.kindSize, s.metadataSize
		if metadataSize > len(snapshot) {
			err = cryptov4.ErrConfiguration
		} else {
			copy(snapshot[:], a.metadata[s.metadataStart:s.metadataStart+metadataSize])
		}
	}
	a.mu.Unlock()
	if err != nil {
		return false, err
	}
	d.mu.Lock()
	methodIndex := -1
	for j, method := range d.streamMethods {
		m := method.registration
		if m.Kind == string(snapshot[:kindSize]) && bytes.Equal(m.Metadata, snapshot[kindSize:metadataSize]) {
			methodIndex = j
			break
		}
	}
	if methodIndex < 0 {
		d.mu.Unlock()
		return false, nil
	}
	if d.closed || !d.activated || !d.streamMethods[methodIndex].allowed {
		d.mu.Unlock()
		return true, ErrApplicationAuthorization
	}
	index := -1
	for j, job := range d.streamSlots {
		if job == nil {
			index = j
			break
		}
	}
	if index < 0 || d.resident >= d.residentLimit {
		d.mu.Unlock()
		return true, cryptov4.ErrCapacity
	}
	hold, err := d.reservation.Borrow()
	if err != nil {
		d.mu.Unlock()
		return true, err
	}
	ctx, cancel := context.WithCancel(transport.context)
	job := &serviceStreamCall{dispatcher: d, transport: transport, registration: d.streamMethods[methodIndex].registration, methodIndex: methodIndex, index: index, handle: h, context: ctx, cancel: cancel, dispatcherHold: hold}
	d.streamSlots[index] = job
	d.active++
	d.resident++
	d.mu.Unlock()
	committed := false
	defer func() {
		if !committed {
			job.release()
		}
	}()
	job.allocation, _, err = transport.core.plan.prepareStream(ctx, 0)
	if err != nil {
		return true, err
	}
	if err = a.checkServiceStreamCredit(h); err != nil {
		return true, err
	}
	if err = job.prepare(); err != nil {
		return true, err
	}
	if err = job.messages.withCurrentAuthorization(func() error { return ctx.Err() }); err != nil {
		return true, err
	}
	committed = true
	go job.run()
	return true, nil
}

func (j *serviceStreamCall) prepare() (err error) {
	d, p, registration := j.dispatcher, j.transport.core.plan, j.registration
	contract, policy, err := d.network.StreamBinding(registration.Method, registration.Namespace, registration.Type, registration.ContractDigest)
	if err != nil {
		return err
	}
	deadline, err := timev4.NewDeadline(d.clock, p.engine.SessionParameters().SessionNotAfterMS)
	if err != nil {
		return err
	}
	r := p.rpc
	r.mu.Lock()
	hashRuntime := r.hashRuntimeBytes
	r.mu.Unlock()
	config := StreamMessagesConfig{Server: true, HardDeadline: deadline, HashRuntimeBytes: hashRuntime, RuntimeBytes: d.runtimeBytes, InputRuntimeBytes: d.runtimeBytes, RouteRuntimeBytes: d.runtimeBytes}
	var charges [10]resourcev4.Vector
	count := 6
	charges[0], err = StreamMessagesCharge(policy, config)
	if err == nil {
		charges[1], err = StreamMessagesInputCharge(policy, config)
	}
	if err == nil {
		charges[2], err = rpcv4.ContractRouteCharge(d.runtimeBytes)
	}
	if err == nil {
		charges[3], err = protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: d.runtimeBytes})
	}
	if err != nil {
		return err
	}
	charges[4] = d.plan.executor.TaskCharge()
	charges[5], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(serviceExecutionAccess{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + 3*128, resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: d.runtimeBytes})
	if err != nil {
		return err
	}
	if registration.EventSource != nil {
		charges[6], err = streamEventSourceCharge(registration.EventSource.config(j))
		if err == nil {
			charges[7], err = streamEventOperationCharge(d.runtimeBytes)
		}
		if err == nil {
			charges[8], err = streamSourceCleanupCharge(d.runtimeBytes, registration.EventSource.CleanupMS)
		}
		if err != nil {
			return err
		}
		charges[9] = d.plan.executor.TaskCharge()
		count = 10
	}
	var requests [10]resourcev4.Request
	for index, charge := range charges[:count] {
		owner := d.owner
		var seed [33]byte
		copy(seed[:16], "stream-service4/")
		copy(seed[16:32], j.allocation.identity[:])
		seed[32] = byte(index)
		digest := sha256.Sum256(seed[:])
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		requests[index] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: d.accounts[:d.accountCount]}
	}
	if err := d.root.ReserveBatch(requests[:count], j.refs[:count]); err != nil {
		return err
	}
	_, authorization, err := d.plan.queryAuthorization()
	if err != nil {
		return err
	}
	delivery, err := authorization.ForkDelivery(j.refs[3])
	if err != nil {
		return err
	}
	config.InputReservation, config.RouteReservation = j.refs[1], j.refs[2]
	j.messages, err = p.prepareMessages(contract, config, j.refs[0], delivery, j.allocation.identity)
	if err != nil {
		delivery.Close(err)
		return err
	}
	j.messages.service = j
	j.messageHold, err = j.messages.reservation.Borrow()
	if err == nil && registration.EventSource != nil {
		j.source, err = prepareStreamEventOperation(j, j.refs[6], j.refs[7], j.refs[8], j.refs[9])
		j.messages.eventSource = j.source
	}
	return err
}

func (j *serviceStreamCall) run() {
	defer j.release()
	a, m := j.handle.owner, j.messages
	var err error
	for {
		_, err = a.Decide(j.context, j.handle, BusinessStream, "", j.allocation.reservation, j.transport.core.plan.writer)
		if !errors.Is(err, ErrOpenPending) && !errors.Is(err, errRecordWriterBusy) {
			break
		}
		if err = a.WaitDecisionOpportunity(j.context, j.handle); err != nil {
			break
		}
	}
	if err != nil {
		_ = a.Cancel(j.handle)
		return
	}
	owner, err := j.allocation.bindMessages(a, j.handle, m)
	if err == nil {
		err = m.bindPreparedMessages(owner)
	}
	if err != nil {
		_ = a.Cancel(j.handle)
		if owner != nil {
			m.retireFailedOwner(owner, err)
		}
		return
	}
	if _, err = m.CaptureNext(j.context); err != nil {
		return
	}
	if m.policy.Semantics == 1 {
		binding, access, e := j.dispatcher.executionBindingAuthority(j.registration.Method, j.registration.Namespace)
		if e != nil {
			err = e
		} else {
			dispatch := ExecutionDispatch{group: j.dispatcher.plan.applicationGroup, History: binding.History, DurableHistory: binding.DurableHistory, Routes: j.transport.core.plan.rpc.routes, Executor: j.dispatcher.plan.executor, Caller: access.caller, Access: access, Class: ApplicationResident}
			_, err = dispatch.DispatchStream(j.context, m, j.handleRequest)
		}
	} else {
		err = (TransientStreamDispatch{group: j.dispatcher.plan.applicationGroup, Executor: j.dispatcher.plan.executor, Class: ApplicationResident, TaskReservation: j.refs[4]}).Dispatch(j.context, m, j.handleRequest)
	}
	if err != nil {
		_ = m.SendSDKError(j.context, serviceRefusal(err))
		return
	}
	if source := m.eventSource; source != nil {
		source.run(j)
		return
	}
	// A canceled ready position never entered user code, so this same
	// original factory task retires its input/history obligation. Running
	// callbacks own their release until actual exit, including provider tails.
	m.mu.Lock()
	invocation := m.invocation
	var queued *QueuedApplicationTask
	if invocation != nil {
		queued = invocation.queued.Load()
	}
	m.mu.Unlock()
	var queuedDone <-chan struct{}
	if queued != nil {
		queuedDone = queued.Done()
	}
	select {
	case <-m.done:
	case <-j.context.Done():
		if queued != nil {
			queued.Cancel()
			<-queued.Done()
			invocation.release()
		}
	case <-queuedDone:
		invocation.release()
		if queued.Canceled() {
			m.Close()
		}
		select {
		case <-m.done:
		case <-j.context.Done():
		}
	}
}

func (j *serviceStreamCall) handleRequest(ctx context.Context, input rpcv4.InputBorrow, m *StreamMessages) (uint32, error) {
	lease := j.dispatcher.plan.lease
	lease.mu.Lock()
	request := StreamRequest{Binding: lease.binding, ApplicationContext: lease.context, Input: input}
	lease.mu.Unlock()
	if err := m.withCurrentAuthorization(func() error { return ctx.Err() }); err != nil {
		return 0, err
	}
	if source := m.eventSource; source != nil {
		subscription, err := source.cleanup.enterSetup(ctx)
		if err != nil {
			return 0, err
		}
		return 0, j.registration.EventSource.Setup(ctx, request, subscription)
	}
	return j.registration.Handler(ctx, request, m)
}

func (j *serviceStreamCall) release() {
	j.source.abortBeforeStart()
	j.cancel()
	if m := j.messages; m != nil {
		m.mu.Lock()
		if !m.workerStarted {
			m.releasePositionLocked()
		}
		m.closeLocked()
		started := m.workerStarted
		m.mu.Unlock()
		if started {
			<-m.done
		}
		j.messages = nil
	}
	j.messageHold.Release()
	j.source.releaseOwned()
	j.source = nil
	if j.allocation != nil {
		j.transport.core.plan.finishStream(j.allocation)
		j.allocation = nil
	}
	j.registration = StreamRegistration{}
	for _, ref := range j.refs {
		ref.Release()
	}
	j.refs = [10]resourcev4.Reference{}
	d := j.dispatcher
	d.mu.Lock()
	if d.streamSlots[j.index] == j {
		d.streamSlots[j.index] = nil
		d.active--
		d.resident--
	}
	d.cleanupLocked()
	d.mu.Unlock()
	j.dispatcherHold.Release()
	j.dispatcher, j.transport = nil, nil
}

// This is a finite SDK permission gate only. The delivery authorization has
// already been checked; no user callback or provider work runs under this lock.
func (j *serviceStreamCall) withPermission(action func() error) error {
	d := j.dispatcher
	if d == nil {
		return ErrApplicationAuthorization
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || !d.activated || j.methodIndex >= len(d.streamMethods) || !d.streamMethods[j.methodIndex].allowed {
		return ErrApplicationAuthorization
	}
	if err := j.context.Err(); err != nil {
		return err
	}
	return action()
}

func (m *StreamMessages) withCurrentAuthorization(action func() error) error {
	return m.authorization.WithCurrentAuthorization(func() error {
		if m.service != nil {
			return m.service.withPermission(action)
		}
		return action()
	})
}

func (m *StreamMessages) checkAuthorization() error {
	return m.withCurrentAuthorization(func() error { return nil })
}
