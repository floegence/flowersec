package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// SessionStreamConfig fixes the shared transport Stream factory's geometry.
// All receives share one Session promise pool; a per-Stream wrapper cannot
// multiply signed MaxCredit. Send rings and method slots are admitted in the
// same original Session/tenant accounts before each OPEN outcome is published.
// The zero value leaves only the lower-level transport assembly enabled.
type SessionStreamConfig struct {
	NormalTerminationMS                                 uint64
	ReceivePoolBytes, ReceiveBytes, InitialReceiveLimit uint64
	SendBytes, QueueBytes, RuntimeBytes                 uint64
	WriteWaiters                                        uint32
	MaxPlaintext, Chunk                                 int
}

const (
	streamFactoryMetadata = iota
	streamFactorySend
	streamFactoryQueue
	streamFactoryOwnership
	streamFactoryInvocation
	streamFactoryAuthorizeTask
	streamFactoryHandlerTask
	streamFactoryNativeReceive
	streamFactoryOwners
)

type sessionStreamAllocation struct {
	service     bool
	floor       *streamServiceFloor
	callerFloor *streamCallerFloor
	serviceRefs [3]resourcev4.Reference
	identity    [16]byte
	refs        [streamFactoryOwners]resourcev4.Reference
	reservation StreamReservation
	queue       SendQueueReservation
	candidate   *StreamOwnership
}

func sessionStreamCharges(config SessionStreamConfig, profile string, frame, maxData uint64, snapshotBytes int) (charges [streamFactoryOwners]resourcev4.Vector, err error) {
	if config.NormalTerminationMS > 60000 || config.ReceivePoolBytes == 0 || config.ReceiveBytes == 0 || config.ReceiveBytes > config.ReceivePoolBytes || config.InitialReceiveLimit > config.ReceiveBytes ||
		config.SendBytes == 0 || config.SendBytes > maxData || config.QueueBytes == 0 || config.WriteWaiters == 0 || config.Chunk <= 0 || uint64(config.Chunk) > config.SendBytes ||
		config.RuntimeBytes == 0 || snapshotBytes < 0 || config.MaxPlaintext <= 0 {
		return charges, cryptov4.ErrConfiguration
	}
	// Include the largest legal future scope/offset encoding before admission.
	recordProfile, err := protocolv4.Profile(profile)
	if err != nil {
		return charges, err
	}
	worst, err := protocolv4.StreamDataPlaintextSize(math.MaxInt64, protocolv4.ClientToServer, int(config.SendBytes))
	if err != nil || worst > config.MaxPlaintext || uint64(config.MaxPlaintext)+uint64(protocolv4.RecordHeaderSize()+recordProfile.TagBytes) > frame {
		return charges, cryptov4.ErrConfiguration
	}
	metadata := uint64(unsafe.Sizeof(sessionStreamAllocation{})) + uint64(snapshotBytes)
	if config.RuntimeBytes > math.MaxUint64-metadata {
		return charges, cryptov4.ErrConfiguration
	}
	charges[streamFactoryMetadata] = resourcev4.Vector{resourcev4.SDKBytes: metadata + config.RuntimeBytes, resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}
	if charges[streamFactorySend], err = SendFlowCharge(config.SendBytes); err != nil {
		return charges, err
	}
	if charges[streamFactoryQueue], err = SendQueueCharge(config.QueueBytes, config.WriteWaiters); err != nil {
		return charges, err
	}
	charges[streamFactoryOwnership] = StreamOwnershipCharge()
	return charges, nil
}

// prepareStream pins the original plan through the factory's actual method
// tail. An exhausted root or account cannot leave a partial allocation behind.
func (p *SessionCorePlan) prepareStream(ctx context.Context, snapshotBytes int) (*sessionStreamAllocation, *OpenAdmission, error) {
	return p.prepareStreamInvocation(ctx, snapshotBytes, nil, false)
}

func (p *SessionCorePlan) prepareStreamInvocation(ctx context.Context, snapshotBytes int, dispatcher *sessionStreamDispatcher, service bool, caller ...*streamCallerFloor) (*sessionStreamAllocation, *OpenAdmission, error) {
	if ctx == nil || len(caller) > 1 || len(caller) != 0 && (dispatcher != nil || service) {
		return nil, nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, nil, cryptov4.ErrClosed
	}
	if p.config.Native && p.nativeStreams == nil || p.receivePool == nil || p.runtime == nil || p.admission == nil || p.writer == nil {
		return nil, nil, cryptov4.ErrConfiguration
	}
	p.admission.mu.Lock()
	accepting := !p.admission.closed && !p.admission.draining && (dispatcher != nil || !p.admission.peerGoAway.set)
	p.admission.mu.Unlock()
	if !accepting {
		return nil, nil, ErrSessionDraining
	}
	if err := p.engine.CheckApplicationAuthorization(); err != nil {
		return nil, nil, err
	}
	if len(caller) == 1 && caller[0] != nil {
		return p.prepareCallerStreamLocked(snapshotBytes, caller[0])
	}
	if p.streamMethods-p.streamServices+p.streamCallerProtected-p.streamCallerUsed >= p.config.Open.Opening+p.config.Open.IngressItems || p.streamCalls == math.MaxUint64 {
		return nil, nil, cryptov4.ErrCapacity
	}
	config := p.config.Streams
	charges, err := sessionStreamCharges(config, p.config.Session.Profile, uint64(p.config.Session.Contract.Limits().MaxFrame), p.config.MaxDataPayloadBytes, snapshotBytes)
	if err != nil {
		return nil, nil, err
	}
	if p.config.Native {
		charges[streamFactoryNativeReceive], err = NativeDataAssemblyCharge(math.MaxInt64, 1-p.role, p.config.Session.Profile, p.config.Session.Contract.Limits().MaxFrame)
		if err != nil {
			return nil, nil, err
		}
	}
	if dispatcher != nil {
		charges[streamFactoryInvocation], err = streamHandlerInvocationCharge(dispatcher.config)
		if err != nil {
			return nil, nil, err
		}
		charges[streamFactoryAuthorizeTask] = dispatcher.executor.TaskCharge()
		charges[streamFactoryHandlerTask] = dispatcher.executor.TaskCharge()
	}
	p.streamCalls++
	var requests [streamFactoryOwners]resourcev4.Request
	var refs [streamFactoryOwners]resourcev4.Reference
	var positions [streamFactoryOwners]int
	count := 0
	for i, charge := range charges {
		if charge == (resourcev4.Vector{}) {
			continue
		}
		key := p.resourceOwner
		var identity [37]byte
		copy(identity[:8], "stream4/")
		copy(identity[8:24], key.Backing[:])
		binary.BigEndian.PutUint64(identity[24:32], p.streamCalls)
		binary.BigEndian.PutUint32(identity[32:36], uint32(i))
		identity[36] = byte(p.role)
		digest := sha256.Sum256(identity[:])
		copy(key.Backing[:], digest[:16])
		requests[count] = resourcev4.Request{Owner: key, Charge: charge, Accounts: p.accounts[:p.accountCount]}
		positions[count] = i
		count++
	}
	var floor *streamServiceFloor
	var complete [streamServiceOwners]resourcev4.Reference
	if service {
		for i := range p.serviceFloors {
			candidate := &p.serviceFloors[i]
			if candidate.used {
				continue
			}
			complete, err = candidate.checkout()
			if err == nil {
				floor = candidate
				floor.used = true
				break
			}
		}
		if floor == nil {
			return nil, nil, cryptov4.ErrCapacity
		}
	} else if err := p.root.ReserveBatch(requests[:count], refs[:count]); err != nil {
		return nil, nil, err
	}
	allocation := &sessionStreamAllocation{floor: floor, identity: requests[0].Owner.Backing}
	if floor != nil {
		copy(allocation.refs[:], complete[:streamFactoryOwners])
		copy(allocation.serviceRefs[:], complete[streamFactoryOwners:streamServiceCallback])
	} else {
		for i, ref := range refs[:count] {
			allocation.refs[positions[i]] = ref
		}
	}
	transferred := false
	defer func() {
		if !transferred {
			allocation.releaseReferences()
			if floor != nil {
				floor.used = false
			}
		}
	}()
	if err = p.buildStreamAllocationLocked(allocation, requests[0].Owner, snapshotBytes); err != nil {
		return nil, nil, err
	}
	p.streamMethods++
	transferred = true
	return allocation, p.admission, nil
}

// All stream factory paths materialize the same flow/queue/ownership graph.
// Caller and delegated-service floors supply original references to this path.
func (p *SessionCorePlan) buildStreamAllocationLocked(allocation *sessionStreamAllocation, owner resourcev4.OwnerKey, snapshotBytes int) (err error) {
	config := p.config.Streams
	allocation.candidate, err = prepareStreamOwnership(allocation.refs[streamFactoryOwnership])
	if err != nil {
		return err
	}
	allocation.candidate.allocationRoot = p.root
	allocation.candidate.allocationOwner = owner
	allocation.candidate.allocationScopes = p.accounts
	allocation.candidate.allocationCount = p.accountCount
	allocation.candidate.allocationRuntimeBytes = config.RuntimeBytes
	if allocation.floor != nil {
		handlers := p.config.Handlers.Plan
		allocation.candidate.allocationExecutor, allocation.candidate.allocationGroup = handlers.executor, handlers.group
		allocation.candidate.allocationExecutionBacking, err = allocation.refs[streamFactoryMetadata].Borrow()
	} else if allocation.callerFloor != nil {
		if p.rpc == nil || p.rpc.plan == nil {
			return cryptov4.ErrConfiguration
		}
		allocation.candidate.allocationExecutor, allocation.candidate.allocationGroup = p.rpc.plan.executor, p.rpc.plan.applicationGroup
		allocation.candidate.allocationExecutionBacking, err = allocation.refs[streamFactoryMetadata].Borrow()
	} else if application := p.application; application != nil {
		application.mu.Lock()
		allocation.candidate.allocationExecutor, allocation.candidate.allocationGroup = application.executor, application.applicationGroup
		allocation.candidate.allocationExecutionBacking, err = application.reservation.Borrow()
		application.mu.Unlock()
	} else if handlers := p.config.Handlers.Plan; handlers != nil {
		handlers.mu.Lock()
		allocation.candidate.allocationExecutor, allocation.candidate.allocationGroup = handlers.executor, handlers.group
		allocation.candidate.allocationExecutionBacking, err = handlers.reservation.Borrow()
		handlers.mu.Unlock()
	} else if p.rpc != nil && p.rpc.plan != nil {
		allocation.candidate.allocationExecutor = p.rpc.plan.executor
		allocation.candidate.allocationGroup = p.rpc.plan.applicationGroup
		allocation.candidate.allocationExecutionBacking, err = p.rpc.plan.reservation.Borrow()
	}
	if err != nil {
		return err
	}
	allocation.queue = SendQueueReservation{Capacity: config.QueueBytes, Waiters: config.WriteWaiters, Chunk: config.Chunk, Reservation: allocation.refs[streamFactoryQueue]}
	allocation.reservation = StreamReservation{NormalTerminationMS: config.NormalTerminationMS, Pool: p.receivePool, OpenStorage: make([]byte, snapshotBytes),
		SendCapacity: config.SendBytes, SendReservation: allocation.refs[streamFactorySend], ReceiveCapacity: config.ReceiveBytes,
		Writer: p.input, MaxPlaintext: config.MaxPlaintext, InitialReceiveLimit: config.InitialReceiveLimit, SendQueue: &allocation.queue}
	allocation.reservation.NativeReceive = allocation.refs[streamFactoryNativeReceive]
	if allocation.floor != nil {
		allocation.reservation.ReceiveProtection = allocation.floor.receive
	}
	if allocation.callerFloor != nil {
		allocation.reservation.ReceiveProtection = allocation.callerFloor.receive
		allocation.reservation.openProtection = allocation.callerFloor.open
	}
	return nil
}

func (allocation *sessionStreamAllocation) releaseReferences() {
	if allocation.candidate != nil {
		allocation.candidate.allocationExecutionBacking.Release()
		allocation.candidate.reservation.Release()
		allocation.candidate.reservation = resourcev4.Reference{}
		allocation.candidate = nil
	}
	clear(allocation.reservation.OpenStorage)
	allocation.reservation = StreamReservation{}
	allocation.queue = SendQueueReservation{}
	for i, ref := range allocation.refs {
		ref.Release() // Transferred generations stay with the original flow.
		allocation.refs[i] = resourcev4.Reference{}
	}
	for i, ref := range allocation.serviceRefs {
		ref.Release()
		allocation.serviceRefs[i] = resourcev4.Reference{}
	}
}

func (p *SessionCorePlan) finishStream(allocation *sessionStreamAllocation) {
	allocation.releaseReferences()
	p.mu.Lock()
	if allocation.floor != nil {
		allocation.floor.used = false
	}
	if allocation.callerFloor != nil {
		floor := allocation.callerFloor
		floor.used = false
		p.streamCallerUsed--
		if floor.closed {
			p.streamCallerProtected--
			floor.registered = false
		}
	}
	p.streamMethods--
	if allocation.service {
		p.streamServices--
	}
	p.notifyLocked()
	p.mu.Unlock()
}

// OpenStream is the shared carrier factory used by the Session facade. It
// publishes a full I/O owner only after the original authenticated acceptance.
// A canceled wait resets that original OPEN; it never reissues its ordinal.
func (c *SessionCore) OpenStream(ctx context.Context, kind string, metadata []byte, deadline *timev4.Deadline) (*StreamOwnership, error) {
	if c == nil || c.plan == nil {
		return nil, cryptov4.ErrConfiguration
	}
	kindCap, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil {
		return nil, err
	}
	metadataCap, err := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
	if err != nil {
		return nil, err
	}
	if len(kind) > kindCap || len(metadata) > metadataCap {
		return nil, cryptov4.ErrConfiguration
	}
	p := c.plan
	allocation, a, err := p.prepareStream(ctx, len(kind)+len(metadata))
	if err != nil {
		return nil, err
	}
	defer p.finishStream(allocation)
	h, _, err := p.openBusinessStream(ctx, allocation, kind, metadata, deadline)
	if err != nil {
		return nil, err
	}
	if err := a.WaitOutcome(ctx, h); err != nil {
		_ = a.Cancel(h)
		return nil, err
	}
	owner, err := allocation.bind(a, h)
	if err != nil {
		_ = a.Cancel(h)
	}
	return owner, err
}

// Every business shape publishes OPEN on its original carrier association.
// Native creation is pinned through that publication, then its authenticated
// scope owns transport cleanup. Message carriers use the shared ingress.
func (p *SessionCorePlan) openBusinessStream(ctx context.Context, allocation *sessionStreamAllocation, kind string, metadata []byte, deadline *timev4.Deadline) (OpenHandle, RecordWriteResult, error) {
	a := p.admission
	association := &CarrierAssociation{shared: a.sharedIngress}
	if p.nativeStreams != nil {
		var protection *nativeStreamProtection
		if allocation.callerFloor != nil {
			protection = allocation.callerFloor.native
		}
		native, err := p.nativeStreams.openProtected(ctx, protection)
		if err != nil {
			return OpenHandle{}, RecordWriteResult{}, err
		}
		defer p.nativeStreams.finishOpen(native)
		association = &native.association
		allocation.reservation.Writer = native.stream
	}
	handle, publication, err := a.OpenLocal(ctx, BusinessStream, kind, metadata, association, allocation.reservation, deadline)
	if allocation.callerFloor != nil && handle.scope != 0 {
		p.mu.Lock()
		allocation.callerFloor.openHandle = handle
		p.mu.Unlock()
	}
	return handle, publication, err
}

// AcceptStream runs after the original immutable handler plan has authorized
// this authenticated pending OPEN. The factory does not authorize a peer kind
// or start a callback. Its prepared application execution permit is owned by
// the caller and must already exist before this acceptance publication.
func (c *SessionCore) AcceptStream(ctx context.Context, h OpenHandle) (*StreamOwnership, error) {
	if c == nil || c.plan == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p := c.plan
	allocation, a, err := p.prepareStream(ctx, 0)
	if err != nil {
		return nil, err
	}
	defer p.finishStream(allocation)
	if h.owner != a {
		return nil, ErrOpenAssociation
	}
	if _, err := a.Decide(ctx, h, BusinessStream, "", allocation.reservation, p.writer); err != nil {
		return nil, err
	}
	if err := a.WaitOutcome(ctx, h); err != nil {
		_ = a.Cancel(h)
		return nil, err
	}
	owner, err := allocation.bind(a, h)
	if err != nil {
		_ = a.Cancel(h)
	}
	return owner, err
}

func (allocation *sessionStreamAllocation) bind(a *OpenAdmission, h OpenHandle) (*StreamOwnership, error) {
	o := allocation.candidate
	owner, err := a.bindStreamOwnership(h, o.reservation, nil, nil, o)
	if err == nil {
		allocation.candidate = nil
	}
	return owner, err
}
