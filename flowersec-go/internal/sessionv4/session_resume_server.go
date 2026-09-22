package sessionv4

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// The original raw Stream factory task owns this bounded preparation and
// waits for the recovery invocation's real exit before entering its handler.
// It creates no listener, pending table, retry chain or independent registry.
type resumeStreamServer struct {
	job            *streamHandlerInvocation
	registration   ResumeStreamBinding
	service        rpcv4.ServiceBinding
	access         *serviceExecutionAccess
	messages       *StreamMessages
	refs           [6]resourcev4.Reference
	messageHold    resourcev4.Reference
	dispatcherHold resourcev4.Reference
	progress       *streamRecoveryProgress
	accepted       bool
	registered     bool
}

func (job *streamHandlerInvocation) prepareResumeServer(binding ResumeStreamBinding) (_ *resumeStreamServer, err error) {
	p := job.dispatcher.core.plan
	p.mu.Lock()
	r := p.rpc
	engine := p.engine
	if p.closed || r == nil || engine == nil {
		p.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	policyResume := p.config.Session.Resume
	p.mu.Unlock()
	enabled, err := protocolv4.ResumeFeatureSelected(engine.NegotiatedFeatures())
	if err != nil {
		return nil, err
	}
	if !enabled || !policyResume.Enabled {
		return nil, rpcv4.ErrExecutionUnsupported
	}
	r.mu.Lock()
	d, hashRuntime := r.dispatch, r.hashRuntimeBytes
	r.mu.Unlock()
	if d == nil {
		return nil, rpcv4.ErrExecutionUnsupported
	}
	contract, policy, err := d.network.ResumeBinding(binding.Method, binding.Namespace, binding.Type, binding.ContractDigest)
	if err != nil {
		return nil, err
	}
	config := StreamMessagesConfig{resume: true, Server: true, HardDeadline: job.deadline, HashRuntimeBytes: hashRuntime, RuntimeBytes: d.runtimeBytes, InputRuntimeBytes: d.runtimeBytes, RouteRuntimeBytes: d.runtimeBytes}
	var charges [6]resourcev4.Vector
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
	if err == nil {
		charges[4], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(resumeStreamServer{})) + uint64(unsafe.Sizeof(resumeTarget{})) + uint64(unsafe.Sizeof(serviceExecutionAccess{})) + 4*128 + 4248, resourcev4.Items: 4}).Add(resourcev4.Vector{resourcev4.SDKBytes: d.runtimeBytes})
	}
	// Only a recovery Stream retains a checkpoint. Ordinary idle raw Streams
	// do not allocate a maximum checkpoint position.
	charges[5] = resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(streamRecoveryProgress{})), resourcev4.Items: 1}
	if err != nil {
		return nil, err
	}
	var requests [6]resourcev4.Request
	var refs [6]resourcev4.Reference
	for index, charge := range charges {
		owner := d.owner
		var seed [33]byte
		copy(seed[:16], "resume-server4/")
		copy(seed[16:32], job.allocation.identity[:])
		seed[32] = byte(index)
		hash := sha256.Sum256(seed[:])
		copy(owner.Instance[:], hash[:16])
		copy(owner.Backing[:], hash[16:])
		requests[index] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: d.accounts[:d.accountCount]}
	}
	if err := d.root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, err
	}
	s := &resumeStreamServer{job: job, registration: binding, refs: refs}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	s.service, s.access, err = d.executionBindingAuthority(binding.Method, binding.Namespace)
	if err != nil {
		return nil, err
	}
	if s.service.DurableHistory == nil || s.service.Recovery == nil {
		return nil, rpcv4.ErrExecutionUnsupported
	}
	// Retain the original dispatcher through the real recovery task exit.
	d.mu.Lock()
	if d.closed || !d.activated || d.active == math.MaxUint32 {
		d.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	pin, err := d.reservation.Borrow()
	if err == nil {
		d.active++
		s.registered = true
	}
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	s.dispatcherHold = pin
	progressBacking, err := s.refs[5].Take(charges[5])
	if err != nil {
		return nil, err
	}
	s.progress = &streamRecoveryProgress{reservation: progressBacking}
	_, authorization, err := d.plan.queryAuthorization()
	if err != nil {
		return nil, err
	}
	delivery, err := authorization.ForkDelivery(s.refs[3])
	if err != nil {
		return nil, err
	}
	config.InputReservation, config.RouteReservation = s.refs[1], s.refs[2]
	s.messages, err = p.prepareMessages(contract, config, s.refs[0], delivery, job.allocation.identity)
	if err != nil {
		delivery.Close(err)
		return nil, err
	}
	s.messageHold, err = s.messages.reservation.Borrow()
	return s, err
}

func (s *resumeStreamServer) run(owner *StreamOwnership) error {
	job, m := s.job, s.messages
	core := job.dispatcher.core
	if err := owner.protectReceiveCredit(serviceStreamQuantum); err != nil {
		return err
	}
	target, err := claimResumeTarget(&job.context, core, owner, s.registration, m.policy, s.refs[4], 1)
	if err != nil {
		return err
	}
	if err := target.transfer(&job.context, core, m); err != nil {
		target.releaseUnused()
		return err
	}
	m.mu.Lock()
	m.startCommitted, m.workerStarted = true, true
	m.mu.Unlock()
	go m.supervise()
	if _, err := m.CaptureNext(&job.context); err != nil {
		m.closeFailedResume(err)
		return err
	}
	// Target and max-token validation apply before an existing recovery id can
	// join its stored result. An old accepted result cannot bind a new Stream.
	verified, err := s.takeInput(&job.context, target)
	if err != nil {
		m.closeFailedResume(err)
		return err
	}
	// Take is a single transfer. Put that same original capability into the
	// invocation path instead of decoding or copying the request a second time.
	d := s.access.dispatcher
	dispatch := ExecutionDispatch{group: d.plan.applicationGroup, DurableHistory: s.service.DurableHistory, Routes: core.plan.rpc.routes, Executor: d.plan.executor, Caller: s.access.caller, Access: s.access, Class: ApplicationShort}
	_, started, err := dispatch.dispatchVerifiedResume(&job.context, m, verified, s.handle)
	if err != nil {
		m.closeFailedResume(err)
		return err
	}
	if !started {
		// A duplicate never consumes a token or invokes the registered handler.
		var body [4248]byte
		h := m.original.Fields()
		t := rpcv4.ExecutionTarget{Service: s.access.service, Caller: s.access.caller, Operation: h.OperationID, RequestDigest: h.RequestDigest, ContractDigest: h.ServiceContractDigest}
		_, n, readErr := s.service.DurableHistory.ReadResult(&job.context, t, s.access, body[:])
		if errors.Is(readErr, rpcv4.ErrResultUnavailable) || errors.Is(readErr, rpcv4.ErrResultExpired) {
			m.mu.Lock()
			if !m.cleaned && m.resumeCodec != nil {
				n, readErr = m.resumeCodec.EncodeResult(body[:], protocolv4.ResumeResult{Status: 2})
			}
			m.mu.Unlock()
		}
		if readErr != nil {
			m.closeFailedResume(readErr)
			return readErr
		}
		if err := s.publish(&job.context, body[:n]); err != nil {
			m.closeFailedResume(err)
			return err
		}
	}
	for {
		m.mu.Lock()
		i, changed := m.invocation, m.stateChanged
		var queued *QueuedApplicationTask
		if i != nil {
			queued = i.queued.Load()
		}
		m.mu.Unlock()
		var queuedDone <-chan struct{}
		if queued != nil {
			queuedDone = queued.Done()
		}
		select {
		case <-queuedDone:
			i.release()
			if queued.Canceled() {
				m.closeFailedResume(cryptov4.ErrClosed)
			}
		case <-m.done:
			m.mu.Lock()
			failure := m.failure
			m.mu.Unlock()
			if failure != nil {
				return failure
			}
			if !s.accepted {
				return rpcv4.ErrRecoveryUnauthorized
			}
			return s.transferProgress(owner)
		case <-job.context.Done():
			if queued != nil {
				queued.Cancel()
				<-queued.Done()
				i.release()
			}
			m.closeFailedResume(job.context.Err())
			<-m.done
			return job.context.Err()
		case <-changed:
		}
	}
}

func (s *resumeStreamServer) takeInput(ctx context.Context, target *resumeTarget) (_ *rpcv4.VerifiedInput, err error) {
	m := s.messages
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(ctx); err != nil {
		return nil, err
	}
	if m.initialInput == nil || m.resumeCodec == nil {
		return nil, ErrStreamMessagePending
	}
	verified, err := m.initialInput.Take()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			verified.Close()
		}
	}()
	borrow, err := verified.Borrow()
	if err != nil {
		return nil, err
	}
	defer borrow.Release()
	payload, _, err := borrow.Bytes()
	if err != nil {
		return nil, err
	}
	request, err := m.resumeCodec.DecodeRequest(payload)
	if err != nil {
		return nil, err
	}
	if request.TransportContext != target.target.TransportContext || request.StreamID != target.target.StreamID || uint64(request.Token.EncodedBytes()) > uint64(s.job.dispatcher.core.plan.config.Session.Resume.MaxTokenBytes) {
		return nil, rpcv4.ErrAssociation
	}
	return verified, nil
}

func (s *resumeStreamServer) handle(ctx context.Context, input rpcv4.InputBorrow, m *StreamMessages) (uint32, error) {
	work := m.invocation.durable
	if err := work.ResolveRecovery(ctx, s.service.Recovery, m.resume.target, func() error { return m.resume.check(s.job.dispatcher.core) }); err != nil {
		return 0, err
	}
	return 0, work.PublishResult(func(_ uint32, body []byte) error { return s.publish(ctx, body) })
}

func (s *resumeStreamServer) publish(ctx context.Context, payload []byte) error {
	m := s.messages
	m.mu.Lock()
	if err := m.checkLocked(ctx); err != nil {
		m.mu.Unlock()
		return err
	}
	if !m.resumeExchange || !m.server || !m.inputEOF || m.pending || m.writeBusy || m.outputClosed {
		m.mu.Unlock()
		return ErrStreamMessageBusy
	}
	result, err := m.resumeCodec.DecodeResult(payload)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if len(payload) > len(m.output) || uint64(len(payload)) > uint64(m.original.Fields().ResponseLimitBytes) {
		m.mu.Unlock()
		return rpcv4.ErrResponseLimit
	}
	n, header, err := m.codec.Encode(m.prefix[2:], "resume_response", m.responseFields(uint32(len(payload))))
	if err == nil {
		err = m.original.MatchResponse(header)
	}
	if err != nil {
		m.mu.Unlock()
		return err
	}
	copy(m.output, payload)
	m.prepareOutputLocked(n, len(payload), true, false)
	s.accepted = result.Status == 0
	if s.accepted {
		s.progress.result = result
	}
	m.mu.Unlock()
	return m.ContinueOutput(ctx)
}

func (m *StreamMessages) closeFailedResume(err error) {
	m.mu.Lock()
	if m.failure == nil {
		m.failure = err
	}
	m.closeLocked()
	m.mu.Unlock()
}

func (s *resumeStreamServer) close() {
	if s == nil {
		return
	}
	if m := s.messages; m != nil {
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
	}
	s.messageHold.Release()
	if s.progress != nil {
		s.progress.reservation.Release()
		s.progress = nil
	}
	if s.registered {
		d := s.access.dispatcher
		d.mu.Lock()
		d.active--
		s.registered = false
		d.cleanupLocked()
		d.mu.Unlock()
	}
	s.dispatcherHold.Release()
	s.dispatcherHold = resourcev4.Reference{}
	for _, ref := range s.refs {
		ref.Release()
	}
	s.refs = [6]resourcev4.Reference{}
	s.messages, s.job, s.access = nil, nil, nil
	s.service = rpcv4.ServiceBinding{}
}
