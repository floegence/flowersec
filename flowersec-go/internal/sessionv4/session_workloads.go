package sessionv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// SessionMethodWorkload fixes one trusted target before Session admission.
// They grant capacity only: runtime Bind still checks the original application
// authority, exact registration, accepted contract and source installation gate.
// The method's contract must appear in the same assembly's trusted Routes.
type SessionMethodWorkload struct {
	initializer bool
	replacement bool
	Namespace   string
	Method      ServiceMethod
	Workload    ServiceMethodWorkload
}

func checkSessionWorkloadRecipes(c RPCServicesConfig) error {
	if len(c.Workloads) > 1024 || c.Workloads != nil && len(c.Workloads) == 0 {
		return cryptov4.ErrConfiguration
	}
	var calls, notifyCalls uint32
	for i, target := range c.Workloads {
		m, recipe := target.Method, target.Workload
		if target.Namespace == "" || len(target.Namespace) > 128 || m.Type == 0 || m.Shape > 2 ||
			m.Method.workload != nil || m.Method.Contract == ([32]byte{}) || m.Method.WorkClass > ApplicationResident ||
			recipe.Type != m.Type || recipe.Calls == 0 || recipe.Calls > 1024 || recipe.RequestBytes > 1048576 || recipe.ResponseLimitBytes > 1048576 {
			return cryptov4.ErrConfiguration
		}
		if m.Shape == 1 {
			if err := checkStreamWorkloadTarget(m.StreamKind, m.StreamMetadata); err != nil {
				return err
			}
		} else if m.StreamKind != "" || len(m.StreamMetadata) != 0 {
			return cryptov4.ErrConfiguration
		}
		if m.Shape != 2 && m.Method.Decode == nil || m.Shape == 2 && (m.Method.Decode != nil || m.Method.DefaultResponseLimitBytes != 0 || m.Method.ExplicitDefaultResponseLimit || recipe.ResponseLimitBytes != 0 || recipe.ExplicitResponseLimit) {
			return cryptov4.ErrConfiguration
		}
		if m.Shape == 2 {
			notifyCalls += uint32(recipe.Calls)
		}
		if err := m.Acceptance.Validate(); err != nil {
			return err
		}
		codec := m.Method.Codec
		if codec.MaxEncodedBytes > 1048576 || codec.ScratchBytes > 1048576 || codec.Encode == nil && (codec.MaxEncodedBytes != 0 || codec.ScratchBytes != 0) {
			return cryptov4.ErrConfiguration
		}
		for _, previous := range c.Workloads[:i] {
			if previous.Namespace == target.Namespace && previous.Method.Type == m.Type && !(previous.initializer && target.initializer) && !previous.replacement && !target.replacement {
				return cryptov4.ErrConfiguration
			}
		}
		calls += uint32(recipe.Calls)
	}
	// The Session's existing short opportunity remains independently reserved.
	if notifyCalls > c.NotifyPublishPending || calls != 0 && calls >= uint32(c.Session.Limits().RPCMaxGeneralOutstanding) {
		return cryptov4.ErrCapacity
	}
	return nil
}

func (target SessionMethodWorkload) responseLimit(policy protocolv4.ServiceContractPolicy) (uint32, error) {
	method, recipe := target.Method, target.Workload
	if policy.Namespace != target.Namespace || policy.Type != method.Type || policy.Shape != method.Shape {
		return 0, rpcv4.ErrMethod
	}
	if err := method.Method.checkExecutionPolicy(policy); err != nil {
		return 0, err
	}
	requestBytes := recipe.RequestBytes
	if method.Method.Codec.Encode != nil {
		requestBytes = method.Method.Codec.MaxEncodedBytes
	}
	if requestBytes > policy.RequestMaxBytes {
		return 0, cryptov4.ErrConfiguration
	}
	return workloadResponseLimit(method.Method, policy, recipe)
}

// Scan each original canonical contract once with one bounded decoder. Both
// requirements and pre-Acquire construction use this exact policy projection.
func visitSessionWorkloads(c RPCServicesConfig, visit func(int, SessionMethodWorkload, protocolv4.ServiceContractPolicy, uint32) error) error {
	if err := checkSessionWorkloadRecipes(c); err != nil {
		return err
	}
	if len(c.Workloads) == 0 {
		return nil
	}
	codec, err := protocolv4.NewServiceContractCodec(c.Routes.ContractNodes)
	if err != nil {
		return err
	}
	var found [1024]bool
	count := 0
	for _, method := range c.Routes.Methods {
		for _, wire := range method.Contracts {
			contract, err := codec.Decode(wire)
			if err != nil {
				return err
			}
			digest, err := contract.Digest()
			if err != nil {
				contract.Release()
				return err
			}
			for i, target := range c.Workloads {
				if target.Method.Method.Contract != digest {
					continue
				}
				if found[i] {
					contract.Release()
					return cryptov4.ErrConfiguration
				}
				_, err = contract.AcceptanceIdentity(target.Method.Acceptance)
				var policy protocolv4.ServiceContractPolicy
				if err == nil {
					policy, err = contract.Policy()
				}
				var limit uint32
				if err == nil {
					limit, err = target.responseLimit(policy)
				}
				if err == nil {
					err = visit(i, target, policy, limit)
				}
				if err != nil {
					contract.Release()
					return err
				}
				found[i], count = true, count+1
			}
			contract.Release()
		}
	}
	if count != len(c.Workloads) {
		return rpcv4.ErrMethod
	}
	return nil
}

func sessionWorkloadRequirements(c RPCServicesConfig) (total resourcev4.Vector, owners uint32, err error) {
	err = visitSessionWorkloads(c, func(_ int, target SessionMethodWorkload, policy protocolv4.ServiceContractPolicy, limit uint32) error {
		metadata, err := methodWorkloadMetadataCharge(c.RuntimeBytes, target.Workload.Calls, target.streamPlan())
		if err != nil {
			return err
		}
		total, err = total.Add(metadata)
		if err != nil {
			return err
		}
		charges, err := target.charges(c, policy, limit)
		if err != nil {
			return err
		}
		owners++
		for component, charge := range charges {
			if charge == (resourcev4.Vector{}) {
				continue
			}
			if component < workloadCompletion {
				charge, err = resourcev4.ProtectedCharge(charge)
			}
			for call := uint16(0); err == nil && call < target.Workload.Calls; call++ {
				total, err = total.Add(charge)
				owners++
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	return
}

func (h *sessionHeadroom) reserveWorkloads(c RPCServicesConfig, core SessionCoreConfig, role protocolv4.Direction, plan *SessionPlan, environment *Environment) error {
	if _, _, err := sessionStreamWorkloadRequirements(core, c, role); err != nil {
		return err
	}
	return visitSessionWorkloads(c, func(i int, target SessionMethodWorkload, policy protocolv4.ServiceContractPolicy, limit uint32) error {
		charges, err := target.charges(c, policy, limit)
		if err != nil {
			return err
		}
		var seed [56]byte
		copy(seed[:16], "rpc-initial/v4")
		if target.initializer {
			copy(seed[:16], "rpc-init-call/v4")
		}
		copy(seed[16:32], c.Owner.Instance[:])
		copy(seed[32:48], c.Owner.Backing[:])
		binary.BigEndian.PutUint64(seed[48:], uint64(i))
		digest := sha256.Sum256(seed[:])
		owner := c.Owner
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		w, err := reserveUnaryWorkloadBacking(c.Root, owner, c.Accounts, c.RuntimeBytes, plan.executor, environment, target.Method.Method, policy, target.Workload.RequestBytes, limit, target.Workload.Calls, charges, target.streamPlan())
		if err != nil {
			return err
		}
		w.initialIndex, w.initialNext = i, h.workloads
		w.initializer = target.initializer
		w.replacement = target.replacement
		h.workloads = w
		if target.replacement {
			if h.workloadController == nil {
				return resourcev4.ErrOwner
			}
			if err := w.reserveControllerHeadroom(h.workloadController, c.Root, owner, c.Accounts); err != nil {
				return err
			}
		}
		if policy.Shape != 2 {
			for j := range w.slots {
				slot := &w.slots[j]
				slot.authority, err = h.source.subscriptions.ReserveSourceDeliveryFloor(slot.authorityBacking)
				if err != nil {
					return err
				}
				if slot.authority != nil {
					slot.authorityBacking = resourcev4.Reference{}
				}
			}
		}
		if h.network != nil && policy.Shape != 2 {
			if err := w.reserveNetwork(h.network); err != nil {
				return err
			}
		}
		if w.stream != nil {
			for j := range w.slots {
				key := streamWorkloadTransportOwner(owner, j)
				w.slots[j].transport, err = reserveStreamCallerBacking(core, c.Root, key, c.Accounts, h.receivePool, len(w.stream.kind)+len(w.stream.metadata))
				if err != nil {
					return err
				}
				w.slots[j].transport.workload = w
			}
		}
		return nil
	})
}

func (w *unaryWorkload) reserveNetwork(network *rpcv4.Network) error {
	if len(w.slots) == 0 {
		return cryptov4.ErrConfiguration
	}
	if w.slots[0].network != (rpcv4.OutgoingProtection{}) {
		for i := range w.slots {
			if err := w.slots[i].network.CheckOriginal(network, w.stream != nil); err != nil {
				return err
			}
		}
		return nil
	}
	positions := make([]rpcv4.OutgoingProtection, len(w.slots))
	if err := network.ProtectOutgoing(positions); err != nil {
		return err
	}
	for i, position := range positions {
		w.slots[i].network = position
	}
	if w.stream != nil {
		for _, position := range positions {
			if err := position.ProtectStreamBacking(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Claim checks the original finite recipe before transferring any owner. A
// changed target cannot consume a smaller pre-Acquire promise.
func (h *sessionHeadroom) checkWorkloads(b *rpcServicesBatch, core *sessionCoreBatch) error {
	if h.workloads == nil {
		if b != nil && len(b.config.Workloads) != 0 {
			return cryptov4.ErrConfiguration
		}
		return nil
	}
	if b == nil || !b.prepared || b.workloadHeadroom != nil {
		return cryptov4.ErrConfiguration
	}
	count := 0
	for w := h.workloads; w != nil; w = w.initialNext {
		if w.initialIndex < 0 || w.initialIndex >= len(b.config.Workloads) || w.services != nil || w.cleaned {
			return cryptov4.ErrConfiguration
		}
		count++
	}
	if count != len(b.config.Workloads) {
		return cryptov4.ErrConfiguration
	}
	return visitSessionWorkloads(b.config, func(i int, target SessionMethodWorkload, policy protocolv4.ServiceContractPolicy, limit uint32) error {
		for w := h.workloads; w != nil; w = w.initialNext {
			if w.initialIndex != i {
				continue
			}
			if w.replacement != target.replacement || w.admissionContract != target.Method.Method.Contract || len(w.slots) != int(target.Workload.Calls) || w.requestBytes != target.Workload.RequestBytes || w.responseBytes != limit || !w.matchesMethod(target.Method.Method, policy) {
				return cryptov4.ErrConfiguration
			}
			if !w.matchesStreamTarget(target.Method) {
				return cryptov4.ErrConfiguration
			}
			for j := range w.slots {
				if w.slots[j].references == nil || w.slots[j].references.CheckAvailable() != nil {
					return cryptov4.ErrConfiguration
				}
				if h.network != nil && target.Method.Shape != 2 {
					if err := w.slots[j].network.CheckOriginal(h.network, w.stream != nil); err != nil {
						return err
					}
				}
				if f := w.slots[j].transport; f != nil {
					if core == nil || f.geometry != callerStreamGeometry(core.config) || f.receive == nil || f.receive.pool != h.receivePool {
						return cryptov4.ErrConfiguration
					}
				}
			}
			return w.metadata.CheckAllocationScope(b.config.Root, b.config.Owner, b.config.Accounts)
		}
		return cryptov4.ErrConfiguration
	})
}

func (r *RPCServices) reserveInitialSessionWorkloads(targets []SessionMethodWorkload, subscriptions *protocolv4.CredentialSubscriptions, headroom **unaryWorkload) error {
	if subscriptions == nil || len(targets) != len(r.initialWorkloads) {
		return cryptov4.ErrConfiguration
	}
	preAdmitted := headroom != nil && *headroom != nil
	for i, target := range targets {
		method, recipe := target.Method, target.Workload
		policy, err := r.routes.BindingPolicy(method.Method.Contract, method.Acceptance)
		if err != nil {
			return err
		}
		limit, err := target.responseLimit(policy)
		if err != nil {
			return err
		}
		var admitted []*unaryWorkload
		if preAdmitted {
			link := headroom
			for *link != nil && (*link).initialIndex != i {
				link = &(*link).initialNext
			}
			if *link == nil {
				return cryptov4.ErrConfiguration
			}
			w := *link
			*link, w.initialNext = w.initialNext, nil
			admitted = []*unaryWorkload{w}
			// Validation may fail before the constructor claims the target.
			defer w.closeUnattached()
		}
		w, err := r.reserveMethodWorkloadAdmission(method.Method, recipe.RequestBytes, limit, recipe.Calls, subscriptions, target.streamPlan(), admitted...)
		if err != nil {
			return err
		}
		w.initialIndex = i
		r.initialWorkloads[i] = w
	}
	return nil
}

// Unpublished Bind/update failure returns a factory target to its original
// Session. Dynamically acquired targets have no earlier promise to restore.
func (w *unaryWorkload) releaseUnpublished() {
	if w == nil {
		return
	}
	r := w.services
	r.mu.Lock()
	if w.initialIndex < 0 || r.closed || r.retired || w.closed || w.cleaned || w.replacement && r.replacementClosed {
		r.mu.Unlock()
		w.seal()
		r.advanceWorkloads()
		return
	}
	if r.initialWorkloads[w.initialIndex] == w {
		r.mu.Unlock()
		return
	}
	for i := range w.slots {
		s := &w.slots[i]
		if s.used || s.building || s.callScopeUsed.Load() || s.operation != nil {
			r.mu.Unlock()
			w.seal()
			r.advanceWorkloads()
			return
		}
	}
	for i := range w.slots {
		w.slots[i].building = true
	}
	r.mu.Unlock()
	// Private replacement targets keep their original pre-Acquire dispatch
	// positions through a readiness retry. Ordinary factory targets can be
	// returned to a different binding only after removing the old association.
	if !w.replacement {
		for i := range w.slots {
			if p := w.slots[i].controller; p != nil {
				p.backing.CloseAfterUse()
				p.cleanupComplete()
			}
		}
	}
	r.mu.Lock()
	for i := range w.slots {
		if !w.replacement {
			w.slots[i].controller = nil
		}
		w.slots[i].building = false
	}
	if !r.closed && !w.closed && (!w.replacement || !r.replacementClosed) {
		w.lineage = w.origin
		w.installed.Store(false)
		r.initialWorkloads[w.initialIndex] = w
	} else {
		w.closed = true
	}
	r.mu.Unlock()
	r.advanceWorkloads()
}

func (target SessionMethodWorkload) streamPlan() *streamPreparationPlan {
	if target.Method.Shape != 1 {
		return nil
	}
	return &streamPreparationPlan{kind: target.Method.StreamKind, metadata: target.Method.StreamMetadata}
}

func (target SessionMethodWorkload) charges(c RPCServicesConfig, policy protocolv4.ServiceContractPolicy, limit uint32) ([workloadOwners]resourcev4.Vector, error) {
	if stream := target.streamPlan(); stream != nil {
		return streamWorkloadChargesWithTask(c.RuntimeBytes, c.HashRuntimeBytes, target.Method.Method, policy, target.Workload.RequestBytes, limit, stream, c.ShortTaskCharge, c.ShortCompletionCharge)
	}
	return methodWorkloadChargesWithTask(c.RuntimeBytes, target.Method.Method, target.Method.Shape, target.Workload.RequestBytes, limit, c.ShortTaskCharge, c.ShortCompletionCharge)
}

func (w *unaryWorkload) matchesStreamTarget(method ServiceMethod) bool {
	if method.Shape != 1 {
		return w.stream == nil
	}
	return w.stream != nil && w.stream.kind == method.StreamKind && bytes.Equal(w.stream.metadata, method.StreamMetadata)
}

func streamWorkloadTransportOwner(owner resourcev4.OwnerKey, index int) resourcev4.OwnerKey {
	var seed [56]byte
	copy(seed[:16], "rpc-transport/v4")
	copy(seed[16:32], owner.Instance[:])
	copy(seed[32:48], owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], uint64(index))
	digest := sha256.Sum256(seed[:])
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	return owner
}
