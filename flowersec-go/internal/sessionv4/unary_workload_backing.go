package sessionv4

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// Reserve the actual reusable references, independent result positions and
// Completion descriptors before a source can Acquire. Namespace subscriptions
// are adopted only from the original verified material before TxA.
func reserveUnaryWorkloadBacking(root *resourcev4.Root, owner resourcev4.OwnerKey, accounts []resourcev4.Account, runtimeBytes uint64, executor *ApplicationExecutor, environment *Environment, method UnaryMethodDefinition, policy protocolv4.ServiceContractPolicy, requestBytes, responseBytes uint32, calls uint16, charges [workloadOwners]resourcev4.Vector, streams ...*streamPreparationPlan) (_ *unaryWorkload, err error) {
	if len(streams) > 1 {
		return nil, resourcev4.ErrOwner
	}
	var stream *streamPreparationPlan
	if len(streams) == 1 {
		stream = streams[0]
	}
	metadata, err := methodWorkloadMetadataCharge(runtimeBytes, calls, stream)
	if err != nil {
		return nil, err
	}
	// Admit the bounded constructor workspace before allocating its arrays.
	// The unpublished metadata owner is unwound if the complete target fails.
	metadataRef, err := root.Reserve(owner, metadata, accounts...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			metadataRef.Release()
		}
	}()
	requests := make([]resourcev4.Request, 1, 1+int(calls)*workloadOwners)
	for slot := range int(calls) {
		for component, charge := range charges {
			if charge == (resourcev4.Vector{}) {
				continue
			}
			key := owner
			ordinal := uint64(1 + slot*workloadOwners + component)
			binary.BigEndian.PutUint64(key.Backing[:8], binary.BigEndian.Uint64(key.Backing[:8])^ordinal)
			if component < workloadCompletion {
				charge, err = resourcev4.ProtectedCharge(charge)
				if err != nil {
					return nil, err
				}
			}
			requests = append(requests, resourcev4.Request{Owner: key, Charge: charge, Accounts: accounts, ResultOwner: policy.Shape == 0 && component == workloadCall+4 || policy.Shape == 1 && component == workloadCall})
		}
	}
	refs := make([]resourcev4.Reference, len(requests))
	refs[0] = metadataRef
	if err = root.ReserveBatch(requests[1:], refs[1:]); err != nil {
		return nil, err
	}
	w := &unaryWorkload{initialIndex: -1, admissionContract: method.Contract, namespace: sha256.Sum256([]byte(policy.Namespace)), methodType: policy.Type, shape: policy.Shape, encoded: method.Codec.Encode != nil, class: method.WorkClass, codecBytes: method.Codec.MaxEncodedBytes, scratchBytes: method.Codec.ScratchBytes, environment: environment, metadata: refs[0], slots: make([]unaryWorkloadSlot, calls), requestBytes: requestBytes, responseBytes: responseBytes}
	copy(w.origin[:16], owner.Instance[:])
	copy(w.origin[16:], owner.Backing[:])
	w.lineage = w.origin
	if stream != nil {
		w.stream = &streamPreparationPlan{workload: w, core: stream.core, kind: strings.Clone(stream.kind), metadata: append([]byte(nil), stream.metadata...)}
	}

	defer func() {
		for _, ref := range refs[1:] {
			ref.Release()
		}
		if err != nil {
			w.closeUnattached()
		}
	}()
	if policy.Shape != 2 {
		positions := make([]environmentResultProtection, calls)
		if err = environment.protectResults(w.metadata, positions); err != nil {
			return nil, err
		}
		for i, position := range positions {
			w.slots[i].result = position
		}
	}

	index := 1
	for i := range w.slots {
		s := &w.slots[i]
		s.workload, s.callScope.workload = w, s
		for component, charge := range charges {
			if charge == (resourcev4.Vector{}) {
				continue
			}
			ref := refs[index]
			index++
			switch component {
			case workloadCompletion:
				s.completion, err = executor.NewCompletionFloor(ref, w.metadata)
			case workloadAuthority:
				s.authorityBacking, err = ref.Take(charge)
			case workloadDependencies:
				s.references, err = resourcev4.NewBorrowPoolForSources(ref, workloadDependencyPositions(policy.Shape))
			default:
				err = s.protect(component, ref, charge)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	return w, nil
}

// Only the unpublished original preparation owns these objects. Once attached,
// the Session's existing coordinator settles all real invocation/result tails.
func (w *unaryWorkload) closeUnattached() {
	if w == nil || w.services != nil || w.cleaned {
		return
	}
	for i := range w.slots {
		w.slots[i].closeOwners()
		w.slots[i].references.Close()
		w.slots[i].controller.cleanupComplete()
	}
	w.metadata.Release()
	w.metadata = resourcev4.Reference{}
	w.stream = nil
	w.cleaned, w.closed = true, true
}

// Metadata belongs to the original declaration, including its immutable
// streaming target. Requirements and actual construction use this charge.
func methodWorkloadMetadataCharge(runtimeBytes uint64, calls uint16, stream *streamPreparationPlan) (resourcev4.Vector, error) {
	metadata, err := unaryWorkloadMetadataCharge(runtimeBytes, calls)
	if err == nil && stream != nil {
		metadata, err = metadata.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(streamPreparationPlan{})) + uint64(len(stream.kind)+len(stream.metadata)), resourcev4.Items: 1})
	}
	return metadata, err
}
