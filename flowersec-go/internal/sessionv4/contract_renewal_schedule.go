package sessionv4

import (
	"errors"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var errContractRenewalQualification = errors.New("sessionv4: contract renewal configuration capacity")

// This local qualification is a trusted deployment input, never a measurement
// inferred from a fast query or a new wire timeout. BatchMS covers acquisition,
// source/network/credit, decode, installation and every physical output tail.
// SuspensionMS covers the complete round's permitted runtime/rekey suspension.
type contractRenewalTiming struct {
	BatchMS, JoinMS, SuspensionMS, TimeErrorMS uint64
}

type contractRenewalBudget struct {
	Methods, Batches                                      uint16
	RequiredMS, AdvanceMS, DeadlineMS, MinimumRemainingMS uint64
}

// A group is an already authenticated actual source and accepting Session.
// Namespace is deliberately absent: one authorized source may legally batch
// several namespaces. Different real Sessions and different source owners are
// never collapsed even when all their digests and method names are identical.
type contractRenewalGroup struct {
	session    *EnvironmentSession
	controller *ConnectionController
	routing    controllerRoutingIdentity
}

// The coordinator stores entries in the Environment's original finite method
// index. No entry is a task, timer, public owner or another copy of a contract.
// Blocked entries remain in timing qualification; they cannot make a round
// appear smaller by lacking a currently usable channel.
type contractRenewalEntry struct {
	client            *UnaryServiceClient
	method            *boundUnaryMethod
	group             contractRenewalGroup
	namespace         string
	typeID            uint32
	digest            [32]byte
	offer             protocolv4.AdmissionOfferBounds
	sourceRemainingMS uint64
	blocked, busy     bool
	nextAttemptMS     uint64
	index             uint16
}

// qualifyContractRenewal evaluates the complete simultaneously retained set.
// Duplicate wire targets cannot coexist in one QueryServiceContracts request;
// duplicate actual owners are packed into separate batches instead of being
// deduplicated or incorrectly charged as one target.
func qualifyContractRenewal(entries []contractRenewalEntry, timing contractRenewalTiming) (contractRenewalBudget, error) {
	var budget contractRenewalBudget
	if len(entries) > 256 || timing.BatchMS == 0 {
		return budget, errContractRenewalQualification
	}
	if len(entries) == 0 {
		return budget, nil
	}
	var groups [256]contractRenewalGroup
	var groupIndex [256]int
	var counts [256]uint16
	var repeated [256]bool
	groupCount := 0
	for i, entry := range entries {
		if entry.group.session == nil || entry.namespace == "" || entry.typeID == 0 || entry.digest == ([32]byte{}) || entry.sourceRemainingMS == 0 {
			return budget, errContractRenewalQualification
		}
		g := 0
		for g < groupCount && groups[g] != entry.group {
			g++
		}
		if g == groupCount {
			groups[g] = entry.group
			groupCount++
		}
		groupIndex[i] = g
		counts[g]++
		for j, previous := range entries[:i] {
			if groupIndex[j] == g && previous.namespace == entry.namespace && previous.typeID == entry.typeID {
				repeated[g] = true
			}
		}
	}
	for g := 0; g < groupCount; g++ {
		// Independent owners of the same target cannot share a request.
		// EDF can produce more batches than optimal bin packing; use the
		// complete singleton upper bound for such a group, never an
		// optimistic arrangement that the original scheduler may not take.
		if repeated[g] {
			budget.Batches += counts[g]
		} else {
			budget.Batches += (counts[g] + 7) / 8
		}
	}
	budget.Methods = uint16(len(entries))
	if timing.BatchMS > math.MaxUint64/uint64(budget.Batches) {
		return contractRenewalBudget{}, errContractRenewalQualification
	}
	required := uint64(budget.Batches) * timing.BatchMS
	for _, duration := range [...]uint64{timing.JoinMS, timing.SuspensionMS, timing.TimeErrorMS} {
		if duration > math.MaxUint64-required {
			return contractRenewalBudget{}, errContractRenewalQualification
		}
		required += duration
	}
	if required > math.MaxUint64-30000 || required+30000 > math.MaxUint64/2 {
		return contractRenewalBudget{}, errContractRenewalQualification
	}
	budget.RequiredMS, budget.AdvanceMS, budget.DeadlineMS = required, required+30000, required+20000
	budget.MinimumRemainingMS = max(uint64(300000), 2*budget.AdvanceMS)
	for _, entry := range entries {
		if entry.sourceRemainingMS < budget.MinimumRemainingMS {
			return contractRenewalBudget{}, errContractRenewalQualification
		}
	}
	return budget, nil
}

func (b contractRenewalBudget) checkOffer(offer protocolv4.AdmissionOfferBounds, previous protocolv4.AdmissionOfferBounds, now timev4.Sample) error {
	if b.Methods == 0 || b.MinimumRemainingMS == 0 || offer.Digest == ([32]byte{}) || offer.NotBeforeMS >= offer.NotAfterMS || now.UpperMS >= offer.NotAfterMS || offer.NotAfterMS-now.UpperMS < b.MinimumRemainingMS {
		return errContractRenewalQualification
	}
	// A future Offer is legal, but managed renewal must cover the whole
	// transition. Initial managed delivery requires a currently usable window.
	if previous == (protocolv4.AdmissionOfferBounds{}) {
		if now.LowerMS < offer.NotBeforeMS {
			return errContractRenewalQualification
		}
	} else if previous.Digest != offer.Digest || offer.NotBeforeMS > previous.NotAfterMS {
		return errContractRenewalQualification
	}
	return nil
}

// selectContractRenewalBatch uses earliest expiry and a persistent rotation
// for equal deadlines. The same original entries survive new registrations;
// new later targets cannot reset the cursor or overtake an older deadline.
// Returned indices are from one legal group and have distinct wire targets.
func selectContractRenewalBatch(entries []contractRenewalEntry, budget contractRenewalBudget, now uint64, cursor int) ([8]int, int, int, error) {
	var output [8]int
	if len(entries) == 0 || len(entries) > 256 || budget.Methods != uint16(len(entries)) || cursor < 0 || cursor >= len(entries) {
		return output, 0, cursor, cryptov4.ErrConfiguration
	}
	first := -1
	eligible := func(i int) bool {
		e := &entries[i]
		return !e.blocked && !e.busy && e.nextAttemptMS <= now && e.offer.Digest == e.digest && e.offer.NotAfterMS != 0 && (e.offer.NotAfterMS <= now || e.offer.NotAfterMS-now <= budget.AdvanceMS)
	}
	for offset := 0; offset < len(entries); offset++ {
		i := (cursor + offset) % len(entries)
		if eligible(i) && (first < 0 || entries[i].offer.NotAfterMS < entries[first].offer.NotAfterMS) {
			first = i
		}
	}
	if first < 0 {
		return output, 0, cursor, nil
	}
	count := 0
	for count < len(output) {
		next := -1
		for offset := 0; offset < len(entries); offset++ {
			i := (cursor + offset) % len(entries)
			if !eligible(i) || entries[i].group != entries[first].group {
				continue
			}
			duplicate := false
			for _, chosen := range output[:count] {
				if entries[i].namespace == entries[chosen].namespace && entries[i].typeID == entries[chosen].typeID {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			if next < 0 || entries[i].offer.NotAfterMS < entries[next].offer.NotAfterMS {
				next = i
			}
		}
		if next < 0 {
			break
		}
		output[count] = next
		count++
	}
	return output, count, (first + 1) % len(entries), nil
}
