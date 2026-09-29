package sessionv4

import (
	"math"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func renewalEntries(count int, groups int) []contractRenewalEntry {
	entries := make([]contractRenewalEntry, count)
	sessions := make([]EnvironmentSession, groups)
	for i := range entries {
		digest := [32]byte{byte(i + 1), byte((i + 1) >> 8)}
		entries[i] = contractRenewalEntry{group: contractRenewalGroup{session: &sessions[i%groups]}, namespace: "example", typeID: uint32(i + 1), digest: digest, offer: protocolv4.AdmissionOfferBounds{Digest: digest, NotBeforeMS: 1, NotAfterMS: 1000000}, sourceRemainingMS: 2000000}
	}
	return entries
}

func TestContractRenewalQualificationCountsActualSourceGroups(t *testing.T) {
	timing := contractRenewalTiming{BatchMS: 2000, JoinMS: 10000, SuspensionMS: 60000, TimeErrorMS: 4000}
	for _, test := range []struct {
		methods, groups                        int
		batches                                uint16
		required, advance, deadline, remaining uint64
	}{
		{71, 1, 9, 92000, 122000, 112000, 300000},
		{142, 2, 18, 110000, 140000, 130000, 300000},
		{256, 1, 32, 138000, 168000, 158000, 336000},
		{256, 256, 256, 586000, 616000, 606000, 1232000},
	} {
		entries := renewalEntries(test.methods, test.groups)
		budget, err := qualifyContractRenewal(entries, timing)
		if err != nil || budget.Batches != test.batches || budget.RequiredMS != test.required || budget.AdvanceMS != test.advance || budget.DeadlineMS != test.deadline || budget.MinimumRemainingMS != test.remaining {
			t.Fatal(test, budget, err)
		}
		entries[0].blocked = true
		blocked, err := qualifyContractRenewal(entries, timing)
		if err != nil || blocked != budget {
			t.Fatal("blocked responsibility disappeared", blocked, err)
		}
		entries[0].sourceRemainingMS = test.remaining - 1
		if _, err = qualifyContractRenewal(entries, timing); err != errContractRenewalQualification {
			t.Fatal(err)
		}
	}
	if _, err := qualifyContractRenewal(renewalEntries(2, 1), contractRenewalTiming{BatchMS: math.MaxUint64}); err != errContractRenewalQualification {
		t.Fatal("overflow accepted", err)
	}
}

func TestContractRenewalSelectionPreservesEDFAndFairRotation(t *testing.T) {
	entries := renewalEntries(18, 2)
	budget, err := qualifyContractRenewal(entries, contractRenewalTiming{BatchMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	entries[7].offer.NotAfterMS--
	batch, count, cursor, err := selectContractRenewalBatch(entries, budget, 1000000, 0)
	if err != nil || count != 8 || batch[0] != 7 || cursor != 8 {
		t.Fatal(batch, count, cursor, err)
	}
	for _, i := range batch[:count] {
		if entries[i].group != entries[7].group {
			t.Fatal("crossed Session")
		}
		entries[i].busy = true
	}
	batch, count, _, err = selectContractRenewalBatch(entries, budget, 1000000, cursor)
	if err != nil || count != 8 || batch[0] != 8 {
		t.Fatal(batch, count, err)
	}
	for i := range entries {
		entries[i].busy = false
		entries[i].offer.NotAfterMS = 1000000
	}
	batch, _, cursor, err = selectContractRenewalBatch(entries, budget, 1000000, 0)
	if err != nil || batch[0] != 0 || cursor != 1 {
		t.Fatal(batch, cursor, err)
	}
	batch, _, _, err = selectContractRenewalBatch(entries, budget, 1000000, cursor)
	if err != nil || batch[0] != 1 {
		t.Fatal("equal deadline rotation reset", batch, err)
	}
	entries[1].nextAttemptMS = 1000001
	entries[3].blocked = true
	batch, count, _, err = selectContractRenewalBatch(entries, budget, 1000000, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range batch[:count] {
		if i == 1 || i == 3 {
			t.Fatal("blocked/backoff selected")
		}
	}
}

func TestContractRenewalQualificationPreservesDuplicateOwners(t *testing.T) {
	entries := renewalEntries(16, 1)
	for i := range entries {
		entries[i].typeID = 1
	}
	budget, err := qualifyContractRenewal(entries, contractRenewalTiming{BatchMS: 2000})
	if err != nil || budget.Batches != 16 {
		t.Fatal("duplicate owners collapsed", budget, err)
	}
	batch, count, _, err := selectContractRenewalBatch(entries, budget, 1000000, 0)
	if err != nil || count != 1 || batch[0] != 0 {
		t.Fatal(batch, count, err)
	}
}
