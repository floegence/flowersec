package main

import (
	"errors"
	"fmt"
	"sort"
)

// The batches keep each invocation below the global hard stop while preserving
// the frozen case contracts. Stream-heavy cases run alone on the 15 GiB runner.
var capacityCollectionBatches = map[string][][]string{
	"stream-wss":    {{"CAP-STREAM-WT-WSS-100X128"}},
	"stream-quic":   {{"CAP-STREAM-WT-QUIC-100X128"}},
	"stream-direct": {{"CAP-STREAM-WT-DIRECT-100X128"}},
	"direct-carriers": {
		{"CAP-DIRECT-WSS-1000"},
		{"CAP-DIRECT-QUIC-1000"},
		{"CAP-DIRECT-WT-1000"},
	},
	"tunnel-matrix": {{
		"CAP-QQ-1000",
		"CAP-QW-1000",
		"CAP-WQ-1000",
		"CAP-WW-1000",
	}},
	"webtransport-quic": {{"CAP-TUNNEL-WT-QUIC-1000"}},
	"webtransport-wss":  {{"CAP-TUNNEL-WT-WSS-1000"}},
}

var capacityCollectionBatchOrder = []string{
	"stream-wss",
	"stream-quic",
	"stream-direct",
	"direct-carriers",
	"tunnel-matrix",
	"webtransport-quic",
	"webtransport-wss",
}

func selectCapacityCollectionBatch(plan collectionPlan, batch string) (collectionPlan, error) {
	lanes, ok := capacityCollectionBatches[batch]
	if !ok {
		return collectionPlan{}, fmt.Errorf("unknown frozen capacity batch %q", batch)
	}
	if plan.Target != "bench-transport-capacity" || len(plan.Missing) != 0 {
		return collectionPlan{}, errors.New("capacity batch requires the complete frozen capacity plan")
	}
	wanted := make(map[string]struct{})
	for _, lane := range lanes {
		for _, id := range lane {
			if _, duplicate := wanted[id]; duplicate {
				return collectionPlan{}, fmt.Errorf("capacity batch %s repeats case %s", batch, id)
			}
			wanted[id] = struct{}{}
		}
	}
	selected := collectionPlan{Target: plan.Target}
	for _, job := range plan.Jobs {
		if job.CaseOwner != "bench-transport-capacity" || job.CaseID == "" {
			return collectionPlan{}, errors.New("capacity plan contains a non-exact producer job")
		}
		if _, ok := wanted[job.CaseID]; ok {
			selected.Jobs = append(selected.Jobs, job)
			delete(wanted, job.CaseID)
		}
	}
	if len(wanted) != 0 {
		missing := make([]string, 0, len(wanted))
		for id := range wanted {
			missing = append(missing, id)
		}
		sort.Strings(missing)
		return collectionPlan{}, fmt.Errorf("capacity batch %s is missing frozen cases: %v", batch, missing)
	}
	return selected, nil
}

func scheduleCapacityCollectionBatch(batch string, cases []scheduledCollectionJob) ([][][]scheduledCollectionJob, error) {
	laneIDs, ok := capacityCollectionBatches[batch]
	if !ok {
		return nil, fmt.Errorf("unknown frozen capacity batch %q", batch)
	}
	byID := make(map[string]scheduledCollectionJob, len(cases))
	for _, scheduled := range cases {
		if scheduled.job.CaseID == "" {
			return nil, errors.New("capacity batch schedule requires exact case IDs")
		}
		if _, duplicate := byID[scheduled.job.CaseID]; duplicate {
			return nil, fmt.Errorf("capacity batch schedule contains duplicate case %s", scheduled.job.CaseID)
		}
		byID[scheduled.job.CaseID] = scheduled
	}
	lanes := make([][]scheduledCollectionJob, len(laneIDs))
	for laneIndex, ids := range laneIDs {
		for _, id := range ids {
			scheduled, exists := byID[id]
			if !exists {
				return nil, fmt.Errorf("capacity batch %s is missing frozen case %s", batch, id)
			}
			lanes[laneIndex] = append(lanes[laneIndex], scheduled)
			delete(byID, id)
		}
	}
	if len(byID) != 0 {
		unknown := make([]string, 0, len(byID))
		for id := range byID {
			unknown = append(unknown, id)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("capacity batch %s contains unknown cases: %v", batch, unknown)
	}
	return [][][]scheduledCollectionJob{lanes}, nil
}
