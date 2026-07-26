package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRawCapacityPartRequiresPinnedPartDirectoryAndStrictJSON(t *testing.T) {
	root := canonicalCollectTestRoot(t)
	partDirectory := filepath.Join(root, "parts", "stream-wss")
	if err := os.MkdirAll(partDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	index := rawCollectionIndex{
		SchemaVersion: 1, Classification: "raw_transport_collection_part",
		Target: "bench-transport-capacity", Batch: "stream-wss",
	}
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(partDirectory, "report.partial.json")
	if err := os.WriteFile(report, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	part, err := loadRawCapacityPart(root, report)
	if err != nil {
		t.Fatal(err)
	}
	if part.root != partDirectory || part.index.Batch != "stream-wss" {
		t.Fatalf("loaded capacity part = %+v", part)
	}

	outside := filepath.Join(root, "outside.json")
	if err := os.WriteFile(outside, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRawCapacityPart(root, outside); err == nil {
		t.Fatal("accepted a capacity report outside parts/<batch>")
	}
	unknown := "{\"schema_version\":1,\"classification\":\"raw_transport_collection_part\",\"target\":\"bench-transport-capacity\",\"batch\":\"stream-wss\",\"unknown\":true}\n"
	if err := os.WriteFile(report, []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRawCapacityPart(root, report); err == nil {
		t.Fatal("accepted a capacity part with unknown JSON fields")
	}
}

func TestCapacityCollectionBatchesExactlyCoverFrozenPlan(t *testing.T) {
	plan, err := buildCollectionPlan("bench-transport-capacity", loadFixtureManifest(t), loadFixtureRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]string)
	for _, batch := range capacityCollectionBatchOrder {
		selected, err := selectCapacityCollectionBatch(plan, batch)
		if err != nil {
			t.Fatal(err)
		}
		cases := make([]scheduledCollectionJob, 0, len(selected.Jobs))
		for index, job := range selected.Jobs {
			if previous := seen[job.CaseID]; previous != "" {
				t.Fatalf("capacity case %s appears in batches %s and %s", job.CaseID, previous, batch)
			}
			seen[job.CaseID] = batch
			cases = append(cases, scheduledCollectionJob{index: index, job: job})
		}
		stages, err := scheduleCapacityCollectionBatch(batch, cases)
		if err != nil {
			t.Fatal(err)
		}
		if len(stages) != 1 || len(stages[0]) != len(capacityCollectionBatches[batch]) {
			t.Fatalf("capacity batch %s schedule = %+v", batch, stages)
		}
		for _, lane := range stages[0] {
			if time.Duration(len(lane))*2*time.Minute > capacityStageWatchdog {
				t.Fatalf("capacity batch %s lane target exceeds %s", batch, capacityStageWatchdog)
			}
		}
	}
	if len(seen) != len(plan.Jobs) || len(seen) != 12 {
		t.Fatalf("capacity batches cover %d cases, plan has %d", len(seen), len(plan.Jobs))
	}
}

func TestMergeRawCapacityIndexesRequiresOneConsistentCompleteMatrix(t *testing.T) {
	plan, err := buildCollectionPlan("bench-transport-capacity", loadFixtureManifest(t), loadFixtureRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	parts := capacityIndexFixtures(t, plan)
	merged, locations, err := mergeRawCapacityIndexes(parts, plan)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Classification != "raw_transport_collection" || merged.Batch != "" ||
		len(merged.Jobs) != 12 || len(locations) != 12 {
		t.Fatalf("merged capacity index = %+v, locations=%d", merged, len(locations))
	}

	t.Run("duplicate batch", func(t *testing.T) {
		mutated := append([]rawCapacityPart(nil), parts...)
		mutated[1] = mutated[0]
		if _, _, err := mergeRawCapacityIndexes(mutated, plan); err == nil {
			t.Fatal("accepted a duplicate capacity batch")
		}
	})
	t.Run("source drift", func(t *testing.T) {
		mutated := capacityIndexFixtures(t, plan)
		mutated[1].index.FinalSHA = strings.Repeat("f", 40)
		if _, _, err := mergeRawCapacityIndexes(mutated, plan); err == nil {
			t.Fatal("accepted capacity parts from different source commits")
		}
	})
	t.Run("missing job", func(t *testing.T) {
		mutated := capacityIndexFixtures(t, plan)
		mutated[0].index.Jobs = nil
		if _, _, err := mergeRawCapacityIndexes(mutated, plan); err == nil {
			t.Fatal("accepted an incomplete capacity batch")
		}
	})
	t.Run("digest drift", func(t *testing.T) {
		mutated := capacityIndexFixtures(t, plan)
		mutated[0].index.Jobs[0].ReportSHA = strings.Repeat("z", 64)
		if _, _, err := mergeRawCapacityIndexes(mutated, plan); err == nil {
			t.Fatal("accepted an invalid report digest")
		}
	})
}

func capacityIndexFixtures(t *testing.T, plan collectionPlan) []rawCapacityPart {
	t.Helper()
	const finalSHA = "1111111111111111111111111111111111111111"
	inputs := map[string]string{
		"manifest": strings.Repeat("2", 64), "registry": strings.Repeat("3", 64),
		"runner_executable": strings.Repeat("4", 64),
	}
	parts := make([]rawCapacityPart, 0, len(capacityCollectionBatchOrder))
	for _, batch := range capacityCollectionBatchOrder {
		selected, err := selectCapacityCollectionBatch(plan, batch)
		if err != nil {
			t.Fatal(err)
		}
		index := rawCollectionIndex{
			SchemaVersion: 1, Classification: "raw_transport_collection_part",
			Target: "bench-transport-capacity", Batch: batch,
			BaseSHA: "0000000000000000000000000000000000000000", FinalSHA: finalSHA,
			InputSHA256: cloneStringMap(inputs),
		}
		for _, job := range selected.Jobs {
			index.Jobs = append(index.Jobs, rawJobRecord{
				ID: job.ID, CaseIDs: []string{job.CaseID}, SourceSHA: finalSHA,
				RunnerExecutableSHA256: inputs["runner_executable"],
				CommandSHA256:          strings.Repeat("5", 64), ReportSHA: strings.Repeat("6", 64),
				Directory: "jobs/" + job.ID,
			})
		}
		parts = append(parts, rawCapacityPart{root: "/parts/" + batch, index: index})
	}
	return parts
}

func TestCapacityCollectionBatchRejectsDrift(t *testing.T) {
	plan, err := buildCollectionPlan("bench-transport-capacity", loadFixtureManifest(t), loadFixtureRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectCapacityCollectionBatch(plan, "unknown"); err == nil {
		t.Fatal("accepted an unknown capacity batch")
	}
	selected, err := selectCapacityCollectionBatch(plan, "stream-wss")
	if err != nil {
		t.Fatal(err)
	}
	cases := []scheduledCollectionJob{{job: selected.Jobs[0]}, {job: selected.Jobs[0]}}
	if _, err := scheduleCapacityCollectionBatch("stream-wss", cases); err == nil {
		t.Fatal("accepted a duplicate capacity case")
	}
	if _, err := scheduleCapacityCollectionBatch("stream-wss", nil); err == nil {
		t.Fatal("accepted a missing capacity case")
	}
}
