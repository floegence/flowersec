package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBrowserCollectorFailurePreservesFirstErrorBesideRunEvidence(t *testing.T) {
	root := t.TempDir()
	evidenceDirectory := filepath.Join(root, "artifacts", "edge-v1-browser-tunnel-wt-quic-run-001")
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	plan := browserCollectorPlan{
		SchemaVersion:     1,
		Topology:          "browser_tunnel_wt_quic",
		ProfileID:         "edge-v1",
		RunNumber:         1,
		EvidenceDirectory: evidenceDirectory,
	}

	path, err := writeBrowserCollectorFailure(plan, []byte(`{"status":"failed","failure":{"phase":"session","message":"first failure"}}`), []byte("collector stdout"), []byte("collector stderr"))
	if err != nil {
		t.Fatal(err)
	}
	if path != evidenceDirectory+".collector-failure.json" {
		t.Fatalf("failure evidence path = %q", path)
	}
	if relative, err := filepath.Rel(evidenceDirectory, path); err != nil || relative == "." || relative[0] != '.' {
		t.Fatalf("failure evidence must stay outside the formal run inventory: relative=%q err=%v", relative, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("failure evidence mode = %o, want 600", info.Mode().Perm())
	}
	var value struct {
		SchemaVersion  int             `json:"schema_version"`
		Classification string          `json:"classification"`
		Topology       string          `json:"topology"`
		ProfileID      string          `json:"profile_id"`
		RunNumber      int             `json:"run_number"`
		Result         json.RawMessage `json:"collector_result"`
		Stdout         string          `json:"stdout"`
		Stderr         string          `json:"stderr"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	var collectorResult struct {
		Status  string `json:"status"`
		Failure struct {
			Phase   string `json:"phase"`
			Message string `json:"message"`
		} `json:"failure"`
	}
	if err := json.Unmarshal(value.Result, &collectorResult); err != nil {
		t.Fatal(err)
	}
	if value.SchemaVersion != 1 || value.Classification != "browser_collector_failure" ||
		value.Topology != plan.Topology || value.ProfileID != plan.ProfileID || value.RunNumber != plan.RunNumber ||
		collectorResult.Status != "failed" || collectorResult.Failure.Phase != "session" || collectorResult.Failure.Message != "first failure" ||
		value.Stdout != "collector stdout" || value.Stderr != "collector stderr" {
		t.Fatalf("failure evidence = %+v collector result = %+v", value, collectorResult)
	}
}
