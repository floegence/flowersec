package flowersec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type retryContract struct {
	Decisions map[string]struct {
		Action          RetryAction `json:"action"`
		Retryable       bool        `json:"retryable"`
		RefreshArtifact bool        `json:"refresh_artifact"`
		CallerCanceled  bool        `json:"caller_canceled"`
		SessionClosed   bool        `json:"session_closed"`
	} `json:"decisions"`
	Connect []retryContractCase `json:"connect"`
	Session []retryContractCase `json:"session"`
}

type retryContractCase struct {
	Decision string              `json:"decision"`
	Codes    map[string][]string `json:"codes"`
}

func TestPublicErrorClassificationMatchesSharedContract(t *testing.T) {
	contract := loadRetryContract(t)
	for _, test := range contract.Connect {
		want := contract.Decisions[test.Decision]
		for _, code := range test.Codes["go"] {
			got := ClassifyConnectError(&ConnectError{code: ConnectErrorCode(code)})
			assertRetryClassification(t, got, want)
		}
	}
	for _, test := range contract.Session {
		want := contract.Decisions[test.Decision]
		for _, code := range test.Codes["go"] {
			got := ClassifySessionError(&SessionError{code: SessionErrorCode(code)})
			assertRetryClassification(t, got, want)
		}
	}
}

func loadRetryContract(t *testing.T) retryContract {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "stability", "public_error_classification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract retryContract
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	return contract
}

func assertRetryClassification(t *testing.T, got ErrorRetryClassification, want struct {
	Action          RetryAction `json:"action"`
	Retryable       bool        `json:"retryable"`
	RefreshArtifact bool        `json:"refresh_artifact"`
	CallerCanceled  bool        `json:"caller_canceled"`
	SessionClosed   bool        `json:"session_closed"`
}) {
	t.Helper()
	if got.Action != want.Action || got.Retryable != want.Retryable ||
		got.RefreshArtifact != want.RefreshArtifact || got.CallerCanceled != want.CallerCanceled ||
		got.SessionClosed != want.SessionClosed {
		t.Fatalf("classification = %+v, want %+v", got, want)
	}
}
