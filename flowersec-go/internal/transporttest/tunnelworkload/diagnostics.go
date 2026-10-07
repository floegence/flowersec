package tunnelworkload

import (
	"encoding/json"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"strings"
	"sync"
	"time"
)

type establishmentStageDiagnostic struct {
	Role         uint8  `json:"role,omitempty"`
	CandidateID  string `json:"candidate_id,omitempty"`
	Carrier      string `json:"carrier,omitempty"`
	Stage        string `json:"stage"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	DurationMS   int64  `json:"duration_ms"`
	Status       string `json:"status"`
	FirstFailure string `json:"first_failure,omitempty"`
}

type establishmentTimeline struct {
	mu           sync.Mutex
	stages       []establishmentStageDiagnostic
	firstFailure string
}

func (timeline *establishmentTimeline) record(
	role uint8,
	candidateID string,
	carrierKind carrier.Kind,
	stage string,
	started, finished time.Time,
	err error,
) {
	if timeline == nil {
		return
	}
	duration := finished.Sub(started)
	if duration < 0 {
		duration = 0
	}
	diagnostic := establishmentStageDiagnostic{
		Role: role, CandidateID: candidateID, Carrier: string(carrierKind), Stage: stage,
		StartedAt: started.UTC().Format(time.RFC3339Nano), FinishedAt: finished.UTC().Format(time.RFC3339Nano),
		DurationMS: duration.Milliseconds(), Status: "GREEN",
	}
	timeline.mu.Lock()
	defer timeline.mu.Unlock()
	if err != nil {
		diagnostic.Status = "RED"
		diagnostic.FirstFailure = compactStageFailure(err)
		if timeline.firstFailure == "" {
			timeline.firstFailure = diagnostic.FirstFailure
		}
	}
	timeline.stages = append(timeline.stages, diagnostic)
}

func (timeline *establishmentTimeline) compact() string {
	if timeline == nil {
		return `{"stages":[],"first_failure":""}`
	}
	timeline.mu.Lock()
	stages := append([]establishmentStageDiagnostic(nil), timeline.stages...)
	firstFailure := timeline.firstFailure
	timeline.mu.Unlock()
	payload, err := json.Marshal(struct {
		Stages       []establishmentStageDiagnostic `json:"stages"`
		FirstFailure string                         `json:"first_failure"`
	}{Stages: stages, FirstFailure: firstFailure})
	if err != nil {
		return `{"stages":[],"first_failure":"diagnostic encoding failed"}`
	}
	return string(payload)
}

func compactStageFailure(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	const maximum = 256
	if len(message) > maximum {
		message = message[:maximum]
	}
	return message
}
