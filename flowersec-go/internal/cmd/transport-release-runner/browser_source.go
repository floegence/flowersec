package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

type browserArtifactSource struct {
	issue     func() (browserServerArtifact, error)
	profile   transportrelease.ProfilePlan
	topology  string
	runNumber int

	mu       sync.Mutex
	records  map[string]*browserArtifactRecord
	acquired map[string]bool
	wg       sync.WaitGroup
	errors   chan error
	ctx      context.Context
	cancel   context.CancelCauseFunc
}

type browserServerArtifact interface {
	ArtifactJSON() string
	AwaitServer(context.Context) (flowersession.SessionV2, error)
	Cancel()
}

type startableBrowserServerArtifact interface {
	Start()
}

type browserArtifactRecord struct {
	artifact browserServerArtifact
	phase    string
	spent    bool
}

type browserArtifactRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	Topology      string `json:"topology,omitempty"`
	ProfileID     string `json:"profile_id,omitempty"`
	RunNumber     int    `json:"run_number,omitempty"`
	Phase         string `json:"phase,omitempty"`
	Count         int    `json:"count,omitempty"`
	SpendToken    string `json:"spend_token,omitempty"`
}

type browserArtifactResponse struct {
	SchemaVersion int                       `json:"schema_version"`
	Artifacts     []browserArtifactEnvelope `json:"artifacts"`
}

type browserArtifactEnvelope struct {
	ArtifactJSON string `json:"artifact_json"`
	SpendToken   string `json:"spend_token"`
}

func newBrowserArtifactSource(endpoint *transportrelease.ProductDirectEndpoint, profile transportrelease.ProfilePlan, topology string, runNumber int) (*browserArtifactSource, error) {
	if endpoint == nil || topology != "browser_webtransport" || runNumber < 1 || profile.ID == "" {
		return nil, errors.New("browser artifact source is not initialized")
	}
	return newBrowserArtifactSourceWithIssuer(func() (browserServerArtifact, error) {
		return endpoint.IssueBrowserArtifact()
	}, profile, topology, runNumber)
}

func newBrowserTunnelArtifactSource(endpoint *tunnelworkload.BrowserEndpoint, profile transportrelease.ProfilePlan, topology string, runNumber int) (*browserArtifactSource, error) {
	if endpoint == nil || !supportedBrowserTunnelTopology(topology) || runNumber < 1 || profile.ID == "" {
		return nil, errors.New("browser tunnel artifact source is not initialized")
	}
	return newBrowserArtifactSourceWithIssuer(func() (browserServerArtifact, error) {
		return endpoint.IssueBrowserArtifact()
	}, profile, topology, runNumber)
}

func newBrowserArtifactSourceWithIssuer(issue func() (browserServerArtifact, error), profile transportrelease.ProfilePlan, topology string, runNumber int) (*browserArtifactSource, error) {
	if issue == nil {
		return nil, errors.New("browser artifact issuer is required")
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	return &browserArtifactSource{
		issue: issue, profile: profile, topology: topology, runNumber: runNumber,
		records: make(map[string]*browserArtifactRecord), acquired: make(map[string]bool),
		errors: make(chan error, profile.Cold.Operations+1),
		ctx:    ctx, cancel: cancel,
	}, nil
}

func (source *browserArtifactSource) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
		http.Error(writer, "request rejected", http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var input browserArtifactRequest
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || input.SchemaVersion != 1 {
		http.Error(writer, "request rejected", http.StatusBadRequest)
		return
	}
	switch input.Action {
	case "acquire":
		source.acquire(writer, input)
	case "spend":
		source.spend(writer, input)
	default:
		http.Error(writer, "request rejected", http.StatusBadRequest)
	}
}

func (source *browserArtifactSource) acquire(writer http.ResponseWriter, input browserArtifactRequest) {
	wantCount := 0
	switch input.Phase {
	case "cold":
		wantCount = source.profile.Cold.Operations
	case "session":
		wantCount = 1
	}
	if input.Topology != source.topology || input.ProfileID != source.profile.ID || input.RunNumber != source.runNumber ||
		wantCount == 0 || input.Count != wantCount || input.SpendToken != "" {
		http.Error(writer, "request rejected", http.StatusBadRequest)
		return
	}
	source.mu.Lock()
	if source.acquired[input.Phase] {
		source.mu.Unlock()
		http.Error(writer, "artifact batch already acquired", http.StatusConflict)
		return
	}
	source.acquired[input.Phase] = true
	source.mu.Unlock()

	envelopes := make([]browserArtifactEnvelope, 0, wantCount)
	issued := make([]*browserArtifactRecord, 0, wantCount)
	for range wantCount {
		artifact, err := source.issue()
		if err != nil {
			source.cancelIssued(issued)
			http.Error(writer, "artifact issuance failed", http.StatusInternalServerError)
			return
		}
		token, err := newBrowserSpendToken()
		if err != nil {
			artifact.Cancel()
			source.cancelIssued(issued)
			http.Error(writer, "artifact issuance failed", http.StatusInternalServerError)
			return
		}
		record := &browserArtifactRecord{artifact: artifact, phase: input.Phase}
		source.mu.Lock()
		if _, exists := source.records[token]; exists {
			source.mu.Unlock()
			artifact.Cancel()
			source.cancelIssued(issued)
			http.Error(writer, "artifact issuance failed", http.StatusInternalServerError)
			return
		}
		source.records[token] = record
		source.mu.Unlock()
		issued = append(issued, record)
		envelopes = append(envelopes, browserArtifactEnvelope{ArtifactJSON: artifact.ArtifactJSON(), SpendToken: token})
	}
	for _, record := range issued {
		source.wg.Add(1)
		go source.serve(record)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(browserArtifactResponse{SchemaVersion: 1, Artifacts: envelopes})
}

func (source *browserArtifactSource) spend(writer http.ResponseWriter, input browserArtifactRequest) {
	if input.SpendToken == "" || input.Topology != "" || input.ProfileID != "" || input.RunNumber != 0 || input.Phase != "" || input.Count != 0 {
		http.Error(writer, "request rejected", http.StatusBadRequest)
		return
	}
	source.mu.Lock()
	record := source.records[input.SpendToken]
	if record == nil || record.spent {
		source.mu.Unlock()
		http.Error(writer, "artifact spend rejected", http.StatusConflict)
		return
	}
	if startable, ok := record.artifact.(startableBrowserServerArtifact); ok {
		startable.Start()
	}
	record.spent = true
	source.mu.Unlock()
	writer.WriteHeader(http.StatusNoContent)
}

func (source *browserArtifactSource) serve(record *browserArtifactRecord) {
	defer source.wg.Done()
	ctx, cancel := context.WithTimeout(source.ctx, time.Duration(source.profile.CellWatchdogMinutes)*time.Minute)
	defer cancel()
	session, err := record.artifact.AwaitServer(ctx)
	if err == nil && record.phase == "session" {
		err = transportrelease.ServeBrowserBulk(ctx, session, []int64{
			source.profile.Bulk.WarmupBytesPerDirection,
			source.profile.Bulk.ScoreBytesPerDirection,
		})
	}
	if err == nil {
		err = closeBrowserServerSession(session, time.Duration(source.profile.CleanupDeadlineSeconds)*time.Second)
	}
	if err != nil {
		source.errors <- fmt.Errorf("browser %s session: %w", record.phase, err)
	}
}

func closeBrowserServerSession(session flowersession.SessionV2, deadline time.Duration) error {
	if session == nil {
		return errors.New("browser server session is unavailable")
	}
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case <-session.Termination():
		return normalizeBrowserServerTermination(session.WaitClosed(context.Background()))
	case <-timer.C:
		if err := session.Close(); err != nil {
			return err
		}
		forceTimer := time.NewTimer(time.Second)
		defer forceTimer.Stop()
		select {
		case <-session.Termination():
			return normalizeBrowserServerTermination(session.WaitClosed(context.Background()))
		case <-forceTimer.C:
			return errors.New("browser server session did not terminate after forced close")
		}
	}
}

func normalizeBrowserServerTermination(err error) error {
	if err == nil || errors.Is(err, flowersession.ErrSessionClosed) {
		return nil
	}
	return fmt.Errorf("browser server session terminated unexpectedly: %w", err)
}

func (source *browserArtifactSource) Finalize(ctx context.Context, abort bool) error {
	if abort {
		source.cancel(errors.New("browser collector stopped before completing the workload"))
	}
	defer source.cancel(errors.New("browser artifact source finalized"))
	done := make(chan struct{})
	go func() {
		source.wg.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-done:
	}
	source.mu.Lock()
	var result error
	for token, record := range source.records {
		if !record.spent {
			result = errors.Join(result, fmt.Errorf("browser artifact %s was not spent", token))
		}
	}
	if !source.acquired["cold"] || !source.acquired["session"] {
		result = errors.Join(result, errors.New("browser collector did not acquire both workload phases"))
	}
	source.mu.Unlock()
	close(source.errors)
	for err := range source.errors {
		result = errors.Join(result, err)
	}
	return result
}

func (source *browserArtifactSource) cancelIssued(records []*browserArtifactRecord) {
	for _, record := range records {
		record.artifact.Cancel()
	}
}

func newBrowserSpendToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}
