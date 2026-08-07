package acceptance

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
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest/tunnelworkload"
)

type browserArtifactSource struct {
	issue          func() (browserServerArtifact, error)
	profile        transporttest.ProfilePlan
	topology       string
	runNumber      int
	coldDiagnostic bool
	workloadStart  func() error
	startOnce      sync.Once
	startErr       error

	mu             sync.Mutex
	records        map[string]*browserArtifactRecord
	acquired       map[string]bool
	wg             sync.WaitGroup
	errors         chan error
	ctx            context.Context
	cancel         context.CancelCauseFunc
	upgradeError   string
	admissionError string
}

type browserServerArtifact interface {
	ArtifactJSON() string
	AwaitServer(context.Context) (flowersession.SessionV2, error)
	Cancel()
}

type startableBrowserServerArtifact interface {
	Start(context.Context) error
}

type browserArtifactRecord struct {
	artifact browserServerArtifact
	phase    string
	started  bool
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

func newDirectBrowserSource(endpoint *transporttest.ProductDirectEndpoint, profile transporttest.ProfilePlan, topology string, runNumber int) (*browserArtifactSource, error) {
	if endpoint == nil || topology != browserDirectTopology || runNumber < 1 || profile.ID == "" {
		return nil, errors.New("browser source is not initialized")
	}
	source, err := newBrowserSource(func() (browserServerArtifact, error) { return endpoint.IssueBrowserArtifact() }, profile, topology, runNumber)
	if err == nil {
		endpoint.SetWebTransportUpgradeDiagnostic(source.recordUpgradeError)
		endpoint.SetWebTransportAdmissionDiagnostic(source.recordAdmissionError)
	}
	return source, err
}

func newTunnelBrowserSource(endpoint *tunnelworkload.BrowserEndpoint, profile transporttest.ProfilePlan, topology string, runNumber int) (*browserArtifactSource, error) {
	if endpoint == nil || !supportedBrowserTopology(topology) || topology == browserDirectTopology || runNumber < 1 || profile.ID == "" {
		return nil, errors.New("browser tunnel source is not initialized")
	}
	return newBrowserSource(func() (browserServerArtifact, error) { return endpoint.IssueBrowserArtifact() }, profile, topology, runNumber)
}

func newBrowserSource(issue func() (browserServerArtifact, error), profile transporttest.ProfilePlan, topology string, runNumber int) (*browserArtifactSource, error) {
	if issue == nil {
		return nil, errors.New("browser artifact issuer is required")
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	return &browserArtifactSource{
		issue: issue, profile: profile, topology: topology, runNumber: runNumber,
		records: make(map[string]*browserArtifactRecord), acquired: make(map[string]bool),
		errors: make(chan error, profile.Cold.Operations+1), ctx: ctx, cancel: cancel,
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
	case "start":
		source.start(writer, request.Context(), input)
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

func (source *browserArtifactSource) start(writer http.ResponseWriter, requestContext context.Context, input browserArtifactRequest) {
	if input.SpendToken == "" || input.Topology != "" || input.ProfileID != "" || input.RunNumber != 0 || input.Phase != "" || input.Count != 0 {
		http.Error(writer, "request rejected", http.StatusBadRequest)
		return
	}
	source.mu.Lock()
	record := source.records[input.SpendToken]
	if record == nil || record.started || record.spent {
		source.mu.Unlock()
		http.Error(writer, "artifact start rejected", http.StatusConflict)
		return
	}
	source.mu.Unlock()
	if err := source.startWorkload(); err != nil {
		http.Error(writer, "workload start rejected", http.StatusServiceUnavailable)
		return
	}
	source.mu.Lock()
	if record.started || record.spent {
		source.mu.Unlock()
		http.Error(writer, "artifact start rejected", http.StatusConflict)
		return
	}
	record.started = true
	source.mu.Unlock()
	if startable, ok := record.artifact.(startableBrowserServerArtifact); ok {
		startContext, cancelStart := context.WithTimeout(
			requestContext,
			time.Duration(source.profile.Cold.OperationDeadlineSeconds)*time.Second,
		)
		defer cancelStart()
		if err := startable.Start(startContext); err != nil {
			http.Error(writer, "artifact peer start failed", http.StatusServiceUnavailable)
			return
		}
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (source *browserArtifactSource) startWorkload() error {
	source.startOnce.Do(func() {
		if source.workloadStart == nil {
			source.startErr = errors.New("workload start callback is unavailable")
			return
		}
		source.startErr = source.workloadStart()
	})
	return source.startErr
}

func (source *browserArtifactSource) spend(writer http.ResponseWriter, input browserArtifactRequest) {
	if input.SpendToken == "" || input.Topology != "" || input.ProfileID != "" || input.RunNumber != 0 || input.Phase != "" || input.Count != 0 {
		http.Error(writer, "request rejected", http.StatusBadRequest)
		return
	}
	source.mu.Lock()
	record := source.records[input.SpendToken]
	if record == nil || !record.started || record.spent {
		source.mu.Unlock()
		http.Error(writer, "artifact spend rejected", http.StatusConflict)
		return
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
		err = transporttest.ServeBrowserBulk(ctx, session, []int64{
			source.profile.Bulk.WarmupBytesPerDirection, source.profile.Bulk.ScoreBytesPerDirection,
		})
	}
	if err == nil {
		err = closeBrowserServerSession(ctx, session, browserServerSessionCloseDeadline(source.profile, record.phase))
	}
	if err != nil {
		source.errors <- fmt.Errorf("browser %s session: %w", record.phase, err)
	}
}

func browserServerSessionCloseDeadline(profile transporttest.ProfilePlan, phase string) time.Duration {
	deadline := time.Duration(profile.CleanupDeadlineSeconds) * time.Second
	if phase == "cold" {
		deadline += time.Duration(profile.Cold.PhaseDeadlineSeconds) * time.Second
	}
	return deadline
}

func closeBrowserServerSession(ctx context.Context, session flowersession.SessionV2, deadline time.Duration) error {
	if session == nil {
		return errors.New("browser server session is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if deadline <= 0 {
		return errors.New("browser server session close deadline is invalid")
	}
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	var triggerErr error
	select {
	case <-session.Termination():
		return nil
	case <-ctx.Done():
		triggerErr = context.Cause(ctx)
	case <-timer.C:
	}
	if err := session.Close(); err != nil {
		return errors.Join(triggerErr, err)
	}
	forceTimer := time.NewTimer(time.Second)
	defer forceTimer.Stop()
	select {
	case <-session.Termination():
		return triggerErr
	case <-forceTimer.C:
		return errors.Join(triggerErr, errors.New("browser server session did not terminate after forced close"))
	}
}

func (source *browserArtifactSource) Finalize(ctx context.Context, abort bool) error {
	if abort {
		source.cancel(errors.New("browser runner stopped before completing the workload"))
	} else {
		source.cancel(errors.New("browser source finalized"))
	}
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
	unspent := 0
	for _, record := range source.records {
		if !record.spent {
			unspent++
		}
	}
	if unspent > 0 {
		result = errors.Join(result, fmt.Errorf("%d browser artifacts were not spent", unspent))
	}
	if !source.acquired["cold"] || (!source.coldDiagnostic && !source.acquired["session"]) {
		result = errors.Join(result, errors.New("browser runner did not acquire both workload phases"))
	}
	if abort && source.upgradeError != "" {
		result = errors.Join(result, fmt.Errorf("server WebTransport upgrade: %s", source.upgradeError))
	}
	if abort && source.admissionError != "" {
		result = errors.Join(result, fmt.Errorf("server WebTransport admission: %s", source.admissionError))
	}
	source.mu.Unlock()
	close(source.errors)
	for err := range source.errors {
		result = errors.Join(result, err)
	}
	return result
}

func (source *browserArtifactSource) recordUpgradeError(err error) {
	if source == nil || err == nil {
		return
	}
	source.mu.Lock()
	if source.upgradeError == "" {
		source.upgradeError = boundedText(err.Error(), 512)
	}
	source.mu.Unlock()
}

func (source *browserArtifactSource) recordAdmissionError(err error) {
	if source == nil || err == nil {
		return
	}
	source.mu.Lock()
	if source.admissionError == "" {
		source.admissionError = boundedText(err.Error(), 512)
	}
	source.mu.Unlock()
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
