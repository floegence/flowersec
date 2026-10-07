// Package browserworkload assembles original current browser engineering peers.
// It adds no SDK credential/source surface or transport authorization protocol.
package browserworkload

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest"
)

const maxBatchBytes = 16 << 20
const maxItemBytes = 256 << 10
const maxRequestBytes = 4096

// Artifact is implemented only by original Go direct/tunnel publication owners.
// Each position retains its actual native preparation, accepted Session and
// cleanup. The browser's acquisition copy is never imported into this owner.
type Artifact interface {
	ArtifactJSON() string
	Start(context.Context) error
	AwaitServer(context.Context) (*fs.Session, error)
	OriginalBrowserRunnerDeclaration(context.Context, interopharness.BrowserRuntimeObservation, *interopharness.BrowserNativeInstallation, uint32) (map[string]any, error)
	InstallOriginalBrowserRunner(context.Context, *interopharness.BrowserRunnerInstallationOwner, interopharness.BrowserRuntimeObservation, map[string]any) error
	CheckOriginalBrowserBatchWindow(context.Context, uint64, uint64) error
	CloseOriginalBrowser(context.Context) error
}

type batchPhase struct {
	profile     string
	phase       string
	count       int
	plan        transporttest.ProfilePlan
	used        bool
	first, last int
}
type batchRecord struct {
	token                                                     string
	artifact                                                  Artifact
	phase                                                     int
	state                                                     string
	ctx                                                       context.Context
	cancel                                                    context.CancelCauseFunc
	startDone, admissionDone, done                            chan struct{}
	startErr, admissionErr, err                               error
	observedSpend                                             bool
	startClosed, admissionClosed, doneClosed, cleanupComplete bool
}
type sourceRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	Topology      string `json:"topology,omitempty"`
	ProfileID     string `json:"profile_id,omitempty"`
	RunNumber     int    `json:"run_number,omitempty"`
	Phase         string `json:"phase,omitempty"`
	Count         int    `json:"count,omitempty"`
	SpendToken    string `json:"spend_token,omitempty"`
}
type delivery struct {
	ArtifactJSON string `json:"artifact_json"`
	SpendToken   string `json:"spend_token"`
}

// Source owns a single finite run's original batch-call positions, tokens and
// worker queue. The local opaque endpoint capability is an engineering host
// channel; tokens provide accounting and cancellation, never spend authority.
// Unknown delivery, canceled acquisition and late cleanup permanently retain
// their consumed local positions. There is no query/reopen/retry/replenish API.
type Source struct {
	mu                sync.Mutex
	ctx               context.Context
	cancel            context.CancelCauseFunc
	path              string
	topology          string
	run               int
	phases            []batchPhase
	records           []*batchRecord
	byToken           map[string]*batchRecord
	next              int
	acquiring, closed bool
	issue             func(context.Context) (Artifact, error)
	bindOrigin        func(string) error
	installation      *interopharness.BrowserRunnerInstallationOwner
	native            *interopharness.BrowserNativeInstallation
	observation       interopharness.BrowserRuntimeObservation
	jobs              chan *batchRecord
	requests          chan struct{}
	workers           sync.WaitGroup
	handlers          sync.WaitGroup
	cleanupGate       chan struct{}
	cleanupComplete   bool
	cleanupJoined     chan struct{}
	failure           error
}

func newSource(ctx context.Context, topology string, run int, phases []batchPhase, concurrency int, issue func(context.Context) (Artifact, error), bindOrigin func(string) error, owner *interopharness.BrowserRunnerInstallationOwner, native *interopharness.BrowserNativeInstallation) (*Source, error) {
	if ctx == nil || run < 1 || concurrency < 1 || concurrency > 128 || len(phases) < 1 || len(phases) > 2 || issue == nil || bindOrigin == nil || owner == nil || native == nil {
		return nil, errors.New("complete original browser batch composition is required")
	}
	total := 0
	for _, phase := range phases {
		if phase.count < 1 || phase.count > 1000-total {
			return nil, errors.New("original browser batch exceeds its finite position table")
		}
		total += phase.count
	}
	var capability [32]byte
	if _, err := rand.Read(capability[:]); err != nil {
		return nil, err
	}
	defer clear(capability[:])
	root, cancel := context.WithCancelCause(ctx)
	source := &Source{ctx: root, cancel: cancel, path: "/artifacts/" + base64.RawURLEncoding.EncodeToString(capability[:]), topology: topology, run: run, phases: append([]batchPhase(nil), phases...), records: make([]*batchRecord, 0, total), byToken: make(map[string]*batchRecord, total), issue: issue, bindOrigin: bindOrigin, installation: owner, native: native, jobs: make(chan *batchRecord, concurrency), requests: make(chan struct{}, 2*concurrency+1), cleanupGate: make(chan struct{}, 1)}
	for range concurrency {
		source.workers.Add(1)
		go source.work()
	}
	return source, nil
}
func (s *Source) Path() string { return s.path }
func (s *Source) fail(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.failure = errors.Join(s.failure, err)
	s.mu.Unlock()
	s.cancel(err)
}
func (s *Source) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return false
	}
	select {
	case s.requests <- struct{}{}:
		s.handlers.Add(1)
		return true
	default:
		return false
	}
}
func (s *Source) end() { <-s.requests; s.handlers.Done() }
func (s *Source) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || len(request.URL.Path) != len(s.path) || subtle.ConstantTimeCompare([]byte(request.URL.Path), []byte(s.path)) != 1 {
		http.NotFound(w, request)
		return
	}
	if !s.begin() {
		http.Error(w, "original source closed", http.StatusConflict)
		return
	}
	defer s.end()
	decoder := json.NewDecoder(http.MaxBytesReader(w, request.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	var input sourceRequest
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || input.SchemaVersion != 1 {
		http.Error(w, "invalid original source request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithCancelCause(request.Context())
	stop := context.AfterFunc(s.ctx, func() { cancel(context.Cause(s.ctx)) })
	defer stop()
	defer cancel(context.Canceled)
	if input.Action == "acquire" {
		if input.SpendToken != "" {
			http.Error(w, "invalid original acquisition", http.StatusBadRequest)
			return
		}
		output, err := s.acquire(ctx, input)
		if err != nil {
			http.Error(w, "original acquisition unavailable", http.StatusConflict)
			return
		}
		defer clear(output)
		w.Header().Set("Content-Type", "application/json")
		count, err := w.Write(output)
		if err != nil || count != len(output) {
			s.fail(errors.Join(err, io.ErrShortWrite))
		}
		return
	}
	if input.Topology != "" || input.ProfileID != "" || input.RunNumber != 0 || input.Phase != "" || input.Count != 0 {
		http.Error(w, "invalid original token action", http.StatusBadRequest)
		return
	}
	var err error
	switch input.Action {
	case "start":
		err = s.start(ctx, input.SpendToken)
	case "spend":
		err = s.observeSpend(ctx, input.SpendToken)
	case "cancel":
		err = s.cancelRecord(ctx, input.SpendToken)
	case "retire":
		err = s.retire(ctx, input.SpendToken)
	default:
		http.Error(w, "unsupported original source action", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "original token action unavailable", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"schema_version":1,"status":"complete"}`))
}
func (s *Source) acquire(ctx context.Context, input sourceRequest) (output []byte, err error) {
	s.mu.Lock()
	if s.closed || s.acquiring || s.next >= len(s.phases) || input.Topology != s.topology || input.RunNumber != s.run {
		s.mu.Unlock()
		return nil, errors.New("original acquisition position is unavailable")
	}
	index := s.next
	phase := &s.phases[index]
	if phase.used || input.ProfileID != phase.profile || input.Phase != phase.phase || input.Count != phase.count {
		s.mu.Unlock()
		return nil, errors.New("acquisition differs from the frozen original call")
	}
	var predecessor []*batchRecord
	if index > 0 {
		for _, record := range s.records {
			if record.phase == index-1 {
				predecessor = append(predecessor, record)
			}
		}
	}
	// Occupy the original call before waiting for runtime/issuance. Failure never
	// restores its phase/count position, including a lost HTTP response.
	phase.used = true
	phase.first = len(s.records)
	s.acquiring = true
	s.next++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.phases[index].last = len(s.records)
		s.acquiring = false
		s.mu.Unlock()
		if err != nil {
			s.fail(err)
		}
	}()
	for _, record := range predecessor {
		select {
		case <-record.done:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
		s.mu.Lock()
		complete := record.state == "complete" && record.observedSpend && record.err == nil
		s.mu.Unlock()
		if !complete {
			return nil, errors.New("original predecessor batch has no complete authorized position")
		}
	}
	observation, err := s.installation.ObserveRuntime(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	previous := s.observation
	s.mu.Unlock()
	if previous.RuntimeID != "" && previous != observation {
		return nil, errors.New("original browser runtime changed within the acquisition run")
	}
	if previous.RuntimeID == "" {
		if err = s.bindOrigin(observation.Origin); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	s.observation = observation
	s.mu.Unlock()
	entries := make([]delivery, 0, input.Count)
	size := 0
	for range input.Count {
		if err = ctx.Err(); err != nil {
			return nil, context.Cause(ctx)
		}
		var tokenBytes [32]byte
		if _, err = rand.Read(tokenBytes[:]); err != nil {
			return nil, err
		}
		token := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
		clear(tokenBytes[:])
		recordCtx, recordCancel := context.WithCancelCause(s.ctx)
		record := &batchRecord{token: token, phase: index, state: "issuing", ctx: recordCtx, cancel: recordCancel, startDone: make(chan struct{}), admissionDone: make(chan struct{}), done: make(chan struct{})}
		s.mu.Lock()
		if _, exists := s.byToken[token]; exists {
			s.mu.Unlock()
			recordCancel(context.Canceled)
			return nil, errors.New("original acquisition token collision")
		}
		s.records = append(s.records, record)
		s.byToken[token] = record
		s.mu.Unlock()
		artifact, issueErr := s.issue(recordCtx)
		s.mu.Lock()
		record.artifact = artifact
		s.mu.Unlock()
		if issueErr != nil {
			return nil, issueErr
		}
		if artifact == nil {
			return nil, errors.New("original issuer returned no batch material")
		}
		wire := artifact.ArtifactJSON()
		if len(wire) == 0 || len(wire) > maxItemBytes || size > maxBatchBytes-len(wire)-256 {
			return nil, errors.New("original acquisition material exceeds its declared response bound")
		}
		size += len(wire) + 256
		businessStreams := uint32(1)
		if phase.phase == "session" && phase.plan.ID == "webtransport-native-isolation" {
			businessStreams = 4
		}
		declaration, declarationErr := artifact.OriginalBrowserRunnerDeclaration(ctx, observation, s.native, businessStreams)
		if declarationErr != nil {
			return nil, declarationErr
		}
		if err = artifact.InstallOriginalBrowserRunner(ctx, s.installation, observation, declaration); err != nil {
			return nil, err
		}
		s.mu.Lock()
		record.state = "installed"
		s.mu.Unlock()
		entries = append(entries, delivery{wire, token})
	}
	output, err = json.Marshal(struct {
		SchemaVersion int        `json:"schema_version"`
		Artifacts     []delivery `json:"artifacts"`
	}{1, entries})
	if err != nil {
		return nil, err
	}
	if len(output) > maxBatchBytes {
		clear(output)
		return nil, errors.New("original acquisition response exceeds its finite bound")
	}
	admissionMS := uint64(phase.plan.Cold.OperationDeadlineSeconds) * 1000
	if phase.phase == "cold" {
		admissionMS = uint64(phase.plan.Cold.PhaseDeadlineSeconds) * 1000
	}
	sessionMS := admissionMS + uint64(phase.plan.CleanupDeadlineSeconds)*1000
	if phase.phase == "session" {
		sessionMS += uint64(phase.plan.RPC.PhaseDeadlineSeconds+phase.plan.Bulk.PhaseDeadlineSeconds) * 1000
	}
	// Check the retained signed material after the whole batch is installed. An
	// expired queue fails this occupied call; it never causes fresh issuance.
	// Reserve a bounded final-check interval inside every original window so
	// the first checked item cannot lose that interval to later item checks.
	checkBudget := uint64(phase.plan.Cold.OperationDeadlineSeconds) * 1000
	admissionMS += checkBudget
	sessionMS += checkBudget
	gate, cancelGate := context.WithTimeout(ctx, time.Duration(checkBudget)*time.Millisecond)
	defer cancelGate()
	for _, entry := range entries {
		s.mu.Lock()
		record := s.byToken[entry.SpendToken]
		s.mu.Unlock()
		if err = record.artifact.CheckOriginalBrowserBatchWindow(gate, admissionMS, sessionMS); err != nil {
			clear(output)
			return nil, err
		}
	}
	if err = gate.Err(); err != nil {
		clear(output)
		return nil, context.Cause(gate)
	}
	// Publish all local token positions only after the entire original batch has
	// been independently installed. No item is exposed from a partial failure.
	s.mu.Lock()
	for _, entry := range entries {
		s.byToken[entry.SpendToken].state = "issued"
	}
	s.mu.Unlock()
	return output, nil
}

// finishUnavailable records an original position that cannot be started. It
// closes local execution waiters, while preserving a failed physical cleanup
// for Source.Close to finish. The token remains consumed in either case.
func (s *Source) finishUnavailable(record *batchRecord, cause error) error {
	s.mu.Lock()
	phase := s.phases[record.phase]
	record.state = "canceling"
	s.mu.Unlock()
	record.cancel(cause)
	cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(phase.plan.CleanupDeadlineSeconds)*time.Second)
	cleanupErr := record.artifact.CloseOriginalBrowser(cleanup)
	cancel()
	s.mu.Lock()
	record.startErr = cause
	record.admissionErr = cause
	record.err = errors.Join(cause, cleanupErr)
	record.cleanupComplete = cleanupErr == nil
	if cleanupErr == nil {
		record.state = "canceled"
	} else {
		record.state = "cleanup_pending"
	}
	if !record.startClosed {
		close(record.startDone)
		record.startClosed = true
	}
	if !record.admissionClosed {
		close(record.admissionDone)
		record.admissionClosed = true
	}
	if !record.doneClosed {
		close(record.done)
		record.doneClosed = true
	}
	s.mu.Unlock()
	if cleanupErr != nil {
		s.fail(cleanupErr)
	}
	return cleanupErr
}
func (s *Source) start(ctx context.Context, token string) error {
	s.mu.Lock()
	record := s.byToken[token]
	if record == nil || record.state != "issued" {
		s.mu.Unlock()
		return errors.New("original artifact start position is unavailable")
	}
	record.state = "queueing"
	s.mu.Unlock()
	select {
	case s.jobs <- record:
	case <-ctx.Done():
		cause := context.Cause(ctx)
		return errors.Join(cause, s.finishUnavailable(record, cause))
	case <-record.ctx.Done():
		cause := context.Cause(record.ctx)
		return errors.Join(cause, s.finishUnavailable(record, cause))
	}
	select {
	case <-record.startDone:
		s.mu.Lock()
		err := record.startErr
		s.mu.Unlock()
		return err
	case <-ctx.Done():
		record.cancel(context.Cause(ctx))
		return context.Cause(ctx)
	case <-record.ctx.Done():
		return context.Cause(record.ctx)
	}
}
func (s *Source) observeSpend(ctx context.Context, token string) error {
	s.mu.Lock()
	record := s.byToken[token]
	if record == nil || record.state == "issued" || record.state == "issuing" || record.state == "installed" || record.state == "canceling" || record.state == "canceled" || record.state == "cleanup_pending" || record.observedSpend {
		s.mu.Unlock()
		return errors.New("original spend observation position is unavailable")
	}
	s.mu.Unlock()
	select {
	case <-record.admissionDone:
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-s.ctx.Done():
		return context.Cause(s.ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.admissionErr != nil || record.observedSpend {
		return errors.New("original Session has no successful admission to observe")
	}
	record.observedSpend = true
	// This records the trusted TS host's already committed durable spend1. It
	// performs no spend transaction and provides no reusable admission rights.
	return nil
}
func (s *Source) cancelRecord(ctx context.Context, token string) error {
	s.mu.Lock()
	record := s.byToken[token]
	if record == nil {
		s.mu.Unlock()
		return errors.New("original token is absent")
	}
	state := record.state
	if state == "issued" {
		record.state = "canceling"
		s.mu.Unlock()
		return s.finishUnavailable(record, context.Canceled)
	}
	if state == "issuing" || state == "installed" {
		s.mu.Unlock()
		return errors.New("original token publication is occupied")
	}
	s.mu.Unlock()
	record.cancel(context.Canceled)
	select {
	case <-record.done:
		s.mu.Lock()
		err := record.err
		complete := record.cleanupComplete
		s.mu.Unlock()
		if !complete {
			return errors.Join(err, errors.New("original token cleanup remains incomplete"))
		}
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
func (s *Source) retire(ctx context.Context, token string) error {
	s.mu.Lock()
	record := s.byToken[token]
	if record == nil || !record.observedSpend {
		s.mu.Unlock()
		return errors.New("original retirement requires its existing spend observation")
	}
	s.mu.Unlock()
	select {
	case <-record.done:
		s.mu.Lock()
		err := record.err
		complete := record.cleanupComplete
		s.mu.Unlock()
		if !complete {
			return errors.Join(err, errors.New("original token cleanup remains incomplete"))
		}
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-s.ctx.Done():
		return context.Cause(s.ctx)
	}
}
func (s *Source) work() {
	defer s.workers.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case record := <-s.jobs:
			s.runRecord(record)
		}
	}
}
func (s *Source) runRecord(record *batchRecord) {
	if cause := context.Cause(record.ctx); cause != nil {
		_ = s.finishUnavailable(record, cause)
		return
	}
	s.mu.Lock()
	phase := s.phases[record.phase]
	s.mu.Unlock()
	connectCtx, cancelConnect := context.WithTimeout(record.ctx, time.Duration(phase.plan.Cold.OperationDeadlineSeconds)*time.Second)
	err := record.artifact.Start(connectCtx)
	s.mu.Lock()
	record.startErr = err
	record.state = "started"
	close(record.startDone)
	record.startClosed = true
	s.mu.Unlock()
	var session *fs.Session
	if err == nil {
		session, err = record.artifact.AwaitServer(connectCtx)
		if err == nil && session == nil {
			err = errors.New("original browser acceptance returned no Session")
		}
	}
	cancelConnect()
	s.mu.Lock()
	record.admissionErr = err
	record.state = "admitted"
	close(record.admissionDone)
	record.admissionClosed = true
	s.mu.Unlock()
	if err == nil && phase.phase == "session" {
		if phase.plan.ID == "webtransport-native-isolation" {
			operation, cancel := context.WithTimeout(record.ctx, time.Duration(phase.plan.RPC.PhaseDeadlineSeconds)*time.Second)
			err = transporttest.ServeBrowserNativeIsolation(operation, session)
			cancel()
		}
		if err == nil {
			operation, cancel := context.WithTimeout(record.ctx, time.Duration(phase.plan.RPC.PhaseDeadlineSeconds+phase.plan.Bulk.PhaseDeadlineSeconds)*time.Second)
			err = transporttest.ServeBrowserBulk(operation, session, []int64{phase.plan.Bulk.WarmupBytesPerDirection, phase.plan.Bulk.ScoreBytesPerDirection})
			cancel()
		}
	}
	if err == nil {
		waitCtx, cancel := context.WithTimeout(record.ctx, time.Duration(phase.plan.Cold.PhaseDeadlineSeconds+phase.plan.RPC.PhaseDeadlineSeconds+phase.plan.Bulk.PhaseDeadlineSeconds+phase.plan.CleanupDeadlineSeconds)*time.Second)
		terminal := session.WaitTermination(waitCtx)
		if waitCtx.Err() != nil {
			err = context.Cause(waitCtx)
		} else {
			err = transporttest.NormalizeCloseError(terminal)
		}
		cancel()
	}
	record.cancel(err)
	cleanup, cancelCleanup := context.WithTimeout(context.Background(), time.Duration(phase.plan.CleanupDeadlineSeconds)*time.Second)
	var cleanupErr error
	if session != nil {
		cleanupErr = errors.Join(transporttest.NormalizeCloseError(session.Close()), session.WaitCleanup(cleanup))
	}
	cleanupErr = errors.Join(cleanupErr, record.artifact.CloseOriginalBrowser(cleanup))
	cancelCleanup()
	err = errors.Join(err, cleanupErr)
	s.mu.Lock()
	record.err = err
	record.cleanupComplete = cleanupErr == nil
	if cleanupErr == nil {
		record.state = "complete"
	} else {
		record.state = "cleanup_pending"
	}
	close(record.done)
	record.doneClosed = true
	s.mu.Unlock()
	if cleanupErr != nil || err != nil && !errors.Is(err, context.Canceled) {
		s.fail(err)
	}
}

// Close ends only this original run and joins its actual work/cleanup. Calling
// it again can finish an incomplete original cleanup; it cannot renew a token,
// restore acquisition slots, create material or start another native attempt.
func (s *Source) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("original source cleanup context is required")
	}
	select {
	case s.cleanupGate <- struct{}{}:
		defer func() { <-s.cleanupGate }()
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	if s.cleanupComplete {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel(context.Canceled)
	if s.cleanupJoined == nil {
		s.cleanupJoined = make(chan struct{})
		go func() { s.handlers.Wait(); s.workers.Wait(); close(s.cleanupJoined) }()
	}
	joined := s.cleanupJoined
	select {
	case <-joined:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	s.mu.Lock()
	records := append([]*batchRecord(nil), s.records...)
	s.mu.Unlock()
	var result error
	for _, record := range records {
		record.cancel(context.Canceled)
		s.mu.Lock()
		alreadyClean := record.cleanupComplete
		s.mu.Unlock()
		var cleanupErr error
		if !alreadyClean && record.artifact != nil {
			cleanupErr = record.artifact.CloseOriginalBrowser(ctx)
		}
		result = errors.Join(result, cleanupErr)
		s.mu.Lock()
		record.cleanupComplete = alreadyClean || cleanupErr == nil
		if record.state != "complete" {
			if record.cleanupComplete {
				record.state = "canceled"
			} else {
				record.state = "cleanup_pending"
			}
			record.err = errors.Join(record.err, context.Canceled, cleanupErr)
		}
		if !record.startClosed {
			record.startErr = context.Canceled
			close(record.startDone)
			record.startClosed = true
		}
		if !record.admissionClosed {
			record.admissionErr = context.Canceled
			close(record.admissionDone)
			record.admissionClosed = true
		}
		if !record.doneClosed {
			close(record.done)
			record.doneClosed = true
		}
		s.mu.Unlock()
	}
	if result == nil {
		s.cleanupComplete = true
	}
	return result
}
func (s *Source) RequireComplete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return s.failure
	}
	if s.acquiring || s.next != len(s.phases) {
		return errors.New("original batch run did not acquire every frozen phase")
	}
	expected := 0
	for _, phase := range s.phases {
		if !phase.used || phase.last-phase.first != phase.count {
			return errors.New("original phase differs from its occupied finite position table")
		}
		expected += phase.count
	}
	if len(s.records) != expected {
		return errors.New("original record table differs from the frozen run")
	}
	for _, record := range s.records {
		if record.state != "complete" || !record.cleanupComplete || record.err != nil || !record.observedSpend {
			return errors.New("original batch run retained an unspent or incomplete position")
		}
	}
	return nil
}
