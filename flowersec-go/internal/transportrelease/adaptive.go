package transportrelease

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	gorillaws "github.com/gorilla/websocket"
)

// AdaptiveCandidate binds one manifest candidate ID to one production carrier.
type AdaptiveCandidate struct {
	ID   string       `json:"id"`
	Kind carrier.Kind `json:"carrier"`
}

// AdaptiveEndpoint owns all listeners participating in one equal-candidate race.
type AdaptiveEndpoint struct {
	candidates []AdaptiveCandidate
	endpoints  map[string]*ProductDirectEndpoint
	trustRoots *x509.CertPool
	closeOnce  sync.Once
	closeErr   error
}

// AdaptiveConnectOperation records one real equal-candidate connection.
type AdaptiveConnectOperation struct {
	ConnectOperation
	StartedCandidates    []string `json:"started_candidates"`
	WinnerCandidate      string   `json:"winner_candidate"`
	CommitCount          int32    `json:"commit_count"`
	CredentialWriteCount int      `json:"credential_write_count"`
}

type adaptivePair struct {
	client    flowersession.SessionV2
	server    flowersession.SessionV2
	closeOnce sync.Once
	closeErr  error
}

// OpenAdaptiveEndpointAt starts every real candidate listener on one server
// address. The returned endpoint uses the production connector state machine.
func OpenAdaptiveEndpointAt(ctx context.Context, listenHost string, candidates []AdaptiveCandidate) (*AdaptiveEndpoint, error) {
	if len(candidates) != 2 {
		return nil, errors.New("adaptive release endpoint requires exactly two candidates")
	}
	seenIDs := make(map[string]struct{}, len(candidates))
	seenKinds := make(map[carrier.Kind]struct{}, len(candidates))
	endpoint := &AdaptiveEndpoint{
		candidates: append([]AdaptiveCandidate(nil), candidates...),
		endpoints:  make(map[string]*ProductDirectEndpoint, len(candidates)),
		trustRoots: x509.NewCertPool(),
	}
	for _, candidate := range candidates {
		if candidate.ID == "" {
			_ = endpoint.Close()
			return nil, errors.New("adaptive candidate ID is required")
		}
		if _, duplicate := seenIDs[candidate.ID]; duplicate {
			_ = endpoint.Close()
			return nil, errors.New("adaptive candidate IDs must be unique")
		}
		if _, duplicate := seenKinds[candidate.Kind]; duplicate {
			_ = endpoint.Close()
			return nil, errors.New("adaptive candidate carriers must be unique")
		}
		if err := candidate.Kind.Validate(); err != nil {
			_ = endpoint.Close()
			return nil, err
		}
		seenIDs[candidate.ID], seenKinds[candidate.Kind] = struct{}{}, struct{}{}
		opened, err := OpenProductDirectEndpointAt(ctx, candidate.Kind, listenHost)
		if err != nil {
			_ = endpoint.Close()
			return nil, err
		}
		certificate, err := x509.ParseCertificate(opened.certificateDER)
		if err != nil {
			_ = opened.Close()
			_ = endpoint.Close()
			return nil, err
		}
		endpoint.trustRoots.AddCert(certificate)
		endpoint.endpoints[candidate.ID] = opened
	}
	return endpoint, nil
}

func (endpoint *AdaptiveEndpoint) Connect(ctx context.Context) (*adaptivePair, []string, string, int32, int, error) {
	if endpoint == nil || len(endpoint.candidates) != 2 || len(endpoint.endpoints) != 2 || endpoint.trustRoots == nil {
		return nil, nil, "", 0, 0, errors.New("adaptive endpoint is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	contract, err := releaseSessionContract(protocolv2.SuiteChaCha20Poly1305)
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	artifact := directArtifact(endpoint.candidates[0].Kind, endpoint.endpoints[endpoint.candidates[0].ID].candidateURL, contract)
	artifact.Path.Candidates = make([]artifactv2.Candidate, 0, len(endpoint.candidates))
	for _, definition := range endpoint.candidates {
		kind := artifactv2.CarrierWebSocket
		switch definition.Kind {
		case carrier.KindQUIC:
			kind = artifactv2.CarrierRawQUIC
		case carrier.KindWebTransport:
			kind = artifactv2.CarrierWebTransport
		}
		artifact.Path.Candidates = append(artifact.Path.Candidates, artifactv2.Candidate{
			ID: definition.ID, Carrier: kind, URL: endpoint.endpoints[definition.ID].candidateURL, WireProfile: rawquic.ALPNDirect,
		})
	}

	type registered struct {
		endpoint *ProductDirectEndpoint
		expected *admissionExpectation
		digest   [32]byte
	}
	type preparedRegistration struct {
		candidate artifactv2.Candidate
		raw       []byte
	}
	preparedRegistrations := make([]preparedRegistration, 0, len(artifact.Path.Candidates))
	for _, candidate := range artifact.Path.Candidates {
		request, buildErr := artifactv2.BuildRequest(artifact, candidate.ID)
		if buildErr != nil {
			return nil, nil, "", 0, 0, buildErr
		}
		raw, marshalErr := artifactv2.MarshalRequest(request)
		if marshalErr != nil {
			return nil, nil, "", 0, 0, marshalErr
		}
		preparedRegistrations = append(preparedRegistrations, preparedRegistration{candidate: candidate, raw: raw})
	}
	registrations := make(map[string]registered, len(endpoint.candidates))
	for _, prepared := range preparedRegistrations {
		candidate, raw := prepared.candidate, prepared.raw
		owner := endpoint.endpoints[candidate.ID]
		expected := &admissionExpectation{raw: raw, contract: contract, result: make(chan productServerResult, 1)}
		digest, registerErr := owner.register(expected)
		if registerErr != nil {
			for _, previous := range registrations {
				previous.endpoint.abandon(previous.digest, previous.expected)
			}
			return nil, nil, "", 0, 0, registerErr
		}
		registrations[candidate.ID] = registered{endpoint: owner, expected: expected, digest: digest}
	}
	winnerID := ""
	defer func() {
		for candidateID, registration := range registrations {
			if candidateID == winnerID {
				registration.endpoint.unregister(registration.digest, registration.expected)
			} else {
				registration.endpoint.abandon(registration.digest, registration.expected)
			}
		}
	}()

	baseTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: endpoint.trustRoots.Clone()}
	webSocketClient := *gorillaws.DefaultDialer
	webSocketClient.TLSClientConfig = baseTLS.Clone()
	webSocketDial, err := connectv2.NewWebSocketCarrierDial(connectv2.WebSocketDialConfig{Dialer: &webSocketClient, Resources: carrierws.DefaultResourcePolicy()})
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	rawQUICDial, err := connectv2.NewRawQUICCarrierDial(connectv2.RawQUICDialConfig{TLSConfig: baseTLS.Clone(), Limits: rawquic.DefaultLimits()})
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	webTransportDial, err := connectv2.NewWebTransportCarrierDial(connectv2.WebTransportDialConfig{
		TLSConfig: baseTLS.Clone(), Limits: carrierwt.DefaultLimits(), Origin: releaseRunnerOrigin,
	})
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	dials := map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierWebSocket: webSocketDial, artifactv2.CarrierRawQUIC: rawQUICDial, artifactv2.CarrierWebTransport: webTransportDial,
	}
	started := make(map[string]*atomic.Int32, len(endpoint.candidates))
	for index, candidate := range endpoint.candidates {
		counter := &atomic.Int32{}
		started[candidate.ID] = counter
		kind := artifact.Path.Candidates[index].Carrier
		base := dials[kind]
		dials[kind] = func(ctx context.Context, value artifactv2.Candidate, contract artifactv2.SessionContract) (connectv2.AdmissionHandle, error) {
			started[value.ID].Add(1)
			return base(ctx, value, contract)
		}
	}
	factory, err := connectv2.NewAdmissionFactory(dials, artifactv2.ReasonRegistry{})
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	spends := &atomic.Int32{}
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: artifact,
		CommitSpend: func(context.Context) error {
			if spends.Add(1) != 1 {
				return errors.New("adaptive artifact spend callback invoked more than once")
			}
			return nil
		},
	}, flowersession.GoCapabilities(), connectv2.Adaptive, factory)
	result, err := connector.Connect(ctx)
	if err != nil {
		return nil, nil, "", spends.Load(), 0, err
	}
	winnerID = result.Candidate.ID
	registration, ok := registrations[winnerID]
	if !ok {
		_ = result.Session.Close()
		return nil, nil, "", spends.Load(), 0, errors.New("adaptive connector selected an unknown candidate")
	}
	var server productServerResult
	select {
	case server = <-registration.expected.result:
	case <-ctx.Done():
		_ = result.Session.Close()
		return nil, nil, "", spends.Load(), 0, context.Cause(ctx)
	}
	if server.err != nil {
		_ = result.Session.Close()
		return nil, nil, "", spends.Load(), 0, server.err
	}
	if server.session == nil {
		_ = result.Session.Close()
		return nil, nil, "", spends.Load(), 0, errors.New("adaptive winner returned no server session")
	}
	startedIDs := make([]string, 0, len(endpoint.candidates))
	for _, candidate := range endpoint.candidates {
		if started[candidate.ID].Load() != 1 {
			_ = result.Session.Close()
			_ = server.session.Close()
			return nil, nil, "", spends.Load(), 0, fmt.Errorf("adaptive candidate %s started %d times", candidate.ID, started[candidate.ID].Load())
		}
		startedIDs = append(startedIDs, candidate.ID)
	}
	credentialWrites := 0
	for _, value := range registrations {
		value.endpoint.pendingMu.Lock()
		if value.expected.claimed {
			credentialWrites++
		}
		value.endpoint.pendingMu.Unlock()
	}
	if spends.Load() != 1 || credentialWrites != 1 {
		_ = result.Session.Close()
		_ = server.session.Close()
		return nil, nil, "", spends.Load(), credentialWrites, errors.New("adaptive connector did not commit exactly one winner")
	}
	return &adaptivePair{client: result.Session, server: server.session}, startedIDs, winnerID, spends.Load(), credentialWrites, nil
}

func (pair *adaptivePair) Close() error {
	if pair == nil {
		return nil
	}
	pair.closeOnce.Do(func() {
		if pair.client != nil {
			pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(pair.client.Close()))
			select {
			case <-pair.client.Termination():
			case <-time.After(3 * time.Second):
				pair.closeErr = errors.Join(pair.closeErr, errors.New("adaptive client did not terminate after local close"))
			}
		}
		if pair.server != nil {
			select {
			case <-pair.server.Termination():
			case <-time.After(3 * time.Second):
				pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(pair.server.Close()))
				select {
				case <-pair.server.Termination():
				case <-time.After(time.Second):
					pair.closeErr = errors.Join(pair.closeErr, errors.New("adaptive server did not terminate after forced close"))
				}
			}
		}
	})
	return pair.closeErr
}

func (endpoint *AdaptiveEndpoint) Close() error {
	if endpoint == nil {
		return nil
	}
	endpoint.closeOnce.Do(func() {
		for index := len(endpoint.candidates) - 1; index >= 0; index-- {
			endpoint.closeErr = errors.Join(endpoint.closeErr, endpoint.endpoints[endpoint.candidates[index].ID].Close())
		}
	})
	return endpoint.closeErr
}

// RunAdaptiveCold executes the frozen cold schedule without retries and records
// the actual candidate race and one-shot admission outcome for every operation.
func RunAdaptiveCold(ctx context.Context, endpoint *AdaptiveEndpoint, plan ColdPlan) ([]AdaptiveConnectOperation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if endpoint == nil || plan.Operations < 1 || plan.MaxInflight < 1 || plan.MaxInflight > plan.Operations ||
		plan.StartRatePerSecond < 1 || plan.OperationDeadlineSeconds < 1 || plan.PhaseDeadlineSeconds < 1 || plan.Retries != 0 {
		return nil, errors.New("invalid adaptive cold-connect workload")
	}
	results := make([]AdaptiveConnectOperation, plan.Operations)
	errorsByOperation := make(chan error, plan.Operations)
	semaphore := make(chan struct{}, plan.MaxInflight)
	var group sync.WaitGroup
	phaseStart := time.Now()
	interval := time.Second / time.Duration(plan.StartRatePerSecond)
	for ordinal := 1; ordinal <= plan.Operations; ordinal++ {
		scheduled := phaseStart.Add(time.Duration(ordinal-1) * interval)
		if err := waitUntil(ctx, scheduled); err != nil {
			errorsByOperation <- err
			break
		}
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			errorsByOperation <- context.Cause(ctx)
			ordinal = plan.Operations
			continue
		}
		group.Add(1)
		go func(ordinal int, scheduled time.Time) {
			defer group.Done()
			defer func() { <-semaphore }()
			operationCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.OperationDeadlineSeconds)*time.Second)
			defer cancel()
			startedAt := time.Now()
			pair, candidates, winner, commits, writes, err := endpoint.Connect(operationCtx)
			duration := time.Since(startedAt)
			if err != nil {
				errorsByOperation <- fmt.Errorf("adaptive cold connection %d: %w", ordinal, err)
				return
			}
			cleanupStarted := time.Now()
			closeErr := pair.Close()
			cleanupDuration := time.Since(cleanupStarted)
			if closeErr != nil {
				errorsByOperation <- fmt.Errorf("adaptive cold connection %d cleanup: %w", ordinal, closeErr)
				return
			}
			results[ordinal-1] = AdaptiveConnectOperation{
				ConnectOperation:  ConnectOperation{Ordinal: ordinal, ScheduledAt: scheduled, StartedAt: startedAt, Duration: duration, CleanupDuration: cleanupDuration},
				StartedCandidates: candidates, WinnerCandidate: winner, CommitCount: commits, CredentialWriteCount: writes,
			}
		}(ordinal, scheduled)
	}
	group.Wait()
	if err := contextCompletionError(ctx); err != nil {
		return nil, err
	}
	close(errorsByOperation)
	var joined error
	for err := range errorsByOperation {
		joined = errors.Join(joined, err)
	}
	if joined != nil {
		return nil, joined
	}
	for index, result := range results {
		if result.Ordinal != index+1 || result.StartedAt.Before(result.ScheduledAt) || result.Duration <= 0 || result.CleanupDuration <= 0 || len(result.StartedCandidates) != 2 ||
			result.WinnerCandidate == "" || result.CommitCount != 1 || result.CredentialWriteCount != 1 {
			return nil, fmt.Errorf("adaptive cold connection %d is incomplete", index+1)
		}
	}
	return results, nil
}
