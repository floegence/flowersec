package transporttest

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// AdaptiveCandidate maps a manifest label to one signed original route.
type AdaptiveCandidate struct {
	ID   string       `json:"id"`
	Kind carrier.Kind `json:"carrier"`
}
type AdaptiveEndpoint struct {
	candidates []AdaptiveCandidate
	endpoints  map[string]*ProductDirectEndpoint
	reporter   *interopharness.Reporter
	trustPEM   string
	closeOnce  sync.Once
	closeErr   error
}
type AdaptiveConnectOperation struct {
	ConnectOperation
	StartedCandidates    []string `json:"started_candidates"`
	WinnerCandidate      string   `json:"winner_candidate"`
	CommitCount          int32    `json:"commit_count"`
	CredentialWriteCount int      `json:"credential_write_count"`
}
type adaptivePair struct{ pair *ProductDirectPair }

func (pair *adaptivePair) Close() error {
	if pair == nil {
		return nil
	}
	return pair.pair.Close()
}

// OpenAdaptiveEndpointAt installs distinct listeners under one explicit
// advancing engineering authority time domain. Each connection will receive
// one signed multi-candidate pool and one original once-only consumption.
func OpenAdaptiveEndpointAt(ctx context.Context, listenHost string, candidates []AdaptiveCandidate) (result *AdaptiveEndpoint, resultErr error) {
	if ctx == nil || len(candidates) != 2 {
		return nil, errors.New("adaptive release endpoint requires two original candidates")
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return nil, err
	}
	reporter.ApplicationProfile = "services"
	endpoint := &AdaptiveEndpoint{candidates: append([]AdaptiveCandidate(nil), candidates...), endpoints: make(map[string]*ProductDirectEndpoint, 2), reporter: reporter}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, endpoint.Close())
		}
	}()
	kinds := make(map[carrier.Kind]bool, 2)
	var trust strings.Builder
	for _, candidate := range candidates {
		if candidate.ID == "" || endpoint.endpoints[candidate.ID] != nil || kinds[candidate.Kind] {
			return nil, errors.New("adaptive candidate labels and carriers must be distinct")
		}
		if _, err := productCarrier(candidate.Kind); err != nil {
			return nil, err
		}
		child, err := reporter.ForkEndpointAuthority()
		if err != nil {
			return nil, err
		}
		opened, err := openProductDirectEndpoint(ctx, candidate.Kind, listenHost, listenHost, releaseRunnerOrigin, protocolv4.DHProfileX25519, defaultMaxInboundStreams, nil, child)
		if err != nil {
			return nil, err
		}
		kinds[candidate.Kind] = true
		endpoint.endpoints[candidate.ID] = opened
		trust.WriteString(opened.server.TrustPEM)
	}
	endpoint.trustPEM = trust.String()
	return endpoint, nil
}

// adaptiveCarrierObserver forwards every original preadmission and native
// preparation. Counts record original method entry; they create no transport,
// spend, winner or admission outcome.
type adaptiveCarrierObserver struct {
	original *flowersec.CarrierSet
	started  [2]atomic.Int32
	entered  [2]chan struct{}
}

func (o *adaptiveCarrierObserver) recordEntry(index uint64) {
	if o.started[index].Add(1) == 1 {
		close(o.entered[index])
	}
}

type adaptiveObservedPreparation struct {
	owner    *adaptiveCarrierObserver
	original sessionv4.CarrierPreparation
}

func (o *adaptiveCarrierObserver) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (*sessionv4.PreparedCarrier, error) {
	if request.Config.Candidate.Index >= 2 {
		return nil, errors.New("original adaptive candidate index is outside the signed set")
	}
	o.recordEntry(request.Config.Candidate.Index)
	return o.original.PrepareCarrier(ctx, request)
}
func (o *adaptiveCarrierObserver) PreparationParallelism() uint8 {
	return o.original.PreparationParallelism()
}
func (o *adaptiveCarrierObserver) AdmitPreparations(request sessionv4.CarrierPreparationAdmissionRequest, output []sessionv4.CarrierPreparation) error {
	if len(output) > 2 {
		return errors.New("original adaptive preparation output exceeds its admitted two positions")
	}
	var originals [2]sessionv4.CarrierPreparation
	err := o.original.AdmitPreparations(request, originals[:len(output)])
	for index, original := range originals[:len(output)] {
		if original != nil {
			output[index] = &adaptiveObservedPreparation{owner: o, original: original}
		}
	}
	return err
}
func (p *adaptiveObservedPreparation) Matches(factory sessionv4.ConsumerCarrierFactory) bool {
	return factory == p.owner && p.original.Matches(p.owner.original)
}
func (p *adaptiveObservedPreparation) Check() error { return p.original.Check() }
func (p *adaptiveObservedPreparation) Close()       { p.original.Close() }
func (p *adaptiveObservedPreparation) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (*sessionv4.PreparedCarrier, error) {
	if request.Config.Candidate.Index >= 2 {
		return nil, errors.New("original adaptive candidate index is outside the signed set")
	}
	p.owner.recordEntry(request.Config.Candidate.Index)
	return p.original.PrepareCarrier(ctx, request)
}

var _ sessionv4.AdmittingConsumerCarrierFactory = (*adaptiveCarrierObserver)(nil)

func (endpoint *AdaptiveEndpoint) Connect(ctx context.Context) (result *adaptivePair, started []string, winner string, commits int32, writes int, resultErr error) {
	if endpoint == nil || ctx == nil || len(endpoint.candidates) != 2 {
		return nil, nil, "", 0, 0, errors.New("original adaptive endpoint and context are required")
	}
	// These candidates have equal signed priority. Keep every index mapping
	// in the same canonical candidate-ID order as the issued Artifact.
	candidates := slices.Clone(endpoint.candidates)
	slices.SortFunc(candidates, func(a, b AdaptiveCandidate) int {
		left := endpoint.endpoints[a.ID].reporter.AuthorityCandidateID()
		right := endpoint.endpoints[b.ID].reporter.AuthorityCandidateID()
		return bytes.Compare(left[:], right[:])
	})
	routes := make([][]byte, 2)
	for index, candidate := range candidates {
		routes[index] = endpoint.endpoints[candidate.ID].server.Runtime.Authority.Route
	}
	first := endpoint.endpoints[candidates[0].ID]
	authority, err := first.server.IssueDirectRouteSet(routes)
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	records := make([]*interopharness.AcceptedRecord, 2)
	var reporter *interopharness.Reporter
	succeeded := false
	defer func() {
		if !succeeded {
			for _, record := range records {
				resultErr = errors.Join(resultErr, record.Close())
			}
			if reporter != nil {
				resultErr = errors.Join(resultErr, reporter.Close())
			}
		}
	}()
	for index, candidate := range candidates {
		accepting := *authority
		accepting.Route = authority.DirectRoutes[index]
		accepting.BrowserRouteDigest = authority.DirectRouteDigests[index]
		accepting.Hello.Index = uint64(index)
		records[index], err = endpoint.endpoints[candidate.ID].registry.Install(&accepting)
		if err != nil {
			return nil, nil, "", 0, 0, err
		}
	}
	reporter, err = interopharness.NewPeerReporter()
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	reporter.ApplicationProfile = "services"
	material := first.server.MaterialFor(authority)
	wire, err := material.JSON()
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	var definition *interopharness.RPCDefinition
	client, err := interopharness.NewClient(ctx, reporter, wire, endpoint.trustPEM, releaseRunnerOrigin, productHandlers(&definition))
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	h := client.Runtime.Authority
	h.Admission[0].Core.MixedCarrier = true
	h.Admission[0].Core.MessageRuntimeBytes = 65536
	h.Admission[0].RPC.MixedCarrier = true
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(endpoint.trustPEM)) {
		return nil, nil, "", 0, 0, errors.New("original adaptive deployment roots are missing")
	}
	config := flowersec.CarrierSetConfig{Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Role: protocolv4.ClientToServer, ConnectionsPerRoute: 1, RuntimeBytes: 65536, FactoryRuntimeBytes: 65536, Endpoints: make([]flowersec.CarrierEndpoint, 2)}
	for index, candidate := range candidates {
		opened := endpoint.endpoints[candidate.ID]
		entry := flowersec.CarrierEndpoint{Route: authority.DirectRoutes[index], RemoteAddress: opened.server.Address, Roots: roots}
		switch candidate.Kind {
		case carrier.KindWebSocket:
			entry.Carrier = 1
			entry.Origin = releaseRunnerOrigin
			entry.WebSocket = interopharness.WebSocketProvider()
		case carrier.KindRawQUIC:
			entry.QUIC = interopharness.QUICProviderFor(h.Admission[0].Core.Session.Contract.Limits().MaxStreams)
		case carrier.KindWebTransport:
			entry.Carrier = 2
			entry.Origin = releaseRunnerOrigin
			entry.WebTransport = interopharness.WebTransportProviderFor(h.Admission[0].Core.Session.Contract.Limits().MaxStreams)
		}
		config.Endpoints[index] = entry
	}
	cost, err := flowersec.CarrierSetCharge(config)
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	set, err := flowersec.NewCarrierSet(config, h.Reserve(cost), h.Environment)
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	reporter.Cleanup(func() {
		set.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reporter.ErrorIf(set.WaitCleanup(cleanup))
	})
	observed := &adaptiveCarrierObserver{original: set, entered: [2]chan struct{}{make(chan struct{}), make(chan struct{})}}
	session, err := client.Runtime.ConnectCandidates(ctx, observed, 2)
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	selected := client.Runtime.SelectedCandidate[0].Load()
	if selected >= 2 || client.Runtime.Authorized[0].Load() != 1 {
		return nil, nil, "", 0, 0, errors.New("original adaptive application did not authorize one selected candidate")
	}
	server, err := records[selected].WaitSession(ctx)
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	echo, err := definition.Bind(ctx, session)
	if err != nil {
		return nil, nil, "", 0, 0, err
	}
	pair := &ProductDirectPair{Client: session, Server: server, Profile: material.Profile, spend: client.Runtime.PoolSpend, echo: echo, closers: []func() error{reporter.Close}}
	for index, candidate := range candidates {
		// Publication can outrun scheduling of a canceled competitor's already
		// dispatched method. Observe its actual wrapper entry before reading the
		// count; this gate delays neither original native preparation nor racing.
		select {
		case <-observed.entered[index]:
		case <-ctx.Done():
			return nil, nil, "", 0, 0, context.Cause(ctx)
		}
		count := observed.started[index].Load()
		if count != 1 {
			return nil, nil, "", 0, 0, fmt.Errorf("original adaptive candidate %s started %d times", candidate.ID, count)
		}
		started = append(started, candidate.ID)
		if records[index].Claimed() {
			writes++
		}
		pair.closers = append(pair.closers, records[index].Close)
	}
	winner = candidates[selected].ID
	commits = pair.SpendCount()
	if commits != 1 || writes != 1 {
		return nil, nil, "", commits, writes, errors.New("original adaptive connector did not spend and admit exactly one winner")
	}
	succeeded = true
	return &adaptivePair{pair: pair}, started, winner, commits, writes, nil
}
func (endpoint *AdaptiveEndpoint) Close() error {
	if endpoint == nil {
		return nil
	}
	endpoint.closeOnce.Do(func() {
		for index := len(endpoint.candidates) - 1; index >= 0; index-- {
			if opened := endpoint.endpoints[endpoint.candidates[index].ID]; opened != nil {
				endpoint.closeErr = errors.Join(endpoint.closeErr, opened.Close())
			}
		}
		if endpoint.reporter != nil {
			endpoint.closeErr = errors.Join(endpoint.closeErr, endpoint.reporter.Close())
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
