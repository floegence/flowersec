package transporttest

import (
	"context"
	"errors"
	"sync"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// AdaptiveBrowserArtifact retains one actual signed WT/WSS candidate set and
// both original accepted positions. It never turns a forced route into adaptive
// authority, reissues material after a lost race or imports a winner receipt.
type AdaptiveBrowserArtifact struct {
	endpoint *AdaptiveEndpoint
	original interopharness.Material
	wire     string
	records  [2]*interopharness.AcceptedRecord
	mu       sync.Mutex
	awaited  bool
	selected int
}

func OpenAdaptiveBrowserBatchEndpointAt(ctx context.Context, host, origin string, plan ProfilePlan, positions int) (result *AdaptiveEndpoint, err error) {
	if ctx == nil || positions < 1 || positions > 1000 || plan.Cold.MaxInflight < 1 || plan.Cold.MaxInflight > 128 || plan.Cold.OperationDeadlineSeconds < 1 || plan.Cold.OperationDeadlineSeconds > 90 {
		return nil, errors.New("finite original adaptive browser profile is required")
	}
	if err = validateBrowserOrigin(origin); err != nil {
		return nil, err
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return nil, err
	}
	reporter.ApplicationProfile = "services"
	reporter.OperationDeadlineMS = uint64(plan.Cold.OperationDeadlineSeconds) * 1000
	reporter.ListenerConnections = uint16(plan.Cold.MaxInflight)
	reporter.AcceptedRoutePositions = uint16(positions + 1)
	endpoint := &AdaptiveEndpoint{candidates: []AdaptiveCandidate{{ID: "quic", Kind: carrier.KindWebTransport}, {ID: "ws", Kind: carrier.KindWebSocket}}, endpoints: make(map[string]*ProductDirectEndpoint, 2), reporter: reporter}
	defer func() {
		if err != nil {
			err = errors.Join(err, endpoint.Close())
		}
	}()
	for _, candidate := range endpoint.candidates {
		child, e := reporter.ForkEndpointAuthority()
		if e != nil {
			return nil, e
		}
		opened, e := openProductDirectEndpoint(ctx, candidate.Kind, host, host, origin, protocolv4.DHProfileX25519, defaultMaxInboundStreams, nil, child)
		if e != nil {
			return nil, e
		}
		endpoint.endpoints[candidate.ID] = opened
		endpoint.trustPEM += opened.nativeServer().TrustPEM
	}
	return endpoint, nil
}
func (e *AdaptiveEndpoint) BindOriginalBrowserRuntimeOrigin(origin string) error {
	if e == nil {
		return errors.New("original adaptive browser owner is required")
	}
	for _, candidate := range e.candidates {
		if err := e.endpoints[candidate.ID].BindOriginalBrowserRuntimeOrigin(origin); err != nil {
			return err
		}
	}
	return nil
}
func (e *AdaptiveEndpoint) BrowserCertificateHashBase64URL() (string, error) {
	if e == nil {
		return "", errors.New("original adaptive browser owner is required")
	}
	return e.endpoints["quic"].CertificateHashBase64URL()
}
func (e *AdaptiveEndpoint) IssueBrowserArtifact() (artifact *AdaptiveBrowserArtifact, err error) {
	if e == nil || len(e.candidates) != 2 {
		return nil, errors.New("original adaptive browser owner is required")
	}
	routes := make([][]byte, 2)
	for index, candidate := range e.candidates {
		routes[index] = e.endpoints[candidate.ID].nativeServer().Runtime.Authority.Route
	}
	first := e.endpoints[e.candidates[0].ID].nativeServer()
	authority, err := first.IssueDirectRouteSet(routes)
	if err != nil {
		return nil, err
	}
	artifact = &AdaptiveBrowserArtifact{endpoint: e, original: first.MaterialFor(authority), selected: -1}
	defer func() {
		if err != nil {
			err = errors.Join(err, artifact.CloseOriginalBrowser(context.Background()))
			artifact = nil
		}
	}()
	for index, candidate := range e.candidates {
		accepting := *authority
		accepting.Route = authority.DirectRoutes[index]
		accepting.BrowserRouteDigest = authority.DirectRouteDigests[index]
		accepting.Hello.Index = uint64(index)
		accepting.Admission[1].Core.MixedCarrier = true
		accepting.Admission[1].Core.MessageRuntimeBytes = 65536
		accepting.Admission[1].RPC.MixedCarrier = true
		artifact.records[index], err = e.endpoints[candidate.ID].registry.Install(&accepting)
		if err != nil {
			return nil, err
		}
	}
	artifact.wire, err = artifact.original.JSON()
	if err != nil {
		return nil, err
	}
	return artifact, nil
}
func (a *AdaptiveBrowserArtifact) ArtifactJSON() string {
	if a == nil {
		return ""
	}
	return a.wire
}
func (a *AdaptiveBrowserArtifact) Start(ctx context.Context) error {
	if a == nil || ctx == nil {
		return errors.New("original adaptive artifact and context are required")
	}
	return ctx.Err()
}
func (a *AdaptiveBrowserArtifact) AwaitServer(ctx context.Context) (*fs.Session, error) {
	if a == nil || ctx == nil {
		return nil, errors.New("original adaptive wait requires a context")
	}
	a.mu.Lock()
	if a.awaited {
		a.mu.Unlock()
		return nil, errors.New("original adaptive admission was already observed")
	}
	a.awaited = true
	a.mu.Unlock()
	wait, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)
	type accepted struct {
		index   int
		session *fs.Session
		err     error
	}
	results := make(chan accepted, 2)
	var workers sync.WaitGroup
	for index, record := range a.records {
		workers.Add(1)
		go func() {
			defer workers.Done()
			session, err := record.WaitSession(wait)
			results <- accepted{index, session, err}
		}()
	}
	defer workers.Wait()
	var winner *fs.Session
	var winnerIndex = -1
	var failed error
	for range 2 {
		result := <-results
		if result.err == nil && result.session != nil {
			if winner != nil {
				failed = errors.Join(failed, errors.New("original adaptive set admitted multiple Sessions"))
				_ = result.session.Close()
			} else {
				winner = result.session
				winnerIndex = result.index
				cancel(context.Canceled)
			}
		} else if !errors.Is(result.err, context.Canceled) {
			failed = errors.Join(failed, result.err)
		}
	}
	if winner == nil {
		return nil, errors.Join(failed, context.Cause(ctx), errors.New("original adaptive set has no admitted winner"))
	}
	for index, record := range a.records {
		if index != winnerIndex {
			failed = errors.Join(failed, record.Close())
		}
	}
	writes := 0
	for _, record := range a.records {
		if record.Claimed() {
			writes++
		}
	}
	if writes != 1 {
		failed = errors.Join(failed, errors.New("original adaptive set did not preserve one accepted position"))
	}
	if failed != nil {
		_ = winner.Close()
		return nil, failed
	}
	a.mu.Lock()
	a.selected = winnerIndex
	a.mu.Unlock()
	return winner, nil
}
func (a *AdaptiveBrowserArtifact) OriginalBrowserRunnerDeclaration(ctx context.Context, observed interopharness.BrowserRuntimeObservation, native *interopharness.BrowserNativeInstallation, streams uint32) (map[string]any, error) {
	return nil, errors.New("adaptive browser requires two independently installed carrier qualifications")
}
func (a *AdaptiveBrowserArtifact) OriginalBrowserAdaptiveDeclaration(ctx context.Context, observed interopharness.BrowserRuntimeObservation, native [2]*interopharness.BrowserNativeInstallation, streams uint32) (map[string]any, error) {
	if a == nil || a.endpoint == nil {
		return nil, errors.New("original adaptive browser artifact is required")
	}
	declarations := make([]map[string]any, 0, 2)
	for index, candidate := range a.endpoint.candidates {
		server := a.endpoint.endpoints[candidate.ID].nativeServer()
		runtime := server.Runtime
		application, err := runtime.OriginalBrowserApplication(1, "echo")
		if err != nil {
			return nil, err
		}
		original := a.original
		original.Route = runtime.Authority.Route
		original.RouteDigest = runtime.Authority.BrowserRouteDigest[:]
		declaration, err := runtime.OriginalBrowserRunnerDeclaration(ctx, original, observed, native[index], application, streams, uint64(index))
		if err != nil {
			return nil, err
		}
		declaration["candidate_index"] = index
		declarations = append(declarations, declaration)
	}
	primary := declarations[0]
	primary["carrier_deployments"] = declarations
	primary["mixed_carrier"] = true
	return primary, nil
}
func (a *AdaptiveBrowserArtifact) InstallOriginalBrowserRunner(ctx context.Context, owner *interopharness.BrowserRunnerInstallationOwner, observed interopharness.BrowserRuntimeObservation, declaration map[string]any) error {
	if a == nil || a.endpoint == nil {
		return errors.New("original adaptive artifact is required")
	}
	return owner.InstallOriginal(ctx, a.wire, a.original, a.endpoint.trustPEM, observed.Origin, observed, declaration)
}
func (a *AdaptiveBrowserArtifact) CheckOriginalBrowserBatchWindow(ctx context.Context, admissionMS, sessionMS uint64) error {
	if a == nil || a.endpoint == nil {
		return errors.New("original adaptive artifact is required")
	}
	return a.endpoint.endpoints[a.endpoint.candidates[0].ID].nativeServer().Runtime.CheckOriginalBrowserBatchWindow(ctx, a.original, admissionMS, sessionMS)
}
func (a *AdaptiveBrowserArtifact) CloseOriginalBrowser(ctx context.Context) error {
	if a == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("original adaptive cleanup context is required")
	}
	var err error
	for _, record := range a.records {
		if record != nil {
			err = errors.Join(err, record.Close())
		}
	}
	return err
}
