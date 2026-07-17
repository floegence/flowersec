// Package reconnect provides supervised reconnect with refreshable connect artifacts.
package reconnect

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	cpclient "github.com/floegence/flowersec/flowersec-go/controlplane/client"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

// SourceKind identifies whether a connect artifact can be acquired more than once.
type SourceKind string

const (
	SourceOnce        SourceKind = "once"
	SourceRefreshable SourceKind = "refreshable"
)

// AcquireContext carries correlation state into a fresh artifact request.
type AcquireContext struct {
	TraceID string
}

// ArtifactSource provides one-time or refreshable connect artifacts.
type ArtifactSource interface {
	Kind() SourceKind
	Acquire(context.Context, AcquireContext) (*protocolio.ConnectArtifact, error)
}

type onceSource struct {
	mu       sync.Mutex
	artifact *protocolio.ConnectArtifact
}

// OnceSource creates an artifact source that can be consumed exactly once.
func OnceSource(artifact *protocolio.ConnectArtifact) ArtifactSource {
	return &onceSource{artifact: artifact}
}

func (s *onceSource) Kind() SourceKind { return SourceOnce }

func (s *onceSource) Acquire(ctx context.Context, _ AcquireContext) (*protocolio.ConnectArtifact, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.artifact == nil {
		return nil, errors.New("one-time artifact source has already been consumed")
	}
	artifact := s.artifact
	s.artifact = nil
	return artifact, nil
}

type refreshableSource struct {
	acquire func(context.Context, AcquireContext) (*protocolio.ConnectArtifact, error)
}

// RefreshableSource creates an artifact source backed by an acquisition function.
func RefreshableSource(acquire func(context.Context, AcquireContext) (*protocolio.ConnectArtifact, error)) ArtifactSource {
	return &refreshableSource{acquire: acquire}
}

func (s *refreshableSource) Kind() SourceKind { return SourceRefreshable }

func (s *refreshableSource) Acquire(ctx context.Context, acquireCtx AcquireContext) (*protocolio.ConnectArtifact, error) {
	if s == nil || s.acquire == nil {
		return nil, errors.New("artifact acquisition function is required")
	}
	return s.acquire(ctx, acquireCtx)
}

// ControlplaneSource creates a refreshable source for the standard artifact endpoint.
func ControlplaneSource(config cpclient.ConnectArtifactRequestConfig) ArtifactSource {
	return RefreshableSource(func(ctx context.Context, acquireCtx AcquireContext) (*protocolio.ConnectArtifact, error) {
		config.TraceID = acquireCtx.TraceID
		return cpclient.RequestConnectArtifact(ctx, config)
	})
}

// EntryControlplaneSource creates a refreshable source for the entry-ticket endpoint.
func EntryControlplaneSource(config cpclient.EntryConnectArtifactRequestConfig) ArtifactSource {
	return RefreshableSource(func(ctx context.Context, acquireCtx AcquireContext) (*protocolio.ConnectArtifact, error) {
		config.TraceID = acquireCtx.TraceID
		return cpclient.RequestEntryConnectArtifact(ctx, config)
	})
}

// Settings configure automatic reconnect attempts and exponential backoff.
type Settings struct {
	Enabled      bool
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Factor       float64
	JitterRatio  float64
}

// DefaultSettings returns the cross-language canonical reconnect defaults.
func DefaultSettings() Settings {
	return Settings{
		MaxAttempts:  defaults.ReconnectMaxAttempts,
		InitialDelay: defaults.ReconnectInitialDelay,
		MaxDelay:     defaults.ReconnectMaxDelay,
		Factor:       defaults.ReconnectFactor,
		JitterRatio:  defaults.ReconnectJitterRatio,
	}
}

func (s Settings) normalized() (Settings, error) {
	if !s.Enabled {
		s.MaxAttempts = 1
		if s.Factor == 0 {
			s.Factor = 1
		}
	}
	if s.MaxAttempts < 1 || s.InitialDelay < 0 || s.MaxDelay < 0 || s.Factor < 1 || math.IsNaN(s.Factor) || s.JitterRatio < 0 || s.JitterRatio > 1 || math.IsNaN(s.JitterRatio) {
		return Settings{}, errors.New("invalid reconnect settings")
	}
	return s, nil
}

func (s Settings) retryDelay(failedAttemptIndex int) time.Duration {
	base := float64(s.InitialDelay) * math.Pow(s.Factor, float64(failedAttemptIndex))
	if base > float64(s.MaxDelay) {
		base = float64(s.MaxDelay)
	}
	jitter := 0.0
	if s.JitterRatio > 0 {
		jitter = (rand.Float64()*2 - 1) * s.JitterRatio
	}
	delay := base * (1 + jitter)
	if delay < 0 {
		return 0
	}
	return time.Duration(delay)
}

// Status is the stable reconnect lifecycle state.
type Status string

const (
	StatusDisconnected Status = "disconnected"
	StatusConnecting   Status = "connecting"
	StatusConnected    Status = "connected"
	StatusError        Status = "error"
)

// State is a snapshot of reconnect status.
type State struct {
	Status Status
	Error  error
	Client client.Client
}

// Connector performs one high-level Flowersec connection attempt.
type Connector func(context.Context, *protocolio.ConnectArtifact, ...client.ConnectOption) (client.Client, error)

// Config defines a supervised connection.
type Config struct {
	Source         ArtifactSource
	ConnectOptions []client.ConnectOption
	Observer       observability.ClientObserver
	Reconnect      Settings
	Connector      Connector
}

// Manager supervises one active Flowersec client at a time.
type Manager struct {
	mu          sync.Mutex
	state       State
	generation  uint64
	cancel      context.CancelFunc
	done        chan error
	subscribers map[chan State]struct{}
}

// NewManager creates a disconnected reconnect manager.
func NewManager() *Manager {
	return &Manager{
		state:       State{Status: StatusDisconnected},
		subscribers: make(map[chan State]struct{}),
	}
}

// State returns the current reconnect state.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Subscribe returns a buffered state stream and an unsubscribe function.
func (m *Manager) Subscribe() (<-chan State, func()) {
	ch := make(chan State, 1)
	m.mu.Lock()
	m.subscribers[ch] = struct{}{}
	current := m.state
	m.mu.Unlock()
	ch <- current
	return ch, func() {
		m.mu.Lock()
		if _, ok := m.subscribers[ch]; ok {
			delete(m.subscribers, ch)
			close(ch)
		}
		m.mu.Unlock()
	}
}

// Connect replaces any active connection and waits for the first successful connection or terminal failure.
func (m *Manager) Connect(ctx context.Context, config Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if config.Source == nil {
		return errors.New("artifact source is required")
	}
	settings, err := config.Reconnect.normalized()
	if err != nil {
		return err
	}
	if settings.Enabled && config.Source.Kind() != SourceRefreshable {
		return errors.New("automatic reconnect requires a refreshable artifact source")
	}
	if err := m.Disconnect(); err != nil {
		return fmt.Errorf("disconnect existing reconnect session: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.generation++
	generation := m.generation
	m.cancel = cancel
	m.done = make(chan error, 1)
	done := m.done
	m.mu.Unlock()
	m.setState(State{Status: StatusConnecting})
	first := make(chan error, 1)
	go func() {
		done <- m.supervise(runCtx, generation, config, settings, first)
		close(done)
	}()
	return <-first
}

// ConnectIfNeeded preserves a healthy or in-progress connection.
func (m *Manager) ConnectIfNeeded(ctx context.Context, config Config) error {
	state := m.State()
	if state.Status == StatusConnected {
		return nil
	}
	if state.Status == StatusConnecting {
		states, unsubscribe := m.Subscribe()
		defer unsubscribe()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case state, ok := <-states:
				if !ok {
					return errors.New("reconnect state stream closed")
				}
				if state.Status == StatusConnected {
					return nil
				}
				if state.Status == StatusError || state.Status == StatusDisconnected {
					if state.Error != nil {
						return state.Error
					}
					return errors.New("reconnect stopped before connecting")
				}
			}
		}
	}
	return m.Connect(ctx, config)
}

// Disconnect stops retries, joins the supervisor, and closes the active client.
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	cancel := m.cancel
	done := m.done
	active := m.state.Client
	m.cancel = nil
	m.done = nil
	m.generation++
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var disconnectErr error
	if done != nil {
		disconnectErr = errors.Join(disconnectErr, <-done)
	}
	if active != nil {
		disconnectErr = errors.Join(disconnectErr, active.Close())
	}
	if disconnectErr != nil {
		m.setState(State{Status: StatusError, Error: disconnectErr})
		return disconnectErr
	}
	m.setState(State{Status: StatusDisconnected})
	return nil
}

func (m *Manager) supervise(ctx context.Context, generation uint64, config Config, settings Settings, first chan<- error) error {
	connector := config.Connector
	if connector == nil {
		connector = func(ctx context.Context, artifact *protocolio.ConnectArtifact, options ...client.ConnectOption) (client.Client, error) {
			return client.Connect(ctx, artifact, options...)
		}
	}
	traceID := ""
	firstSent := false
	attemptSeq := 0
	for {
		var lastErr error
		for attempt := 1; attempt <= settings.MaxAttempts; attempt++ {
			if err := ctx.Err(); err != nil {
				if !firstSent {
					first <- err
				}
				return nil
			}
			attemptSeq++
			attemptStart := time.Now()
			observer := observability.WithClientObserverContext(config.Observer, observability.ClientObserverContext{
				Path:         fserrors.PathAuto,
				AttemptSeq:   attemptSeq,
				AttemptStart: attemptStart,
			})
			emit(observer, attemptCode(attempt), observability.DiagnosticResultRetry)
			artifact, err := config.Source.Acquire(ctx, AcquireContext{TraceID: traceID})
			if err == nil && artifact == nil {
				err = errors.New("artifact source returned nil artifact")
			}
			if err == nil && artifact.Correlation != nil && artifact.Correlation.TraceID != nil {
				traceID = *artifact.Correlation.TraceID
				observer = observability.WithClientObserverContext(observer, observability.ClientObserverContext{TraceID: &traceID})
			}
			var connected client.Client
			if err == nil {
				options := append([]client.ConnectOption(nil), config.ConnectOptions...)
				if observer != nil {
					options = append(options, client.WithObserver(observer))
				}
				connected, err = connector(ctx, artifact, options...)
			}
			if err == nil {
				if !m.isCurrent(generation) {
					return connected.Close()
				}
				m.setState(State{Status: StatusConnected, Client: connected})
				emit(observer, "reconnect_connected", observability.DiagnosticResultOK)
				if !firstSent {
					first <- nil
					firstSent = true
				}
				done := clientTermination(connected)
				if done == nil {
					return nil
				}
				select {
				case <-ctx.Done():
					return connected.Close()
				case <-done:
					lastErr = errors.New("Flowersec session terminated")
				}
				_ = connected.Close()
				if !settings.Enabled {
					m.setState(State{Status: StatusError, Error: lastErr})
					return nil
				}
				m.setState(State{Status: StatusConnecting, Error: lastErr})
				emit(observer, "reconnect_scheduled", observability.DiagnosticResultRetry)
				if !waitRetry(ctx, settings.retryDelay(0)) {
					return nil
				}
				break
			}
			lastErr = err
			if isTerminal(err) || attempt == settings.MaxAttempts || !settings.Enabled {
				finalErr := err
				if !isTerminal(err) && settings.Enabled {
					finalErr = fmt.Errorf("reconnect attempts exhausted after %d attempts: %w", attempt, err)
				}
				m.setState(State{Status: StatusError, Error: finalErr})
				emit(observer, "reconnect_exhausted", observability.DiagnosticResultFail)
				if !firstSent {
					first <- finalErr
				}
				return nil
			}
			m.setState(State{Status: StatusConnecting, Error: err})
			emit(observer, "reconnect_scheduled", observability.DiagnosticResultRetry)
			if !waitRetry(ctx, settings.retryDelay(attempt-1)) {
				if !firstSent {
					first <- ctx.Err()
				}
				return nil
			}
		}
		if !settings.Enabled {
			if !firstSent {
				first <- lastErr
			}
			return nil
		}
	}
}

func waitRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (m *Manager) setState(state State) {
	m.mu.Lock()
	m.state = state
	for subscriber := range m.subscribers {
		select {
		case subscriber <- state:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- state:
			default:
			}
		}
	}
	m.mu.Unlock()
}

func (m *Manager) isCurrent(generation uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generation == generation
}

func clientTermination(value client.Client) <-chan struct{} {
	internal, ok := value.(client.ClientInternal)
	if !ok || internal.Mux() == nil {
		return nil
	}
	return internal.Mux().CloseChan()
}

func isTerminal(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	var flowersecErr *fserrors.Error
	if !errors.As(err, &flowersecErr) {
		return false
	}
	_, ok := terminalConnectCodes[flowersecErr.Code]
	return ok
}

var terminalConnectCodes = map[fserrors.Code]struct{}{
	fserrors.CodeInvalidInput:          {},
	fserrors.CodeInvalidOption:         {},
	fserrors.CodeRoleMismatch:          {},
	fserrors.CodeTransportPolicyDenied: {},
	fserrors.CodeInvalidPSK:            {},
	fserrors.CodeInvalidSuite:          {},
	fserrors.CodeMissingGrant:          {},
	fserrors.CodeMissingConnectInfo:    {},
	fserrors.CodeMissingTunnelURL:      {},
	fserrors.CodeMissingWSURL:          {},
	fserrors.CodeMissingChannelID:      {},
	fserrors.CodeMissingToken:          {},
	fserrors.CodeMissingInitExp:        {},
}

func emit(observer observability.ClientObserver, code string, result observability.DiagnosticResult) {
	if observer == nil {
		return
	}
	observer.OnDiagnosticEvent(observability.DiagnosticEvent{
		Path:       string(fserrors.PathAuto),
		Stage:      observability.DiagnosticStageReconnect,
		CodeDomain: observability.DiagnosticCodeDomainEvent,
		Code:       code,
		Result:     result,
	})
}

func attemptCode(attempt int) string {
	if attempt == 1 {
		return "reconnect_attempt"
	}
	return "reconnect_retry_attempt"
}
