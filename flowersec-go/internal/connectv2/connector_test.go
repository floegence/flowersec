package connectv2_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

func TestAdaptiveRaceUsesOneBarrierAndCommitsOnlyAfterLosersClose(t *testing.T) {
	events := &eventLog{}
	attempts := map[string]*fakeAttempt{
		"w1": {id: "w1", readyDelay: 40 * time.Millisecond, events: events},
		"q1": {id: "q1", readyDelay: 5 * time.Millisecond, abortDelay: 15 * time.Millisecond, events: events},
		"t1": {id: "t1", readyDelay: 80 * time.Millisecond, abortDelay: 10 * time.Millisecond, events: events},
	}
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)), allCapabilities(), connectv2.Adaptive, fakeFactory{attempts: attempts})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := connector.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if result.Candidate.ID != "q1" {
		t.Fatalf("winner = %q, want q1", result.Candidate.ID)
	}
	if starts := events.times("start"); len(starts) != 3 || maxTime(starts).Sub(minTime(starts)) > 10*time.Millisecond {
		t.Fatalf("candidate starts did not share a barrier: %v", starts)
	}
	commit := events.first("commit:q1")
	for _, loser := range []string{"w1", "t1"} {
		closed := events.first("abort-done:" + loser)
		if closed.IsZero() || commit.Before(closed) {
			t.Fatalf("credential committed before %s was locally closed: %v", loser, events.values())
		}
		if attempts[loser].commitCount.Load() != 0 {
			t.Fatalf("loser %s committed credentials", loser)
		}
	}
	if attempts["q1"].commitCount.Load() != 1 {
		t.Fatalf("winner commit count = %d", attempts["q1"].commitCount.Load())
	}
}

func TestArtifactLeaseSpendFailureKeepsCredentialBytesAtZero(t *testing.T) {
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events}
	spendErr := errors.New("durable SPENT fsync failed")
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: validArtifact(t),
		CommitSpend: func(context.Context) error {
			events.add("spend")
			return spendErr
		},
	}, allCapabilities(), connectv2.RequireWebSocket, fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}})
	_, err := connector.Connect(context.Background())
	if !errors.Is(err, spendErr) {
		t.Fatalf("Connect error = %v", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeCredentialCommitFailed)
	if attempt.commitCount.Load() != 0 {
		t.Fatalf("credential commit count = %d, want zero", attempt.commitCount.Load())
	}
	if connector.State() != connectv2.StateTerminated {
		t.Fatalf("state = %s, want terminated", connector.State())
	}
	if events.first("abort-done:w1").IsZero() {
		t.Fatal("winner remained writable after spend failure")
	}
}

func TestStructuredConnectErrorPreservesTunnelPath(t *testing.T) {
	artifact := validTunnelArtifact(t)
	spendErr := errors.New("tunnel durable spend failed")
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: artifact,
		CommitSpend: func(context.Context) error {
			return spendErr
		},
	}, allCapabilities(), connectv2.RequireWebSocket, fakeFactory{attempts: map[string]*fakeAttempt{
		"w1": {id: "w1", events: &eventLog{}},
	}})

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, spendErr) {
		t.Fatalf("Connect error = %v", err)
	}
	assertConnectError(t, err, fserrors.PathTunnel, fserrors.StageHandshake, fserrors.CodeCredentialCommitFailed)
}

func TestArtifactLeaseSpendCompletesBeforeCredentialWrite(t *testing.T) {
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events}
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: validArtifact(t),
		CommitSpend: func(context.Context) error {
			events.add("spend")
			return nil
		},
	}, allCapabilities(), connectv2.RequireWebSocket, fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}})
	if _, err := connector.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	spend := events.first("spend")
	commit := events.first("commit:w1")
	if spend.IsZero() || commit.IsZero() || commit.Before(spend) {
		t.Fatalf("spend/commit order = %v", events.values())
	}
}

func TestExpiredArtifactDoesNotStartCandidatesOrSpend(t *testing.T) {
	artifact := validArtifact(t)
	now := time.Unix(2_000_000_000, 0)
	artifact = withArtifactExpiry(t, artifact, now)
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events}
	var spends atomic.Int32
	connector := connectv2.NewConnector(
		connectv2.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				spends.Add(1)
				return nil
			},
		},
		allCapabilities(),
		connectv2.RequireWebSocket,
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
		connectv2.WithConnectorClock(func() time.Time { return now }),
	)

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrArtifactExpired) {
		t.Fatalf("Connect error = %v, want ErrArtifactExpired", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeTimeout)
	if attempt.startCount.Load() != 0 || spends.Load() != 0 || attempt.commitCount.Load() != 0 {
		t.Fatalf("expired artifact crossed the zero-use boundary: starts=%d spends=%d commits=%d", attempt.startCount.Load(), spends.Load(), attempt.commitCount.Load())
	}
}

func TestArtifactExpiryAfterRacePreventsSpendAndCredentialWrite(t *testing.T) {
	artifact := validArtifact(t)
	now := time.Unix(2_000_000_000, 0)
	expires := now.Add(time.Minute)
	artifact = withArtifactExpiry(t, artifact, expires)
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events, readyHook: func() { now = expires }}
	var spends atomic.Int32
	connector := connectv2.NewConnector(
		connectv2.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				spends.Add(1)
				return nil
			},
		},
		allCapabilities(),
		connectv2.RequireWebSocket,
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
		connectv2.WithConnectorClock(func() time.Time { return now }),
	)

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrArtifactExpired) {
		t.Fatalf("Connect error = %v, want ErrArtifactExpired", err)
	}
	if spends.Load() != 0 || attempt.commitCount.Load() != 0 {
		t.Fatalf("expired artifact was spent or written: spends=%d commits=%d", spends.Load(), attempt.commitCount.Load())
	}
}

func TestArtifactExpiryDuringSpendPreventsCredentialWrite(t *testing.T) {
	artifact := validArtifact(t)
	now := time.Unix(2_000_000_000, 0)
	expires := now.Add(time.Minute)
	artifact = withArtifactExpiry(t, artifact, expires)
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events}
	var spends atomic.Int32
	connector := connectv2.NewConnector(
		connectv2.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				spends.Add(1)
				now = expires
				return nil
			},
		},
		allCapabilities(),
		connectv2.RequireWebSocket,
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
		connectv2.WithConnectorClock(func() time.Time { return now }),
	)

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrArtifactExpired) {
		t.Fatalf("Connect error = %v, want ErrArtifactExpired", err)
	}
	if spends.Load() != 1 || attempt.commitCount.Load() != 0 {
		t.Fatalf("post-spend expiry boundary = spends %d commits %d, want 1/0", spends.Load(), attempt.commitCount.Load())
	}
}

func TestArtifactExpiryWhileCandidateIsBlockedReportsExpiry(t *testing.T) {
	base := time.Unix(2_000_000_000, 950_000_000)
	expires := base.Add(50 * time.Millisecond)
	artifact := withArtifactExpiry(t, validArtifact(t), expires)
	started := time.Now()
	events := &eventLog{}
	attempt := &fakeAttempt{
		id:         "w1",
		events:     events,
		readyBlock: make(chan struct{}),
	}
	var spends atomic.Int32
	connector := connectv2.NewConnector(
		connectv2.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				spends.Add(1)
				return nil
			},
		},
		allCapabilities(),
		connectv2.RequireWebSocket,
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
		connectv2.WithConnectorClock(func() time.Time { return base.Add(time.Since(started)) }),
	)

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrArtifactExpired) {
		t.Fatalf("Connect error = %v, want ErrArtifactExpired", err)
	}
	if spends.Load() != 0 || attempt.commitCount.Load() != 0 {
		t.Fatalf("expired blocked attempt crossed spend boundary: spends=%d commits=%d", spends.Load(), attempt.commitCount.Load())
	}
}

func TestConnectEstablishesAndReturnsCarrierNeutralSessionV2(t *testing.T) {
	artifact := validArtifact(t)
	events := &eventLog{}
	attempt := &fakeAttempt{id: "q1", events: events}
	var establishedConfig session.Config
	factory := fakeFactory{
		attempts: map[string]*fakeAttempt{"q1": attempt},
		configMu: &sync.Mutex{},
		config:   &establishedConfig,
	}

	result, err := connectv2.NewConnector(
		inMemoryLease(artifact),
		allCapabilities(),
		connectv2.RequireQUICFamily,
		factory,
	).Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if result.Session == nil {
		t.Fatal("Connect returned a nil SessionV2")
	}
	if result.Candidate.Carrier != artifactv2.CarrierRawQUIC {
		t.Fatalf("chosen candidate carrier = %q", result.Candidate.Carrier)
	}
	if establish := events.first("establish:q1"); establish.IsZero() || establish.Before(events.first("commit:q1")) {
		t.Fatalf("session establishment order = %v", events.values())
	}
	config := factory.lastConfig()
	if config.Role != session.RoleClient || config.Path != session.PathDirect ||
		config.ChannelID != artifact.Session.ChannelID ||
		config.SessionContractHash != artifact.Session.ContractHash ||
		config.PSK != artifact.Session.E2EEPSK ||
		config.MaxInboundStreams != artifact.Session.MaxInboundStreams ||
		config.IdleTimeout != time.Duration(artifact.Session.IdleTimeoutSeconds)*time.Second ||
		config.EstablishTimeout != time.Duration(artifact.Session.EstablishTimeoutSeconds)*time.Second ||
		config.RekeyPrepareTimeout != time.Duration(artifact.Session.RekeyPrepareTimeoutSeconds)*time.Second ||
		config.RekeyCompletionTimeout != time.Duration(artifact.Session.RekeyCompletionTimeoutSeconds)*time.Second ||
		config.LocalAdmissionBinding == ([32]byte{}) ||
		config.PeerAdmissionBinding != config.LocalAdmissionBinding {
		t.Fatalf("unexpected session config: %+v", config)
	}
}

func TestConnectorPassesArtifactSessionContractToEveryCandidate(t *testing.T) {
	artifact := validArtifact(t)
	factory := &contractRecordingFactory{attempts: newImmediateAttempts()}
	result, err := connectv2.NewConnector(
		inMemoryLease(artifact), allCapabilities(), connectv2.Adaptive, factory,
	).Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Session == nil {
		t.Fatal("missing established session")
	}
	for _, candidate := range artifact.Path.Candidates {
		contract, ok := factory.contract(candidate.ID)
		if !ok {
			t.Fatalf("candidate %s did not receive a session contract", candidate.ID)
		}
		if contract.MaxInboundStreams != artifact.Session.MaxInboundStreams || contract.ContractHash != artifact.Session.ContractHash {
			t.Fatalf("candidate %s contract = %+v", candidate.ID, contract)
		}
	}
}

func TestSessionEstablishmentFailureClosesCarrierAndKeepsArtifactSpent(t *testing.T) {
	establishErr := errors.New("authenticated handshake failed")
	closed := &atomic.Bool{}
	attempt := &fakeAttempt{id: "w1", events: &eventLog{}, session: &fakeSession{kind: carrier.KindWebSocket, closed: closed}}
	factory := fakeFactory{
		attempts:     map[string]*fakeAttempt{"w1": attempt},
		establishErr: establishErr,
	}
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)), allCapabilities(), connectv2.RequireWebSocket, factory)
	if _, err := connector.Connect(context.Background()); !errors.Is(err, establishErr) {
		t.Fatalf("Connect error = %v", err)
	}
	if connector.State() != connectv2.StateSpent {
		t.Fatalf("state = %s, want spent", connector.State())
	}
	if !closed.Load() {
		t.Fatal("carrier remained open after session establishment failure")
	}
}

func TestConnectRejectsCarrierPathMismatchBeforeSessionHandshake(t *testing.T) {
	closed := &atomic.Bool{}
	attempts := newImmediateAttempts()
	attempts["w1"].session = &fakeSession{
		kind: carrier.KindWebSocket, path: carrier.PathTunnel, closed: closed,
	}
	connector := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		allCapabilities(),
		connectv2.RequireWebSocket,
		fakeFactory{attempts: attempts},
	)
	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrInvalidFactory) {
		t.Fatalf("Connect path mismatch error = %v, want ErrInvalidFactory", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageAttach, fserrors.CodeAttachFailed)
	if !closed.Load() {
		t.Fatal("path-mismatched carrier session remained open")
	}
}

func TestArrayOrderDoesNotOverrideReadiness(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		artifact := validArtifact(t)
		if reverse {
			artifact.Path.Candidates[0], artifact.Path.Candidates[1] = artifact.Path.Candidates[1], artifact.Path.Candidates[0]
		}
		attempts := map[string]*fakeAttempt{
			"w1": {id: "w1", readyDelay: 30 * time.Millisecond, events: &eventLog{}},
			"q1": {id: "q1", readyDelay: time.Millisecond, events: &eventLog{}},
			"t1": {id: "t1", readyDelay: 50 * time.Millisecond, events: &eventLog{}},
		}
		result, err := connectv2.NewConnector(inMemoryLease(artifact), allCapabilities(), connectv2.Adaptive, fakeFactory{attempts: attempts}).Connect(context.Background())
		if err != nil {
			t.Fatalf("Connect(reverse=%v): %v", reverse, err)
		}
		if result.Candidate.ID != "q1" {
			t.Fatalf("winner(reverse=%v) = %s", reverse, result.Candidate.ID)
		}
	}
}

func TestExplicitPoliciesFilterWithoutCreatingAPrimaryCarrier(t *testing.T) {
	tests := []struct {
		policy connectv2.Policy
		want   map[string]bool
	}{
		{policy: connectv2.RequireWebSocket, want: map[string]bool{"w1": true}},
		{policy: connectv2.RequireQUICFamily, want: map[string]bool{"q1": true, "t1": true}},
	}
	for _, tt := range tests {
		attempts := newImmediateAttempts()
		_, err := connectv2.NewConnector(inMemoryLease(validArtifact(t)), allCapabilities(), tt.policy, fakeFactory{attempts: attempts}).Connect(context.Background())
		if err != nil {
			t.Fatalf("Connect(%s): %v", tt.policy, err)
		}
		for id, attempt := range attempts {
			if got := attempt.startCount.Load() > 0; got != tt.want[id] {
				t.Fatalf("policy %s candidate %s started=%v", tt.policy, id, got)
			}
		}
	}
}

func TestCapabilityFilterUsesExactTuple(t *testing.T) {
	descriptor := session.CapabilityDescriptor{
		Language: "go", Runtime: "test", SchemaVersion: 2,
		Tuples: []session.CapabilityTuple{{
			Carrier: carrier.KindWebSocket, NetworkMode: session.NetworkDial, SessionRole: session.RoleClient, Path: session.PathDirect,
		}},
		Unsupported: []session.UnsupportedCapability{
			{Carrier: carrier.KindQUIC, Reason: "test_not_supported"},
			{Carrier: carrier.KindWebTransport, Reason: "test_not_supported"},
		},
	}
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)), descriptor, connectv2.Adaptive, fakeFactory{attempts: newImmediateAttempts()})
	result, err := connector.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if result.Candidate.ID != "w1" {
		t.Fatalf("winner = %s, want only supported w1", result.Candidate.ID)
	}
}

func TestArtifactCanOnlyBeClaimedOnceEvenWhenCommitFails(t *testing.T) {
	attempts := newImmediateAttempts()
	commitErr := errors.New("partial admission write")
	attempts["q1"].commitErr = commitErr
	attempts["t1"].commitErr = commitErr
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)), allCapabilities(), connectv2.RequireQUICFamily, fakeFactory{attempts: attempts})
	if _, err := connector.Connect(context.Background()); !errors.Is(err, commitErr) {
		t.Fatalf("first Connect error = %v", err)
	} else {
		assertConnectError(t, err, fserrors.PathDirect, fserrors.StageAttach, fserrors.CodeAttachFailed)
	}
	if connector.State() != connectv2.StateSpent {
		t.Fatalf("state = %s, want spent", connector.State())
	}
	if _, err := connector.Connect(context.Background()); !errors.Is(err, connectv2.ErrArtifactClaimed) {
		t.Fatalf("second Connect error = %v", err)
	}
}

func TestCandidateFailuresExposeStableStructuredDiagnostics(t *testing.T) {
	attempts := newImmediateAttempts()
	for id, attempt := range attempts {
		attempt.readyErr = fmt.Errorf("%s transport failed", id)
	}
	_, err := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		allCapabilities(),
		connectv2.Adaptive,
		fakeFactory{attempts: attempts},
	).Connect(context.Background())
	structured := assertConnectError(t, err, fserrors.PathDirect, fserrors.StageConnect, fserrors.CodeDialFailed)
	if len(structured.Diagnostics) != len(attempts) {
		t.Fatalf("diagnostics = %d, want %d: %+v", len(structured.Diagnostics), len(attempts), structured.Diagnostics)
	}
	seen := make(map[string]bool, len(structured.Diagnostics))
	for _, diagnostic := range structured.Diagnostics {
		seen[diagnostic.CandidateID] = true
		if diagnostic.Stage != fserrors.StageConnect || diagnostic.Code != fserrors.CodeDialFailed {
			t.Errorf("diagnostic %s = %s/%s, want connect/dial_failed", diagnostic.CandidateID, diagnostic.Stage, diagnostic.Code)
		}
	}
	for id := range attempts {
		if !seen[id] {
			t.Errorf("missing diagnostic for candidate %s", id)
		}
	}
}

func TestConcurrentConnectRejectsSecondClaim(t *testing.T) {
	release := make(chan struct{})
	attempts := newImmediateAttempts()
	for _, attempt := range attempts {
		attempt.readyBlock = release
	}
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)), allCapabilities(), connectv2.Adaptive, fakeFactory{attempts: attempts})
	firstDone := make(chan error, 1)
	go func() {
		_, err := connector.Connect(context.Background())
		firstDone <- err
	}()
	deadline := time.Now().Add(time.Second)
	for connector.State() != connectv2.StatePreconnect {
		if time.Now().After(deadline) {
			t.Fatal("first Connect did not claim artifact")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := connector.Connect(context.Background()); !errors.Is(err, connectv2.ErrArtifactClaimed) {
		t.Fatalf("concurrent Connect error = %v", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Connect: %v", err)
	}
}

func TestConnectDeadlineIncludesLoserCleanup(t *testing.T) {
	events := &eventLog{}
	attempts := map[string]*fakeAttempt{
		"q1": {id: "q1", events: events},
		"t1": {id: "t1", readyDelay: time.Hour, abortDelay: time.Hour, events: events},
	}
	connector := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		allCapabilities(),
		connectv2.RequireQUICFamily,
		fakeFactory{attempts: attempts},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageAttach, fserrors.CodeTimeout)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Connect exceeded its total establishment deadline: %v", elapsed)
	}
	for _, id := range []string{"q1", "t1"} {
		if !attempts[id].locallyClosed.Load() {
			t.Fatalf("candidate %s remained locally writable: %v", id, events.values())
		}
	}
}

func TestConnectDeadlineIncludesWinnerCleanupAfterSpendFailure(t *testing.T) {
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", abortDelay: time.Hour, events: events}
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: validArtifact(t),
		CommitSpend: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}, allCapabilities(), connectv2.RequireWebSocket, fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeTimeout)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Connect exceeded its total establishment deadline: %v", elapsed)
	}
	if !attempt.locallyClosed.Load() {
		t.Fatalf("winner remained locally writable: %v", events.values())
	}
}

func assertConnectError(t *testing.T, err error, path fserrors.Path, stage fserrors.Stage, code fserrors.Code) *fserrors.Error {
	t.Helper()
	var structured *fserrors.Error
	if !errors.As(err, &structured) {
		t.Fatalf("Connect error type = %T, want *fserrors.Error: %v", err, err)
	}
	if structured.Path != path || structured.Stage != stage || structured.Code != code {
		t.Fatalf("Connect error = %s/%s/%s, want %s/%s/%s: %v", structured.Path, structured.Stage, structured.Code, path, stage, code, err)
	}
	return structured
}

func TestConnectDeadlineIncludesCandidateRace(t *testing.T) {
	events := &eventLog{}
	readyBlock := make(chan struct{})
	attempts := map[string]*fakeAttempt{
		"q1": {id: "q1", readyBlock: readyBlock, abortDelay: time.Hour, events: events},
		"t1": {id: "t1", readyBlock: readyBlock, abortDelay: time.Hour, events: events},
	}
	connector := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		allCapabilities(),
		connectv2.RequireQUICFamily,
		fakeFactory{attempts: attempts},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("candidate race exceeded the total establishment deadline: %v", elapsed)
	}
	for _, attempt := range attempts {
		if attempt.commitCount.Load() != 0 || !events.first("ready:"+attempt.id).IsZero() {
			t.Fatalf("candidate %s crossed the credential-free ready barrier: %v", attempt.id, events.values())
		}
	}
}

func TestConnectDeadlineIncludesFSB2Admission(t *testing.T) {
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", commitWaitForContext: true, events: events}
	connector := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		allCapabilities(),
		connectv2.RequireWebSocket,
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("FSB2 admission exceeded the total establishment deadline: %v", elapsed)
	}
	if connector.State() != connectv2.StateSpent {
		t.Fatalf("state = %s, want spent", connector.State())
	}
	if !attempt.locallyClosed.Load() {
		t.Fatalf("winner remained locally writable: %v", events.values())
	}
}

func TestConnectDeadlineIncludesSessionEstablishment(t *testing.T) {
	events := &eventLog{}
	closed := &atomic.Bool{}
	attempt := &fakeAttempt{
		id: "w1", events: events,
		session: &fakeSession{kind: carrier.KindWebSocket, closed: closed},
	}
	connector := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		allCapabilities(),
		connectv2.RequireWebSocket,
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}, establishWaitForContext: true},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("session establishment exceeded the total establishment deadline: %v", elapsed)
	}
	if connector.State() != connectv2.StateSpent {
		t.Fatalf("state = %s, want spent", connector.State())
	}
	if !closed.Load() {
		t.Fatalf("carrier remained open: %v", events.values())
	}
}

type fakeFactory struct {
	attempts                map[string]*fakeAttempt
	establishErr            error
	establishWaitForContext bool
	configMu                *sync.Mutex
	config                  *session.Config
}

type contractRecordingFactory struct {
	mu       sync.Mutex
	attempts map[string]*fakeAttempt
	seen     map[string]artifactv2.SessionContract
}

func (factory *contractRecordingFactory) NewAttempt(candidate artifactv2.Candidate, contract artifactv2.SessionContract) (connectv2.Attempt, error) {
	factory.mu.Lock()
	if factory.seen == nil {
		factory.seen = make(map[string]artifactv2.SessionContract)
	}
	factory.seen[candidate.ID] = contract
	factory.mu.Unlock()
	return factory.attempts[candidate.ID], nil
}

func (factory *contractRecordingFactory) contract(candidateID string) (artifactv2.SessionContract, bool) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	contract, ok := factory.seen[candidateID]
	return contract, ok
}

func (*contractRecordingFactory) Establish(_ context.Context, carrierSession carrier.Session, config session.Config) (session.SessionV2, error) {
	return &fakeSessionV2{carrierSession: carrierSession, config: config}, nil
}

func (factory fakeFactory) NewAttempt(candidate artifactv2.Candidate, _ artifactv2.SessionContract) (connectv2.Attempt, error) {
	attempt := factory.attempts[candidate.ID]
	if attempt == nil {
		return nil, fmt.Errorf("missing attempt %s", candidate.ID)
	}
	return attempt, nil
}

func (factory fakeFactory) Establish(ctx context.Context, carrierSession carrier.Session, config session.Config) (session.SessionV2, error) {
	if factory.configMu != nil && factory.config != nil {
		factory.configMu.Lock()
		*factory.config = config
		factory.configMu.Unlock()
	}
	if fake, ok := carrierSession.(*fakeSession); ok && fake.events != nil {
		fake.events.add("establish:" + fake.id)
	} else if fake, ok := carrierSession.(fakeSession); ok && fake.events != nil {
		fake.events.add("establish:" + fake.id)
	}
	if factory.establishErr != nil {
		return nil, factory.establishErr
	}
	if factory.establishWaitForContext {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &fakeSessionV2{carrierSession: carrierSession, config: config}, nil
}

func (factory fakeFactory) lastConfig() session.Config {
	if factory.configMu == nil || factory.config == nil {
		return session.Config{}
	}
	factory.configMu.Lock()
	defer factory.configMu.Unlock()
	return *factory.config
}

type fakeAttempt struct {
	id                   string
	readyDelay           time.Duration
	abortDelay           time.Duration
	readyBlock           <-chan struct{}
	readyErr             error
	commitErr            error
	commitWaitForContext bool
	events               *eventLog
	startCount           atomic.Int32
	commitCount          atomic.Int32
	locallyClosed        atomic.Bool
	aborted              chan struct{}
	abortOnce            sync.Once
	session              carrier.Session
	readyHook            func()
}

func (attempt *fakeAttempt) Ready(ctx context.Context) (connectv2.Prepared, error) {
	attempt.startCount.Add(1)
	attempt.events.add("start:" + attempt.id)
	if attempt.readyBlock != nil {
		select {
		case <-attempt.readyBlock:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	timer := time.NewTimer(attempt.readyDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	if attempt.readyErr != nil {
		return nil, attempt.readyErr
	}
	attempt.events.add("ready:" + attempt.id)
	if attempt.readyHook != nil {
		attempt.readyHook()
	}
	return (*fakePrepared)(attempt), nil
}

func (attempt *fakeAttempt) Abort(ctx context.Context) error {
	attempt.abortOnce.Do(func() {
		attempt.events.add("abort-start:" + attempt.id)
		attempt.locallyClosed.Store(true)
		timer := time.NewTimer(attempt.abortDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		attempt.events.add("abort-done:" + attempt.id)
		if attempt.aborted != nil {
			close(attempt.aborted)
		}
	})
	return nil
}

type fakePrepared fakeAttempt

func (prepared *fakePrepared) Commit(ctx context.Context, fsb2 []byte) (carrier.Session, error) {
	attempt := (*fakeAttempt)(prepared)
	if len(fsb2) < artifactv2.FSB2HeaderSize || string(fsb2[:4]) != "FSB2" {
		return nil, errors.New("missing FSB2")
	}
	attempt.commitCount.Add(1)
	attempt.events.add("commit:" + attempt.id)
	if attempt.commitWaitForContext {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	kind := carrier.KindQUIC
	if attempt.id == "w1" {
		kind = carrier.KindWebSocket
	} else if attempt.id == "t1" {
		kind = carrier.KindWebTransport
	}
	carrierSession := attempt.session
	if carrierSession == nil {
		carrierSession = &fakeSession{kind: kind, id: attempt.id, events: attempt.events, closed: &atomic.Bool{}}
	}
	return carrierSession, attempt.commitErr
}

func (prepared *fakePrepared) Close(ctx context.Context) error {
	return (*fakeAttempt)(prepared).Abort(ctx)
}

type fakeSession struct {
	kind   carrier.Kind
	path   carrier.Path
	id     string
	events *eventLog
	closed *atomic.Bool
}

func (session fakeSession) Kind() carrier.Kind { return session.kind }
func (session fakeSession) Path() carrier.Path {
	if session.path == "" {
		return carrier.PathDirect
	}
	return session.path
}
func (fakeSession) MaxIncomingStreams() uint16 { return 34 }
func (fakeSession) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, errors.New("unused")
}
func (fakeSession) AcceptStream(context.Context) (carrier.Stream, error) {
	return nil, errors.New("unused")
}
func (session fakeSession) CloseWithError(carrier.ApplicationError) error {
	if session.closed != nil {
		session.closed.Store(true)
	}
	return nil
}
func (session fakeSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	if session.closed != nil {
		session.closed.Store(true)
	}
	return nil
}
func (session fakeSession) Close() error {
	if session.closed != nil {
		session.closed.Store(true)
	}
	return nil
}

type fakeSessionV2 struct {
	carrierSession  carrier.Session
	config          session.Config
	terminationMu   sync.Mutex
	termination     chan struct{}
	terminationOnce sync.Once
}

func (value *fakeSessionV2) Path() session.PathKind             { return value.config.Path }
func (value *fakeSessionV2) ChosenCarrier() carrier.Kind        { return value.carrierSession.Kind() }
func (value *fakeSessionV2) EndpointInstanceID() (string, bool) { return "", false }
func (value *fakeSessionV2) RPC() session.RPCPeer               { return fakeRPCPeer{} }
func (value *fakeSessionV2) UnreliableMessages() (session.UnreliableMessageChannel, error) {
	return nil, session.ErrUnreliableUnavailable
}
func (value *fakeSessionV2) OpenStream(context.Context, string, session.Metadata) (session.ByteStream, error) {
	return nil, errors.New("unused")
}
func (value *fakeSessionV2) AcceptStream(context.Context) (session.IncomingStream, error) {
	return session.IncomingStream{}, errors.New("unused")
}
func (value *fakeSessionV2) Rekey(context.Context) error { return nil }
func (value *fakeSessionV2) ProbeLiveness(context.Context) (time.Duration, error) {
	return time.Millisecond, nil
}
func (value *fakeSessionV2) terminationChannel() chan struct{} {
	value.terminationMu.Lock()
	defer value.terminationMu.Unlock()
	if value.termination == nil {
		value.termination = make(chan struct{})
	}
	return value.termination
}
func (value *fakeSessionV2) Termination() <-chan struct{} { return value.terminationChannel() }
func (value *fakeSessionV2) WaitClosed(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-value.Termination():
		return session.ErrSessionClosed
	}
}
func (value *fakeSessionV2) Close() error {
	terminated := value.terminationChannel()
	value.terminationOnce.Do(func() { close(terminated) })
	return value.carrierSession.Close()
}

type fakeRPCPeer struct{}

func (fakeRPCPeer) Call(context.Context, uint32, any, any) error { return nil }
func (fakeRPCPeer) Notify(context.Context, uint32, any) error    { return nil }

type event struct {
	name string
	at   time.Time
}

type eventLog struct {
	mu     sync.Mutex
	events []event
}

func (log *eventLog) add(name string) {
	log.mu.Lock()
	log.events = append(log.events, event{name: name, at: time.Now()})
	log.mu.Unlock()
}

func (log *eventLog) first(name string) time.Time {
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, event := range log.events {
		if event.name == name {
			return event.at
		}
	}
	return time.Time{}
}

func (log *eventLog) times(prefix string) []time.Time {
	log.mu.Lock()
	defer log.mu.Unlock()
	var out []time.Time
	for _, event := range log.events {
		if len(event.name) >= len(prefix) && event.name[:len(prefix)] == prefix {
			out = append(out, event.at)
		}
	}
	return out
}

func (log *eventLog) values() []event {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]event(nil), log.events...)
}

func minTime(values []time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}

func maxTime(values []time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.After(result) {
			result = value
		}
	}
	return result
}

func newImmediateAttempts() map[string]*fakeAttempt {
	events := &eventLog{}
	return map[string]*fakeAttempt{
		"w1": {id: "w1", readyDelay: 3 * time.Millisecond, events: events},
		"q1": {id: "q1", readyDelay: time.Millisecond, events: events},
		"t1": {id: "t1", readyDelay: 2 * time.Millisecond, events: events},
	}
}

func allCapabilities() session.CapabilityDescriptor { return session.GoCapabilities() }

func inMemoryLease(artifact artifactv2.Artifact) connectv2.ArtifactLease {
	return connectv2.ArtifactLease{Artifact: artifact, CommitSpend: func(context.Context) error { return nil }}
}

func validArtifact(t *testing.T) artifactv2.Artifact {
	t.Helper()
	sessionContract := artifactv2.SessionContract{
		ChannelID: "channel-1", InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: 32, AllowedSuites: []uint16{1, 2}, DefaultSuite: 1,
	}
	for index := range sessionContract.E2EEPSK {
		sessionContract.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(sessionContract)
	if err != nil {
		t.Fatalf("ComputeSessionContractHash: %v", err)
	}
	sessionContract.ContractHash = hash
	artifact := artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: sessionContract,
		Path: artifactv2.ArtifactPath{
			Kind: artifactv2.PathDirect, RendezvousGroupID: "group-1", ListenerAudience: "listener-1",
			RoutingToken: "opaque-route", Candidates: []artifactv2.Candidate{
				{ID: "w1", Carrier: artifactv2.CarrierWebSocket, URL: "wss://example.test/flowersec/v2/direct", WireProfile: "flowersec-direct/2"},
				{ID: "q1", Carrier: artifactv2.CarrierRawQUIC, URL: "quic://example.test:443", WireProfile: "flowersec-direct/2"},
				{ID: "t1", Carrier: artifactv2.CarrierWebTransport, URL: "https://example.test/flowersec/webtransport/v2/direct", WireProfile: "flowersec-direct/2"},
			},
		},
		Scoped: []artifactv2.ScopeMetadata{}, Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
	if err := artifactv2.ValidateArtifact(artifact); err != nil {
		t.Fatalf("ValidateArtifact: %v", err)
	}
	return artifact
}

func validTunnelArtifact(t *testing.T) artifactv2.Artifact {
	t.Helper()
	artifact := validArtifact(t)
	artifact.Path.Kind = artifactv2.PathTunnel
	artifact.Path.RoutingToken = ""
	artifact.Path.Role = 1
	artifact.Path.LocalEndpointInstanceID = "endpoint-local"
	artifact.Path.ExpectedPeerEndpointInstanceID = "endpoint-peer"
	artifact.Path.Token = "opaque-attach"
	artifact.Path.Candidates = []artifactv2.Candidate{
		{ID: "w1", Carrier: artifactv2.CarrierWebSocket, URL: "wss://example.test/flowersec/v2/tunnel", WireProfile: "flowersec-tunnel/2"},
		{ID: "q1", Carrier: artifactv2.CarrierRawQUIC, URL: "quic://example.test:443", WireProfile: "flowersec-tunnel/2"},
		{ID: "t1", Carrier: artifactv2.CarrierWebTransport, URL: "https://example.test/flowersec/webtransport/v2/tunnel", WireProfile: "flowersec-tunnel/2"},
	}
	if err := artifactv2.ValidateArtifact(artifact); err != nil {
		t.Fatalf("ValidateArtifact: %v", err)
	}
	return artifact
}

func withArtifactExpiry(t *testing.T, artifact artifactv2.Artifact, expiresAt time.Time) artifactv2.Artifact {
	t.Helper()
	artifact.Session.InitExpireAtUnixSeconds = expiresAt.Unix()
	hash, _, err := artifactv2.ComputeSessionContractHash(artifact.Session)
	if err != nil {
		t.Fatalf("ComputeSessionContractHash: %v", err)
	}
	artifact.Session.ContractHash = hash
	return artifact
}
