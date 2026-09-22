package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// Reissue the fixture under its same independently configured signing key.
// The production lease verifier still checks the new exact Artifact/proof/set.
func raceMaterialFixture(t *testing.T, source string, indices []uint64, budget map[string]protocolv4.Field, websocket ...bool) *admissionIntegrationFixture {
	t.Helper()
	f := admissionIntegration(t, context.Background(), source)
	original := f.trust.artifact
	var candidates [][]byte
	for index := range 3 {
		id := [16]byte{byte(30 + index)}
		changes := map[string]protocolv4.Field{"candidate_id": admissionBytes(id[:]), "priority": {Number: uint64(index)}}
		if len(websocket) > 0 && websocket[0] {
			leg := original.Field("candidates").Index(0).Named("Candidate", "direct_leg")
			wire := admissionMap(t, "Leg", leg.Encoded(), map[string]protocolv4.Field{"carrier": {Number: 1}, "path": admissionText("/flowersec/v4/direct"), "alpn": admissionText("http/1.1"), "subprotocol": admissionText("flowersec.direct.v4")})
			changes["direct_leg"] = protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: wire}
		}
		candidate := admissionMap(t, "Candidate", original.Field("candidates").Index(0).Encoded(), changes)
		candidates = append(candidates, candidate)
	}
	wire, _ := original.Bytes()
	f.trust.artifact = initialSignTemplate(t, "Artifact", wire, map[string]protocolv4.Field{"candidates": admissionArray(candidates...)}, [32]byte{71, 23, 4})
	var err error
	f.trust.session, err = f.trust.artifact.SessionParameters()
	if err != nil {
		t.Fatal(err)
	}
	if source == "preauthorized_pool" {
		workspace, err := protocolv4.NewPoolSelectionWorkspace(65536, 65536)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := workspace.Derive(f.trust.artifact, indices)
		if err != nil {
			t.Fatal(err)
		}
		artifact, set, routes, err := selection.Digests()
		if err != nil {
			t.Fatal(err)
		}
		selection.Release()
		reference := f.trust.proof.Field("candidate_selection")
		encodedIndices := []byte{0x80 | byte(len(indices))}
		for _, index := range indices {
			encodedIndices = append(encodedIndices, byte(index))
		}
		attemptBudget := reference.Named("PoolSelectionRef", "attempt_budget").Encoded()
		if budget != nil {
			attemptBudget = admissionMap(t, "PoolAttemptBudget", attemptBudget, budget)
		}
		ref := admissionMap(t, "PoolSelectionRef", reference.Encoded(), map[string]protocolv4.Field{
			"artifact_digest": admissionBytes(artifact[:]), "candidate_set_digest": admissionBytes(set[:]), "candidate_indices": {Kind: protocolv4.EncodedArray, Bytes: encodedIndices},
			"attempt_budget": {Kind: protocolv4.EncodedMap, Bytes: attemptBudget},
		}, source)
		wire, _ := f.trust.proof.Bytes()
		f.trust.proof = initialSignTemplate(t, "ActivationAuthorization", wire, map[string]protocolv4.Field{"artifact_digest": admissionBytes(artifact[:]), "candidate_selection": {Kind: protocolv4.EncodedMap, Bytes: ref}, "route_selection": admissionBytes(routes[:])}, [32]byte{71, 23, 4}, source)
	}
	return f
}

func admittedTestRace(t *testing.T, f *admissionIntegrationFixture, factory ConsumerCarrierFactory) (*sourcePreparation, *EnvironmentSession, *ArtifactLease) {
	t.Helper()
	m, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	c := sourceConnectTestConfig(t, f, identity, immediateMaterialProvider{lease}, factory)
	charge, err := SourcePreparationCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := c.Preparation.Take(charge)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := c.Dependencies.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	host := environmentTestOwner(t, f, 248, 1)
	s := newEnvironmentSession(host, 0, context.Background())
	p := &sourcePreparation{config: c, material: m, reservation: owned, shared: shared}
	if err := p.selection.begin(m, c.Generation, c.Hello.Attempt); err != nil {
		t.Fatal(err)
	}
	config := c.Admission
	config.Core.Session, config.Initial.Profile = lease.session, lease.session.Profile
	p.race.init(p, s, config)
	t.Cleanup(func() {
		s.context.cancel()
		if err := p.cleanup(); err != nil {
			t.Error(err)
		}
	})
	return p, s, lease
}

func waitRaceSignal[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("original candidate did not progress")
		var zero T
		return zero
	}
}

func TestCandidateRaceWinnerDoesNotWaitForCanceledLoser(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			f := raceMaterialFixture(t, source, []uint64{0, 1, 2}, nil)
			entered := make(chan uint64, 3)
			canceled := make(chan struct{}, 1)
			release := make(chan struct{})
			defer close(release)
			var loser *PreparedCarrier
			provider := &preparedTestProvider{environment: f.environment}
			p, _, lease := admittedTestRace(t, f, carrierFactoryFunc(func(ctx context.Context, request CarrierPreparationRequest) (*PreparedCarrier, error) {
				if len(request.Route) == 0 || request.Config.Attempt != f.trust.attempt {
					return nil, cryptov4.ErrConfiguration
				}
				entered <- request.Config.Candidate.Index
				if request.Config.Candidate.Index == 0 {
					var err error
					loser, err = NewPreparedMessages(context.Background(), request.Config, provider)
					if err != nil {
						return nil, err
					}
					<-ctx.Done()
					canceled <- struct{}{}
					<-release
					return loser, nil
				}
				return NewPreparedMessages(ctx, request.Config, &preparedTestProvider{environment: f.environment})
			}))
			type result struct {
				p   *PreparedCarrier
				err error
			}
			resultCh := make(chan result, 1)
			go func() { winner, _, err := p.race.prepare(); resultCh <- result{winner, err} }()
			if got := waitRaceSignal(t, entered); got != 0 {
				t.Fatal(got)
			}
			if got := waitRaceSignal(t, entered); got != 1 {
				t.Fatal(got)
			}
			got := waitRaceSignal(t, resultCh)
			if got.err != nil || got.p.AdmissionBinding().Candidate.Index != 1 {
				t.Fatal(got.err)
			}
			p.prepared = got.p
			waitRaceSignal(t, canceled)
			if lease.claimed || provider.retires.Load() != 0 {
				t.Fatal("prepare spent or refunded blocked loser")
			}
			before := f.root.Snapshot()
			cleanup := make(chan error, 1)
			go func() { cleanup <- p.race.cleanup() }()
			select {
			case err := <-cleanup:
				t.Fatal("blocked original provider reported cleanup", err)
			case <-time.After(10 * time.Millisecond):
			}
			if before != f.root.Snapshot() {
				t.Fatal("blocked loser returned its charge")
			}
			release <- struct{}{}
			if err := waitRaceSignal(t, cleanup); err != nil {
				t.Fatal(err)
			}
			if provider.retires.Load() != 1 || provider.reads.Load() != 0 || provider.writes.Load() != 0 {
				t.Fatal("loser activated or failed retirement")
			}
		})
	}
}

func TestCandidateRaceSignedSubsetAndCumulativeLimits(t *testing.T) {
	cases := []struct {
		name      string
		budget    map[string]protocolv4.Field
		addresses uint8
		want      int
	}{
		{"subset", nil, 1, 2},
		{"address", map[string]protocolv4.Field{"total_address_attempts": {Number: 1}}, 2, 1},
		{"bytes", map[string]protocolv4.Field{"total_preauth_bytes": {Number: 131072}}, 2, 1},
		{"work", map[string]protocolv4.Field{"total_work_units": {Number: 128}}, 2, 1},
		{"per-candidate", nil, 8, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := raceMaterialFixture(t, "preauthorized_pool", []uint64{1, 2}, tc.budget)
			var calls atomic.Int32
			p, _, lease := admittedTestRace(t, f, carrierFactoryFunc(func(_ context.Context, request CarrierPreparationRequest) (*PreparedCarrier, error) {
				calls.Add(1)
				if request.Config.Candidate.Index == 0 || request.AddressAttempt > 1 {
					t.Error("outside original signed preparation set")
				}
				return nil, errors.New("synthetic numeric attempt failure")
			}))
			p.config.AddressAttempts = tc.addresses
			winner, _, err := p.race.prepare()
			if winner != nil || err == nil || int(calls.Load()) != tc.want {
				t.Fatal(winner, err, calls.Load(), tc.want)
			}
			if lease.claimed {
				t.Fatal("failed preparations claimed original lease")
			}
		})
	}
}

func TestCandidateRaceCancellationAndAbnormalMethodsRetainPositions(t *testing.T) {
	for _, failure := range []string{"return", "panic", "goexit"} {
		t.Run(failure, func(t *testing.T) {
			f := raceMaterialFixture(t, "preauthorized_pool", []uint64{0, 1, 2}, nil)
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			defer close(release)
			var calls atomic.Int32
			p, s, _ := admittedTestRace(t, f, carrierFactoryFunc(func(ctx context.Context, _ CarrierPreparationRequest) (*PreparedCarrier, error) {
				calls.Add(1)
				entered <- struct{}{}
				defer func() { <-release }()
				<-ctx.Done()
				switch failure {
				case "panic":
					panic("private provider failure")
				case "goexit":
					runtime.Goexit()
				}
				return nil, ctx.Err()
			}))
			result := make(chan error, 1)
			go func() { _, _, err := p.race.prepare(); result <- err }()
			waitRaceSignal(t, entered)
			waitRaceSignal(t, entered)
			s.context.cancel()
			if err := waitRaceSignal(t, result); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			before := f.root.Snapshot()
			cleanup := make(chan error, 1)
			go func() { cleanup <- p.race.cleanup() }()
			select {
			case err := <-cleanup:
				t.Fatal("original method defers lost", err)
			case <-time.After(10 * time.Millisecond):
			}
			if calls.Load() != 2 || f.root.Snapshot() != before {
				t.Fatal("canceled tasks lost concurrency or charge")
			}
			release <- struct{}{}
			release <- struct{}{}
			if err := waitRaceSignal(t, cleanup); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMaterialPreparationExclusiveAndReversibleBeforeClaim(t *testing.T) {
	f := raceMaterialFixture(t, "preauthorized_pool", []uint64{0, 1, 2}, nil)
	m, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	cost, _ := ConnectionMaterialCharge(8192)
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 286), cost)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	other, err := NewConnectionMaterial(lease, identity, m.generation, 8192, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var a, b materialPreparation
	if err = a.begin(m, m.generation, f.trust.attempt); err != nil {
		t.Fatal(err)
	}
	if err = b.begin(other, other.generation, f.trust.attempt); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal(err)
	}
	if _, _, err = m.Establishment(InitialHello{}, EstablishmentLimits{}, m.generation, resourcev4.Reference{}, resourcev4.Reference{}); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("manual activation escaped preparation", err)
	}
	a.close()
	if lease.claimed {
		t.Fatal("preparation release became durable/local claim")
	}
	if err = b.begin(other, other.generation, f.trust.attempt); err != nil {
		t.Fatal(err)
	}
	other.Close()
	select {
	case <-other.done:
		t.Fatal("Close released an original preparation pin")
	default:
	}
	b.close()
	select {
	case <-other.done:
	default:
		t.Fatal("real preparation retirement kept dead pin")
	}
}

func TestCandidateRaceReplacesFailedWinnerBeforeEstablishment(t *testing.T) {
	f := raceMaterialFixture(t, "preauthorized_pool", []uint64{0, 1, 2}, nil)
	held := &preparedTestProvider{environment: f.environment, closeEntered: make(chan struct{}), closeRelease: make(chan struct{})}
	defer close(held.closeRelease)
	p, _, lease := admittedTestRace(t, f, carrierFactoryFunc(func(ctx context.Context, request CarrierPreparationRequest) (*PreparedCarrier, error) {
		provider := &preparedTestProvider{environment: f.environment}
		if request.Config.Candidate.Index == 0 {
			provider = held
		}
		return NewPreparedMessages(ctx, request.Config, provider)
	}))
	first, _, err := p.race.prepare()
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	if err := p.race.rejectWinner(first); err != nil {
		t.Fatal(err)
	}
	waitRaceSignal(t, held.closeEntered)
	second, _, err := p.race.prepare()
	if err != nil || second.AdmissionBinding().Candidate.Index != 1 {
		t.Fatal(err)
	}
	p.prepared = second
	if held.retires.Load() != 0 || lease.claimed {
		t.Fatal("replacement refunded blocked original or spent")
	}
	// Final admission is an ownership barrier even before durable store work.
	second.mu.Lock()
	second.admission = &SessionAdmissionReservation{}
	second.mu.Unlock()
	if err := p.race.rejectWinner(second); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("adopted carrier was replaceable", err)
	}
	second.mu.Lock()
	second.admission = nil
	second.mu.Unlock()
	held.closeRelease <- struct{}{}
}

func TestCandidateRaceRetiresWinnerCanceledBeforeHandoff(t *testing.T) {
	f := raceMaterialFixture(t, "preauthorized_pool", []uint64{0}, nil)
	provider := &preparedTestProvider{environment: f.environment}
	p, s, _ := admittedTestRace(t, f, carrierFactoryFunc(func(ctx context.Context, request CarrierPreparationRequest) (*PreparedCarrier, error) {
		return NewPreparedMessages(ctx, request.Config, provider)
	}))
	if _, _, err := p.race.prepare(); err != nil {
		t.Fatal(err)
	}
	s.context.cancel()
	if err := p.race.cleanup(); err != nil {
		t.Fatal(err)
	}
	if provider.retires.Load() != 1 {
		t.Fatal("winner without source handoff escaped cleanup")
	}
}

func TestLiveIssuanceRejectsChangedWinnerBeforeDurableClaim(t *testing.T) {
	f := raceMaterialFixture(t, "live_authority", nil, nil)
	cost, err := protocolv4.LiveActivationPlanCharge()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 290), cost)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	plan, err := protocolv4.NewLiveActivationPlan(f.trust.artifact, f.trust.rules, f.trust.delegation, f.trust.once, f.trust.issueSigner, protocolv4.LiveActivationConfig{Index: 1, Attempt: f.trust.attempt, IssuedAt: 1150, ActivationEnd: 1400, SessionEnd: 4000}, ref, f.environment, f.preauth)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	fields, _, err := plan.CopyProjection(make([]byte, 4096))
	if err != nil {
		t.Fatal(err)
	}
	if err = plan.MatchOriginal(f.trust.session, f.trust.attempt, fields.Winner); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"candidate", "route", "attempt", "artifact"} {
		t.Run(change, func(t *testing.T) {
			session, attempt, winner := f.trust.session, f.trust.attempt, fields.Winner
			switch change {
			case "candidate":
				winner.Index = 0
			case "route":
				winner.RouteDigest[0] ^= 1
			case "attempt":
				attempt[0] ^= 1
			case "artifact":
				session.ArtifactDigest[0] ^= 1
			}
			if err := plan.MatchOriginal(session, attempt, winner); err == nil {
				t.Fatal("different winner matched issuance")
			}
		})
	}
	// The Session path calls this gate before attaching, authorizing application,
	// beginning the claim or touching a store. Nil store is deliberately unusable.
	fake := &SessionEstablishment{&sessionEstablishment{session: f.trust.session, expected: fields.Winner, reservation: f.preauth, shared: f.environment, material: EstablishmentMaterial{Role: protocolv4.ClientToServer, Source: "live_authority", Hello: InitialHello{Attempt: [16]byte{88}}}}}
	admission := &SessionAdmissionReservation{}
	if _, err := fake.ConnectLiveSQLite(admission, nil, nil, plan, ledgerv4.LiveSpendOwner{}, func() error { return nil }, func(context.Context) (bool, error) {
		t.Error("policy called for changed original binding")
		return true, nil
	}, resourcev4.Reference{}, resourcev4.Reference{}); err == nil {
		t.Fatal("changed plan entered claim")
	}
	if admission.claimed || admission.liveSpend != nil {
		t.Fatal("wrong projection consumed lease")
	}
}

type abnormalIssuanceSigner struct{ fail func() }

func (s abnormalIssuanceSigner) PublicKey() []byte           { s.fail(); return nil }
func (s abnormalIssuanceSigner) Sign([]byte) ([]byte, error) { return nil, cryptov4.ErrClosed }

func TestLiveIssuanceConstructorJoinsAbnormalSigner(t *testing.T) {
	for _, failure := range []string{"panic", "goexit"} {
		t.Run(failure, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "live_authority")
			charge, err := protocolv4.LiveActivationPlanCharge()
			if err != nil {
				t.Fatal(err)
			}
			before := f.root.Snapshot()
			ref, err := f.root.Reserve(admissionResourceKey(f.owner, 290), charge)
			if err != nil {
				t.Fatal(err)
			}
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				signer := abnormalIssuanceSigner{fail: func() {
					defer func() { close(entered); <-release }()
					if failure == "panic" {
						panic("private signer failure")
					}
					runtime.Goexit()
				}}
				_, _ = protocolv4.NewLiveActivationPlan(f.trust.artifact, f.trust.rules, f.trust.delegation, f.trust.once, signer, protocolv4.LiveActivationConfig{Index: 0, Attempt: f.trust.attempt, IssuedAt: 1150, ActivationEnd: 1400, SessionEnd: 4000}, ref, f.environment, f.preauth)
			}()
			waitRaceSignal(t, entered)
			if f.root.Snapshot() == before {
				t.Fatal("blocked signer refunded plan")
			}
			close(release)
			waitRaceSignal(t, done)
			if f.root.Snapshot() != before {
				t.Fatal("abnormal constructor leaked original workspace")
			}
		})
	}
}
