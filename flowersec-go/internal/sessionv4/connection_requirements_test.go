package sessionv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestConnectionRequirementsRejectBeforeAcquisition(t *testing.T) {
	for _, kind := range []string{"independent", "isolation", "datagram", "profile"} {
		t.Run(kind, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			m, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
			m.Close()
			host := environmentTestOwner(t, f, 248, 1)
			c := sourceConnectTestConfig(t, f, identity, materialProviderFunc(func(context.Context, MaterialLeaseRequest) (*ArtifactLease, error) {
				t.Error("unavailable requirement reached issuer")
				return lease, nil
			}), carrierFactoryFunc(func(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error) {
				t.Error("unavailable requirement reached carrier")
				return nil, nil
			}))
			want := protocolv4.ErrRequiredGuaranteeUnavailable
			switch kind {
			case "independent":
				c.Requirements.Connection.IndependentReliableReadProgress = true
			case "isolation":
				c.Requirements.Connection.BoundStreamInputIsolation = true
			case "datagram":
				c.Requirements.Connection.Datagram = true
			case "profile":
				profile := protocolv4.V4ApplicationProfileServices
				c.Requirements.Connection.ApplicationProfile = &profile
				want = protocolv4.ErrConnectionRequirementUnavailable
			}
			before := f.root.Snapshot()
			_, err := host.startSource(context.Background(), c, environmentEstablishment{kind: 1, pool: PoolSessionInput{}}, nil)
			if !errors.Is(err, want) || f.root.Snapshot() != before || lease.claimed {
				t.Fatalf("requirement changed ownership: %v", err)
			}
		})
	}
}

func TestConnectionRequirementsSourceCapturesValues(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	m, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	m.Close()
	profile := protocolv4.V4ApplicationProfileTransport
	requirements := MaterialRequirements{ApplicationProfile: "transport", Connection: protocolv4.V4ConnectionRequirements{ApplicationProfile: &profile, LocalConsumerTls13Verification: true}}
	a := acquisitionTestOwner(t, f, context.Background(), identity, requirements)
	profile = protocolv4.V4ApplicationProfileExecution
	material, err := a.Acquire(materialProviderFunc(func(_ context.Context, r MaterialLeaseRequest) (*ArtifactLease, error) {
		if r.Requirements.ApplicationProfile != "transport" || !r.Requirements.Connection.LocalConsumerTls13Verification || r.Requirements.Connection.ApplicationProfile != nil {
			t.Error("requirements were not captured into detached compiled values")
		}
		r.Requirements.Connection.LocalConsumerTls13Verification = false
		return lease, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	material.Close()
}

func TestConnectionRequirementsRefusalPreservesAdmissionInputs(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	c := f.config
	c.Requirements.IndependentReliableReadProgress = true
	before := f.root.Snapshot()
	a, err := NewSessionAdmissionReservation(context.Background(), c, f.prepared, f.trust.subscriptions[0], f.root, admissionResourceKey(f.owner, 202), f.environment, f.preauth, f.scope, nil, nil)
	if a != nil || !errors.Is(err, protocolv4.ErrRequiredGuaranteeUnavailable) || f.root.Snapshot() != before || f.prepared.Check() != nil {
		t.Fatalf("refusal consumed caller input: %v", err)
	}
	// The exact original prepared owner/subscription can still be admitted.
	f.config.Requirements.LocalConsumerTls13Verification = true
	f.reserve(t, context.Background())
}

type changingAssuranceProvider struct {
	*preparedTestProvider
	changed atomic.Bool
}

func (p *changingAssuranceProvider) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	class := "native_websocket_tls13"
	if p.changed.Load() {
		class = "browser_websocket_terminator"
	}
	g, _ := protocolv4.ConnectionAssurance(class)
	return g, nil
}

func TestConnectionRequirementsRecheckOriginalProviderBeforeClaim(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	provider := &changingAssuranceProvider{preparedTestProvider: f.provider}
	f.prepared.provider = provider
	f.config.Requirements.LocalConsumerTls13Verification = true
	a := f.reserve(t, context.Background())
	provider.changed.Store(true)
	if claim, err := a.beginClaim(); claim != nil || !errors.Is(err, protocolv4.ErrRequiredGuaranteeUnavailable) || a.claimed || a.committed {
		t.Fatalf("changed original provider crossed claim gate: %v", err)
	}
}

func TestConnectionRequirementsSignedCandidateCannotAssertNativeGuarantees(t *testing.T) {
	f := raceMaterialFixture(t, "preauthorized_pool", []uint64{0}, nil, true)
	g, _ := protocolv4.ConnectionAssurance("native_websocket_tls13")
	if err := f.trust.artifact.CheckDirectConnectionGuarantees(0, protocolv4.ClientToServer, g); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"independent", "isolation", "datagram", "scope", "unobserved_tls"} {
		bad := g
		switch field {
		case "independent":
			bad.ReliableProgress = protocolv4.V4ReliableProgressIndependentWithinProfile
		case "isolation":
			bad.BoundStreamInputIsolation = protocolv4.V4BoundStreamInputIsolationBoundStreamWithinProfile
		case "datagram":
			bad.Datagram = true
		case "scope":
			bad.Scope = protocolv4.V4ConnectionGuaranteeScopeCompleteRelayPath
		case "unobserved_tls":
			bad.LocalConsumerTls13Verification = protocolv4.V4ConsumerTLS13VerificationNotApplicable
		}
		if err := f.trust.artifact.CheckDirectConnectionGuarantees(0, protocolv4.ClientToServer, bad); err == nil {
			t.Fatal("accepted unsupported provider assertion", field)
		}
	}
}

func TestConnectionRequirementsCandidateSkipsBeforeProviderAndSpend(t *testing.T) {
	f := raceMaterialFixture(t, "preauthorized_pool", []uint64{0, 1}, nil, true)
	p, _, lease := admittedTestRace(t, f, carrierFactoryFunc(func(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error) {
		t.Error("ineligible signed candidate reached provider")
		return nil, errors.New("unexpected provider call")
	}))
	p.race.config.Requirements.IndependentReliableReadProgress = true
	if prepared, _, err := p.race.prepare(); prepared != nil || !errors.Is(err, protocolv4.ErrRequiredGuaranteeUnavailable) || lease.claimed || p.race.attempts != 0 {
		t.Fatalf("ineligible candidate consumed budget or lease: %v", err)
	}
}

func TestConnectionRequirementsCaptureAcceptedProfileBeforeAsyncWork(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	c := f.config
	profile := protocolv4.V4ApplicationProfileServices
	c.Requirements.ApplicationProfile = &profile
	captured, err := c.CaptureRequirements()
	if err != nil {
		t.Fatal(err)
	}
	profile = protocolv4.V4ApplicationProfileTransport
	if captured.Requirements.ApplicationProfile != nil {
		t.Fatal("retained mutable profile pointer")
	}
	if _, _, err = SessionAdmissionRequirements(captured); !errors.Is(err, protocolv4.ErrConnectionRequirementUnavailable) {
		t.Fatal("caller mutation weakened accepted requirements", err)
	}
}
