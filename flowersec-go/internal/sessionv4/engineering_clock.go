package sessionv4

import (
	"encoding/hex"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

const engineeringInitialReceiveLimit uint64 = 16384

// EngineeringAuthorityTime is implemented only by an explicitly enabled peer.
// The epoch is a local authority input; remote peer times never install anchors.
// Its Clock must advance and fail closed if its local continuity is unavailable.
type EngineeringBootstrapProvider interface {
	AuthorityBootstrapProvider() protocolv4.NamespaceBootstrapProvider
}
type EngineeringNamespaceRoot interface {
	AuthorityNamespaceRoot() *protocolv4.NamespaceTrustRoot
}
type EngineeringNamespaceCapacity interface{ AuthorityNamespaceSubscribers() uint32 }
type EngineeringStreamCapacity interface{ AuthorityMaxStreams() uint32 }
type EngineeringCarrierHost interface{ AuthorityCarrierHost() string }
type EngineeringCandidateIdentity interface{ AuthorityCandidateID() [16]byte }
type EngineeringDirectRouteSet interface{ AuthorityDirectRoutes() [][]byte }
type EngineeringApplicationProfile interface{ AuthorityApplicationProfile() string }

type EngineeringOperationBudget interface{ AuthorityOperationMS() uint64 }

// Long native outage scenarios need independently signed material that remains
// valid through the observation window. Zero keeps the ordinary 60-second
// activation. This changes issuance inputs, never credential validation.
type EngineeringActivationWindow interface{ AuthorityActivationWindowMS() uint64 }

func engineeringOperationMS(t AuthorityReporter) uint64 {
	if budget, ok := t.(EngineeringOperationBudget); ok {
		value := budget.AuthorityOperationMS()
		if value == 0 || value > 90000 {
			t.Fatal("invalid engineering operation deadline")
		}
		return value
	}
	return 10000
}

type EngineeringAuthorityIdentity interface {
	AuthorityLeaseID() [16]byte
	AuthorityAttemptID() [16]byte
}

type EngineeringAuthorityTime interface {
	AuthorityEpochMS() uint64
	AuthorityClock() *timev4.Clock
}

func authorityTime(t AuthorityReporter, value uint64) uint64 {
	p, enabled := t.(EngineeringAuthorityTime)
	if !enabled || value == 0 || value > 100000 {
		return value
	}
	if source, ok := t.(EngineeringActivationWindow); ok && (value == 1400 || value == 1500) {
		if window := source.AuthorityActivationWindowMS(); window != 0 {
			if window < 60000 || window > 180000 {
				t.Fatal("engineering activation window is outside the signed credential envelope")
			}
			// Activation and its delegation share 1400; the Artifact initiation
			// ceiling remains thirty seconds later and before identity expiry.
			return p.AuthorityEpochMS() + window + (value-1400)*300
		}
	}
	// Preserve the canonical authority's ordering with finite useful engineering
	// windows: the activation ends after 60s and the Session after 14 minutes.
	if value >= 1200 {
		return p.AuthorityEpochMS() + (value-1200)*300
	}
	return p.AuthorityEpochMS() - (1200-value)*300
}
func authorityDuration(t AuthorityReporter, value uint64) uint64 {
	if _, enabled := t.(EngineeringAuthorityTime); enabled {
		return value * 300
	}
	return value
}
func authorityBootstrapIssued(t AuthorityReporter, clock *timev4.Clock) uint64 {
	if _, enabled := t.(EngineeringAuthorityTime); !enabled {
		return 1000
	}
	sample, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	return sample.LowerMS
}

// Only the named schema fields below belong to the authority's finite windows.
// Digests, counters, budgets, epochs, IDs and application values are never shifted.
// Already projected epoch values are unchanged when the map is signed again.
func authorityFields(t AuthorityReporter, schema string, fields []protocolv4.Field) []protocolv4.Field {
	if _, enabled := t.(EngineeringAuthorityTime); !enabled {
		return fields
	}
	absolute := map[string][]string{
		"NamespaceCapacity":              {"cohort_time_origin_ms"},
		"IdentityCertificate":            {"issued_at_ms", "expires_at_ms"},
		"Artifact":                       {"issued_at_ms", "initiation_not_after_ms", "session_not_after_ms"},
		"ActivationAuthorization":        {"issued_at_ms", "activation_not_after_ms", "session_not_after_ms"},
		"ConnectionActivationDelegation": {"signing_not_before_ms", "signing_not_after_ms", "max_activation_not_after_ms", "max_session_not_after_ms"},
		"CredentialIssuerAuthorization":  {"signing_not_before_ms", "signing_not_after_ms", "max_credential_not_after_ms"},
		"HeadSignerDelegation":           {"issued_at_ms", "not_before_ms", "not_after_ms"},
		"FreshnessHead":                  {"this_update_ms", "next_update_ms"},
		"TrustConfig":                    {"issued_at_ms", "not_after_ms"},
		"TrustBootstrapResponse":         {"issued_at_ms", "not_after_ms"},
		"Grant":                          {"issued_at_ms", "not_after_ms"},
	}
	duration := map[string][]string{
		"NamespaceCapacity":          {"cohort_duration_ms", "max_certificate_impact_ms", "max_connection_impact_ms"},
		"CredentialRevocationPolicy": {"max_staleness_ms", "max_head_signer_lifetime_ms"},
		"CohortPolicySegment":        {"certificate_impact_ms", "connection_impact_ms"},
		"PublicationPolicy":          {"max_head_validity_ms", "max_signer_lifetime_ms"},
	}
	for i := range fields {
		if identity, ok := t.(EngineeringAuthorityIdentity); ok && fields[i].Name == "lease_id" && (schema == "Artifact" || schema == "ActivationAuthorization") {
			id := identity.AuthorityLeaseID()
			fields[i].Bytes = append([]byte(nil), id[:]...)
		}
		if identity, ok := t.(EngineeringAuthorityIdentity); ok && fields[i].Name == "attempt_id" && schema == "ActivationAuthorization" {
			id := identity.AuthorityAttemptID()
			fields[i].Bytes = append([]byte(nil), id[:]...)
		}
		for _, name := range absolute[schema] {
			if fields[i].Name == name {
				if schema == "NamespaceCapacity" && name == "cohort_time_origin_ms" && fields[i].Number == 0 {
					fields[i].Number = t.(EngineeringAuthorityTime).AuthorityEpochMS() - 1200*300
				} else {
					fields[i].Number = authorityTime(t, fields[i].Number)
				}
			}
		}
		for _, name := range duration[schema] {
			if fields[i].Name == name && fields[i].Number <= 100000 {
				fields[i].Number = authorityDuration(t, fields[i].Number)
			}
		}
	}
	return fields
}

// CanonicalTemplate is available to engineering authorities only. Each peer
// signs its own resulting credential; these unsigned fields confer no trust.
func CanonicalTemplate(id string) ([]byte, error) { return hex.DecodeString(engineeringTemplates[id]) }

type authorityFixture struct {
	root                 *resourcev4.Root
	environment, preauth resourcev4.Reference
	owner                resourcev4.OwnerKey
	scope                SessionResourceScope
	trust                *sessionAdmissionTrustFixture
	config               SessionAdmissionConfig
}

func newAuthorityFixture(t AuthorityReporter, source string, declared ...*resourcev4.Config) *authorityFixture {
	f := &authorityFixture{}
	limit := engineeringSessionLimit()
	var err error
	accounts, reservations, references := uint32(16), uint32(512), uint32(4096)
	if _, engineering := t.(EngineeringAuthorityTime); engineering {
		accounts, reservations, references = 512, 8192, 65536
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: accounts, ReservationSlots: reservations, ReferenceSlots: references}
	if len(declared) > 1 {
		t.Fatal("one original engineering root declaration is required")
	}
	if len(declared) == 1 && declared[0] != nil {
		config = *declared[0]
	}
	f.root, err = resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.root.Close)
	f.owner = resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{83}, Backing: [16]byte{1}, Kind: 83}
	f.environment, err = f.root.Reserve(f.owner, resourcev4.Vector{resourcev4.SDKBytes: 1, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.environment.Release)
	application := "transport"
	if policy, enabled := t.(EngineeringApplicationProfile); enabled {
		application = policy.AuthorityApplicationProfile()
	}
	if p, enabled := t.(EngineeringAuthorityTime); enabled {
		f.trust = newSessionAdmissionTrustProfile(t, f.root, f.environment, f.owner, source, application, p.AuthorityClock())
	} else {
		f.trust = newSessionAdmissionTrustProfile(t, f.root, f.environment, f.owner, source, application)
	}
	f.scope = engineeringScope(t, f.root, config.Limit, limit, 1)
	f.preauth, err = f.root.Reserve(admissionResourceKey(f.owner, 200), resourcev4.Vector{resourcev4.SDKBytes: 4 << 20, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.preauth.Release)
	deadline, err := timev4.NewAge(f.trust.clock, engineeringOperationMS(t), f.trust.session.SessionNotAfterMS)
	if err != nil {
		t.Fatal(err)
	}
	c := engineeringBaseCore(f.trust.session, f.trust.clock)
	f.config = SessionAdmissionConfig{Core: c, Features: f.trust.features, Initial: InitialConfig{Role: protocolv4.ClientToServer, Profile: c.Session.Profile, ActivationSourceProfile: source, Limits: InitialLimits{int(c.Session.Contract.Limits().MaxFrame), 4096}, Deadline: deadline}, RuntimeBytes: 32768, InitialRuntimeBytes: 32768}
	return f
}

// Admit the complete remaining rekey responsibility in each direction. A
// legal barrier entry has a map, two integer keys and two uint64 values, at
// most 21 bytes. The fixed phase envelope covers both supported public keys,
// identifiers, digests, MACs and the enclosing map/array headers.
func engineeringRekeyReserve(t AuthorityReporter, profile string, maximum, maxFrame uint32) cryptov4.MaintenanceReserve {
	limit, err := protocolv4.FieldItemLimit("REKEY_INIT", "client_barrier")
	if err != nil {
		t.Fatal(err)
	}
	entries := min(uint64(maximum), uint64(limit))
	plaintext := int(256 + 21*entries)
	spec, err := protocolv4.Profile(profile)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := protocolv4.RecordPrefix(protocolv4.FrameRekey, protocolv4.RecordHeader{}, plaintext, profile, maxFrame)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := protocolv4.RecordAAD(profile, protocolv4.ClientToServer, prefix)
	if err != nil {
		t.Fatal(err)
	}
	blocks := func(size int) uint64 { return uint64(size/16) + uint64((size%16+15)/16) }
	return cryptov4.MaintenanceReserve{Calls: 4, Blocks: 4 * (blocks(len(aad)) + blocks(plaintext) + 1), Bytes: 4 * uint64(plaintext+spec.TagBytes)}
}

// EngineeringActiveCapacity explicitly signs every requested business slot and
// the original profile's future internal/management positions. Bootstrap is
// one of those internal positions and remains in the same positive ledger.
func EngineeringActiveCapacity(application string, business uint32) (uint32, error) {
	geometry, _, err := internalChannelGeometry(application)
	if err != nil {
		return 0, err
	}
	fixed := geometry.RPC + geometry.Notify + geometry.Management
	if business > 128 {
		return 0, cryptov4.ErrConfiguration
	}
	return business + fixed, nil
}

func engineeringBaseCore(parameters protocolv4.ArtifactSessionParameters, clock *timev4.Clock) SessionCoreConfig {
	return SessionCoreConfig{Session: parameters, Clock: clock,
		Open: openResourceLimits(), MaxScopes: 4, PendingScopes: 2, WorkSlots: 4,
		Maintenance:     cryptov4.MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024},
		EngineResources: cryptov4.EngineResourceOptions{RuntimeBytes: 4096}, RuntimeBytes: 65536,
		MessageCarrier: true, MessageRuntimeBytes: 8192, DecoderNodes: 128, MaxDataPayloadBytes: 1024, SendWorkers: [3]uint32{1},
		ProbeSlots: 2, PongSlots: 2, RekeyWaitSlots: 2,
		Automatic: AutomaticLivenessPolicy{1000000, 1000, 1000, 3}, Messages: MaintenanceMessagePolicy{8, 1000, 10000},
		Termination: StreamTerminationPolicy{10000, 1000, 8}, Rekey: RekeyPhaseBudgets{5000, 10000, 30000},
		SharedDiscard: SharedDiscardPolicy{16, 65536, 10000}, NativeIngress: MaintenanceIngressPolicy{10000, 1000, 8},
		DispatchTimeoutMS: 10000, RetirementTimeoutMS: 10000,
	}
}
