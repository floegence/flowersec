package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type immutableLiveTunnelBundle struct {
	f        *admissionIntegrationFixture
	material *ConnectionMaterial
	identity *ApplicationIdentity
	lease    *ArtifactLease
	grant    *protocolv4.SignedMap
	tunnel   *engineeringTunnelMaterials
	reserve  func(resourcev4.Vector) resourcev4.Reference
}

// Only authority inputs change here. Lease, identity, subscriptions, Grant
// capture and allow receipt use the original production constructors and gates.
func newImmutableLiveTunnelBundle(t *testing.T, role protocolv4.Direction) immutableLiveTunnelBundle {
	t.Helper()
	f := admissionIntegration(t, context.Background(), "live_authority")
	for _, subscriptions := range f.trust.subscriptions {
		subscriptions.Close()
	}
	template := admissionDocument(t, "Artifact", initialFixture(t, "artifact_transport_fields")).Root().Named("Artifact", "candidates").Index(1)
	route := admissionEncode(t, "Route", map[string]protocolv4.Field{
		"candidate_id": admissionField(template.Named("Candidate", "candidate_id")), "path_kind": {Number: 1},
		"client_leg": {Kind: protocolv4.EncodedMap, Bytes: template.Named("Candidate", "client_leg").Encoded()},
		"server_leg": {Kind: protocolv4.EncodedMap, Bytes: template.Named("Candidate", "server_leg").Encoded()},
	})
	limits := protocolv4.RelayGrantLimits{TotalBytes: 1 << 30, RateBytesPerSecond: 1 << 20, QueueBytes: 1 << 20, PendingMappings: 16, ResidentMappings: 128, TotalMappings: 4096, QueueItems: 128}
	recipe := EngineeringTunnelRecipe{Route: route, RelaySubject: "relay-1", RelayAudience: "relay-1", RelayIdentitySeed: [32]byte{93, 7}, GrantIssuerID: [16]byte{94, 8}, GrantIssuerSeed: [32]byte{95, 9}, Limits: [2]protocolv4.RelayGrantLimits{limits, limits}}
	candidate, tunnel := engineeringTunnelCandidate(t, f.authorityFixture, &recipe, protocolv4.DHProfileX25519)
	reference := f.trust.artifact.Field("candidates").Index(0).Named("Candidate", "revocation_namespace_refs").Index(0)
	ref := admissionMap(t, "RevocationNamespaceRef", reference.Encoded(), map[string]protocolv4.Field{"role_mask": {Number: 7}})
	candidate = admissionMap(t, "Candidate", candidate, map[string]protocolv4.Field{"revocation_namespace_refs": admissionArray(ref)})
	artifactBytes, err := f.trust.artifact.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	f.trust.artifact = initialSignTemplate(t, "Artifact", artifactBytes, map[string]protocolv4.Field{"candidates": admissionArray(candidate)}, [32]byte{71, 23, 4})
	f.trust.session, err = f.trust.artifact.SessionParameters()
	if err != nil {
		t.Fatal(err)
	}
	_, routeDigest, err := f.trust.artifact.CopyCandidateRoute(0, make([]byte, 16384))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := f.trust.artifact.Field("candidates").Index(0).Named("Candidate", "candidate_id").ByteString()
	f.trust.candidate = protocolv4.PoolMember{CandidateID: [16]byte(id), RouteDigest: routeDigest}
	proofBytes, err := f.trust.proof.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	f.trust.proof = initialSignTemplate(t, "ActivationAuthorization", proofBytes, map[string]protocolv4.Field{
		"artifact_digest": admissionBytes(f.trust.session.ArtifactDigest[:]), "candidate_selection": admissionBytes(id), "route_selection": admissionBytes(routeDigest[:]),
	}, [32]byte{71, 23, 4}, "live_authority")
	parent, err := f.trust.artifact.DetachCredential()
	if err != nil {
		t.Fatal(err)
	}
	f.trust.trust.scopes[0] = parent.Scope()
	engineeringIssueTunnelGrants(t, f.authorityFixture, tunnel)
	// This fixture's activation is issued after the parent Artifact's cohort.
	// Each Grant needs its own issue-time cohort while retaining the exact old
	// parent reference; a production namespace must reject the copied old cohort.
	capacity := admissionDocument(t, "NamespaceCapacity", initialFixture(t, "namespace_capacity_fields")).Root()
	origin, _ := capacity.Named("NamespaceCapacity", "cohort_time_origin_ms").Uint()
	duration, _ := capacity.Named("NamespaceCapacity", "cohort_duration_ms").Uint()
	for index, original := range tunnel.grants {
		wire, err := original.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		issued, _ := original.Field("issued_at_ms").Uint()
		namespace := admissionMap(t, "GrantNamespace", original.Field("namespace").Encoded(), map[string]protocolv4.Field{"revocation_epoch": {Number: (issued - origin) / duration}})
		tunnel.grants[index] = initialSignTemplate(t, "Grant", wire, map[string]protocolv4.Field{"namespace": {Kind: protocolv4.EncodedMap, Bytes: namespace}}, recipe.GrantIssuerSeed)
		engineeringAddCredentialAuthority(t, f.authorityFixture, tunnel.grants[index])
	}
	validation := func(original *protocolv4.SignedMap) protocolv4.CredentialValidation {
		credential, err := original.DetachCredential()
		if err != nil {
			t.Fatal(err)
		}
		for _, authority := range f.trust.trust.additional {
			if authority.scope == credential.Scope() {
				return protocolv4.CredentialValidation{Namespace: f.trust.namespace, Issuer: authority.permission, Policy: f.trust.trust.policy}
			}
		}
		t.Fatal("original tunnel issuer permission is missing")
		return protocolv4.CredentialValidation{}
	}
	serial := uint32(300)
	reserve := func(cost resourcev4.Vector) resourcev4.Reference {
		serial++
		ref, err := f.root.Reserve(admissionResourceKey(f.owner, serial), cost)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	grant := tunnel.grants[role]
	credential, err := grant.DetachCredential()
	if err != nil {
		t.Fatal(err)
	}
	pending := protocolv4.LiveGrantPreparation{Scope: credential.Scope(), Validation: validation(grant)}
	var common [3]protocolv4.CredentialValidation
	for index := range common {
		common[index] = protocolv4.CredentialValidation{Namespace: f.trust.namespace, Issuer: f.trust.trust.permissions[index], Policy: f.trust.trust.policy}
	}
	config := ArtifactLeaseConfig{Artifact: f.trust.artifact, ClientCertificate: f.trust.certificates[0], ServerCertificate: f.trust.certificates[1], Source: "live_authority", Validation: common,
		Verification: LiveProofVerification{Rules: f.trust.rules, Delegation: f.trust.delegation, Once: f.trust.once, Key: f.trust.proof.Key()}, MapBytes: 65536, MapNodes: 4096, RuntimeBytes: 65536,
		Tunnels: []ArtifactLeaseTunnel{{CandidateIndex: 0, Role: role, LiveGrant: &pending, RelayCertificate: tunnel.relay, RelayValidation: validation(tunnel.relay)}},
	}
	leaseCharge, err := ArtifactLeaseCharge(config.MapBytes, config.MapNodes, config.RuntimeBytes, len(config.Tunnels))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := NewArtifactLease(config, reserve(leaseCharge), f.preauth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Close)
	identityCharge, err := ApplicationIdentityCharge(4096, 8192)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewApplicationIdentity(ApplicationIdentityConfig{Certificate: f.trust.certificates[role], Signer: f.trust.signers[role], StaticDH: f.trust.keys[role], Validation: common[int(role)+1], Role: role, MapNodes: 4096, RuntimeBytes: 8192}, reserve(identityCharge), f.preauth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Close)
	materialCharge, err := ConnectionMaterialCharge(8192)
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewConnectionMaterial(lease, identity, MaterialGeneration{Source: [16]byte{1}, Generation: 1}, 8192, reserve(materialCharge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(material.Close)
	return immutableLiveTunnelBundle{f: f, material: material, identity: identity, lease: lease, grant: grant, tunnel: tunnel, reserve: reserve}
}

func TestLiveGrantRecipientRetriesContainingRequestRefusal(t *testing.T) {
	for _, mismatch := range []string{"digest", "pairing"} {
		t.Run(mismatch, func(t *testing.T) {
			bundle := newImmutableLiveTunnelBundle(t, protocolv4.ServerToClient)
			f := bundle.f
			carrierCharge, err := PreparedCarrierCharge(8192)
			if err != nil {
				t.Fatal(err)
			}
			provider := &preparedTestProvider{environment: f.environment}
			prepared, err := NewPreparedMessages(context.Background(), PreparedCarrierConfig{Candidate: f.trust.candidate, Attempt: f.trust.attempt, Session: f.trust.session, Role: protocolv4.ServerToClient, Deadline: f.config.Initial.Deadline, Reservation: bundle.reserve(carrierCharge), Environment: f.environment, RuntimeBytes: 8192}, provider)
			if err != nil {
				t.Fatal(err)
			}
			cleanupPreparedTest(t, prepared)
			charge, err := TunnelServerAllowRecipientCharge(8192, true)
			if err != nil {
				t.Fatal(err)
			}
			recipient, err := NewTunnelServerAllowRecipient(bundle.material, prepared, [16]byte{53}, 8192, bundle.reserve(charge), bundle.reserve(protocolv4.CredentialSubscriptionsCharge()), f.environment, true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(recipient.Close)
			request, err := recipient.Binding()
			if err != nil {
				t.Fatal(err)
			}
			request.Grant, err = bundle.grant.Digest("grant_digest")
			if err != nil {
				t.Fatal(err)
			}
			pairing, _ := bundle.grant.Field("pairing_id").ByteString()
			request.Pairing = [16]byte(pairing)
			wire, err := bundle.grant.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			bundle.material.Close()
			bundle.identity.Close()
			bundle.lease.Close()
			held := f.root.Snapshot().Charged
			wrong := request
			if mismatch == "digest" {
				wrong.Grant[0] ^= 1
			} else {
				wrong.Pairing[0] ^= 1
			}
			if err := recipient.Receive(context.Background(), wrong, wire); !errors.Is(err, protocolv4.ErrHopAuthContext) {
				t.Fatal("signed Grant bypassed its containing request", err)
			}
			if recipient.closed || recipient.allowed || recipient.grantMap != nil || prepared.allowGranted || f.root.Snapshot().Charged != held {
				t.Fatal("containing-request refusal consumed registration or refunded its reusable backing")
			}
			for range 2 {
				if err := recipient.Receive(context.Background(), request, wire); err != nil {
					t.Fatal("same registration lost valid first capture or exact duplicate", err)
				}
			}
			if !recipient.allowed || !prepared.allowGranted || recipient.delivered != request || f.root.Snapshot().Charged != held {
				t.Fatal("successful receipt changed the original allow fact or full charge")
			}
			if provider.reads.Load() != 0 || provider.writes.Load() != 0 || prepared.activated {
				t.Fatal("allow receipt manufactured carrier activation or credential publication")
			}
			recipient.Close()
			if err := recipient.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			for _, wait := range []func(context.Context) error{bundle.material.WaitCleanup, bundle.identity.WaitCleanup, bundle.lease.WaitCleanup} {
				if err := wait(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestImmutablePendingTunnelGrantUsesEstablishmentOwner(t *testing.T) {
	for _, role := range []protocolv4.Direction{protocolv4.ClientToServer, protocolv4.ServerToClient} {
		t.Run(map[protocolv4.Direction]string{protocolv4.ClientToServer: "client", protocolv4.ServerToClient: "server"}[role], func(t *testing.T) {
			bundle := newImmutableLiveTunnelBundle(t, role)
			entry := bundle.lease.tunnelMaterial(0, role)
			if entry == nil || !entry.pendingGrant || entry.codecs[0] != nil || entry.maps[0] != nil || bundle.lease.codecs[4] != nil {
				t.Fatal("pending lease allocated or manufactured a Grant fact")
			}
			limits := EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
			charge, err := EstablishmentCharge(limits)
			if err != nil {
				t.Fatal(err)
			}
			plan, subscriptions, err := bundle.material.Establishment(InitialHello{Index: 0, Attempt: bundle.f.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}, limits, bundle.material.generation, bundle.reserve(charge), bundle.reserve(protocolv4.CredentialSubscriptionsCharge()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := plan.Retire(); err != nil {
					t.Error(err)
				}
			})
			if plan.codecs[6] == nil || plan.codecs[7] == nil || plan.codecs[8] != nil || plan.material.Grant != nil {
				t.Fatal("pending establishment omitted its original Grant verification capacity")
			}
			held := bundle.f.root.Snapshot().Charged
			proof, err := bundle.f.trust.proof.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.bindLiveProof(proof); err != nil {
				t.Fatal(err)
			}
			grant, err := bundle.grant.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			input := bytes.Clone(grant)
			input[len(input)-1] ^= 1
			if _, err := plan.bindLiveGrantClosure(input); err == nil || plan.material.Grant != nil {
				t.Fatal("invalid first Grant became an establishment fact", err)
			}
			copy(input, grant)
			closure, err := plan.bindLiveGrantClosure(input)
			if err != nil {
				t.Fatal("pending Grant lost original first-verification capacity", err)
			}
			clear(input)
			if err := subscriptions.CompleteLiveGrant(closure); err != nil {
				t.Fatal(err)
			}
			retained, err := plan.material.Grant.Bytes()
			if err != nil || !bytes.Equal(retained, grant) || entry.maps[0] != nil || entry.codecs[0] != nil || bundle.f.root.Snapshot().Charged != held {
				t.Fatal("Grant capture borrowed input, changed lease ownership or refunded full charge", err)
			}
			bundle.identity.Close()
			bundle.lease.Close()
			bundle.material.Close()
			plan.Close()
			if bundle.f.root.Snapshot().Charged != held {
				t.Fatal("Close refunded captured immutable tunnel facts before retirement")
			}
			if err := plan.Retire(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
