package sessionv4

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// UseEngineeringLivePeerMaterial installs a consumer-only original live recipe.
// It cannot reuse the fixture's SQLite spend authority or delegated signer. The
// caller must supply the independently installed control provider; the actual
// native preparation and original Session own all request/proof verification.
func (h *PublicQUICTestHarness) UseEngineeringLivePeerMaterial(t AuthorityReporter, config ArtifactLeaseBytesConfig, identitySeed, dhSeed [32]byte, control LiveControlConfig, role protocolv4.Direction, admissionIdentity ledgerv4.SQLiteIdentity) {
	if role != protocolv4.ClientToServer && role != protocolv4.ServerToClient {
		t.Fatal("invalid original live peer role")
	}
	if config.Source != "live_authority" || len(config.Proof) != 0 || len(config.Tunnels) == 0 || role == protocolv4.ClientToServer && (control.Provider == nil || !control.Tunnel) {
		t.Fatal("imported live tunnel requires its independent original control provider and pending material")
	}
	var controlCharge resourcev4.Vector
	if role == protocolv4.ClientToServer {
		var err error
		if controlCharge, err = LiveControlCharge(control); err != nil {
			t.Fatal(err)
		}
	}
	config.Trust = h.Lease.Trust
	for index := range config.Tunnels {
		entry := &config.Tunnels[index]
		if entry.LiveGrant == nil || len(entry.Grant) != 0 {
			t.Fatal("imported live tunnel cannot carry an issued Grant")
		}
		if entry.GrantTrust == nil {
			entry.GrantTrust = config.Trust[0]
		}
		if entry.RelayTrust == nil {
			entry.RelayTrust = config.Trust[0]
		}
	}
	charge, err := ArtifactLeaseCharge(config.MapBytes, config.MapNodes, config.RuntimeBytes, len(config.Tunnels))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := NewArtifactLeaseFromBytes(config, h.Reserve(charge), h.Preauth)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	route, digest, err := lease.maps[0].CopyCandidateRoute(0, make([]byte, 16384))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(h.Hello.Attempt[:]); err != nil || h.Hello.Attempt == ([16]byte{}) {
		t.Fatal("original live attempt entropy unavailable")
	}
	h.Lease = config
	h.Route = append([]byte(nil), route...)
	h.ArtifactDigest = lease.session.ArtifactDigest
	h.BrowserRouteDigest = digest
	// The consumer has no spend/signing capability. Existing reporter cleanup
	// still owns any setup fixture stores until their original workers retire.
	h.Pool = nil
	h.Live = nil
	if role == protocolv4.ClientToServer {
		h.Live = &LiveSessionInput{Control: control, Buffers: h.Reserve(controlCharge)}
	}
	h.LiveIssuance = SourceLiveIssuance{}
	h.BrowserAuthorize = nil
	if role == protocolv4.ServerToClient {
		// Keep the originally opened local AdmissionLedger identity fixed. Only its
		// application mapping comes from B's independently installed, freshly
		// verified registry; acquisition material cannot select a store or scope.
		if h.Store == nil || admissionIdentity.Authority == "" || admissionIdentity.StoreID == ([32]byte{}) || admissionIdentity.Generation == 0 {
			t.Fatal("original live B AdmissionLedger is unavailable")
		}
		parent, err := lease.maps[0].DetachCredential()
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := lease.maps[3].DetachCredential()
		if err != nil {
			t.Fatal(err)
		}
		scope := parent.Scope()
		h.Authority = engineeringInstalledLiveAdmission{identity: admissionIdentity, tenant: scope.Tenant, audience: scope.Audience, issuer: scope.Issuer, server: certificate.Facts().Digest}
	}
	features, ok := lease.maps[0].Field("allowed_features").Uint()
	if !ok {
		t.Fatal("original live feature envelope is missing")
	}
	datagramMask, _ := protocolv4.DatagramFeatureMask()
	for index := range h.Admission {
		h.Admission[index].Core.Session = lease.session
		h.Admission[index].Core.Datagrams = features&datagramMask != 0
	}
	h.Hello.Index = 0
	h.Hello.Offered = features
	h.Hello.Policy.RouteAllowedFeatures = features
	featuresEnvelope, err := lease.maps[0].FeatureEnvelope(0, protocolv4.FeatureEnvelopePolicy{LocalCapabilities: features, ProposedOffer: features, RouteAllowedFeatures: features})
	if err != nil {
		t.Fatal(err)
	}
	for index := range h.Admission {
		h.Admission[index].Features = featuresEnvelope
	}
	curve := ecdh.X25519()
	if lease.session.Profile == protocolv4.DHProfileP256 {
		curve = ecdh.P256()
	}
	key, err := curve.NewPrivateKey(dhSeed[:])
	if err != nil {
		t.Fatal(err)
	}
	certificate := config.ClientCertificate
	if role == protocolv4.ServerToClient {
		certificate = config.ServerCertificate
	}
	h.Identity[role] = ApplicationIdentityBytesConfig{Certificate: certificate, Trust: config.Trust[1+int(role)], Role: role, Signer: bootstrapSigner{ed25519.NewKeyFromSeed(identitySeed[:])}, StaticDH: publicFixtureDH{key}, MapNodes: 4096, RuntimeBytes: 8192}
}

// This engineering consumer has admission capability only. It cannot use the
// fixture's live spend, signer or ParentWinner publication authority.
type engineeringInstalledLiveAdmission struct {
	identity         ledgerv4.SQLiteIdentity
	tenant, audience string
	issuer           [16]byte
	server           [32]byte
}

func (a engineeringInstalledLiveAdmission) CheckAdmission(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	fields, err := facts.Fields()
	if err != nil || identity != a.identity || fields.Tenant != a.tenant || fields.Audience != a.audience || fields.Issuer != a.issuer || fields.ServerIdentity != a.server {
		return ledgerv4.ErrFenced
	}
	return nil
}
