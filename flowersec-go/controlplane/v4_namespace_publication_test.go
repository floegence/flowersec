package controlplane_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func controlNumber(name string, n uint64) protocolv4.Field {
	return protocolv4.Field{Name: name, Number: n}
}
func controlText(name, text string) protocolv4.Field {
	return protocolv4.Field{Name: name, Kind: protocolv4.TextString, Text: text}
}
func controlBytes(name string, wire []byte) protocolv4.Field {
	return protocolv4.Field{Name: name, Kind: protocolv4.ByteString, Bytes: wire}
}
func controlMap(name string, wire []byte) protocolv4.Field {
	return protocolv4.Field{Name: name, Kind: protocolv4.EncodedMap, Bytes: wire}
}
func controlArray(name string, wire []byte) protocolv4.Field {
	return protocolv4.Field{Name: name, Kind: protocolv4.EncodedArray, Bytes: wire}
}
func encodeControlMap(t *testing.T, schema string, fields ...protocolv4.Field) []byte {
	t.Helper()
	wire, err := protocolv4.EncodeMap(make([]byte, 65536), schema, fields)
	if err != nil {
		t.Fatal(schema, err)
	}
	return wire
}

type controlPublicationSigner struct {
	key              ed25519.PrivateKey
	entered, release chan struct{}
	calls            atomic.Int32
}

func (s *controlPublicationSigner) PublicKey() []byte { return s.key.Public().(ed25519.PublicKey) }
func (s *controlPublicationSigner) Sign(input []byte) ([]byte, error) {
	s.calls.Add(1)
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	return ed25519.Sign(s.key, input), nil
}

type controlPublicationAccess struct {
	scope  protocolv4.NamespacePublicationScope
	denied atomic.Bool
}

func (a *controlPublicationAccess) CheckPublicationMutation(scope protocolv4.NamespacePublicationScope) error {
	if scope != a.scope {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (a *controlPublicationAccess) CheckPublicationRead(scope protocolv4.NamespacePublicationScope, authentication []byte) error {
	if scope != a.scope || a.denied.Load() || !bytes.Equal(authentication, []byte("registered-reader")) {
		return ledgerv4.ErrDenied
	}
	return nil
}

type publicPublicationFixture struct {
	*controlResources
	trust              *protocolv4.NamespaceTrustStore
	rootSigner, signer *controlPublicationSigner
	signerID           [16]byte
	state              []byte
	access             *controlPublicationAccess
	identity           ledgerv4.SQLiteIdentity
	limits             ledgerv4.SQLiteLimits
	config             controlplane.SQLitePublicationConfig
	backing            *ledgerv4.SQLiteBacking
	store              *controlplane.SQLitePublicationStore
}

func newPublicPublicationFixture(t *testing.T) *publicPublicationFixture {
	t.Helper()
	f := &publicPublicationFixture{controlResources: newControlResources(t), signerID: [16]byte{2}}
	rootSeed, headSeed, rootID := [32]byte{71}, [32]byte{91}, [16]byte{1}
	f.rootSigner = &controlPublicationSigner{key: ed25519.NewKeyFromSeed(rootSeed[:])}
	f.signer = &controlPublicationSigner{key: ed25519.NewKeyFromSeed(headSeed[:])}
	capacity := encodeControlMap(t, "NamespaceCapacity", controlText("tenant_id", "tenant"), controlText("revocation_authority_id", "authority"), controlText("capacity_schema_revision", "4"), controlNumber("max_state_encoded_bytes", 4096), controlNumber("max_revoked_issuers", 16), controlNumber("max_revoked_certificates", 16), controlNumber("max_revoked_leases", 16), controlNumber("max_cohort_policy_segments", 16), controlNumber("max_head_encoded_bytes", 1024), controlNumber("max_trust_proof_bytes", 65536), controlNumber("max_trust_proof_entries", 256), controlNumber("cohort_time_origin_ms", 0), controlNumber("cohort_duration_ms", 1000), controlNumber("max_certificate_impact_ms", 1000), controlNumber("max_connection_impact_ms", 10000))
	publication := encodeControlMap(t, "PublicationPolicy", controlText("publication_policy_id", "publication"), controlNumber("publication_policy_revision", 1), controlNumber("max_head_validity_ms", 1000), controlNumber("max_signer_lifetime_ms", 10000))
	rules, err := protocolv4.NewNamespaceRules(capacity, publication)
	if err != nil {
		t.Fatal(err)
	}
	scope := rules.PublicationScope(1)
	f.access = &controlPublicationAccess{scope: scope}
	delegationID := [16]byte{3}
	delegation := encodeControlMap(t, "HeadSignerDelegation", controlText("schema_revision", "4"), controlText("tenant_id", scope.Tenant), controlText("revocation_authority_id", scope.Authority), controlBytes("namespace_capacity_digest", scope.Capacity[:]), controlNumber("authority_generation", 1), controlBytes("delegation_id", delegationID[:]), controlBytes("signer_key_id", f.signerID[:]), controlBytes("signer_public_key", f.signer.PublicKey()), controlNumber("purpose", 0), controlText("publication_policy_id", "publication"), controlNumber("publication_policy_revision", 1), controlNumber("issued_at_ms", 900), controlNumber("not_before_ms", 900), controlNumber("not_after_ms", 5000))
	fields := []protocolv4.Field{controlText("schema_revision", "4"), controlText("tenant_id", scope.Tenant), controlText("revocation_authority_id", scope.Authority), controlNumber("authority_generation", 1), controlNumber("revision", 1), controlNumber("issued_at_ms", 900), controlNumber("not_after_ms", 6000), controlMap("capacity", capacity), controlMap("publication", publication), controlArray("head_delegations", append([]byte{0x81}, delegation...)), controlBytes("signing_key_id", rootID[:])}
	for _, name := range []string{"credential_policies", "issuer_authorizations", "activation_delegations", "once_authorities", "retired_issuers", "rejected_head_signers"} {
		fields = append(fields, controlArray(name, []byte{0x80}))
	}
	codec, err := protocolv4.NewSignedMapCodec("TrustConfig", 16384, 8192)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.Sign(fields, rootSeed, protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Release()
	wire, err := signed.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	trustLimits := protocolv4.NamespaceTrustLimits{Configurations: 2, ConfigBytes: 16384, MapNodes: 8192, RuntimeBytes: 4096}
	cost, err := protocolv4.NamespaceTrustCharge(trustLimits)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := f.environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	f.trust, err = protocolv4.NewNamespaceTrustStore(protocolv4.NamespaceTrustRoot{Tenant: scope.Tenant, Authority: scope.Authority, KeyID: rootID, PublicKey: [32]byte(f.rootSigner.PublicKey()), MaxLifetimeMS: 10000}, trustLimits, f.clock, wire, f.reserve(cost), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.trust.Close()
		f.root.Close()
		if err := f.trust.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	segment := encodeControlMap(t, "CohortPolicySegment", controlNumber("first_cohort", 0), controlNumber("last_cohort", 100), controlNumber("certificate_impact_ms", 1000), controlNumber("connection_impact_ms", 10000))
	f.state = encodeControlMap(t, "RevocationState", controlText("schema_revision", "4"), controlText("tenant_id", scope.Tenant), controlText("revocation_authority_id", scope.Authority), controlBytes("namespace_capacity_digest", scope.Capacity[:]), controlNumber("authority_generation", 1), controlArray("credential_revocation_floors", []byte{0x82, 0, 0}), controlText("publication_policy_id", "publication"), controlNumber("publication_policy_revision", 1), controlArray("revoked_issuers", []byte{0x80}), controlArray("revoked_certificates", []byte{0x80}), controlArray("revoked_leases", []byte{0x80}), controlArray("cohort_policy_segments", append([]byte{0x81}, segment...)))
	f.limits = ledgerv4.SQLiteLimits{MaxPages: 256, MaxRecords: 64, MaxRecordBytes: 65536, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	f.identity = ledgerv4.SQLiteIdentity{Authority: "authority", StoreID: [32]byte{7}, Generation: 1}
	f.config = controlplane.SQLitePublicationConfig{Scope: scope, Clock: f.clock, Trust: f.trust, Access: f.access, HistorySlots: 4, MaxAuthenticationBytes: 128}
	path := filepath.Join(t.TempDir(), "publication.db")
	cost, err = ledgerv4.SQLiteBackingCharge(f.limits)
	if err != nil {
		t.Fatal(err)
	}
	f.backing, err = ledgerv4.NewSQLiteBacking(path, f.limits, f.reserve(cost), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.backing.Close()
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		if err := f.backing.ReleaseRemoved(); err != nil {
			t.Error(err)
		}
	})
	f.open(true)
	return f
}
func (f *publicPublicationFixture) open(create bool) {
	f.t.Helper()
	a, b, c, err := controlplane.SQLitePublicationStoreCharges(f.limits, f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	owner, first, second := f.reserve(a), f.reserve(b), f.reserve(c)
	if create {
		f.store, err = controlplane.CreateSQLitePublicationStore(context.Background(), f.backing, f.identity, controlContinuity{f.identity}, f.config, owner, first, second, f.environment)
	} else {
		f.store, err = controlplane.OpenSQLitePublicationStore(context.Background(), f.backing, f.identity, controlContinuity{f.identity}, f.config, owner, first, second, f.environment)
	}
	store := f.store
	if store != nil {
		f.t.Cleanup(func() { f.closeStore(store) })
	}
	if err != nil {
		f.t.Fatal(err)
	}
	owner.Release()
	first.Release()
	second.Release()
}
func (f *publicPublicationFixture) closeStore(store *controlplane.SQLitePublicationStore) {
	f.t.Helper()
	store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.WaitCleanup(ctx); err != nil {
		f.t.Fatal(err)
	}
	if err := store.Retire(); err != nil {
		f.t.Fatal(err)
	}
}
func (f *publicPublicationFixture) publisher() *controlplane.NamespacePublisher {
	f.t.Helper()
	c := controlplane.NamespacePublisherConfig{Clock: f.clock, Trust: f.trust, Store: f.store, Signer: f.signer, SignerID: f.signerID, Generation: 1, WorkMS: 1000, MinimumValidityMS: 10, RuntimeBytes: 65536}
	a, b, err := controlplane.NamespacePublisherCharges(c)
	if err != nil {
		f.t.Fatal(err)
	}
	owner, state := f.reserve(a), f.reserve(b)
	p, err := controlplane.NewNamespacePublisher(c, owner, state, f.environment)
	if err != nil {
		f.t.Fatal(err)
	}
	owner.Release()
	state.Release()
	f.t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			f.t.Error(err)
		}
	})
	return p
}

func TestNamespacePublicationCommitsSignedSnapshotAndReopens(t *testing.T) {
	f := newPublicPublicationFixture(t)
	ctx := context.Background()
	if version, err := f.store.ReplaceState(ctx, 0, f.state); err != nil || version != 1 {
		t.Fatal(version, err)
	}
	if _, err := f.store.ReplaceState(ctx, 0, f.state); err != controlplane.PublicationFailure("publication_conflict") {
		t.Fatal("stale replacement changed authoritative state", err)
	}
	state, head := make([]byte, 4096), make([]byte, 1024)
	if _, _, _, err := f.store.ReadPublished(ctx, []byte("registered-reader"), [32]byte{}, state, head); err != controlplane.PublicationFailure("publication_unavailable") {
		t.Fatal("unpublished state escaped", err)
	}
	p := f.publisher()
	first, err := p.Publish(ctx)
	if err != nil || first.Sequence != 1 || first.Snapshot != 1 || first.StateDigest == ([32]byte{}) {
		t.Fatal(first, err)
	}
	got, n, m, err := f.store.ReadPublished(ctx, []byte("registered-reader"), first.StateDigest, state, head)
	if err != nil || got != first || !bytes.Equal(state[:n], f.state) {
		t.Fatal("published state changed", got, err)
	}
	codec, err := protocolv4.NewSignedMapCodec("FreshnessHead", 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.Verify(head[:m], [32]byte(f.signer.PublicKey()), protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal("published Head signature", err)
	}
	digest, err := signed.Digest("freshness_head_digest")
	sequence, _ := signed.Field("head_sequence").Uint()
	stateDigest, _ := signed.Field("state_digest").ByteString()
	if err != nil || digest != first.HeadDigest || sequence != first.Sequence || !bytes.Equal(stateDigest, first.StateDigest[:]) {
		t.Fatal("durable version differs from signed Head", err)
	}
	signed.Release()
	p.Close()
	if err := p.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	f.closeStore(f.store)
	f.open(false)
	p = f.publisher()
	second, err := p.Publish(ctx)
	if err != nil || second.Sequence != first.Sequence+1 || second.Snapshot != first.Snapshot || second.StateDigest != first.StateDigest {
		t.Fatal("restart lost original publication facts", second, err)
	}
	f.access.denied.Store(true)
	if _, n, m, err := f.store.ReadPublished(ctx, []byte("registered-reader"), first.StateDigest, state, head); err != controlplane.PublicationFailure("publication_refused") || n != 0 || m != 0 {
		t.Fatal("known digest bypassed namespace authorization", n, m, err)
	}
}

func TestNamespaceCloseWaitsForActualSignerWithoutPublishing(t *testing.T) {
	f := newPublicPublicationFixture(t)
	if _, err := f.store.ReplaceState(context.Background(), 0, f.state); err != nil {
		t.Fatal(err)
	}
	f.signer.entered, f.signer.release = make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-f.signer.release:
		default:
			close(f.signer.release)
		}
	}()
	p := f.publisher()
	done := make(chan error, 1)
	go func() { _, err := p.Publish(context.Background()); done <- err }()
	select {
	case <-f.signer.entered:
	case err := <-done:
		t.Fatal("signer not entered", err)
	case <-time.After(2 * time.Second):
		t.Fatal("signer not entered")
	}
	before := f.root.Snapshot()
	p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := p.WaitCleanup(ctx); err != controlplane.PublicationFailure("expired") {
		t.Fatal("cleanup completed before signer", err)
	}
	if after := f.root.Snapshot(); after != before {
		t.Fatal("cancel refunded live signer", before, after)
	}
	close(f.signer.release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("late signature published")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("signer did not return")
	}
	if err := p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.store.ReadPublished(context.Background(), []byte("registered-reader"), [32]byte{}, make([]byte, 4096), make([]byte, 1024)); err != controlplane.PublicationFailure("publication_unavailable") {
		t.Fatal("cancelled publication became readable", err)
	}
}

func TestNamespaceHTTPSRejectsUnauthenticatedReadAndCleansUp(t *testing.T) {
	f := newPublicPublicationFixture(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.UnixMilli(0), NotAfter: time.UnixMilli(10000), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, f.rootSigner.key.Public(), f.rootSigner.key)
	if err != nil {
		t.Fatal(err)
	}
	c := controlplane.NamespaceHTTPSConfig{Clock: f.clock, Trust: f.trust, Scope: f.access.scope, BootstrapSigner: f.rootSigner, ClientCertificateDER: der, RequestsPerMinute: 60, Burst: 20, WorkMS: 1000, BootstrapValidityMS: 1000, RuntimeBytes: 65536}
	cost, err := controlplane.NamespaceHTTPSServiceCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot()
	owner := f.reserve(cost)
	service, err := controlplane.NewNamespaceHTTPSService(f.store, c, owner, f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		service.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	owner.Release()
	response := httptest.NewRecorder()
	service.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/head", nil))
	if response.Code != http.StatusForbidden || response.Body.Len() != 0 {
		t.Fatal("unauthenticated namespace read was served", response.Code)
	}
	service.Close()
	if err := service.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after := f.root.Snapshot(); after != before {
		t.Fatal("HTTPS service retained resources", before, after)
	}
}
