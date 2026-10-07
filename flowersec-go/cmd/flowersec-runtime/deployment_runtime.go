package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/runtimehost"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type runtimeMapSigner struct{ key ed25519.PrivateKey }

func (s runtimeMapSigner) PublicKey() []byte { return s.key.Public().(ed25519.PublicKey) }
func (s runtimeMapSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

type deploymentRuntime struct {
	config      deploymentConfig
	root        *resourcev4.Root
	owner       resourcev4.OwnerKey
	environment resourcev4.Reference
	accounts    []resourcev4.Account
	clock       *timev4.Clock
	registry    *protocolv4.NamespaceRegistry
	trust       []*protocolv4.NamespaceTrustStore
	namespaces  []*protocolv4.LiveNamespace
	providers   []*controlv4.HTTPSBootstrapProvider
	backing     [3]*ledgerv4.SQLiteBacking
	stores      [3]*ledgerv4.SQLiteStore
	history     [3]*runtimeHistory
	relay       *runtimehost.Relay
	native      *runtimehost.NativeRelay
	pool        *controlv4.PoolHTTPSService
	tls         *tls.Config
	access      *runtimeTopUpAccess
	keys        []runtimeMapSigner
	cleanup     []func(context.Context) error
}

type runtimeTopUpAccess struct {
	tenant    string
	source    [16]byte
	principal ledgerv4.AuditPrincipal
	clock     *timev4.Clock
	notAfter  uint64
}

func (a *runtimeTopUpAccess) CheckTopUpAccess(tenant string, source [16]byte) error {
	if a == nil || tenant != a.tenant || source != a.source {
		return ledgerv4.ErrDenied
	}
	now, err := a.clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(a.notAfter) {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (a *runtimeTopUpAccess) TopUpAuditPrincipal(tenant string, source [16]byte) (ledgerv4.AuditPrincipal, error) {
	if err := a.CheckTopUpAccess(tenant, source); err != nil {
		return ledgerv4.AuditPrincipal{}, err
	}
	return a.principal, nil
}

type runtimeHistory struct {
	identity  ledgerv4.SQLiteIdentity
	epoch     uint64
	provision bool
	clock     *timev4.Clock
	notAfter  uint64
}

func (h *runtimeHistory) Check(identity ledgerv4.SQLiteIdentity, epoch uint64, create bool) error {
	if h == nil || identity != h.identity {
		return ledgerv4.ErrOwner
	}
	if create {
		if !h.provision || h.epoch != 0 || epoch != 0 {
			return ledgerv4.ErrOwner
		}
	} else if epoch == 0 || epoch != h.epoch && epoch != h.epoch+1 {
		return ledgerv4.ErrOwner
	}
	now, err := h.clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(h.notAfter) {
		return ledgerv4.ErrFenced
	}
	return nil
}

func (r *deploymentRuntime) reserve(cost resourcev4.Vector) (resourcev4.Reference, resourcev4.OwnerKey, error) {
	owner := r.owner
	if _, err := rand.Read(owner.Instance[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	if _, err := rand.Read(owner.Backing[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	ref, err := r.root.Reserve(owner, cost, r.accounts...)
	return ref, owner, err
}

// The shared executor belongs to the root. Its real calls borrow the
// invocation's original Tenant and Environment scopes independently.
func (r *deploymentRuntime) reserveApplicationExecutor(cost resourcev4.Vector) (resourcev4.Reference, error) {
	owner := r.owner
	if _, err := rand.Read(owner.Instance[:]); err != nil {
		return resourcev4.Reference{}, err
	}
	if _, err := rand.Read(owner.Backing[:]); err != nil {
		return resourcev4.Reference{}, err
	}
	return r.root.Reserve(owner, cost)
}
func readRuntimeFile(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(maximum) {
		return nil, errors.New("runtime input exceeds its fixed file bound")
	}
	input, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(input) > maximum {
		return nil, errors.New("runtime input read failed")
	}
	return input, nil
}
func (r *deploymentRuntime) signer(spec signerSpec) (runtimeMapSigner, error) {
	seed, err := readRuntimeFile(spec.SeedFile, 32)
	if err != nil {
		return runtimeMapSigner{}, err
	}
	defer clear(seed)
	if len(seed) != 32 {
		return runtimeMapSigner{}, errors.New("signer seed file must contain exactly 32 binary bytes")
	}
	signer := runtimeMapSigner{key: ed25519.NewKeyFromSeed(seed)}
	r.keys = append(r.keys, signer)
	return signer, nil
}
func runtimeTLSRoots(path string) (*x509.CertPool, error) {
	wire, err := readRuntimeFile(path, 65536)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(wire) {
		return nil, errors.New("independent TLS roots are invalid")
	}
	return roots, nil
}
func newDeploymentInfrastructure(ctx context.Context, c deploymentConfig, tenantName string, storeCount int) (_ *deploymentRuntime, err error) {
	var cost resourcev4.Vector
	var ref resourcev4.Reference
	r := &deploymentRuntime{config: c}
	success := false
	defer func() {
		if !success {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(c.ShutdownMS)*time.Millisecond)
			defer cancel()
			err = errors.Join(err, r.Close(cleanup))
		}
	}()
	r.root, err = resourcev4.NewRoot(c.Resources)
	if err != nil {
		return nil, err
	}
	r.owner = resourcev4.OwnerKey{ProfileRevision: c.Resources.ProfileRevision, Environment: [16]byte(c.Environment), Kind: 1}
	// The immutable JSON, TLS trust/key graph, history gates and startup parsers
	// are admitted before any namespace, store or native listener is opened.
	r.environment, _, err = r.reserve(resourcev4.Vector{resourcev4.SDKBytes: 4 << 20, resourcev4.ProviderBytes: 4 << 20, resourcev4.Items: 128, resourcev4.WorkSlots: 8, resourcev4.Tasks: 8, resourcev4.Timers: 8, resourcev4.Connections: 8, resourcev4.NativeHandles: 16, resourcev4.TLSHandshakes: 8})
	if err != nil {
		return nil, err
	}
	tenantID := sha256.Sum256([]byte(tenantName))
	tenant, err := r.root.Account(resourcev4.AccountKey{Kind: resourcev4.TenantAccount, ID: [16]byte(tenantID[:16])}, c.Resources.Limit)
	if err != nil {
		return nil, err
	}
	environment, err := r.root.Account(resourcev4.AccountKey{Kind: resourcev4.EnvironmentAccount, ID: [16]byte(c.Environment)}, c.Resources.Limit)
	if err != nil {
		return nil, err
	}
	r.accounts = []resourcev4.Account{tenant, environment}
	r.clock, err = newRuntimeClock(c.Clock)
	if err != nil {
		return nil, err
	}
	registry := protocolv4.NamespaceRegistryConfig{Continuity: protocolv4.OnlineBootstrap, Entries: uint32(len(c.Namespaces)), RuntimeBytes: 65536}
	cost, err = protocolv4.NamespaceRegistryCharge(registry)
	if err != nil {
		return nil, err
	}
	ref, _, err = r.reserve(cost)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	r.registry, err = protocolv4.NewNamespaceRegistry(registry, ref)
	if err != nil {
		return nil, err
	}
	for _, namespace := range c.Namespaces {
		if err = r.bootstrap(ctx, namespace); err != nil {
			return nil, err
		}
	}
	for i, spec := range c.Stores {
		if i >= storeCount {
			break
		}
		history, e := r.verifyHistory(spec)
		if e != nil {
			return nil, e
		}
		r.history[i] = history
		cost, e := ledgerv4.SQLiteBackingCharge(spec.Limits)
		if e != nil {
			return nil, e
		}
		backingRef, _, e := r.reserve(cost)
		if e != nil {
			return nil, e
		}
		r.backing[i], e = ledgerv4.NewSQLiteBacking(spec.Path, spec.Limits, backingRef, r.environment)
		backingRef.Release()
		if e != nil {
			return nil, e
		}
		if c.Role == "relay" && i == 1 {
			continue
		}
		cost, e = ledgerv4.SQLiteStoreCharge(spec.Limits)
		if e != nil {
			return nil, e
		}
		storeRef, _, e := r.reserve(cost)
		if e != nil {
			return nil, e
		}
		if spec.History.Provision {
			r.stores[i], e = ledgerv4.CreateSQLite(ctx, r.backing[i], spec.Identity, history, storeRef, r.environment)
		} else {
			r.stores[i], e = ledgerv4.OpenSQLite(ctx, r.backing[i], spec.Identity, history, storeRef, r.environment)
		}
		storeRef.Release()
		if e != nil {
			return nil, e
		}
	}
	success = true
	return r, nil
}

func newDeploymentRuntime(ctx context.Context, c deploymentConfig) (_ *deploymentRuntime, err error) {
	var cost resourcev4.Vector
	var ref resourcev4.Reference
	r, err := newDeploymentInfrastructure(ctx, c, c.Pool.Tenant, 3)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(c.ShutdownMS)*time.Millisecond)
			defer cancel()
			err = errors.Join(err, r.Close(cleanup))
		}
	}()
	pool := c.Pool
	base := pool.ArtifactIssuer
	base.Clock = r.clock
	for i, index := range pool.Trust {
		base.Trust[i] = r.trust[index]
	}
	artifact, err := r.signer(pool.ArtifactSigner)
	if err != nil {
		return nil, err
	}
	base.Signer = artifact
	activation, err := r.signer(pool.ActivationSigner)
	if err != nil {
		return nil, err
	}
	fence, err := r.signer(pool.FenceSigner)
	if err != nil {
		return nil, err
	}
	relaySigner, err := r.signer(c.Relay.Signer)
	if err != nil {
		return nil, err
	}
	authentication, err := readRuntimeFile(pool.AuthenticationFile, 16384)
	if err != nil {
		return nil, err
	}
	defer clear(authentication)
	issuePolicy := pool.IssuePolicy
	issuePolicy.Trust = base.Trust[0]
	issuePolicy.Clock = r.clock
	policy := controlv4.PoolTunnelDeploymentPolicyConfig{RuntimeBytes: 65536}
	owner := r.owner
	if _, err = rand.Read(owner.Instance[:]); err != nil {
		return nil, err
	}
	if _, err = rand.Read(owner.Backing[:]); err != nil {
		return nil, err
	}
	deployment := &policy.Deployment
	*deployment = controlv4.PoolTunnelDeploymentConfig{IssueStore: r.stores[0], RelayStore: r.stores[2], IssueIdentity: c.Stores[0].Identity, SourceBacking: r.backing[1], SourceContinuity: r.history[1], ProvisionSource: c.Stores[1].History.Provision,
		Root: r.root, Owner: owner, Accounts: r.accounts, RuntimeBytes: 65536}
	deployment.Host = controlv4.ArtifactIssueHostConfig{Policy: issuePolicy, RuntimeBytes: 65536, Shares: []controlv4.ArtifactIssueShareConfig{{Identity: c.Stores[0].Identity, MaxOutstanding: pool.MaxOutstanding, StateBytes: pool.StateBytes,
		ClientIdentity: [32]byte(pool.ClientIdentityDigest), ServerIdentity: [32]byte(pool.ServerIdentityDigest), AuthenticationKind: controlv4.ArtifactIssueLocalCredential, AuthenticationDigest: sha256.Sum256(authentication), ReadNamespaces: pool.ReadNamespaces}}}
	deployment.Issue = ledgerv4.SQLiteDirectIssueConfig{Policy: issuePolicy, MaxOutstanding: pool.MaxOutstanding, StateBytes: pool.StateBytes, RequestsPerMinute: 60, Burst: 4, WorkMS: 2000, RuntimeBytes: 65536}
	verify := controlv4.PoolBatchVerificationConfig{Clock: r.clock, Tenant: pool.Tenant, Audience: pool.Audience, CryptoProfile: pool.CryptoProfile, SourceIncarnation: [16]byte(pool.SourceIncarnation), ArtifactIssuer: base.IssuerKeyID,
		Pool: [32]byte(pool.PoolDigest), ClientIdentity: [32]byte(pool.ClientIdentityDigest), ServerIdentity: [32]byte(pool.ServerIdentityDigest), ActivationSigningKeyID: pool.ActivationSigningKeyID, Trust: base.Trust, Root: r.root, Owner: owner, Accounts: r.accounts, RuntimeBytes: 65536}
	deployment.Source = controlv4.PoolSourceAuthorityConfig{Identity: c.Stores[1].Identity, Fence: pool.OwnerFence, Verification: verify, IssuanceLimits: controlv4.PoolSourceIssuanceLimits{MaxBatchCount: 1, MaxItemBytes: 65536}}
	deployment.Journal = ledgerv4.SQLiteTopUpServerConfig{Tenant: pool.Tenant, Source: [16]byte(pool.SourceIncarnation), FenceKey: pool.FenceKey, Clock: r.clock, RetirementSkewMS: pool.RetirementSkewMS}
	var parallelLookups uint32
	for _, route := range pool.Routes {
		lookups, err := runtimehost.RelayAuthorityParallelLookups(route.Limits, 1)
		if err != nil {
			return nil, err
		}
		parallelLookups = max(parallelLookups, lookups)
	}
	deployment.Relay = ledgerv4.SQLiteRelayAuthorityConfig{Identity: c.Stores[2].Identity, MaxParents: pool.MaxOutstanding, ParallelLookups: parallelLookups, RuntimeBytes: 65536}
	deployment.Authority = controlv4.PoolTunnelAuthorityConfig{Root: r.root, Owner: owner, Accounts: r.accounts, RuntimeBytes: 65536, Artifact: protocolv4.ArtifactIssuerConfig{Base: base},
		Batch: controlv4.PoolBatchSigningConfig{Clock: r.clock, ArtifactAuthentication: append([]byte(nil), authentication...), Tenant: pool.Tenant, Audience: pool.Audience, CryptoProfile: pool.CryptoProfile,
			ActivationSigningKeyID: pool.ActivationSigningKeyID, Source: [16]byte(pool.SourceIncarnation), ArtifactIssuerID: base.IssuerKeyID, Pool: [32]byte(pool.PoolDigest), Trust: base.Trust, ClientCertificate: base.ClientCertificate, ServerCertificate: base.ServerCertificate,
			Signer: activation, Indices: pool.Indices, Budget: pool.Budget, Root: r.root, Owner: owner, Accounts: r.accounts, WorkMS: 10000, RuntimeBytes: 65536},
		Publication: controlv4.PoolRelayFactoryConfig{Clock: r.clock, SourceIdentity: c.Stores[1].Identity, Tenant: pool.Tenant, Audience: pool.Audience, CryptoProfile: pool.CryptoProfile, SourceIncarnation: [16]byte(pool.SourceIncarnation), ArtifactIssuer: base.IssuerKeyID,
			Pool: [32]byte(pool.PoolDigest), ClientIdentity: [32]byte(pool.ClientIdentityDigest), ServerIdentity: [32]byte(pool.ServerIdentityDigest), ActivationSigningKeyID: pool.ActivationSigningKeyID, Trust: base.Trust, Root: r.root, Owner: owner, Accounts: r.accounts, RuntimeBytes: 65536},
		Service: controlv4.PoolServiceConfig{Tenant: pool.Tenant, Source: [16]byte(pool.SourceIncarnation), TopUpContract: [32]byte(pool.TopUpContract), AckContract: [32]byte(pool.AckContract), ApplicationErrorCode: pool.ApplicationErrorCode, CallMS: 10000, RuntimeBytes: 65536}}
	for _, route := range pool.Routes {
		if int(route.Candidate) >= len(base.Candidates) || policy.Routes[route.Candidate] != nil || int(route.RelayTrust) >= len(r.trust) {
			return nil, errors.New("original Grant route manifest is invalid")
		}
		original := &controlv4.PoolTunnelSigningRoute{GrantIssuers: route.GrantIssuers, RelayCertificate: route.RelayCertificate, RelayTrust: r.trust[route.RelayTrust], Service: route.Service, RelayAudience: route.RelayAudience, Limits: route.Limits}
		for side := range 2 {
			if int(route.GrantTrust[side]) >= len(r.trust) {
				return nil, errors.New("independent Grant namespace is missing")
			}
			original.GrantTrust[side] = r.trust[route.GrantTrust[side]]
			original.GrantSigners[side], err = r.signer(route.GrantSigners[side])
			if err != nil {
				return nil, err
			}
		}
		policy.Routes[route.Candidate] = original
	}
	native := runtimehost.NativeRelayConfig{Root: r.root, Owner: r.owner, Accounts: r.accounts, Clock: r.clock, Environment: r.environment, Route: c.Relay.Route, Deployment: c.Relay.Deployment}
	for side, leg := range c.Relay.Legs {
		address, e := netip.ParseAddrPort(leg.Listen)
		if e != nil {
			return nil, e
		}
		certificate, e := loadRuntimeTLS(leg.CertificateFile, leg.PrivateKeyFile)
		if e != nil {
			return nil, e
		}
		roots, e := runtimeTLSRoots(leg.TLSRootsFile)
		if e != nil {
			return nil, e
		}
		quic := fs.DefaultQUICLimits()
		quic.MaxInboundStreams = 140
		transport := fs.DefaultWebTransportLimits()
		transport.MaxInboundStreams = 140
		native.Legs[side] = runtimehost.NativeRelayLeg{Address: address, Carrier: leg.Carrier, Certificate: certificate, Roots: roots, Origin: leg.Origin,
			QUIC:         fs.QUICProviderOptions{Limits: quic, StreamSlots: 140, RuntimeBytes: 65536, ProviderBytes: 140 << 20, ProviderTasks: 16},
			WebTransport: fs.WebTransportProviderOptions{Limits: transport, StreamSlots: 140, RuntimeBytes: 65536, ProviderBytes: 140 << 20, ProviderTasks: 16},
			WebSocket:    fs.WebSocketProviderOptions{MaxMessageBytes: 65544, ReadBufferBytes: 1024, WriteBufferBytes: 1024, HandshakeBytes: 8192, MaxControlsPerSecond: 16, HandshakeTimeout: 5 * time.Second, MessageTimeout: 30 * time.Second, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20, ProviderTasks: 4}}
	}
	r.native, err = runtimehost.NewNativeRelay(native)
	if err != nil {
		return nil, err
	}
	relay := runtimehost.RelayConfig{Policy: policy, FenceSigner: fence, ProofValidityMS: 30000, RelaySigner: relaySigner, RelayInstance: [16]byte(c.Relay.Instance), RelayGeneration: c.Relay.Generation, Prepare: r.native.Prepare, RuntimeBytes: 65536}
	cost, err = runtimehost.RelayCharge(relay)
	if err != nil {
		return nil, err
	}
	ref, owner, err = r.reserve(cost)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	relay.Policy.Deployment.Owner = owner
	r.relay, err = runtimehost.NewRelay(ctx, relay, ref, r.environment)
	if err != nil {
		return nil, err
	}
	certificate, err := loadRuntimeTLS(c.TLS.CertificateFile, c.TLS.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	clientRoots, err := runtimeTLSRoots(c.TLS.ClientRootsFile)
	if err != nil {
		return nil, err
	}
	clientDER, err := readRuntimeFile(c.TLS.ClientCertificateFile, 16384)
	if err != nil {
		return nil, err
	}
	client, err := x509.ParseCertificate(clientDER)
	if err != nil {
		return nil, err
	}
	r.tls = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientCAs: clientRoots, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	r.access = &runtimeTopUpAccess{tenant: pool.Tenant, source: [16]byte(pool.SourceIncarnation), principal: ledgerv4.AuditPrincipal{Actor: sha256.Sum256(clientDER), Role: 1}, clock: r.clock, notAfter: uint64(client.NotAfter.UnixMilli())}
	service, err := r.relay.Service()
	if err != nil {
		return nil, err
	}
	https := controlv4.PoolHTTPSServiceConfig{Service: service, OwnerProof: r.relay.OwnerProof(), OriginalCommitted: r.relay.DispatchOriginal, Access: r.access, Clock: r.clock, Tenant: pool.Tenant, Source: [16]byte(pool.SourceIncarnation), ClientCertificateDER: clientDER,
		RequestsPerMinute: 60, Burst: 4, WorkMS: 10000, RuntimeBytes: 65536}
	cost, err = controlv4.PoolHTTPSServiceCharge(https)
	if err != nil {
		return nil, err
	}
	ref, _, err = r.reserve(cost)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	r.pool, err = controlv4.NewPoolHTTPSService(https, ref, r.environment)
	if err != nil {
		return nil, err
	}
	success = true
	return r, nil
}

func newRuntimeClock(c clockSpec) (*timev4.Clock, error) {
	if c.Qualification == "" || len(c.Incarnation) != 16 {
		return nil, timev4.ErrUnavailable
	}
	started := time.Now()
	incarnation := [16]byte(c.Incarnation)
	var mu sync.Mutex
	var last uint64
	clock, err := timev4.NewClock(c.Profile, func() (timev4.Tick, error) {
		now := time.Now()
		elapsed := now.Sub(started)
		if elapsed < 0 {
			return timev4.Tick{}, timev4.ErrUnavailable
		}
		monotonic := uint64(elapsed / time.Millisecond)
		wall := now.UnixMilli() - started.UnixMilli()
		if wall < 0 || uint64(wall) > monotonic && uint64(wall)-monotonic > c.DriftToleranceMS || monotonic > uint64(wall) && monotonic-uint64(wall) > c.DriftToleranceMS {
			return timev4.Tick{}, timev4.ErrUnavailable
		}
		mu.Lock()
		defer mu.Unlock()
		if monotonic < last {
			return timev4.Tick{}, timev4.ErrUnavailable
		}
		last = monotonic
		return timev4.Tick{Milliseconds: monotonic, Incarnation: incarnation}, nil
	})
	if err != nil {
		return nil, err
	}
	mark, err := clock.Monotonic()
	if err == nil {
		err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: c.LowerMS, UpperMS: c.UpperMS})
	}
	if err != nil {
		clock.Close()
		return nil, err
	}
	return clock, nil
}
func loadRuntimeTLS(certificateFile, keyFile string) (tls.Certificate, error) {
	certificate, err := readRuntimeFile(certificateFile, 65536)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(certificate)
	key, err := readRuntimeFile(keyFile, 16384)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(key)
	return tls.X509KeyPair(certificate, key)
}
func (r *deploymentRuntime) bootstrap(ctx context.Context, c namespaceSpec) error {
	cost, err := protocolv4.NamespaceTrustCharge(c.TrustLimits)
	if err != nil {
		return err
	}
	ref, _, err := r.reserve(cost)
	if err != nil {
		return err
	}
	defer ref.Release()
	trust, err := protocolv4.NewNamespaceTrustAnchor(c.Root, c.TrustLimits, r.clock, ref, r.environment)
	if err != nil {
		return err
	}
	r.trust = append(r.trust, trust)
	if err = r.registry.Register(trust); err != nil {
		return err
	}
	roots, err := runtimeTLSRoots(c.TLSRootsFile)
	if err != nil {
		return err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots}
	if c.TLSClientCertificateFile != "" || c.TLSClientKeyFile != "" {
		certificate, e := loadRuntimeTLS(c.TLSClientCertificateFile, c.TLSClientKeyFile)
		if e != nil {
			return e
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	address, err := netip.ParseAddrPort(c.Address)
	if err != nil {
		return err
	}
	providerConfig := controlv4.HTTPSBootstrapConfig{BaseURL: c.URL, RemoteAddress: address, TLS: config, HeaderBytes: 8192, Timeout: 10 * time.Second, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20}
	cost, err = controlv4.HTTPSBootstrapCharge(providerConfig)
	if err != nil {
		return err
	}
	ref, _, err = r.reserve(cost)
	if err != nil {
		return err
	}
	defer ref.Release()
	provider, err := controlv4.NewHTTPSBootstrapProvider(providerConfig, ref, r.environment)
	if err != nil {
		return err
	}
	r.providers = append(r.providers, provider)
	allocation := protocolv4.NamespaceAllocation{Root: r.root, Accounts: r.accounts}
	for i := range allocation.Owners {
		allocation.Owners[i] = r.owner
		if _, err = rand.Read(allocation.Owners[i].Instance[:]); err != nil {
			return err
		}
		if _, err = rand.Read(allocation.Owners[i].Backing[:]); err != nil {
			return err
		}
	}
	cost, err = protocolv4.NamespaceBootstrapCharge(c.BootstrapLimits)
	if err != nil {
		return err
	}
	ref, _, err = r.reserve(cost)
	if err != nil {
		return err
	}
	defer ref.Release()
	job, err := protocolv4.NewNamespaceOnlineBootstrap(ctx, trust, c.BootstrapLimits, allocation, ref)
	if err != nil {
		return err
	}
	namespace, runErr := job.Run(ctx, provider)
	job.Close()
	cleanupErr := job.WaitCleanup(ctx)
	if cleanupErr == nil {
		cleanupErr = job.Retire()
	}
	if namespace != nil {
		r.namespaces = append(r.namespaces, namespace)
	}
	return errors.Join(runErr, cleanupErr)
}

func (r *deploymentRuntime) verifyHistory(c storeSpec) (*runtimeHistory, error) {
	h := c.History
	if h.Authority != c.Identity.Authority || len(h.StoreID) != 32 || [32]byte(h.StoreID) != c.Identity.StoreID || h.Generation != c.Identity.Generation || h.Provision && h.Epoch != 0 || !h.Provision && h.Epoch == 0 || len(h.PathDigest) != 32 || len(h.DatabaseDigest) != 32 || len(h.WALDigest) != 32 {
		return nil, ledgerv4.ErrOwner
	}
	pathDigest := sha256.Sum256([]byte(c.Path))
	if pathDigest != [32]byte(h.PathDigest) {
		return nil, ledgerv4.ErrOwner
	}
	// This exact ordered envelope is signed by the independently installed
	// history authority. It is never produced from a SQLite read or a peer Grant.
	signing := struct {
		Domain                                string
		Authority                             string
		StoreID                               []byte
		Generation, Epoch, NotAfterMS         uint64
		Provision                             bool
		PathDigest, DatabaseDigest, WALDigest []byte
	}{"flowersec-runtime-history-1", h.Authority, h.StoreID, h.Generation, h.Epoch, h.NotAfterMS, h.Provision, h.PathDigest, h.DatabaseDigest, h.WALDigest}
	message, err := json.Marshal(signing)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(ed25519.PublicKey(c.HistoryKey), message, h.Signature) {
		return nil, ledgerv4.ErrOwner
	}
	now, err := r.clock.Sample()
	if err != nil || !now.ValidBefore(h.NotAfterMS) {
		return nil, ledgerv4.ErrFenced
	}
	maximum := int64(c.Limits.MaxPages)*8192 + 1048576
	for i, path := range []string{c.Path, c.Path + "-wal"} {
		expected := h.DatabaseDigest
		if i == 1 {
			expected = h.WALDigest
		}
		info, e := os.Lstat(path)
		if h.Provision {
			if !errors.Is(e, os.ErrNotExist) || [32]byte(expected) != ([32]byte{}) {
				return nil, ledgerv4.ErrOwner
			}
			continue
		}
		if errors.Is(e, os.ErrNotExist) && i == 1 && [32]byte(expected) == ([32]byte{}) {
			continue
		}
		if e != nil || !info.Mode().IsRegular() || info.Size() > maximum {
			return nil, ledgerv4.ErrOwner
		}
		file, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		hash := sha256.New()
		var scratch [32768]byte
		_, e = io.CopyBuffer(hash, io.LimitReader(file, maximum+1), scratch[:])
		closeErr := file.Close()
		clear(scratch[:])
		if e != nil || closeErr != nil || !bytesEqualRuntime(hash.Sum(nil), expected) {
			return nil, ledgerv4.ErrOwner
		}
	}
	return &runtimeHistory{identity: c.Identity, epoch: h.Epoch, provision: h.Provision, clock: r.clock, notAfter: h.NotAfterMS}, nil
}
func bytesEqualRuntime(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := range left {
		diff |= left[i] ^ right[i]
	}
	return diff == 0
}

// Serve exposes the original authenticated control service. A successful new
// batch invokes DispatchOriginal; replay serves retained bytes without native
// preparation. Server shutdown joins original requests before issuer cleanup.
func (r *deploymentRuntime) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", r.config.TLS.Listen)
	if err != nil {
		return err
	}
	bounded := &runtimeBoundedListener{Listener: listener, positions: make(chan struct{}, 8), stop: make(chan struct{})}
	server := &http.Server{Handler: r.pool, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, TLSConfig: r.tls}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(bounded, r.tls)) }()
	var serveErr error
	select {
	case <-ctx.Done():
		serveErr = context.Cause(ctx)
	case serveErr = <-done:
		done = nil
	}
	cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.ShutdownMS)*time.Millisecond)
	defer cancel()
	shutdownErr := server.Shutdown(cleanup)
	if shutdownErr != nil {
		_ = server.Close()
	}
	_ = bounded.Close()
	if done != nil {
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				serveErr = errors.Join(serveErr, err)
			}
		case <-cleanup.Done():
			serveErr = errors.Join(serveErr, cleanup.Err())
		}
	}
	closeErr := r.Close(cleanup)
	if errors.Is(serveErr, context.Canceled) || errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) {
		serveErr = nil
	}
	return errors.Join(serveErr, shutdownErr, closeErr)
}
func (r *deploymentRuntime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var failures []error
	if r.pool != nil {
		r.pool.Close()
		failures = append(failures, r.pool.WaitCleanup(ctx))
	}
	if r.relay != nil {
		r.relay.Close()
	}
	if r.native != nil {
		r.native.Close()
	}
	if r.relay != nil {
		failures = append(failures, r.relay.WaitCleanup(ctx))
	}
	if r.native != nil {
		failures = append(failures, r.native.WaitCleanup(ctx))
	}
	for _, store := range r.stores {
		if store != nil {
			store.Close()
			failures = append(failures, store.WaitCleanup(ctx))
			if ctx.Err() == nil {
				failures = append(failures, store.Retire())
			}
		}
	}
	for _, provider := range r.providers {
		provider.Close()
		failures = append(failures, provider.WaitCleanup(ctx))
	}
	for _, namespace := range r.namespaces {
		namespace.Close(nil)
		failures = append(failures, namespace.WaitCleanup(ctx))
	}
	if r.registry != nil {
		r.registry.Close()
	}
	for _, trust := range r.trust {
		trust.Close()
	}
	for _, namespace := range r.namespaces {
		failures = append(failures, namespace.DestroyEnvironment())
	}
	for _, trust := range r.trust {
		failures = append(failures, trust.DestroyEnvironment())
	}
	if r.registry != nil {
		failures = append(failures, r.registry.DestroyEnvironment())
	}
	for _, backing := range r.backing {
		if backing != nil {
			backing.Close()
		}
	}
	for _, key := range r.keys {
		clear(key.key)
	}
	if r.clock != nil {
		r.clock.Close()
	}
	r.environment.Release()
	for _, account := range r.accounts {
		account.Close()
	}
	if r.root != nil {
		r.root.Close()
	}
	return errors.Join(failures...)
}

type runtimeBoundedListener struct {
	net.Listener
	positions chan struct{}
	stop      chan struct{}
	once      sync.Once
}
type runtimeBoundedConnection struct {
	net.Conn
	listener *runtimeBoundedListener
	once     sync.Once
}

func (l *runtimeBoundedListener) Accept() (net.Conn, error) {
	select {
	case l.positions <- struct{}{}:
	case <-l.stop:
		return nil, net.ErrClosed
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.positions
		return nil, err
	}
	return &runtimeBoundedConnection{Conn: connection, listener: l}, nil
}
func (l *runtimeBoundedListener) Close() error {
	l.once.Do(func() { close(l.stop) })
	return l.Listener.Close()
}
func (c *runtimeBoundedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.listener.positions })
	return err
}
