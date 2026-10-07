package interopharness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/runtimehost"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type PoolRelay struct {
	Runtime                                         *Runtime
	Host                                            *runtimehost.Relay
	Native                                          *runtimehost.NativeRelay
	Material                                        [2]Material
	Namespace                                       NamespaceRecord
	TrustPEM, Origin                                string
	Carriers                                        [2]string
	Addresses                                       [2]netip.AddrPort
	CertificateDER                                  []byte
	ClientTLSCertificatePEM, ClientTLSPrivateKeyPEM string
	ServerTLSCertificatePEM, ServerTLSPrivateKeyPEM string
	start                                           chan struct{}
	originalRelayIdentitySeed                       [32]byte
	originalRelayTLSIdentity                        *tls.Certificate
	startOnce                                       sync.Once
}

func (p *PoolRelay) CloseOwners() {
	if p == nil {
		return
	}
	if p.Host != nil {
		p.Host.Close()
	}
	if p.Native != nil {
		p.Native.Close()
	}
	if p.Runtime != nil {
		p.Runtime.CloseOwners()
	}
}
func (p *PoolRelay) WaitOwners(ctx context.Context) error {
	if p == nil {
		return nil
	}
	var result error
	if p.Host != nil {
		result = errors.Join(result, p.Host.WaitCleanup(ctx))
	}
	if p.Native != nil {
		result = errors.Join(result, p.Native.WaitCleanup(ctx))
	}
	if p.Runtime != nil {
		result = errors.Join(result, p.Runtime.WaitOwners(ctx))
	}
	return result
}

type engineeringNewHistory struct{ identity ledgerv4.SQLiteIdentity }

func (h engineeringNewHistory) Check(identity ledgerv4.SQLiteIdentity, epoch uint64, create bool) error {
	if identity != h.identity || create && epoch != 0 || !create && epoch != 1 {
		return ledgerv4.ErrOwner
	}
	return nil
}

type engineeringSourceAccess struct {
	tenant    string
	source    [16]byte
	principal ledgerv4.AuditPrincipal
}

func (a engineeringSourceAccess) CheckTopUpAccess(tenant string, source [16]byte) error {
	if tenant != a.tenant || source != a.source {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (a engineeringSourceAccess) TopUpAuditPrincipal(tenant string, source [16]byte) (ledgerv4.AuditPrincipal, error) {
	return a.principal, a.CheckTopUpAccess(tenant, source)
}

// NewPoolRelay performs actual finite issuance at the relay's original source.
// It never accepts a caller's Grants as committed-public-registration evidence.
// The ready materials are the bytes returned by that real PoolService COMMIT;
// peer bootstrap and both native/e2e handshakes still run independently.
type PoolRelayTLSManifest struct {
	Certificate tls.Certificate
	Roots       *x509.CertPool
	TrustPEM    string
	Policy      []byte
}
type PoolRelayOptions struct {
	EndpointListeners [2]bool
	ListenerAddresses [2]netip.AddrPort
	ListenHost        string
	SocketScope       assemblyv4.NativeDialScope
	TLS               *PoolRelayTLSManifest
	// OriginalOwner is a trusted engineering issuer callback, captured before
	// issuance. It transfers the one original successful publication and prevents
	// the local Go host from dispatching the same paired route.
	OriginalOwner func(*PoolRelay) error
}

func NewPoolRelay(ctx context.Context, reporter *Reporter, carriers [2]string, origin string, options ...PoolRelayOptions) (*PoolRelay, error) {
	return construct(reporter, func() *PoolRelay {
		if len(options) > 1 {
			reporter.Fatal("one original topology direction policy is required")
		}
		directions := PoolRelayOptions{EndpointListeners: [2]bool{false, true}}
		if len(options) == 1 {
			directions = options[0]
		}
		if directions.ListenHost == "" {
			directions.ListenHost = "127.0.0.1"
		}
		listenHost, parseErr := netip.ParseAddr(directions.ListenHost)
		if parseErr != nil || listenHost.IsUnspecified() || listenHost.IsMulticast() || listenHost.Zone() != "" {
			reporter.Fatal("relay requires one numeric unicast host")
		}
		reporter.ApplicationProfile = "services"
		reporter.MaxStreams = nativeParityMaxStreams
		reporter.originalPoolDeployment = true
		certificate, roots, trustPEM, tlsPolicy, err := TLSMaterial(directions.ListenHost)
		if err != nil {
			reporter.Fatal(err)
		}
		if directions.TLS != nil {
			manifest := directions.TLS
			if manifest.Certificate.PrivateKey == nil || len(manifest.Certificate.Certificate) == 0 || manifest.Roots == nil || manifest.TrustPEM == "" || len(manifest.Policy) == 0 {
				reporter.Fatal("complete independently installed relay TLS manifest is required")
			}
			certificate = manifest.Certificate
			certificate.Certificate = make([][]byte, len(manifest.Certificate.Certificate))
			for i, der := range manifest.Certificate.Certificate {
				certificate.Certificate[i] = append([]byte(nil), der...)
			}
			roots = manifest.Roots.Clone()
			trustPEM = manifest.TrustPEM
			tlsPolicy = append([]byte(nil), manifest.Policy...)
		}
		clientCertificate, clientRoots, clientTrustPEM, _, err := TLSMaterial(directions.ListenHost)
		if err != nil {
			reporter.Fatal(err)
		}
		clientKey, err := x509.MarshalPKCS8PrivateKey(clientCertificate.PrivateKey)
		if err != nil {
			reporter.Fatal(err)
		}
		defer clear(clientKey)
		clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKey})
		defer clear(clientKeyPEM)
		serverCertificate, serverRoots, serverTrustPEM, _, err := TLSMaterial(directions.ListenHost)
		if err != nil {
			reporter.Fatal(err)
		}
		serverKey, err := x509.MarshalPKCS8PrivateKey(serverCertificate.PrivateKey)
		if err != nil {
			reporter.Fatal(err)
		}
		defer clear(serverKey)
		serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKey})
		defer clear(serverKeyPEM)
		var addresses [2]netip.AddrPort
		for side, carrier := range carriers {
			if (directions.EndpointListeners[side] || directions.OriginalOwner != nil) && directions.ListenerAddresses[side].IsValid() {
				address := directions.ListenerAddresses[side]
				if address.Port() == 0 || !address.Addr().IsLoopback() || address.Addr() != listenHost {
					reporter.Fatal("prebound endpoint listener must match the original local relay address")
				}
				addresses[side] = address
				continue
			}
			err = assemblyv4.RunNativeDial(ctx, directions.SocketScope, func() error {
				if carrier == "websocket" {
					probe, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IP(listenHost.AsSlice())})
					if e != nil {
						return e
					}
					addresses[side] = probe.Addr().(*net.TCPAddr).AddrPort()
					return probe.Close()
				}
				probe, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(listenHost.AsSlice())})
				if e != nil {
					return e
				}
				addresses[side] = probe.LocalAddr().(*net.UDPAddr).AddrPort()
				return probe.Close()
			})
			if err != nil {
				reporter.Fatal(err)
			}
		}
		route, profile, err := engineeringRelayRoute(reporter, carriers, addresses, tlsPolicy, origin, directions.EndpointListeners)
		if err != nil {
			reporter.Fatal(err)
		}
		var relaySeed, grantSeed [32]byte
		var grantIssuer [16]byte
		if _, err = rand.Read(relaySeed[:]); err != nil {
			reporter.Fatal(err)
		}
		if _, err = rand.Read(grantSeed[:]); err != nil {
			reporter.Fatal(err)
		}
		if _, err = rand.Read(grantIssuer[:]); err != nil {
			reporter.Fatal(err)
		}
		limits := nativeParityRelayLimits(carriers)
		recipe := sessionv4.EngineeringTunnelRecipe{Route: route, RelaySubject: "parity-relay", RelayAudience: "flowersec.parity.relay", RelayIdentitySeed: relaySeed, GrantIssuerID: grantIssuer, GrantIssuerSeed: grantSeed, Limits: [2]protocolv4.RelayGrantLimits{limits, limits}}
		if err = reporter.SetTunnelRecipe(recipe); err != nil {
			reporter.Fatal(err)
		}
		authority := sessionv4.NewEngineeringNativeHarness(reporter, "preauthorized_pool", protocolv4.DHProfileX25519, carriers[0], addresses[0], tlsPolicy, origin, limits.DatagramBytes != 0)
		if authority.PoolIssue == nil {
			reporter.Fatal("original Pool issuance recipe was not installed")
		}
		runtime, err := NewRuntime(ctx, reporter, authority, nil, nil)
		if err != nil {
			reporter.Fatal(err)
		}
		source := authority.PoolIssue
		parent, namespace, err := source.Base.Trust[0].ResolveIssuerPolicy(protocolv4.IssuerPolicySelection{Schema: "Artifact", Issuer: source.Base.IssuerKeyID, Audience: source.Base.Audience, Profile: source.Base.CryptoProfile, PolicyID: source.Base.RevocationPolicyID, PolicyRevision: source.Base.RevocationPolicyRevision})
		if err != nil {
			reporter.Fatal(err)
		}
		_ = parent
		namespace.RoleMask = 7
		source.Policy.Namespaces = []protocolv4.NamespaceReference{namespace}
		activationIssuer, err := source.Base.Trust[0].ResolveActivationIssuer(source.Base.IssuerKeyID, source.ActivationSigningKeyID)
		if err != nil {
			reporter.Fatal(err)
		}
		var stores [3]*ledgerv4.SQLiteStore
		var backing [3]*ledgerv4.SQLiteBacking
		var identities [3]ledgerv4.SQLiteIdentity
		var history [3]engineeringNewHistory
		disk := reporter.TempDir()
		storeLimits := ledgerv4.SQLiteLimits{MaxPages: 8192, MaxRecords: 16, MaxRecordBytes: 524288, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20, DiskOverheadBytes: 65536}
		for i := range identities {
			identities[i] = ledgerv4.SQLiteIdentity{Authority: []string{"parity.issuer", "parity.source", activationIssuer.WinnerAuthority}[i], Generation: 1}
			if _, err = rand.Read(identities[i].StoreID[:]); err != nil {
				reporter.Fatal(err)
			}
			history[i] = engineeringNewHistory{identities[i]}
			cost, e := ledgerv4.SQLiteBackingCharge(storeLimits)
			if e != nil {
				reporter.Fatal(e)
			}
			backing[i], e = ledgerv4.NewSQLiteBacking(filepath.Join(disk, []string{"issuer.db", "source.db", "relay.db"}[i]), storeLimits, authority.Reserve(cost), authority.Environment)
			if e != nil {
				reporter.Fatal(e)
			}
			if i == 1 {
				continue
			}
			cost, e = ledgerv4.SQLiteStoreCharge(storeLimits)
			if e != nil {
				reporter.Fatal(e)
			}
			stores[i], e = ledgerv4.CreateSQLite(ctx, backing[i], identities[i], history[i], authority.Reserve(cost), authority.Environment)
			if e != nil {
				reporter.Fatal(e)
			}
		}
		reporter.Cleanup(func() {
			for _, store := range stores {
				if store != nil {
					store.Close()
					reporter.ErrorIf(store.WaitCleanup(context.Background()))
					reporter.ErrorIf(store.Retire())
				}
			}
			for _, disk := range backing {
				if disk != nil {
					disk.Close()
				}
			}
			if err := os.RemoveAll(disk); err != nil {
				reporter.ErrorIf(err)
			}
			for _, back := range backing {
				if back != nil {
					reporter.ErrorIf(back.ReleaseRemoved())
				}
			}
		})
		stateBytes, err := ledgerv4.SQLiteDirectIssueStateShareBytes(1)
		if err != nil {
			reporter.Fatal(err)
		}
		clientMap, err := protocolv4.NewSignedMapCodec("IdentityCertificate", 8192, 4096)
		if err != nil {
			reporter.Fatal(err)
		}
		client, err := clientMap.VerifyCredential(source.Base.ClientCertificate, source.Base.Trust[1])
		if err != nil {
			reporter.Fatal(err)
		}
		clientDigest, err := client.Digest("certificate_digest")
		client.Release()
		if err != nil {
			reporter.Fatal(err)
		}
		serverMap, err := protocolv4.NewSignedMapCodec("IdentityCertificate", 8192, 4096)
		if err != nil {
			reporter.Fatal(err)
		}
		server, err := serverMap.VerifyCredential(source.Base.ServerCertificate, source.Base.Trust[2])
		if err != nil {
			reporter.Fatal(err)
		}
		serverDigest, err := server.Digest("certificate_digest")
		server.Release()
		if err != nil {
			reporter.Fatal(err)
		}
		var sourceID [16]byte
		var poolDigest, authentication, fenceSeed [32]byte
		var fenceID [16]byte
		for _, dst := range [][]byte{sourceID[:], poolDigest[:], authentication[:], fenceSeed[:], fenceID[:]} {
			if _, err = rand.Read(dst); err != nil {
				reporter.Fatal(err)
			}
		}
		fenceSigner := engineeringControlSigner{ed25519.NewKeyFromSeed(fenceSeed[:])}
		reporter.Cleanup(func() { clear(fenceSigner.key) })
		now, err := authority.Clock.Sample()
		if err != nil {
			reporter.Fatal(err)
		}
		owner := authority.Owner()
		accounts := []resourcev4.Account{authority.Scope[0].Tenant}
		verification := controlv4.PoolBatchVerificationConfig{Clock: authority.Clock, Tenant: source.Base.Tenant, Audience: source.Base.Audience, CryptoProfile: source.Base.CryptoProfile, SourceIncarnation: sourceID, ArtifactIssuer: source.Base.IssuerKeyID,
			Pool: poolDigest, ClientIdentity: clientDigest, ServerIdentity: serverDigest, ActivationSigningKeyID: source.ActivationSigningKeyID, Trust: source.Base.Trust, Root: authority.Root, Owner: owner, Accounts: accounts, RuntimeBytes: 65536}
		parallelLookups, err := runtimehost.RelayAuthorityParallelLookups(authority.Tunnel.Limits, 1)
		if err != nil {
			reporter.Fatal(err)
		}
		deployment := controlv4.PoolTunnelDeploymentConfig{IssueStore: stores[0], RelayStore: stores[2], IssueIdentity: identities[0], SourceBacking: backing[1], SourceContinuity: history[1], ProvisionSource: true, Root: authority.Root, Owner: owner, Accounts: accounts, RuntimeBytes: 65536,
			Host:    controlv4.ArtifactIssueHostConfig{Policy: source.Policy, RuntimeBytes: 65536, Shares: []controlv4.ArtifactIssueShareConfig{{Identity: identities[0], MaxOutstanding: 1, StateBytes: stateBytes, ClientIdentity: clientDigest, ServerIdentity: serverDigest, AuthenticationKind: controlv4.ArtifactIssueLocalCredential, AuthenticationDigest: sha256.Sum256(authentication[:]), ReadNamespaces: []protocolv4.NamespaceReference{namespace}}}},
			Issue:   ledgerv4.SQLiteDirectIssueConfig{Policy: source.Policy, MaxOutstanding: 1, StateBytes: stateBytes, RequestsPerMinute: 60, Burst: 1, WorkMS: 2000, RuntimeBytes: 65536},
			Source:  controlv4.PoolSourceAuthorityConfig{Identity: identities[1], Fence: ledgerv4.TopUpSourceFence{Generation: 1, LeaseUntilMS: now.LowerMS + 60000}, Verification: verification, IssuanceLimits: controlv4.PoolSourceIssuanceLimits{MaxBatchCount: 1, MaxItemBytes: 65536}},
			Journal: ledgerv4.SQLiteTopUpServerConfig{Tenant: source.Base.Tenant, Source: sourceID, FenceKey: protocolv4.TopUpFenceAuthority{KeyID: fenceID, PublicKey: [32]byte(fenceSigner.PublicKey())}, Clock: authority.Clock, RetirementSkewMS: 1},
			Relay:   ledgerv4.SQLiteRelayAuthorityConfig{Identity: identities[2], MaxParents: 1, ParallelLookups: parallelLookups, RuntimeBytes: 65536}}
		deployment.Authority = controlv4.PoolTunnelAuthorityConfig{Root: authority.Root, Owner: owner, Accounts: accounts, RuntimeBytes: 65536, Artifact: protocolv4.ArtifactIssuerConfig{Base: source.Base},
			Batch: controlv4.PoolBatchSigningConfig{Clock: authority.Clock, ArtifactAuthentication: authentication[:], Tenant: source.Base.Tenant, Audience: source.Base.Audience, CryptoProfile: source.Base.CryptoProfile, ActivationSigningKeyID: source.ActivationSigningKeyID,
				Source: sourceID, ArtifactIssuerID: source.Base.IssuerKeyID, Pool: poolDigest, Trust: source.Base.Trust, ClientCertificate: source.Base.ClientCertificate, ServerCertificate: source.Base.ServerCertificate, Signer: source.ActivationSigner,
				Indices: []uint64{0}, Budget: protocolv4.PoolAttemptLimits{CandidateAddressAttempts: 1, CandidatePreauthBytes: 131072, CandidateWorkUnits: 128, TotalAddressAttempts: 1, TotalPreauthBytes: 131072, TotalWorkUnits: 128, ParallelCandidates: 1}, Root: authority.Root, Owner: owner, Accounts: accounts, WorkMS: reporter.operationMS(10000), RuntimeBytes: 65536},
			Publication: controlv4.PoolRelayFactoryConfig{Clock: authority.Clock, SourceIdentity: identities[1], Tenant: source.Base.Tenant, Audience: source.Base.Audience, CryptoProfile: source.Base.CryptoProfile, SourceIncarnation: sourceID, ArtifactIssuer: source.Base.IssuerKeyID,
				Pool: poolDigest, ClientIdentity: clientDigest, ServerIdentity: serverDigest, ActivationSigningKeyID: source.ActivationSigningKeyID, Trust: source.Base.Trust, Root: authority.Root, Owner: owner, Accounts: accounts, RuntimeBytes: 65536},
			Service: controlv4.PoolServiceConfig{Tenant: source.Base.Tenant, Source: sourceID, TopUpContract: sha256.Sum256([]byte("flowersec.parity.pool.top-up")), AckContract: sha256.Sum256([]byte("flowersec.parity.pool.ack")), ApplicationErrorCode: 1, CallMS: reporter.operationMS(10000), RuntimeBytes: 65536}}
		policy := controlv4.PoolTunnelDeploymentPolicyConfig{Deployment: deployment, RuntimeBytes: 65536}
		policy.Routes[0] = &controlv4.PoolTunnelSigningRoute{GrantIssuers: [2][16]byte{source.GrantIssuer, source.GrantIssuer}, GrantTrust: [2]*protocolv4.NamespaceTrustStore{source.Base.Trust[0], source.Base.Trust[0]}, GrantSigners: [2]protocolv4.MapSigner{source.GrantSigner, source.GrantSigner},
			RelayCertificate: authority.Tunnel.RelayCertificate, RelayTrust: source.Base.Trust[0], Service: source.Base.Audience, RelayAudience: source.RelayAudience, Limits: authority.Tunnel.Limits}
		policyDecoder, err := protocolv4.NewDecoder(8192, 1024)
		if err != nil {
			reporter.Fatal(err)
		}
		policyDocument, err := policyDecoder.DecodeMap(tlsPolicy, "TLSPolicy", protocolv4.DecodeContext{})
		if err != nil {
			reporter.Fatal(err)
		}
		nativePolicy, err := tlspolicy.Capture(policyDocument.Root())
		policyDocument.Release()
		if err != nil {
			reporter.Fatal(err)
		}
		start := make(chan struct{})
		nativeConfig := runtimehost.NativeRelayConfig{Start: start, Root: authority.Root, Owner: authority.Owner(), Accounts: accounts, Clock: authority.Clock, Environment: authority.Environment, Route: authority.Route, Deployment: protocolv4.RelayDeploymentBinding{RouteDigest: authority.BrowserRouteDigest, Profile: profile}}
		for side, carrier := range carriers {
			legRoots := roots
			if directions.EndpointListeners[side] {
				if side == 0 {
					legRoots = clientRoots
				} else {
					legRoots = serverRoots
				}
			}
			// Pin-only native listeners and dialers do not admit a CA fallback.
			// Bootstrap HTTPS retains its separate original trust installation.
			if !nativePolicy.RequiresRoots() {
				legRoots = nil
			}
			nativeConfig.Legs[side] = reporter.nativeScopedLeg(carrier, addresses[side], certificate, legRoots, directions.SocketScope)
			if carrier != "raw-quic" {
				nativeConfig.Legs[side].Origin = origin
			}
		}
		native, err := runtimehost.NewNativeRelay(nativeConfig)
		if err != nil {
			reporter.Fatal(err)
		}
		// Register each physical owner as soon as it is acquired. Construction
		// may fail before the original-owner callback runs, and those tails must
		// remain retryable through the reporter's bounded cleanup path.
		reporter.Owner(native.Close, native.WaitCleanup)
		relay := runtimehost.RelayConfig{Policy: policy, FenceSigner: fenceSigner, ProofValidityMS: max(uint64(30000), reporter.operationMS(30000)), RelaySigner: authority.Tunnel.RelaySigner, RelayInstance: [16]byte{31}, RelayGeneration: 1, Prepare: native.Prepare, RuntimeBytes: 65536}
		cost, err := runtimehost.RelayCharge(relay)
		if err != nil {
			reporter.Fatal(err)
		}
		ref, err := authority.Root.Reserve(owner, cost, accounts...)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(ref.Release)
		relayHost, err := runtimehost.NewRelay(ctx, relay, ref, authority.Environment)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Owner(relayHost.Close, relayHost.WaitCleanup)
		reporter.Cleanup(func() {
			relayHost.Close()
			native.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reporter.ErrorIf(relayHost.WaitCleanup(cleanup))
			reporter.ErrorIf(native.WaitCleanup(cleanup))
		})
		bootstrapServer := &Server{Runtime: runtime, Address: addresses[0], certificate: certificate, TrustPEM: trustPEM, Origin: origin}
		var namespaceRecord NamespaceRecord
		err = assemblyv4.RunNativeDial(ctx, directions.SocketScope, func() error {
			var err error
			namespaceRecord, err = bootstrapServer.startBootstrap(reporter)
			return err
		})
		if err != nil {
			reporter.Fatal(err)
		}
		request := protocolv4.TopUpRequestFacts{Tenant: source.Base.Tenant, Source: sourceID, Pool: poolDigest, Identity: clientDigest, Generation: 1, DeadlineMS: now.LowerMS + max(uint64(30000), reporter.operationMS(30000)), DesiredCount: 1, MaxItemBytes: 65536}
		binary.BigEndian.PutUint64(request.Operation[:8], 1)
		if _, err = rand.Read(request.Operation[8:]); err != nil {
			reporter.Fatal(err)
		}
		request.Digest, err = protocolv4.ComputeTopUpRequestDigest(request)
		if err != nil {
			reporter.Fatal(err)
		}
		output := make([]byte, 524288)
		defer clear(output)
		access := engineeringSourceAccess{tenant: request.Tenant, source: sourceID, principal: ledgerv4.AuditPrincipal{Actor: sha256.Sum256(authentication[:]), Role: 1}}
		buildOriginal := func(reply []byte) (*PoolRelay, error) {
			materials, e := engineeringOriginalMaterial(reply, request, namespaceRecord, source, profile)
			if e != nil {
				return nil, e
			}
			return &PoolRelay{Runtime: runtime, Host: relayHost, Native: native, Material: materials, Namespace: namespaceRecord, TrustPEM: trustPEM + clientTrustPEM + serverTrustPEM, Origin: origin, Carriers: carriers, Addresses: addresses, CertificateDER: append([]byte(nil), certificate.Certificate[0]...), ClientTLSCertificatePEM: engineeringCertificatePEM(clientCertificate), ClientTLSPrivateKeyPEM: string(clientKeyPEM), ServerTLSCertificatePEM: engineeringCertificatePEM(serverCertificate), ServerTLSPrivateKeyPEM: string(serverKeyPEM), start: start}, nil
		}
		if directions.OriginalOwner != nil {
			var original *PoolRelay
			_, err = relayHost.IssueToOriginalOwner(ctx, access, request, output, func(_ context.Context, _ protocolv4.TopUpRequestFacts, reply []byte) error {
				var e error
				original, e = buildOriginal(reply)
				if e != nil {
					return e
				}
				original.originalRelayIdentitySeed = relaySeed
				original.originalRelayTLSIdentity = &certificate
				defer func() { clear(original.originalRelayIdentitySeed[:]); original.originalRelayTLSIdentity = nil }()
				return directions.OriginalOwner(original)
			})
			if err != nil {
				reporter.Fatal(err)
			}
			if original == nil {
				reporter.Fatal("original relay owner cannot adopt a replayed response")
			}
			return original
		}
		n, err := relayHost.Issue(ctx, access, request, output)
		if err != nil {
			reporter.Fatal(err)
		}
		original, err := buildOriginal(output[:n:n])
		if err != nil {
			reporter.Fatal(err)
		}
		return original
	})
}

type engineeringControlSigner struct{ key ed25519.PrivateKey }

func (s engineeringControlSigner) PublicKey() []byte { return s.key.Public().(ed25519.PublicKey) }
func (s engineeringControlSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

func engineeringRelayNativeLeg(carrier string, address netip.AddrPort, certificate tls.Certificate, roots *x509.CertPool) runtimehost.NativeRelayLeg {
	kind := uint64(0)
	if carrier == "websocket" {
		kind = 1
	} else if carrier == "webtransport" {
		kind = 2
	}
	return runtimehost.NativeRelayLeg{Address: address, Carrier: kind, Certificate: certificate, Roots: roots, QUIC: QUICProviderFor(139), WebTransport: WebTransportProviderFor(139), WebSocket: WebSocketProvider()}
}
func engineeringRelayRoute(reporter *Reporter, carriers [2]string, addresses [2]netip.AddrPort, tlsPolicy []byte, origin string, endpointListeners [2]bool) ([]byte, string, error) {
	var legs [2][]byte
	var kinds [2]uint64
	for side, carrier := range carriers {
		kind, path, alpn, subprotocol := uint64(0), "", "flowersec-tunnel/4", ""
		if carrier == "websocket" {
			kind, path, alpn, subprotocol = 1, "/flowersec/v4/tunnel", "http/1.1", "flowersec.tunnel.v4"
		} else if carrier == "webtransport" {
			kind, path, alpn = 2, "/flowersec/webtransport/v4/tunnel", "h3"
		} else if carrier != "raw-quic" {
			return nil, "", errors.New("unknown independent relay carrier")
		}
		kinds[side] = kind
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, "", err
		}
		dialer, listener := uint64(side), uint64(2)
		if endpointListeners[side] {
			dialer, listener = 2, uint64(side)
		}
		host := addresses[side].Addr().String()
		// The explicit local fixture can install a DNS identity before issuance.
		// Both the signed route and original publication retain this exact host.
		if side == 0 && reporter.RouteHost != "" {
			if reporter.RouteHost != "localhost" || !addresses[side].Addr().IsLoopback() {
				return nil, "", errors.New("engineering relay DNS binding must be explicit loopback localhost")
			}
			host = reporter.RouteHost
		}
		fields := []protocolv4.Field{{Name: "access_class"}, {Name: "leg_id", Kind: protocolv4.ByteString, Bytes: id[:]}, {Name: "endpoint_role", Number: uint64(side)}, {Name: "dialer_role", Number: dialer}, {Name: "listener_role", Number: listener},
			{Name: "carrier", Number: kind}, {Name: "host", Kind: protocolv4.TextString, Text: host}, {Name: "port", Number: uint64(addresses[side].Port())}, {Name: "path", Kind: protocolv4.TextString, Text: path}, {Name: "alpn", Kind: protocolv4.TextString, Text: alpn}, {Name: "subprotocol", Kind: protocolv4.TextString, Text: subprotocol}, {Name: "tls_policy", Kind: protocolv4.EncodedMap, Bytes: tlsPolicy}}
		if kind > 0 {
			encoded := append([]byte{0x81, 0x78, byte(len(origin))}, []byte(origin)...)
			if len(origin) < 24 {
				encoded = append([]byte{0x81, 0x60 | byte(len(origin))}, []byte(origin)...)
			}
			policy, err := protocolv4.EncodeMap(make([]byte, 1024), "OriginPolicy", []protocolv4.Field{{Name: "origins", Kind: protocolv4.EncodedArray, Bytes: encoded}, {Name: "allow_absent", Kind: protocolv4.Boolean, Number: 1}})
			if err != nil {
				return nil, "", err
			}
			fields = append(fields, protocolv4.Field{Name: "origin_policy", Kind: protocolv4.EncodedMap, Bytes: policy})
		}
		wire, err := protocolv4.EncodeMap(make([]byte, 4096), "Leg", fields)
		if err != nil {
			return nil, "", err
		}
		legs[side] = wire
	}
	var registry struct {
		Relay struct {
			Profiles []struct {
				ID     string `json:"id"`
				Client uint64 `json:"client_carrier"`
				Server uint64 `json:"server_carrier"`
			} `json:"profiles"`
		} `json:"relay"`
	}
	if err := json.Unmarshal([]byte(protocolv4.CarrierProviderRegistryJSON), &registry); err != nil {
		return nil, "", err
	}
	profile := ""
	for _, item := range registry.Relay.Profiles {
		if item.Client == kinds[0] && item.Server == kinds[1] {
			profile = item.ID
			break
		}
	}
	if profile == "" {
		return nil, "", errors.New("original carrier pair is not an admitted relay profile")
	}
	id := reporter.AuthorityCandidateID()
	route, err := protocolv4.EncodeMap(make([]byte, 16384), "Route", []protocolv4.Field{{Name: "candidate_id", Kind: protocolv4.ByteString, Bytes: id[:]}, {Name: "path_kind", Number: 1}, {Name: "client_leg", Kind: protocolv4.EncodedMap, Bytes: legs[0]}, {Name: "server_leg", Kind: protocolv4.EncodedMap, Bytes: legs[1]}})
	return route, profile, err
}
func engineeringOriginalMaterial(reply []byte, request protocolv4.TopUpRequestFacts, namespace NamespaceRecord, recipe *sessionv4.EngineeringPoolIssueRecipe, relayProfile string) (result [2]Material, err error) {
	decoder, err := protocolv4.NewDecoder(524288, 256)
	if err != nil {
		return result, err
	}
	doc, err := decoder.DecodeShape(reply, "", protocolv4.DecodeContext{})
	if err != nil {
		return result, err
	}
	defer doc.Release()
	code, _ := doc.Root().Index(0).Text()
	response, _ := doc.Root().Index(1).ByteString()
	if code != "success" {
		return result, fmt.Errorf("original PoolService issuance did not commit a new batch: response code %q", code)
	}
	codec, err := protocolv4.NewTopUpCodec()
	if err != nil {
		return result, err
	}
	batch, err := codec.ParseResponse(response, request)
	if err != nil {
		return result, err
	}
	defer batch.Release()
	material, err := batch.Material(0)
	if err != nil {
		return result, err
	}
	bundleDecoder, err := protocolv4.NewDecoder(65536, 256)
	if err != nil {
		return result, err
	}
	bundle, err := bundleDecoder.DecodeShape(material, "", protocolv4.DecodeContext{})
	if err != nil {
		return result, err
	}
	defer bundle.Release()
	x := bundle.Root()
	if x.Len() != 5 || x.Index(4).Len() != 2 {
		return result, errors.New("actual paired material is incomplete")
	}
	artifact, _ := x.Index(0).ByteString()
	activation, _ := x.Index(1).ByteString()
	client, _ := x.Index(2).ByteString()
	server, _ := x.Index(3).ByteString()
	signedCodec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 16384)
	if err != nil {
		return result, err
	}
	signed, err := signedCodec.VerifyCredential(artifact, recipe.Base.Trust[0])
	if err != nil {
		return result, err
	}
	defer signed.Release()
	route, digest, err := signed.CopyCandidateRoute(0, make([]byte, 16384))
	if err != nil {
		return result, err
	}
	for side := range result {
		identity, dh := recipe.ClientIdentitySeed, recipe.ClientDHSeed
		if side == 1 {
			identity, dh = recipe.ServerIdentitySeed, recipe.ServerDHSeed
		}
		m := Material{WireRevision: 4, Profile: recipe.Base.CryptoProfile, Source: "preauthorized_pool", Generation: Generation{Source: append([]byte(nil), request.Source[:]...), Generation: request.Generation}, Role: uint8(side),
			Artifact: append([]byte(nil), artifact...), Activation: append([]byte(nil), activation...), ClientCertificate: append([]byte(nil), client...), ServerCertificate: append([]byte(nil), server...), Route: append([]byte(nil), route...), RouteDigest: append([]byte(nil), digest[:]...),
			ActivationSigningKeyID: recipe.ActivationSigningKeyID, IdentitySeed: append([]byte(nil), identity[:]...), DHSeed: append([]byte(nil), dh[:]...), Namespaces: []NamespaceRecord{namespace}, RelayDeployment: protocolv4.RelayDeploymentBinding{RouteDigest: digest, Profile: relayProfile}}
		for index := range 2 {
			entry := x.Index(4).Index(index)
			candidate, _ := entry.Index(0).Uint()
			role, _ := entry.Index(1).Uint()
			grant, _ := entry.Index(2).ByteString()
			relay, _ := entry.Index(3).ByteString()
			m.Tunnels = append(m.Tunnels, TunnelMaterial{CandidateIndex: candidate, Role: uint8(role), Grant: append([]byte(nil), grant...), RelayCertificate: append([]byte(nil), relay...), GrantNamespace: 0, RelayNamespace: 0})
		}
		result[side] = m
	}
	return result, nil
}

// MaterialJSON returns the exact newly committed endpoint material for one
// logical tunnel side. The bytes are serialized from the committed response;
// callers must still bootstrap the pinned namespace before connecting.
func (p *PoolRelay) MaterialJSON(side uint8) (string, error) {
	if p == nil || side > 1 {
		return "", errors.New("invalid original pool endpoint side")
	}
	return p.Material[side].JSON()
}

// EndpointMaterialsJSON returns both endpoint records in client/server order.
// Each record carries its own logical role and independent relay deployment
// binding, so a consumer cannot accidentally reuse the opposite side.
func (p *PoolRelay) EndpointMaterialsJSON() ([2]string, error) {
	var result [2]string
	if p == nil {
		return result, errors.New("nil original pool relay")
	}
	for side := range result {
		value, err := p.MaterialJSON(uint8(side))
		if err != nil {
			return result, err
		}
		result[side] = value
	}
	return result, nil
}

// Start releases only the already published original carrier preparations.
// It conveys no Grant, registration, allow or admission authority.
func (r *PoolRelay) Start() {
	if r != nil && r.start != nil {
		r.startOnce.Do(func() { close(r.start) })
	}
}

func engineeringRelayNativeScopedLeg(carrier string, address netip.AddrPort, certificate tls.Certificate, roots *x509.CertPool, scope assemblyv4.NativeDialScope) runtimehost.NativeRelayLeg {
	leg := engineeringRelayNativeLeg(carrier, address, certificate, roots)
	leg.SocketScope = scope
	return leg
}

// OriginalRelayIdentitySeed is available only while the trusted original owner
// callback is active. The source clears it before that callback returns.
func (p *PoolRelay) OriginalRelayIdentitySeed() ([32]byte, error) {
	if p == nil || p.originalRelayIdentitySeed == ([32]byte{}) {
		return [32]byte{}, errors.New("original relay identity handoff is unavailable")
	}
	return p.originalRelayIdentitySeed, nil
}

func (p *PoolRelay) OriginalRelayTLSIdentity() ([]byte, []byte, error) {
	if p == nil || p.originalRelayIdentitySeed == ([32]byte{}) || p.originalRelayTLSIdentity == nil || len(p.originalRelayTLSIdentity.Certificate) == 0 {
		return nil, nil, errors.New("original relay TLS handoff is unavailable")
	}
	key, err := x509.MarshalPKCS8PrivateKey(p.originalRelayTLSIdentity.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), p.originalRelayTLSIdentity.Certificate[0]...), key, nil
}
