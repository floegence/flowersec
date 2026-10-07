// Package parityclient is a complete public-SDK consumer for the bounded
// flowersec.parity application over one direct, TLS-verified WebSocket route.
package parityclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

// Material contains issuer-supplied signed bytes, never a trust root or local key.
// This example accepts a client-side, preauthorized direct WSS invitation only.
type Material struct {
	Artifact, Activation, ClientCertificate, ServerCertificate []byte
	ActivationSigningKeyID                                     string
	Generation                                                 fs.MaterialGeneration
}

// Configuration separates application-installed trust, keys, time and history
// from the invitation. The caller must keep Clock, Signer and StaticDH alive
// until Close succeeds. Their provider qualifications are deployment inputs.
type Configuration struct {
	Material     Material
	Namespace    fs.NamespaceTrustRoot
	BootstrapURL string
	TLSRoots     *x509.CertPool
	Clock        *fs.Clock
	Signer       fs.IdentitySigner
	StaticDH     fs.StaticDH
	Origin       string
	// HistoryDirectory must be a new absolute directory in durable storage.
	// Creation is exclusive. No missing-file fallback or history reset exists.
	HistoryDirectory string
	HistoryIdentity  fs.SQLiteIdentity
}

// Client owns transport/application resources and one original source. Its
// persistent backing survives Close: transport cleanup never deletes spend
// history or reports that retained disk capacity has been released.
type Client struct {
	mu                                sync.Mutex
	ready, started, connected, closed bool
	lifetime                          context.Context
	cancel                            context.CancelFunc
	serial                            uint64
	owner                             fs.ResourceOwnerKey
	root                              *fs.ResourceRoot
	dependencies                      fs.ResourceReference
	scope                             fs.SessionResourceScope
	clock                             *fs.Clock
	verification                      *fs.VerificationNamespaces
	trust                             *fs.NamespaceTrustStore
	namespace                         *fs.LiveNamespace
	bootstrap                         *fs.NamespaceOnlineBootstrap
	environment                       *fs.TransportEnvironment
	executor                          *fs.ApplicationExecutor
	plan                              *fs.SessionPlan
	identity                          *fs.ApplicationIdentity
	lease                             *fs.ArtifactLease
	factory                           *fs.WebSocketCarrierFactory
	backing                           *fs.SQLiteBacking
	store                             *fs.SQLiteStore
	spend                             fs.ResourceReference
	observation                       fs.PoolSpendObservation
	source                            *oneShotSource
	options                           fs.ConnectOptions
	definition                        fs.ServiceDefinition
	session                           *fs.Session
	service                           *fs.ServiceClient
	historyDirectory                  string
	ownedHostCleanup                  func()
}

// New provisions a fresh consumer history and builds the complete public owner
// graph before Connect acquires material. A non-nil Client must be closed even
// when New returns an error; it retains any partially constructed cleanup tail.
func New(ctx context.Context, config Configuration) (*Client, error) {
	if ctx == nil || config.Clock == nil || config.Signer == nil || config.StaticDH == nil ||
		config.TLSRoots == nil || len(config.TLSRoots.Subjects()) == 0 ||
		config.Namespace.Tenant == "" || config.Namespace.Authority == "" ||
		!filepath.IsAbs(config.HistoryDirectory) || filepath.Clean(config.HistoryDirectory) != config.HistoryDirectory ||
		config.HistoryIdentity.Authority == "" || config.HistoryIdentity.StoreID == ([32]byte{}) || config.HistoryIdentity.Generation == 0 ||
		config.Material.Generation.Source == ([16]byte{}) || config.Material.Generation.Generation == 0 {
		return nil, errors.New("parity client requires explicit trust, keys, clock and fresh history configuration")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(config.BootstrapURL) == 0 || len(config.BootstrapURL) > 2048 || len(config.Origin) == 0 || len(config.Origin) > 2048 {
		return nil, errors.New("parity bootstrap endpoint and origin exceed their declared bounds")
	}
	for _, wire := range [][]byte{config.Material.Artifact, config.Material.Activation, config.Material.ClientCertificate, config.Material.ServerCertificate} {
		if len(wire) == 0 || len(wire) > 65536 {
			return nil, errors.New("signed material exceeds its declared bound")
		}
	}
	c := &Client{clock: config.Clock, historyDirectory: config.HistoryDirectory}
	c.lifetime, c.cancel = context.WithCancel(context.Background())
	if err := c.initialize(ctx, config); err != nil {
		return c, err
	}
	c.ready = true
	return c, nil
}

func (c *Client) initialize(ctx context.Context, config Configuration) error {
	resourceConfig := fs.ResourceConfig{
		ProfileRevision: sha256.Sum256([]byte("flowersec/parityclient/wss/1")),
		AccountSlots:    16, ReservationSlots: 2048, ReferenceSlots: 16384,
		Limit: fs.ResourceVector{
			fs.SDKBytes: 512 << 20, fs.ProviderBytes: 64 << 20, fs.DiskBytes: 64 << 20,
			fs.Items: 8192, fs.WorkSlots: 2048, fs.Tasks: 2048, fs.Timers: 2048,
			fs.Connections: 16, fs.TLSHandshakes: 16, fs.Sessions: 4, fs.NativeHandles: 64,
		},
	}
	var err error
	c.root, err = fs.NewResourceRoot(resourceConfig)
	if err != nil {
		return err
	}
	c.owner = fs.ResourceOwnerKey{ProfileRevision: resourceConfig.ProfileRevision, Kind: 1}
	if _, err = rand.Read(c.owner.Environment[:]); err != nil {
		return err
	}
	// Includes the bounded application descriptors, imported bytes, TLS roots,
	// identity providers and synchronous bootstrap adapter's local state.
	c.dependencies, err = c.reserve(fs.ResourceVector{fs.SDKBytes: 4 << 20, fs.ProviderBytes: 1 << 20, fs.Items: 32}, nil)
	if err != nil {
		return err
	}
	tenant := sha256.Sum256([]byte(config.Namespace.Tenant))
	c.scope.Tenant, err = c.root.Account(fs.ResourceAccountKey{Kind: fs.TenantAccount, ID: [16]byte(tenant[:16])}, resourceConfig.Limit)
	if err != nil {
		return err
	}
	c.scope.Session, err = c.root.Account(fs.ResourceAccountKey{Kind: fs.SessionAccount, ID: c.owner.Environment}, resourceConfig.Limit)
	if err != nil {
		return err
	}
	if err = c.installNamespace(ctx, config); err != nil {
		return err
	}
	if err = c.installMaterial(config); err != nil {
		return err
	}
	if err = c.installHistory(ctx, config.HistoryIdentity); err != nil {
		return err
	}
	return c.installApplication(config)
}

func (c *Client) nextOwner() fs.ResourceOwnerKey {
	c.serial++
	owner := c.owner
	binary.BigEndian.PutUint64(owner.Instance[8:], c.serial)
	binary.BigEndian.PutUint64(owner.Backing[8:], c.serial)
	return owner
}

func (c *Client) reserve(cost fs.ResourceVector, err error) (fs.ResourceReference, error) {
	if err != nil {
		return fs.ResourceReference{}, err
	}
	return c.root.Reserve(c.nextOwner(), cost)
}

func (c *Client) installMaterial(config Configuration) error {
	leaseConfig := fs.ArtifactLeaseBytesConfig{
		Artifact: config.Material.Artifact, Proof: config.Material.Activation,
		ClientCertificate: config.Material.ClientCertificate, ServerCertificate: config.Material.ServerCertificate,
		Source: "preauthorized_pool", ActivationSigningKeyID: config.Material.ActivationSigningKeyID,
		Trust:    [3]*fs.NamespaceTrustStore{c.trust, c.trust, c.trust},
		MapBytes: 65536, MapNodes: 4096, RuntimeBytes: 65536,
	}
	ref, err := c.reserve(fs.ArtifactLeaseCharge(leaseConfig.MapBytes, leaseConfig.MapNodes, leaseConfig.RuntimeBytes))
	if err != nil {
		return err
	}
	c.lease, err = fs.NewArtifactLeaseFromBytes(leaseConfig, ref, c.dependencies)
	ref.Release()
	if err != nil {
		return err
	}
	identityConfig := fs.ApplicationIdentityBytesConfig{
		Certificate: config.Material.ClientCertificate, Trust: c.trust, Role: fs.ClientToServer,
		Signer: config.Signer, StaticDH: config.StaticDH, MapNodes: 4096, RuntimeBytes: 65536,
	}
	ref, err = c.reserve(fs.ApplicationIdentityCharge(identityConfig.MapNodes, identityConfig.RuntimeBytes))
	if err != nil {
		return err
	}
	c.identity, err = fs.NewApplicationIdentityFromBytes(identityConfig, ref, c.dependencies)
	ref.Release()
	return err
}

// freshHistory grants only the initial provisioning epoch of this exact new
// directory. Reopening requires the application's independent continuity owner;
// a database row or an observation receipt cannot establish rollback safety.
type freshHistory struct{ identity fs.SQLiteIdentity }

func (h freshHistory) Check(identity fs.SQLiteIdentity, epoch uint64, create bool) error {
	if identity != h.identity || create && epoch != 0 || !create && epoch != 1 {
		return errors.New("consumer history continuity is not authorized")
	}
	return nil
}

type poolAuthority struct {
	identity fs.SQLiteIdentity
	original fs.PoolSpendFields
}

func (a poolAuthority) CheckPoolSpend(identity fs.SQLiteIdentity, facts fs.PoolSpendFacts) error {
	fields, err := facts.Fields()
	if err != nil {
		return err
	}
	if identity != a.identity || fields != a.original {
		return errors.New("consumer authority does not cover this invitation")
	}
	return nil
}

func (c *Client) installHistory(ctx context.Context, identity fs.SQLiteIdentity) error {
	// Exclusive provisioning refuses a second attempt even after an uncertain
	// bootstrap or connection outcome. Never delete and recreate this directory.
	if err := os.Mkdir(c.historyDirectory, 0o700); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(c.historyDirectory)); err != nil {
		return err
	}
	limits := fs.SQLiteLimits{MaxPages: 128, MaxRecords: 16, MaxRecordBytes: 4096,
		RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	ref, err := c.reserve(fs.SQLiteBackingCharge(limits))
	if err != nil {
		return err
	}
	c.backing, err = fs.NewSQLiteBacking(filepath.Join(c.historyDirectory, "spend.sqlite"), limits, ref, c.dependencies)
	ref.Release()
	if err != nil {
		return err
	}
	ref, err = c.reserve(fs.SQLiteStoreCharge(limits))
	if err != nil {
		return err
	}
	c.store, err = fs.CreateSQLite(ctx, c.backing, identity, freshHistory{identity}, ref, c.dependencies)
	ref.Release()
	if err != nil {
		return err
	}
	if err = syncDirectory(c.historyDirectory); err != nil {
		return err
	}
	facts, err := c.lease.PoolSpendFacts(0)
	if err != nil {
		return err
	}
	fields, err := facts.Fields()
	if err != nil {
		return err
	}
	c.spend, err = c.reserve(fs.SQLitePoolSpendCharge(limits.MaxRecordBytes))
	if err != nil {
		return err
	}
	c.options.Pool = &fs.PoolSessionInput{Store: c.store, Authority: poolAuthority{identity, fields},
		Consume: c.spend, Observation: &c.observation}
	c.source = &oneShotSource{lease: c.lease, trust: c.trust, expected: fields}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

type oneShotSource struct {
	mu       sync.Mutex
	lease    *fs.ArtifactLease
	trust    *fs.NamespaceTrustStore
	expected fs.PoolSpendFields
	acquired bool
}

func (s *oneShotSource) PreparationNamespaces(clock *fs.Clock, environment fs.ResourceReference) ([3]*fs.LiveNamespace, error) {
	namespace, err := s.trust.NamespaceForPreparation(clock, environment)
	return [3]*fs.LiveNamespace{namespace, namespace, namespace}, err
}

func (s *oneShotSource) AcquireLease(ctx context.Context, request fs.MaterialLeaseRequest) (*fs.ArtifactLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acquired {
		return nil, errors.New("original invitation source has already been acquired")
	}
	if request.IdentityDigest != s.expected.ClientIdentity || request.Tenant != s.expected.Tenant ||
		request.Audience != s.expected.Audience || request.Profile != s.expected.Profile || request.Role != fs.ClientToServer ||
		request.Requirements.ApplicationProfile != "services" {
		return nil, errors.New("original source does not match the application identity or requirements")
	}
	s.acquired = true
	return s.lease, nil
}

// Connect performs exactly one attempt. It does not retry, reacquire or infer
// whether remote work ran from cancellation. The returned SDK error is preserved.
func (c *Client) Connect(ctx context.Context) (*fs.Session, error) {
	c.mu.Lock()
	if !c.ready || c.closed || c.started || c.environment == nil || c.source == nil {
		c.mu.Unlock()
		return nil, errors.New("parity client is closed, incomplete or already started")
	}
	c.started = true
	c.mu.Unlock()
	session, err := fs.Connect(ctx, c.source, fs.ConnectorOptions{Environment: c.environment, ConnectOptions: c.options})
	if err != nil {
		return nil, err
	}
	c.session = session
	if c.SourceAcquisitions() != 1 || !c.SpendStatus().CommitKnown {
		return nil, errors.New("original consumer did not report definite durable consumption")
	}
	c.connected = true
	return session, nil
}

// SourceAcquisitions counts only the original one-use provider's transfer.
// Acquisition is not evidence of durable consumption or remote execution.
func (c *Client) SourceAcquisitions() uint32 {
	if c == nil || c.source == nil {
		return 0
	}
	c.source.mu.Lock()
	defer c.source.mu.Unlock()
	if c.source.acquired {
		return 1
	}
	return 0
}

// SpendStatus is the public observation written by the original SQLite
// consumer. Reading it creates no admission, replay or confirmation authority.
func (c *Client) SpendStatus() fs.PoolSpendStatus {
	if c == nil {
		return fs.PoolSpendStatus{}
	}
	return c.observation.Snapshot()
}

// Close joins physical transport cleanup, then retires its application owners.
// Call after Connect/Exchange return. A timeout retains ownership for another
// Close call. The durable history directory and backing remain caller-owned.
func (c *Client) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("cleanup context is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.connected = false
	if c.service != nil {
		c.service.Close()
		if err := c.service.WaitCleanup(ctx); err != nil {
			return err
		}
		c.service = nil
	}
	if c.session != nil {
		closeErr := c.session.Close()
		if err := c.session.WaitCleanup(ctx); err != nil {
			return errors.Join(closeErr, err)
		}
		c.session = nil
		if closeErr != nil {
			return closeErr
		}
	}
	if c.environment != nil {
		c.environment.Close()
		if err := c.environment.WaitCleanup(ctx); err != nil {
			return err
		}
		c.environment = nil
	}
	if c.plan != nil {
		c.plan.Close()
		if err := c.plan.Retire(); err != nil {
			return err
		}
		c.plan = nil
	}
	if c.lease != nil {
		c.lease.Close()
		if err := c.lease.WaitCleanup(ctx); err != nil {
			return err
		}
		c.lease = nil
	}
	if c.identity != nil {
		c.identity.Close()
		if err := c.identity.WaitCleanup(ctx); err != nil {
			return err
		}
		c.identity = nil
	}
	if c.factory != nil {
		c.factory.Close()
		if err := c.factory.WaitCleanup(ctx); err != nil {
			return err
		}
		c.factory = nil
	}
	if c.executor != nil {
		c.executor.Close()
		select {
		case <-c.executor.Done():
			c.executor = nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.spend.Release()
	if c.store != nil {
		c.store.Close()
		if err := c.store.WaitCleanup(ctx); err != nil {
			return err
		}
		if err := c.store.Retire(); err != nil {
			return err
		}
		c.store = nil
	}
	if c.backing != nil {
		c.backing.Close()
	}
	if c.bootstrap != nil {
		c.bootstrap.Close()
		if err := c.bootstrap.WaitCleanup(ctx); err != nil {
			return err
		}
		if err := c.bootstrap.Retire(); err != nil {
			return err
		}
		c.bootstrap = nil
	}
	if c.verification != nil {
		c.verification.Close()
	}
	if c.trust != nil {
		c.trust.Close()
	}
	if c.namespace != nil {
		if err := c.namespace.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.root != nil {
		c.root.Close()
	}
	if c.trust != nil {
		if err := c.trust.DestroyEnvironment(); err != nil {
			return err
		}
		c.trust = nil
	}
	if c.verification != nil {
		if err := c.verification.DestroyEnvironment(); err != nil {
			return err
		}
		c.verification = nil
	}
	c.dependencies.Release()
	if c.ownedHostCleanup != nil {
		c.ownedHostCleanup()
		c.ownedHostCleanup = nil
	}
	return nil
}
