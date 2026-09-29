package controlv4

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

const OperationsResponseBytes = 65536

// OperationsReader registers an independently authenticated management client.
// The exact client certificate must also pass the listener's client CA check.
// This registration grants this deployment's aggregate operations read and
// only its explicitly enabled diagnostic rights. It grants no authorization
// administration, audit read, or Session capability.
type OperationsReader struct {
	CertificateDER                     []byte
	ReadDiagnostics, DeleteDiagnostics bool
	CorrelateDiagnostics               bool
}

type OperationsConfig struct {
	Diagnostics *diagnosticv4.MemoryExporter
	// Incidents enables a separate, bounded management-only correlation table.
	// Its exporter must represent one independently authorized diagnostic scope.
	DiagnosticIncidents bool
	Maintenance         *AuditMaintenance
	Root                *resourcev4.Root
	Environment         *sessionv4.Environment
	Clock               *timev4.Clock
	Executor            *sessionv4.ApplicationExecutor
	Verification        *protocolv4.NamespaceRegistry
	AuditStores         []OperationsAuditStore
	Readers             []OperationsReader
	// Empty selects loopback only. Prefixes must be canonical and number <= 8.
	ManagementNetworks []netip.Prefix
	// These are finite immutable deployment registration values, not a claim
	// that a named provider/runtime profile has passed qualification.
	RuntimeProfile, ProviderFamily, FeatureProfile string
	RequestsPerMinute                              uint16
	CallMS, RuntimeBytes                           uint64
}

type operationsReader struct {
	digest                             [32]byte
	notBefore, notAfter                uint64
	revoked                            bool
	readDiagnostics, deleteDiagnostics bool
	correlateDiagnostics               bool
}

// OperationsService owns one bounded snapshot/publication position. The HTTP
// server, TLS listener and client authentication roots have separately admitted
// dependencies. Mount only on that management listener, never a Session route.
// It does not start a server, discover interfaces, or enable itself by default.
type OperationsService struct {
	incidents                              []operationsIncident
	incidentWake, incidentStop             chan struct{}
	incidentRunning                        bool
	diagnostics                            resourcev4.Reference
	maintenance                            resourcev4.Reference
	mu                                     sync.Mutex
	config                                 OperationsConfig
	readers                                [16]operationsReader
	networks                               [8]netip.Prefix
	readerCount, networkCount              int
	reservation, dependencies, environment resourcev4.Reference
	executor, verification                 resourcev4.Reference
	stores                                 [8]operationsStoreOwner
	storeCount                             int
	origin                                 timev4.Mark
	hasOrigin                              bool
	requests                               uint16
	cancel                                 context.CancelFunc
	done                                   chan struct{}
	busy, closed, cleaned                  bool
	denied, capacity                       atomic.Uint64
}

func operationsName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.') {
			return false
		}
	}
	return true
}

func OperationsServiceCharge(c OperationsConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Environment == nil || c.Clock == nil || len(c.Readers) == 0 || len(c.Readers) > 16 || len(c.ManagementNetworks) > 8 || len(c.AuditStores) > 8 || c.RequestsPerMinute == 0 || c.RequestsPerMinute > 60 || c.CallMS == 0 || c.CallMS > 10000 || c.RuntimeBytes == 0 || !operationsName(c.RuntimeProfile) || !operationsName(c.ProviderFamily) || !operationsName(c.FeatureProfile) {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	// Includes bounded X.509 registration parsing, the complete snapshot, JSON
	// encoder/output backing and the original request timer. Runtime overhead
	// and the management listener's native resources require their own profile.
	base := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(OperationsService{})) + controlCallContextBytes + 6*OperationsResponseBytes,
		resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1}
	if c.DiagnosticIncidents {
		if c.Diagnostics == nil {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		var err error
		base, err = base.Add(operationsIncidentCharge())
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	return base.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewOperationsService(c OperationsConfig, reservation, dependencies resourcev4.Reference) (*OperationsService, error) {
	cost, err := OperationsServiceCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckRoot(c.Root); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		shared.Release()
		return nil, err
	}
	p := &OperationsService{config: c, reservation: owned, dependencies: shared, done: make(chan struct{})}
	adopted := false
	defer func() {
		if !adopted {
			p.Close()
		}
	}()
	for _, reader := range c.Readers {
		if len(reader.CertificateDER) == 0 || len(reader.CertificateDER) > 16384 {
			return nil, resourcev4.ErrConfiguration
		}
		certificate, err := x509.ParseCertificate(reader.CertificateDER)
		if err != nil || certificate.NotBefore.UnixMilli() < 0 || certificate.NotAfter.UnixMilli() <= certificate.NotBefore.UnixMilli() {
			return nil, resourcev4.ErrConfiguration
		}
		digest := sha256.Sum256(reader.CertificateDER)
		for _, existing := range p.readers[:p.readerCount] {
			if existing.digest == digest {
				return nil, resourcev4.ErrConfiguration
			}
		}
		if reader.CorrelateDiagnostics && (!c.DiagnosticIncidents || !reader.ReadDiagnostics) {
			return nil, resourcev4.ErrConfiguration
		}
		p.readers[p.readerCount] = operationsReader{digest: digest, notBefore: uint64(certificate.NotBefore.UnixMilli()), notAfter: uint64(certificate.NotAfter.UnixMilli()), readDiagnostics: reader.ReadDiagnostics, deleteDiagnostics: reader.DeleteDiagnostics, correlateDiagnostics: reader.CorrelateDiagnostics}
		p.readerCount++
	}
	if len(c.ManagementNetworks) == 0 {
		p.networks[0], p.networks[1] = netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")
		p.networkCount = 2
	} else {
		for _, network := range c.ManagementNetworks {
			if !network.IsValid() || network.Addr().Zone() != "" || network != network.Masked() {
				return nil, resourcev4.ErrConfiguration
			}
			p.networks[p.networkCount] = network
			p.networkCount++
		}
	}
	p.config.Readers, p.config.ManagementNetworks = nil, nil
	p.config.RuntimeProfile = strings.Clone(c.RuntimeProfile)
	p.config.ProviderFamily = strings.Clone(c.ProviderFamily)
	p.config.FeatureProfile = strings.Clone(c.FeatureProfile)
	p.environment, err = c.Environment.BorrowOperations(owned)
	if err != nil {
		return nil, err
	}
	if c.Executor != nil {
		p.executor, err = c.Executor.BorrowOperations(owned)
		if err != nil {
			return nil, err
		}
	}
	if c.Verification != nil {
		p.verification, err = c.Verification.Borrow(owned)
		if err != nil {
			return nil, err
		}
	}
	for i, store := range c.AuditStores {
		if store.Store == nil || store.Access == nil {
			return nil, resourcev4.ErrConfiguration
		}
		for _, previous := range p.stores[:i] {
			if previous.Store == store.Store {
				return nil, resourcev4.ErrConfiguration
			}
		}
		pin, err := store.Store.BorrowOperations(owned)
		if err != nil {
			return nil, err
		}
		p.stores[i] = operationsStoreOwner{OperationsAuditStore: store, pin: pin}
		p.storeCount++
	}
	if c.Diagnostics != nil {
		p.diagnostics, err = c.Diagnostics.BorrowOperations(owned)
		if err != nil {
			return nil, err
		}
	}
	if c.Maintenance != nil {
		p.maintenance, err = c.Maintenance.BorrowOperations(owned)
		if err != nil {
			return nil, err
		}
	}
	p.config.AuditStores = nil
	if c.DiagnosticIncidents {
		p.incidents = make([]operationsIncident, operationsIncidentSlots)
		p.incidentWake, p.incidentStop = make(chan struct{}, 1), make(chan struct{})
		p.incidentRunning = true
		go p.runIncidents()
	}
	adopted = true
	return p, nil
}

type operationsSnapshot struct {
	Diagnostics        *diagnosticv4.MemoryExporterSnapshot       `json:"diagnostics,omitempty"`
	Maintenance        *AuditMaintenanceSnapshot                  `json:"maintenance,omitempty"`
	Executor           *sessionv4.ExecutorOperationsSnapshot      `json:"executor,omitempty"`
	Verification       *protocolv4.NamespaceOperationsSnapshot    `json:"verification,omitempty"`
	Stores             []operationsStoreSnapshot                  `json:"stores,omitempty"`
	Revision           string                                     `json:"revision"`
	ObservedUTCMS      uint64                                     `json:"observed_utc_ms"`
	RuntimeProfile     string                                     `json:"runtime_profile"`
	ProviderFamily     string                                     `json:"provider_family"`
	FeatureProfile     string                                     `json:"feature_profile"`
	Resources          resourcev4.OperationsSnapshot              `json:"resources"`
	Environment        sessionv4.EnvironmentSnapshot              `json:"environment"`
	Metrics            [diagnosticv4.MetricCount]operationsMetric `json:"metrics"`
	MetricDimensions   diagnosticv4.Dimensions                    `json:"metric_dimensions"`
	ResourceDimensions [resourcev4.Dimensions]string              `json:"resource_dimensions"`
	Denied             uint64                                     `json:"denied"`
	CapacityRejected   uint64                                     `json:"capacity_rejected"`
}

type operationsMetric struct {
	Metric string              `json:"metric"`
	Counts diagnosticv4.Counts `json:"counts"`
}

func operationsIncrement(v *atomic.Uint64) {
	for {
		old := v.Load()
		if old == ^uint64(0) || v.CompareAndSwap(old, old+1) {
			return
		}
	}
}

func (p *OperationsService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p == nil || r == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, status := p.begin()
	if status != http.StatusOK {
		http.Error(w, "management read unavailable", status)
		return
	}
	defer p.finish()
	var controller *http.ResponseController
	read := operationsReadsBody(r)
	started := false
	defer func() {
		// Keep the position through flush, the real observer and both reset
		// callbacks, including panic/Goexit in any original host operation.
		defer func() {
			ctx.finish()
			if controller != nil {
				defer controller.SetWriteDeadline(time.Time{})
				if read {
					_ = controller.SetReadDeadline(time.Time{})
				}
			}
		}()
		if started {
			_ = controller.Flush()
		}
	}()
	reader, status := p.authenticate(r)
	if status != http.StatusOK {
		http.Error(w, "management read unavailable", status)
		return
	}
	controller = http.NewResponseController(w)
	if err := ctx.startHTTPDirections(r.Context(), w, read); err != nil {
		http.Error(w, "management deadline unavailable", http.StatusServiceUnavailable)
		return
	}
	started = true
	if ctx.Err() != nil || !p.current(reader) {
		http.Error(w, "management read unavailable", http.StatusForbidden)
		return
	}
	if r.URL != nil && (r.URL.Path == "/operations/diagnostics" || r.URL.Path == "/operations/diagnostics/all") {
		p.serveDiagnostics(ctx, reader, w, r)
		return
	}
	if r.URL != nil && (r.URL.Path == "/operations/diagnostics/incidents" || r.URL.Path == "/operations/diagnostics/incidents/links" || r.URL.Path == "/operations/diagnostics/incidents/lookup") {
		p.serveIncident(ctx, reader, w, r)
		return
	}
	if r.URL == nil || r.Method != http.MethodGet || r.URL.Path != "/operations" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Body != nil && r.Body != http.NoBody {
		http.Error(w, "invalid management request", http.StatusBadRequest)
		return
	}
	// Authentication, rate and work-slot checks precede all inspected owners.
	c := p.config
	now, err := c.Clock.Sample()
	if err != nil || ctx.Err() != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	snapshot := operationsSnapshot{Revision: "flowersec-operations-1", ObservedUTCMS: now.UpperMS,
		RuntimeProfile: c.RuntimeProfile, ProviderFamily: c.ProviderFamily, FeatureProfile: c.FeatureProfile,
		Resources: c.Root.OperationsSnapshot(), Environment: c.Environment.OperationsSnapshot(),
		MetricDimensions: diagnosticv4.CounterDimensions(), ResourceDimensions: resourcev4.DimensionNames(),
		Denied: p.denied.Load(), CapacityRejected: p.capacity.Load()}
	for i := range snapshot.Metrics {
		metric := diagnosticv4.Metric(i)
		snapshot.Metrics[i] = operationsMetric{Metric: metric.String(), Counts: c.Environment.DiagnosticCounts(metric)}
	}
	if c.Diagnostics != nil {
		v := c.Diagnostics.Snapshot()
		snapshot.Diagnostics = &v
	}
	if c.Executor != nil {
		v := c.Executor.OperationsSnapshot()
		snapshot.Executor = &v
	}
	if c.Verification != nil {
		v := c.Verification.OperationsSnapshot()
		snapshot.Verification = &v
	}
	if c.Maintenance != nil {
		v := c.Maintenance.Snapshot()
		snapshot.Maintenance = &v
	}
	var principals [8]ledgerv4.AuditPrincipal
	var stores [8]operationsStoreSnapshot
	snapshot.Stores = stores[:p.storeCount]
	if status := p.inspectStores(ctx, reader, &snapshot, &principals); status != http.StatusOK {
		http.Error(w, "management read unavailable", status)
		return
	}
	body, err := json.Marshal(snapshot)
	if err != nil || len(body) > OperationsResponseBytes {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	defer clear(body)
	if ctx.Err() != nil || !p.current(reader) || !p.storePermissionsCurrent(principals) || ctx.Err() != nil || !p.current(reader) {
		http.Error(w, "management read unavailable", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) // Original position remains occupied through actual return.
}

// RevokeReader permanently revokes one original registration. Only trusted
// local management composition calls this; HTTP exposes no permission mutation.
// Rotation requires a separately admitted service with explicit registrations.
func (p *OperationsService) RevokeReader(index int) error {
	if p == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || index < 0 || index >= p.readerCount {
		return resourcev4.ErrOwner
	}
	p.readers[index].revoked = true
	p.clearReaderIncidentsLocked(index)
	return nil
}

func (p *OperationsService) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancel()
	p.cancel = nil
	p.busy = false
	p.cleanupLocked()
}

func (p *OperationsService) cleanupLocked() {
	if !p.closed || p.busy || p.incidentRunning || p.cleaned {
		return
	}
	p.cleaned = true
	clear(p.incidents)
	p.incidents = nil
	p.incidentWake, p.incidentStop = nil, nil
	p.config = OperationsConfig{}
	clear(p.readers[:])
	clear(p.networks[:])
	p.environment.Release()
	p.diagnostics.Release()
	p.diagnostics = resourcev4.Reference{}
	p.maintenance.Release()
	p.maintenance = resourcev4.Reference{}
	p.executor.Release()
	p.verification.Release()
	for i := range p.stores {
		p.stores[i].pin.Release()
		p.stores[i] = operationsStoreOwner{}
	}
	p.executor, p.verification = resourcev4.Reference{}, resourcev4.Reference{}
	p.dependencies.Release()
	p.reservation.Release()
	p.environment, p.dependencies, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	close(p.done)
}

func (p *OperationsService) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		clear(p.incidents)
		if p.incidentStop != nil {
			close(p.incidentStop)
		}
	}
	if p.cancel != nil {
		p.cancel()
	}
	p.cleanupLocked()
}

func (p *OperationsService) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*OperationsService) String() string               { return "Flowersec.OperationsService" }
func (*OperationsService) GoString() string             { return "Flowersec.OperationsService" }
func (*OperationsService) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
