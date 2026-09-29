package ledgerv4_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type operationsCompositionWriter struct{ *httptest.ResponseRecorder }

func (*operationsCompositionWriter) SetWriteDeadline(time.Time) error { return nil }

func operationsComposition(t *testing.T) (*ledgerv4.OperationsStoreHarness, *controlv4.OperationsService, func() *http.Request) {
	t.Helper()
	h := ledgerv4.NewOperationsStoreHarness(t)
	dependencies := h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 65536})
	environmentConfig := sessionv4.EnvironmentConfig{Positions: 2, RuntimeBytes: 65536}
	ecost, err := sessionv4.EnvironmentCharge(environmentConfig)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := sessionv4.NewEnvironment(environmentConfig, h.Reserve(ecost), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		environment.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := environment.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := environment.Retire(); err != nil {
			t.Error(err)
		}
	})
	executorConfig := sessionv4.ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, Ready: 4, ResidentReady: 2,
		Diagnostics: true, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}
	xcost, err := sessionv4.ApplicationExecutorCharge(executorConfig)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := sessionv4.NewApplicationExecutor(executorConfig, h.Reserve(xcost))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		executor.Close()
		select {
		case <-executor.Done():
		case <-time.After(time.Second):
			t.Error("executor not retired")
		}
	})
	registryConfig := protocolv4.NamespaceRegistryConfig{Continuity: protocolv4.OnlineBootstrap, Entries: 2, RuntimeBytes: 4096}
	rcost, err := protocolv4.NamespaceRegistryCharge(registryConfig)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := protocolv4.NewNamespaceRegistry(registryConfig, h.Reserve(rcost))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		registry.Close()
		h.Root.Close()
		if err := registry.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.UnixMilli(1), NotAfter: time.UnixMilli(100000), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cfg := controlv4.OperationsConfig{Root: h.Root, Environment: environment, Clock: h.Clock,
		Executor: executor, Verification: registry, AuditStores: []controlv4.OperationsAuditStore{{Store: h.Store, Access: h.Access}},
		Readers: []controlv4.OperationsReader{{CertificateDER: der}}, RuntimeProfile: "test", ProviderFamily: "wss", FeatureProfile: "transport",
		RequestsPerMinute: 60, CallMS: 1000, RuntimeBytes: 65536}
	cost, err := controlv4.OperationsServiceCharge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	service, err := controlv4.NewOperationsService(cfg, h.Reserve(cost), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		service.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := service.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/operations", nil)
		r.RemoteAddr = "127.0.0.1:12345"
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
		return r
	}
	return h, service, request
}

func TestOperationsCompositionUsesExistingStoreAndExecutor(t *testing.T) {
	h, service, request := operationsComposition(t)
	w := &operationsCompositionWriter{httptest.NewRecorder()}
	service.ServeHTTP(w, request())
	if w.Code != http.StatusOK {
		t.Fatal("aggregate query failed", w.Code, w.Body.String())
	}
	var snapshot struct {
		Executor     sessionv4.ExecutorOperationsSnapshot   `json:"executor"`
		Verification protocolv4.NamespaceOperationsSnapshot `json:"verification"`
		Stores       []struct {
			State string
			Audit ledgerv4.AuditStatus
		} `json:"stores"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Executor.Limits.Running != 2 || snapshot.Executor.Limits.DiagnosticReady != 4 || snapshot.Verification.Capacity != 2 || len(snapshot.Stores) != 1 || snapshot.Stores[0].State != "available" || snapshot.Stores[0].Audit.Policy.OrdinaryRecords != 128 {
		t.Fatal("registered owner aggregates missing", snapshot)
	}
	for _, forbidden := range []string{"tenant-1", "actor", "certificate", "event_id", "source_id"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatal("sensitive record escaped operations projection", forbidden)
		}
	}
	h.Revoke()
	w = &operationsCompositionWriter{httptest.NewRecorder()}
	service.ServeHTTP(w, request())
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "resources") {
		t.Fatal("revoked store read leaked deployment snapshot")
	}
}

func TestOperationsCompositionRechecksManagementAfterActualSQL(t *testing.T) {
	h, service, request := operationsComposition(t)
	var once sync.Once
	h.AfterQuery(func() {
		once.Do(func() {
			if err := service.RevokeReader(0); err != nil {
				t.Error(err)
			}
		})
	})
	w := &operationsCompositionWriter{httptest.NewRecorder()}
	service.ServeHTTP(w, request())
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "resources") {
		t.Fatal("revocation during original SQL read published snapshot", w.Code)
	}
}
