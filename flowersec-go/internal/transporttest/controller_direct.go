package transporttest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v4"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/protocolv3"
	flowersession "github.com/floegence/flowersec/flowersec-go/v4/internal/sessionv3"
)

// ControllerArtifactPlan is an explicit release-harness artifact state. The
// stale pin and unavailable URL plans model deployment refreshes; they never
// change the connector's security mode or silently fall back to CA.
type ControllerArtifactPlan string

const (
	ControllerPlanCurrentPin  ControllerArtifactPlan = "current-pin"
	ControllerPlanExpiringPin ControllerArtifactPlan = "expiring-pin"
	ControllerPlanStalePin    ControllerArtifactPlan = "stale-pin"
	ControllerPlanUnavailable ControllerArtifactPlan = "unavailable"
)

type controllerArtifactRecord struct {
	expected *admissionExpectation
	digest   [sha256.Size]byte
	spent    atomic.Int32
	retired  atomic.Int32
}

// ProductControllerArtifactSource issues one fresh production artifact per
// acquisition and exposes only the server-side session rendezvous needed by
// the release workload. Candidate, pin, and FSB3 details remain internal.
type ProductControllerArtifactSource struct {
	endpoint *ProductDirectEndpoint
	plans    []ControllerArtifactPlan

	mu           sync.Mutex
	records      []*controllerArtifactRecord
	acquiredAt   []time.Time
	acquisitions int
}

func NewProductControllerArtifactSource(endpoint *ProductDirectEndpoint, plans []ControllerArtifactPlan) (*ProductControllerArtifactSource, error) {
	if endpoint == nil || len(plans) == 0 {
		return nil, errors.New("controller artifact source requires endpoint and plans")
	}
	return &ProductControllerArtifactSource{endpoint: endpoint, plans: append([]ControllerArtifactPlan(nil), plans...)}, nil
}

func (source *ProductControllerArtifactSource) Acquire(ctx context.Context) (flowersec.ArtifactLease, *flowersec.ArtifactSourceError) {
	if source == nil || source.endpoint == nil {
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(errors.New("controller artifact source is not initialized"))
	}
	if err := ctx.Err(); err != nil {
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(err)
	}
	source.mu.Lock()
	index := source.acquisitions
	source.acquisitions++
	plan := ControllerPlanCurrentPin
	if index < len(source.plans) {
		plan = source.plans[index]
	}
	source.acquiredAt = append(source.acquiredAt, time.Now())
	source.mu.Unlock()

	contract, err := releaseSessionContractV3WithStreams(protocolv3.SuiteChaCha20Poly1305, defaultMaxInboundStreams)
	if err != nil {
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(err)
	}
	artifact := directArtifactV3(source.endpoint.kind, source.endpoint.candidateURL, contract)
	if len(artifact.Path.Candidates) != 1 {
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(errors.New("controller artifact candidate count changed"))
	}
	candidate := &artifact.Path.Candidates[0]
	leafPin := base64.RawURLEncoding.EncodeToString(source.endpoint.certificateHash[:])
	certificate, err := x509.ParseCertificate(source.endpoint.certificateDER)
	if err != nil || !time.Now().Before(certificate.NotAfter) {
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(errors.New("controller endpoint certificate is unavailable or expired"))
	}
	currentPinPolicy := artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
		Algorithm: "sha-256", ValueBase64URL: leafPin, NotAfterUnixS: certificate.NotAfter.Unix(),
	}}}
	switch plan {
	case ControllerPlanCurrentPin:
		candidate.TLS = currentPinPolicy
	case ControllerPlanStalePin:
		stale := sha256.Sum256([]byte("flowersec-controller-stale-pin"))
		candidate.TLS = artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
			Algorithm: "sha-256", ValueBase64URL: base64.RawURLEncoding.EncodeToString(stale[:]), NotAfterUnixS: certificate.NotAfter.Unix(),
		}}}
	case ControllerPlanExpiringPin:
		policyExpiry := time.Now().Unix() + 4
		if policyExpiry > certificate.NotAfter.Unix() {
			policyExpiry = certificate.NotAfter.Unix()
		}
		candidate.TLS = artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
			Algorithm: "sha-256", ValueBase64URL: leafPin, NotAfterUnixS: policyExpiry,
		}}}
	case ControllerPlanUnavailable:
		candidate.TLS = currentPinPolicy
		candidate.URL = unavailableCandidateURL(candidate.URL)
	default:
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(errors.New("unknown controller artifact plan"))
	}
	expectedFSB3, err := expectedDirectAdmission(artifact)
	if err != nil {
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(err)
	}
	digest := sha256.Sum256(expectedFSB3)
	expected := &admissionExpectation{raw: expectedFSB3, contract: contract, result: make(chan productServerResult, 1)}
	registeredDigest, err := source.endpoint.register(expected)
	if err != nil {
		return flowersec.ArtifactLease{}, flowersec.NewRetryableArtifactSourceError(err)
	}
	digest = registeredDigest
	record := &controllerArtifactRecord{expected: expected, digest: digest}
	source.mu.Lock()
	if index >= len(source.records) {
		source.records = append(source.records, record)
	} else {
		source.records[index] = record
	}
	source.mu.Unlock()
	leaseReady := false
	defer func() {
		if !leaseReady {
			source.endpoint.abandon(digest, expected)
		}
	}()
	rawArtifact, err := artifactv3.MarshalArtifactJSON(artifact)
	if err != nil {
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(err)
	}
	opaque, err := flowersec.ParseArtifact(rawArtifact)
	if err != nil {
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(err)
	}
	lease, err := flowersec.NewArtifactLeaseWithRetirement(
		opaque,
		func(context.Context) error {
			if record.spent.Add(1) != 1 {
				return errors.New("controller artifact spend callback invoked more than once")
			}
			return nil
		},
		func(context.Context) error {
			if record.retired.Add(1) != 1 {
				return errors.New("controller artifact retire callback invoked more than once")
			}
			source.endpoint.abandon(digest, expected)
			return nil
		},
	)
	if err != nil {
		return flowersec.ArtifactLease{}, flowersec.NewTerminalArtifactSourceError(err)
	}
	leaseReady = true
	return lease, nil
}

func (source *ProductControllerArtifactSource) WaitServer(ctx context.Context, acquisition int) (flowersession.Session, error) {
	if source == nil {
		return nil, errors.New("controller artifact source is nil")
	}
	source.mu.Lock()
	if acquisition < 0 || acquisition >= len(source.records) {
		source.mu.Unlock()
		return nil, errors.New("controller server acquisition is unavailable")
	}
	record := source.records[acquisition]
	source.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case result := <-record.expected.result:
		if result.err != nil {
			return nil, result.err
		}
		source.endpoint.unregister(record.digest, record.expected)
		return result.session, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (source *ProductControllerArtifactSource) AcquisitionCount() int {
	if source == nil {
		return 0
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.acquisitions
}

func (source *ProductControllerArtifactSource) AcquisitionTimes() []time.Time {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return append([]time.Time(nil), source.acquiredAt...)
}

func (source *ProductControllerArtifactSource) SpendCount(acquisition int) int32 {
	source.mu.Lock()
	defer source.mu.Unlock()
	if acquisition < 0 || acquisition >= len(source.records) {
		return 0
	}
	return source.records[acquisition].spent.Load()
}

func (source *ProductControllerArtifactSource) RetireCount(acquisition int) int32 {
	source.mu.Lock()
	defer source.mu.Unlock()
	if acquisition < 0 || acquisition >= len(source.records) {
		return 0
	}
	return source.records[acquisition].retired.Load()
}

func unavailableCandidateURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := parsed.Hostname()
	if host == "" {
		return raw
	}
	parsed.Host = host + ":1"
	if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]:1"
	}
	return parsed.String()
}

// NewProductControllerPair binds the opaque public client Session to the
// server Session delivered by a ProductControllerArtifactSource.
func NewProductControllerPair(client flowersec.Session, server flowersession.Session) *ProductDirectPair {
	return &ProductDirectPair{Client: client, Server: server}
}

// ProductControllerConnectorOptions returns the endpoint's deployment trust
// roots and origin for a production ConnectionController.
func (endpoint *ProductDirectEndpoint) ProductControllerConnectorOptions() flowersec.ConnectorOptions {
	return flowersec.ConnectorOptions{TrustRoots: endpoint.trustRoots, Origin: releaseRunnerOrigin, ConnectTimeout: 10 * time.Second}
}

var _ flowersec.ArtifactSource = (*ProductControllerArtifactSource)(nil)
