package transporttest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// The listener's base plan and every accepted plan belong to the same original
// root. Each retains two query positions in its finite 128-owner SDK lane.
const productDirectCapacityGroupPositions = 63

// Capacity provisions every finite deployment before the measured ramp. The
// signed engineering envelope permits this window; ordinary deployments retain
// their default and every actual Connect still checks the original expiry.
const productCapacityActivationWindowMS = 180000

type productDirectTLS struct {
	certificate tls.Certificate
	roots       *x509.CertPool
	trustPEM    string
	policy      []byte
}

type productDirectCapacityGroup struct {
	endpoint  *ProductDirectEndpoint
	positions int
	assigned  int
}

// ProductDirectCapacityEndpoint aggregates independent original deployments.
// Routes, signed material, namespace, executor and accepted resources always
// remain with the listener that created them. Sharing only the original TLS
// installation preserves the browser runner's one exact leaf pin.
type ProductDirectCapacityEndpoint struct {
	ctx       context.Context
	cancel    context.CancelCauseFunc
	mu        sync.Mutex
	groups    []productDirectCapacityGroup
	positions int
	nextGroup int
	prepared  bool
	issued    bool
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

func OpenProductDirectCapacityEndpoint(ctx context.Context, kind carrier.Kind, positions int) (*ProductDirectCapacityEndpoint, error) {
	return openProductDirectCapacityEndpoint(ctx, kind, "127.0.0.1", releaseRunnerOrigin, positions, defaultMaxInboundStreams, positions, 0)
}

func openProductDirectCapacityEndpoint(ctx context.Context, kind carrier.Kind, host, origin string, positions int, streams uint16, concurrent int, operationMS uint64) (_ *ProductDirectCapacityEndpoint, resultErr error) {
	if ctx == nil || positions < 1 || positions > 1000 || streams == 0 || streams > 128 || concurrent < 1 || concurrent > 1000 {
		return nil, errors.New("finite original direct deployment capacity is required")
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	certificate, roots, trustPEM, policy, err := interopharness.TLSMaterial(host)
	if err != nil {
		return nil, err
	}
	originalTLS := &productDirectTLS{certificate: certificate, roots: roots, trustPEM: trustPEM, policy: policy}
	child, cancel := context.WithCancelCause(ctx)
	owner := &ProductDirectCapacityEndpoint{ctx: child, cancel: cancel, positions: positions}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, owner.Close())
		}
	}()
	for remaining := positions; remaining > 0; {
		count := min(remaining, productDirectCapacityGroupPositions)
		reporter, err := interopharness.NewPeerReporter()
		if err != nil {
			return nil, err
		}
		capacity := sessionv4.EngineeringHostCapacity{Sessions: uint32(count + 1), Materials: uint32(count + 1)}
		if streams == 128 {
			capacity.BusinessStreams = uint32(streams)
		}
		reporter.Capacity = &capacity
		reporter.ActivationWindowMS = productCapacityActivationWindowMS
		reporter.OperationDeadlineMS = operationMS
		reporter.ListenerConnections = uint16(min(count, concurrent))
		reporter.AcceptedRoutePositions = uint16(count + 1)
		endpoint, err := openProductDirectEndpointWithHandlers(child, kind, host, host, origin, protocolv4.DHProfileX25519, streams, nil, nil, originalTLS, reporter)
		if err != nil {
			return nil, fmt.Errorf("open original direct deployment group %d: %w", len(owner.groups)+1, errors.Join(err, reporter.Close()))
		}
		owner.groups = append(owner.groups, productDirectCapacityGroup{endpoint: endpoint, positions: count})
		remaining -= count
	}
	return owner, nil
}

// PrepareCapacity keeps the original authority/client preparation before the
// measured ramp. Failure retires every group, including unconsumed material;
// a failed or canceled position is never issued again.
func (e *ProductDirectCapacityEndpoint) PrepareCapacity(ctx context.Context, positions int) (resultErr error) {
	if e == nil || ctx == nil || positions != e.positions {
		return errors.New("original direct aggregate capacity differs from its installation")
	}
	e.mu.Lock()
	started := false
	defer func() {
		e.mu.Unlock()
		if resultErr != nil && started {
			resultErr = errors.Join(resultErr, e.Close())
		}
	}()
	if e.closed || e.prepared || e.issued {
		return errors.New("original direct aggregate preparation is single-use")
	}
	e.prepared = true
	started = true
	for i := range e.groups {
		group := &e.groups[i]
		if err := group.endpoint.PrepareCapacity(ctx, group.positions); err != nil {
			return fmt.Errorf("prepare original direct deployment group %d: %w", i+1, err)
		}
	}
	return context.Cause(e.ctx)
}

// claimPosition fixes the original route owner before any asynchronous work.
// Failure consumes that same position; the aggregate cannot reroute or retry it.
func (e *ProductDirectCapacityEndpoint) claimPosition(ctx context.Context, browser bool) (*ProductDirectEndpoint, error) {
	if e == nil || ctx == nil {
		return nil, errors.New("original direct aggregate and context are required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, errProductDirectEndpointClosed
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if err := context.Cause(e.ctx); err != nil {
		return nil, err
	}
	if browser == e.prepared {
		return nil, errors.New("original direct aggregate acquisition mode differs from preparation")
	}
	for e.nextGroup < len(e.groups) {
		group := &e.groups[e.nextGroup]
		if group.assigned == group.positions {
			e.nextGroup++
			continue
		}
		group.assigned++
		e.issued = true
		return group.endpoint, nil
	}
	return nil, errors.New("original direct aggregate positions exhausted")
}

func (e *ProductDirectCapacityEndpoint) Connect(ctx context.Context) (*ProductDirectPair, error) {
	endpoint, err := e.claimPosition(ctx, false)
	if err != nil {
		return nil, err
	}
	return endpoint.Connect(ctx)
}

func (e *ProductDirectCapacityEndpoint) IssueBrowserArtifact() (*ProductDirectBrowserArtifact, error) {
	if e == nil {
		return nil, errors.New("original direct browser aggregate is required")
	}
	endpoint, err := e.claimPosition(e.ctx, true)
	if err != nil {
		return nil, err
	}
	return endpoint.IssueBrowserArtifact()
}

func (e *ProductDirectCapacityEndpoint) CertificateHashBase64URL() (string, error) {
	if e == nil {
		return "", errors.New("original direct browser aggregate is required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || len(e.groups) == 0 {
		return "", errProductDirectEndpointClosed
	}
	return e.groups[0].endpoint.CertificateHashBase64URL()
}

func (e *ProductDirectCapacityEndpoint) BindOriginalBrowserRuntimeOrigin(origin string) error {
	if e == nil {
		return errors.New("original direct browser aggregate is required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.issued || e.prepared {
		return errors.New("original direct browser aggregate origin is already consumed")
	}
	for _, group := range e.groups {
		if err := group.endpoint.BindOriginalBrowserRuntimeOrigin(origin); err != nil {
			return err
		}
	}
	return nil
}

func (e *ProductDirectCapacityEndpoint) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		// Start shutdown of every original deployment before joining any one.
		e.cancel(errProductDirectEndpointClosed)
		e.mu.Lock()
		e.closed = true
		groups := e.groups
		e.mu.Unlock()
		for _, group := range groups {
			group.endpoint.cancel(errProductDirectEndpointClosed)
		}
		for i := len(groups) - 1; i >= 0; i-- {
			e.closeErr = errors.Join(e.closeErr, groups[i].endpoint.Close())
		}
	})
	return e.closeErr
}
