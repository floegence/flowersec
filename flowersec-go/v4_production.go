package flowersec

// This file is the public assembly boundary for the authenticated wire-v4
// implementation.  The concrete owners remain in internal/sessionv4; these
// wrappers only make the original owner graph reachable from the public Go
// module without exposing carrier handles, keys, or a second protocol engine.

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// Resource aliases are opaque accounting handles.  Callers use them only to
// pre-admit the finite graph required by a v4 environment and its sessions.
type ResourceRoot = resourcev4.Root
type ResourceConfig = resourcev4.Config
type ResourceReference = resourcev4.Reference
type ResourceOwnerKey = resourcev4.OwnerKey
type ResourceVector = resourcev4.Vector
type ResourceAccount = resourcev4.Account

func ResourceBackingBytes(c ResourceConfig) (uint64, error) {
	return resourcev4.BackingBytes(c)
}

func NewResourceRoot(c ResourceConfig) (*ResourceRoot, error) {
	return resourcev4.NewRoot(c)
}

// Protocol and key capability values are immutable/opaque inputs to the
// authenticated v4 constructors.  No constructor below serializes or returns
// a private key or credential.
type SignedMap = protocolv4.SignedMap
type SignedMapCodec = protocolv4.SignedMapCodec
type SessionContract = protocolv4.SessionContract
type AdmissionFacts = protocolv4.AdmissionFacts
type AdmissionFields = protocolv4.AdmissionFields
type ActivationTrustBinding = protocolv4.ActivationTrustBinding
type NamespaceTrustStore = protocolv4.NamespaceTrustStore
type CredentialValidation = protocolv4.CredentialValidation
type MapSigner = protocolv4.MapSigner
type Direction = protocolv4.Direction
type StaticDH = cryptov4.StaticDH
type IdentitySigner = cryptov4.IdentitySigner

const (
	ClientToServer = protocolv4.ClientToServer
	ServerToClient = protocolv4.ServerToClient
)

// The configuration aliases preserve the current constructors' validation
// and resource checks at the public module boundary.
type EnvironmentConfig = sessionv4.EnvironmentConfig
type EnvironmentSnapshot = sessionv4.EnvironmentSnapshot
type ApplicationIdentityConfig = sessionv4.ApplicationIdentityConfig
type ApplicationIdentityBytesConfig = sessionv4.ApplicationIdentityBytesConfig
type ApplicationIdentity = sessionv4.ApplicationIdentity
type MaterialGeneration = sessionv4.MaterialGeneration
type MaterialRequirements = sessionv4.MaterialRequirements
type MaterialLeaseRequest = sessionv4.MaterialLeaseRequest
type ConnectionMaterialSource = sessionv4.MaterialLeaseProvider
type MaterialNamespaceProvider = sessionv4.MaterialNamespaceProvider
type MaterialNamespaceSet = sessionv4.MaterialNamespaceSet
type MaterialNamespaceSetProvider = sessionv4.MaterialNamespaceSetProvider
type CarrierPreparationRequest = sessionv4.CarrierPreparationRequest
type ConsumerCarrierFactory = sessionv4.ConsumerCarrierFactory
type PreparedCarrier = sessionv4.PreparedCarrier
type PreparedCarrierConfig = sessionv4.PreparedCarrierConfig
type EstablishmentLimits = sessionv4.EstablishmentLimits
type InitialHello = sessionv4.InitialHello
type SessionAdmissionConfig = sessionv4.SessionAdmissionConfig
type SessionResourceScope = sessionv4.SessionResourceScope
type SourceConnectConfig = sessionv4.SourceConnectConfig
type MaterialConnectConfig = sessionv4.MaterialConnectConfig
type PoolSessionInput = sessionv4.PoolSessionInput
type LiveSessionInput = sessionv4.LiveSessionInput
type ServeConfig = sessionv4.ServeConfig
type ServeGroup = sessionv4.ServeGroup

func NewApplicationIdentity(c ApplicationIdentityConfig, reservation, dependencies ResourceReference) (*ApplicationIdentity, error) {
	return sessionv4.NewApplicationIdentity(c, reservation, dependencies)
}

func NewApplicationIdentityFromBytes(c ApplicationIdentityBytesConfig, reservation, dependencies ResourceReference) (*ApplicationIdentity, error) {
	return sessionv4.NewApplicationIdentityFromBytes(c, reservation, dependencies)
}

// ArtifactLease is the authenticated, one-use material returned by a
// caller-owned issuer/provider.  It remains opaque after construction.
type ArtifactLease = sessionv4.ArtifactLease
type ArtifactLeaseConfig = sessionv4.ArtifactLeaseConfig
type ArtifactLeaseBytesConfig = sessionv4.ArtifactLeaseBytesConfig

func NewArtifactLease(c ArtifactLeaseConfig, reservation, dependencies ResourceReference) (*ArtifactLease, error) {
	return sessionv4.NewArtifactLease(c, reservation, dependencies)
}

func NewArtifactLeaseFromBytes(c ArtifactLeaseBytesConfig, reservation, dependencies ResourceReference) (*ArtifactLease, error) {
	return sessionv4.NewArtifactLeaseFromBytes(c, reservation, dependencies)
}

// ConnectionMaterial owns one captured identity/lease pair.  The
// underlying sessionv4 material is never replaced and can only be consumed by
// one of the explicit pool/live authority paths below.
type ConnectionMaterial struct{ inner *sessionv4.ConnectionMaterial }

func NewConnectionMaterial(lease *ArtifactLease, identity *ApplicationIdentity, generation MaterialGeneration, runtimeBytes uint64, reservation ResourceReference) (*ConnectionMaterial, error) {
	inner, err := sessionv4.NewConnectionMaterial(lease, identity, generation, runtimeBytes, reservation)
	if err != nil {
		return nil, err
	}
	return &ConnectionMaterial{inner: inner}, nil
}

func (m *ConnectionMaterial) Close() {
	if m != nil && m.inner != nil {
		m.inner.Close()
	}
}

func (m *ConnectionMaterial) WaitCleanup(ctx context.Context) error {
	if m == nil || m.inner == nil {
		return ErrTransportUnavailable
	}
	return m.inner.WaitCleanup(ctx)
}

// TransportEnvironment owns reusable v4 factories and the original admitted Session
// positions.  Close/WaitCleanup delegate to the same internal owner graph.
type TransportEnvironment struct{ inner *sessionv4.Environment }

// Environment is retained as the concise public name used by the runtime harness.
type Environment = TransportEnvironment

// EnvironmentOptions is the compatibility spelling for TransportEnvironmentOptions.
type EnvironmentOptions = TransportEnvironmentOptions

func newTransportEnvironment(c EnvironmentConfig, reservation, dependencies ResourceReference) (*TransportEnvironment, error) {
	inner, err := sessionv4.NewEnvironment(c, reservation, dependencies)
	if err != nil {
		return nil, err
	}
	return &TransportEnvironment{inner: inner}, nil
}

func (e *TransportEnvironment) Close() {
	if e != nil && e.inner != nil {
		e.inner.Close()
	}
}

func (e *TransportEnvironment) WaitCleanup(ctx context.Context) error {
	if e == nil || e.inner == nil {
		return ErrTransportUnavailable
	}
	if err := e.inner.WaitCleanup(ctx); err != nil {
		return err
	}
	return e.inner.Retire()
}

// DiagnosticCounts returns the environment's finite unsampled aggregate observation.
// A nil or retired environment returns an empty snapshot.
func (e *TransportEnvironment) DiagnosticCounts(metric DiagnosticMetric) DiagnosticCounts {
	if e == nil || e.inner == nil {
		return DiagnosticCounts{}
	}
	return e.inner.DiagnosticCounts(metric)
}

func (e *TransportEnvironment) Snapshot() EnvironmentSnapshot {
	if e == nil || e.inner == nil {
		return EnvironmentSnapshot{}
	}
	return e.inner.OperationsSnapshot()
}

// CreateMaterial hosts one caller-supplied issuer/provider result in the
// original bounded material slot.  The callback runs under the internal
// environment's cancellation and cleanup owner; a returned material is
// adopted exactly once and is never copied into a second graph.
func (e *TransportEnvironment) CreateMaterial(ctx context.Context, factory func(context.Context) (*ConnectionMaterial, error)) (*ConnectionMaterial, error) {
	if ctx == nil || factory == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if e == nil || e.inner == nil {
		return nil, ErrTransportUnavailable
	}
	inner, err := e.inner.CreateMaterial(ctx, func(callbackCtx context.Context) (*sessionv4.ConnectionMaterial, error) {
		material, factoryErr := factory(callbackCtx)
		if material == nil {
			return nil, factoryErr
		}
		if material.inner == nil {
			return nil, ErrTransportUnavailable
		}
		return material.inner, factoryErr
	})
	if err != nil {
		return nil, err
	}
	return &ConnectionMaterial{inner: inner}, nil
}

func (e *TransportEnvironment) ConnectSourcePool(ctx context.Context, c SourceConnectConfig, spend PoolSessionInput) (*Session, error) {
	if e == nil || e.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := e.inner.ConnectSourcePool(ctx, c, spend)
	if err != nil {
		return nil, err
	}
	return newSessionFromEnvironment(s), nil
}

func (e *TransportEnvironment) ConnectSourceLiveSQLite(ctx context.Context, c SourceConnectConfig, spend LiveSessionInput) (*Session, error) {
	if e == nil || e.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := e.inner.ConnectSourceLiveSQLite(ctx, c, spend)
	if err != nil {
		return nil, err
	}
	return newSessionFromEnvironment(s), nil
}

func (e *TransportEnvironment) ConnectMaterialPool(ctx context.Context, m *ConnectionMaterial, c MaterialConnectConfig, spend PoolSessionInput) (*Session, error) {
	if e == nil || e.inner == nil || m == nil || m.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := e.inner.ConnectMaterialPool(ctx, m.inner, c, spend)
	if err != nil {
		return nil, err
	}
	return newSessionFromEnvironment(s), nil
}

func (e *TransportEnvironment) ConnectMaterialLiveSQLite(ctx context.Context, m *ConnectionMaterial, c MaterialConnectConfig, spend LiveSessionInput) (*Session, error) {
	if e == nil || e.inner == nil || m == nil || m.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := e.inner.ConnectMaterialLiveSQLite(ctx, m.inner, c, spend)
	if err != nil {
		return nil, err
	}
	return newSessionFromEnvironment(s), nil
}
