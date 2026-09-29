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
type V4ResourceRoot = resourcev4.Root
type V4ResourceConfig = resourcev4.Config
type V4ResourceReference = resourcev4.Reference
type V4ResourceOwnerKey = resourcev4.OwnerKey
type V4ResourceVector = resourcev4.Vector
type V4ResourceAccount = resourcev4.Account

func NewV4ResourceRoot(c V4ResourceConfig) (*V4ResourceRoot, error) {
	return resourcev4.NewRoot(c)
}

// Protocol and key capability values are immutable/opaque inputs to the
// authenticated v4 constructors.  No constructor below serializes or returns
// a private key or credential.
type V4SignedMap = protocolv4.SignedMap
type V4SignedMapCodec = protocolv4.SignedMapCodec
type V4NamespaceTrustStore = protocolv4.NamespaceTrustStore
type V4CredentialValidation = protocolv4.CredentialValidation
type V4MapSigner = protocolv4.MapSigner
type V4Direction = protocolv4.Direction
type V4StaticDH = cryptov4.StaticDH
type V4IdentitySigner = cryptov4.IdentitySigner

const (
	V4ClientToServer = protocolv4.ClientToServer
	V4ServerToClient = protocolv4.ServerToClient
)

// The following configuration aliases preserve the internal constructors'
// validation and resource checks while keeping the public API on the v6
// module.  They are intentionally prefixed so legacy v3 types cannot be
// confused with the current wire-v4 graph.
type V4EnvironmentConfig = sessionv4.EnvironmentConfig
type V4EnvironmentSnapshot = sessionv4.EnvironmentSnapshot
type V4ApplicationIdentityConfig = sessionv4.ApplicationIdentityConfig
type V4ApplicationIdentityBytesConfig = sessionv4.ApplicationIdentityBytesConfig
type V4ApplicationIdentity = sessionv4.ApplicationIdentity
type V4MaterialGeneration = sessionv4.MaterialGeneration
type V4MaterialRequirements = sessionv4.MaterialRequirements
type V4MaterialLeaseRequest = sessionv4.MaterialLeaseRequest
type V4MaterialLeaseProvider = sessionv4.MaterialLeaseProvider
type V4MaterialNamespaceProvider = sessionv4.MaterialNamespaceProvider
type V4MaterialNamespaceSet = sessionv4.MaterialNamespaceSet
type V4MaterialNamespaceSetProvider = sessionv4.MaterialNamespaceSetProvider
type V4CarrierPreparationRequest = sessionv4.CarrierPreparationRequest
type V4ConsumerCarrierFactory = sessionv4.ConsumerCarrierFactory
type V4PreparedCarrier = sessionv4.PreparedCarrier
type V4PreparedCarrierConfig = sessionv4.PreparedCarrierConfig
type V4EstablishmentLimits = sessionv4.EstablishmentLimits
type V4InitialHello = sessionv4.InitialHello
type V4SessionAdmissionConfig = sessionv4.SessionAdmissionConfig
type V4SessionResourceScope = sessionv4.SessionResourceScope
type V4SourceConnectConfig = sessionv4.SourceConnectConfig
type V4MaterialConnectConfig = sessionv4.MaterialConnectConfig
type V4PoolSessionInput = sessionv4.PoolSessionInput
type V4LiveSessionInput = sessionv4.LiveSessionInput
type V4ServeConfig = sessionv4.ServeConfig
type V4ServeGroup = sessionv4.ServeGroup

func NewV4ApplicationIdentity(c V4ApplicationIdentityConfig, reservation, dependencies V4ResourceReference) (*V4ApplicationIdentity, error) {
	return sessionv4.NewApplicationIdentity(c, reservation, dependencies)
}

func NewV4ApplicationIdentityFromBytes(c V4ApplicationIdentityBytesConfig, reservation, dependencies V4ResourceReference) (*V4ApplicationIdentity, error) {
	return sessionv4.NewApplicationIdentityFromBytes(c, reservation, dependencies)
}

// V4ArtifactLease is the authenticated, one-use material returned by a
// caller-owned issuer/provider.  It remains opaque after construction.
type V4ArtifactLease = sessionv4.ArtifactLease
type V4ArtifactLeaseConfig = sessionv4.ArtifactLeaseConfig
type V4ArtifactLeaseBytesConfig = sessionv4.ArtifactLeaseBytesConfig

func NewV4ArtifactLease(c V4ArtifactLeaseConfig, reservation, dependencies V4ResourceReference) (*V4ArtifactLease, error) {
	return sessionv4.NewArtifactLease(c, reservation, dependencies)
}

func NewV4ArtifactLeaseFromBytes(c V4ArtifactLeaseBytesConfig, reservation, dependencies V4ResourceReference) (*V4ArtifactLease, error) {
	return sessionv4.NewArtifactLeaseFromBytes(c, reservation, dependencies)
}

// V4AuthenticatedMaterial owns one captured identity/lease pair.  The
// underlying sessionv4 material is never replaced and can only be consumed by
// one of the explicit pool/live authority paths below.
type V4AuthenticatedMaterial struct{ inner *sessionv4.ConnectionMaterial }

func NewV4AuthenticatedMaterial(lease *V4ArtifactLease, identity *V4ApplicationIdentity, generation V4MaterialGeneration, runtimeBytes uint64, reservation V4ResourceReference) (*V4AuthenticatedMaterial, error) {
	inner, err := sessionv4.NewConnectionMaterial(lease, identity, generation, runtimeBytes, reservation)
	if err != nil {
		return nil, err
	}
	return &V4AuthenticatedMaterial{inner: inner}, nil
}

func (m *V4AuthenticatedMaterial) Close() {
	if m != nil && m.inner != nil {
		m.inner.Close()
	}
}

func (m *V4AuthenticatedMaterial) WaitCleanup(ctx context.Context) error {
	if m == nil || m.inner == nil {
		return ErrTransportUnavailable
	}
	return m.inner.WaitCleanup(ctx)
}

// V4Environment owns reusable v4 factories and the original admitted Session
// positions.  Close/WaitCleanup delegate to the same internal owner graph.
type V4Environment struct{ inner *sessionv4.Environment }

func NewV4Environment(c V4EnvironmentConfig, reservation, dependencies V4ResourceReference) (*V4Environment, error) {
	inner, err := sessionv4.NewEnvironment(c, reservation, dependencies)
	if err != nil {
		return nil, err
	}
	return &V4Environment{inner: inner}, nil
}

func (e *V4Environment) Close() {
	if e != nil && e.inner != nil {
		e.inner.Close()
	}
}

func (e *V4Environment) WaitCleanup(ctx context.Context) error {
	if e == nil || e.inner == nil {
		return ErrTransportUnavailable
	}
	if err := e.inner.WaitCleanup(ctx); err != nil {
		return err
	}
	return e.inner.Retire()
}

func (e *V4Environment) Snapshot() V4EnvironmentSnapshot {
	if e == nil || e.inner == nil {
		return V4EnvironmentSnapshot{}
	}
	return e.inner.OperationsSnapshot()
}

// CreateMaterial hosts one caller-supplied issuer/provider result in the
// original bounded material slot.  The callback runs under the internal
// environment's cancellation and cleanup owner; a returned material is
// adopted exactly once and is never copied into a second graph.
func (e *V4Environment) CreateMaterial(ctx context.Context, factory func(context.Context) (*V4AuthenticatedMaterial, error)) (*V4AuthenticatedMaterial, error) {
	if e == nil || e.inner == nil || factory == nil {
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
	return &V4AuthenticatedMaterial{inner: inner}, nil
}

func (e *V4Environment) ConnectSourcePool(ctx context.Context, c V4SourceConnectConfig, spend V4PoolSessionInput) (*V4Session, error) {
	if e == nil || e.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := e.inner.ConnectSourcePool(ctx, c, spend)
	if err != nil {
		return nil, err
	}
	return newV4SessionFromEnvironment(s), nil
}

func (e *V4Environment) ConnectSourceLiveSQLite(ctx context.Context, c V4SourceConnectConfig, spend V4LiveSessionInput) (*V4Session, error) {
	if e == nil || e.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := e.inner.ConnectSourceLiveSQLite(ctx, c, spend)
	if err != nil {
		return nil, err
	}
	return newV4SessionFromEnvironment(s), nil
}

func (e *V4Environment) ConnectMaterialPool(ctx context.Context, m *V4AuthenticatedMaterial, c V4MaterialConnectConfig, spend V4PoolSessionInput) (*V4Session, error) {
	if e == nil || e.inner == nil || m == nil || m.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := e.inner.ConnectMaterialPool(ctx, m.inner, c, spend)
	if err != nil {
		return nil, err
	}
	return newV4SessionFromEnvironment(s), nil
}

func (e *V4Environment) ConnectMaterialLiveSQLite(ctx context.Context, m *V4AuthenticatedMaterial, c V4MaterialConnectConfig, spend V4LiveSessionInput) (*V4Session, error) {
	if e == nil || e.inner == nil || m == nil || m.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := e.inner.ConnectMaterialLiveSQLite(ctx, m.inner, c, spend)
	if err != nil {
		return nil, err
	}
	return newV4SessionFromEnvironment(s), nil
}
