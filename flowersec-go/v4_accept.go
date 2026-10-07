package flowersec

import (
	"context"
	"net/http"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type AcceptedEntranceConfig = sessionv4.AcceptedEntranceConfig
type AcceptedSessionInput = sessionv4.AcceptedSessionInput
type AdmissionOwner = ledgerv4.AdmissionOwner
type SQLiteAdmissionAuthority = ledgerv4.SQLiteAdmissionAuthority
type WebSocketUpgradeConfig = websocket.UpgradeConfig
type AcceptedWebSocketEndpoint = protocolv4.AcceptedWebSocketEndpoint

// AcceptedMaterialSource is a trusted bounded resolver. Hello is borrowed,
// unauthenticated routing input, never application authorization. A nonnil
// material transfers its original cleanup ownership, including on error.
type AcceptedMaterialSource interface {
	ResolveAcceptedMaterial(context.Context, []byte) (*ConnectionMaterial, InitialHello, error)
}

type v4AcceptedMaterialSource struct{ source AcceptedMaterialSource }

func (s v4AcceptedMaterialSource) ResolveAcceptedMaterial(ctx context.Context, hello []byte) (*sessionv4.ConnectionMaterial, sessionv4.InitialHello, error) {
	if ctx == nil || s.source == nil || isNilInterface(s.source) {
		return nil, sessionv4.InitialHello{}, cryptov4.ErrConfiguration
	}
	material, selected, err := s.source.ResolveAcceptedMaterial(ctx, hello)
	if material == nil {
		return nil, selected, err
	}
	return material.inner, selected, err
}

type ServeOptions struct {
	Config      ServeConfig
	Reservation ResourceReference
}

func ServeCharge(c ServeConfig) (ResourceVector, error) { return sessionv4.ServeCharge(c) }

// Serve registers one aggregate under the original TransportEnvironment. The host
// attaches its ingress to this handle exclusively and retains the native HTTP
// listener/parsing budget separately. Drain fences new ingress and aggregates
// the original Sessions; closing the handle never closes the shared TransportEnvironment.
func (e *TransportEnvironment) Serve(ctx context.Context, options ServeOptions) (*ServeHandle, error) {
	if e == nil || e.inner == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	group, err := e.inner.NewServeGroup(ctx, options.Config, options.Reservation)
	if err != nil {
		return nil, err
	}
	return newServeHandle(group), nil
}

// WebSocketAcceptOptions contains one fresh application plan and exact local
// resource scope. Input's owner, entrance, establishment, subscriptions, buffers and
// invocation must be empty: this boundary admits their workspaces together.
// Upgrade checks the host's original deployment policy before hijacking; its
// signed-route check is mandatory before durable admission and FSA/Noise.
type WebSocketAcceptOptions struct {
	Input                   AcceptedSessionInput
	Source                  AcceptedMaterialSource
	Limits                  EstablishmentLimits
	Entrance                AcceptedEntranceConfig
	Server                  *WebSocketServer
	Upgrade                 WebSocketUpgradeConfig
	Provider                WebSocketProviderOptions
	Dependencies            ResourceReference
	Accounts                []ResourceAccount
	LocalCapabilities       uint64
	RuntimeBytes            uint64
	IngressRuntimeBytes     uint64
	IntakeRuntimeBytes      uint64
	MaxAdmissionRecordBytes uint32
}

// AcceptWebSocket runs physical upgrade, material verification, durable
// admission, Noise and both READY messages under the same original ingress.
// It returns only an authenticated Session. The boolean reports actual HTTP
// hijack, even on error; when true the caller must not write an HTTP response.
// The original writer/request borrow always ends before this method returns.
func (h *ServeHandle) AcceptWebSocket(ctx context.Context, writer http.ResponseWriter, request *http.Request, options WebSocketAcceptOptions) (*Session, bool, error) {
	if h == nil || h.inner == nil || ctx == nil || writer == nil || request == nil || options.Source == nil || isNilInterface(options.Source) {
		return nil, false, cryptov4.ErrConfiguration
	}
	i := options.Input
	if i.Root == nil || i.Store == nil || i.Authority == nil || i.Entrance != nil || i.Establishment != nil || i.Subscriptions != nil ||
		i.Owner != (AdmissionOwner{}) ||
		i.Buffers != (ResourceReference{}) || i.Invocation != (ResourceReference{}) || i.Config.Application == nil ||
		i.Config.Core.Native || !i.Config.Core.MessageCarrier || i.Config.Initial.Role != protocolv4.ServerToClient ||
		i.Config.Initial.Deadline != options.Entrance.Initial.Deadline || i.Config.Initial.Profile != options.Entrance.Initial.Profile ||
		i.Config.Initial.ActivationSourceProfile != options.Entrance.Initial.ActivationSourceProfile ||
		!i.Config.Initial.Deadline.BelongsTo(i.Config.Core.Clock) || len(options.Accounts) == 0 || len(options.Accounts) > resourcev4.MaxAccountsPerCharge {
		return nil, false, cryptov4.ErrConfiguration
	}
	ingress, err := h.inner.BeginIngress()
	if err != nil {
		return nil, false, err
	}
	defer ingress.Release()
	c := sessionv4.AcceptedIngressConfig{RuntimeBytes: options.IngressRuntimeBytes, Dependencies: options.Dependencies,
		Intake: sessionv4.AcceptedIntakeConfig{Input: i, Resolver: v4AcceptedMaterialSource{options.Source}, Limits: options.Limits,
			RuntimeBytes: options.IntakeRuntimeBytes, LocalCapabilities: options.LocalCapabilities, Dependencies: options.Dependencies}}
	factoryConfig := assemblyv4.WebSocketIngressConfig{Root: i.Root, Owner: v4AssemblyOwner(i.ResourceOwner, "http-ingress", 0),
		Environment: i.Environment, Dependencies: options.Dependencies, Accounts: options.Accounts,
		Entrance: options.Entrance, Server: options.Server, Upgrade: options.Upgrade, Options: options.Provider, RuntimeBytes: options.RuntimeBytes}
	var charges [7]resourcev4.Vector
	charges[0], err = sessionv4.AcceptedIngressCharge(c)
	if err == nil {
		charges[1], err = sessionv4.AcceptedIntakeCharge(c.Intake)
	}
	if err == nil {
		charges[2], err = sessionv4.EstablishmentCharge(options.Limits)
	}
	charges[3] = protocolv4.CredentialSubscriptionsCharge()
	if err == nil {
		charges[4], charges[5], err = ledgerv4.SQLiteAdmissionCharges(options.MaxAdmissionRecordBytes)
	}
	if err == nil {
		charges[6], err = assemblyv4.WebSocketIngressCharge(factoryConfig)
	}
	if err != nil {
		return nil, false, err
	}
	var reservations [7]resourcev4.Reference
	var allocations [7]resourcev4.Request
	for index := range allocations {
		allocations[index] = resourcev4.Request{Owner: v4AssemblyOwner(i.ResourceOwner, "accept", uint64(index)), Charge: charges[index], Accounts: options.Accounts}
	}
	allocations[6].Owner = factoryConfig.Owner
	if err = i.Root.ReserveBatch(allocations[:], reservations[:]); err != nil {
		return nil, false, err
	}
	adopted := false
	defer func() {
		reservations[6].Release()
		if !adopted {
			for _, ref := range reservations[:6] {
				ref.Release()
			}
		}
	}()
	factory, err := assemblyv4.NewWebSocketIngress(writer, request, factoryConfig, reservations[6])
	if err != nil {
		return nil, false, err
	}
	defer factory.FinishHTTP()
	c.Factory, c.Reservation, c.Intake.Reservation = factory, reservations[0], reservations[1]
	c.Intake.Establishment, c.Intake.Subscriptions = reservations[2], reservations[3]
	c.Intake.Input.Buffers, c.Intake.Input.Invocation = reservations[4], reservations[5]
	var result *sessionv4.EnvironmentSession
	result, adopted, err = ingress.AcceptOwned(ctx, c)
	factory.FinishHTTP()
	if err != nil {
		return nil, factory.Hijacked(), err
	}
	return newSessionFromEnvironment(result), factory.Hijacked(), nil
}
