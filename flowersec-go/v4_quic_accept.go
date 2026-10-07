package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// QUICAcceptOptions supplies the original entrance policy, a fresh application
// plan and the listener's exact preauth account generations. Input's owner,
// entrance, establishment, subscriptions, buffers and invocation must be empty.
type QUICAcceptOptions struct {
	Input                   AcceptedSessionInput
	Source                  AcceptedMaterialSource
	Limits                  EstablishmentLimits
	Entrance                AcceptedEntranceConfig
	Dependencies            ResourceReference
	Accounts                []ResourceAccount
	LocalCapabilities       uint64
	IngressRuntimeBytes     uint64
	IntakeRuntimeBytes      uint64
	MaxAdmissionRecordBytes uint32
}

// AcceptQUIC atomically reserves the same six original admission owners as the
// other Serve entrances, then runs ClientHello, verification, durable admission,
// Noise and both READY flights. A successfully claimed ingress is consumed even
// on error. The only successful result is the authenticated original Session.
func (h *ServeHandle) AcceptQUIC(ctx context.Context, accepted *QUICIngress, options QUICAcceptOptions) (*Session, error) {
	if h == nil || h.inner == nil || ctx == nil || accepted == nil || accepted.inner == nil || options.Source == nil || isNilInterface(options.Source) {
		return nil, cryptov4.ErrConfiguration
	}
	i := options.Input
	if i.Root == nil || i.Store == nil || i.Authority == nil || i.Entrance != nil || i.Establishment != nil || i.Subscriptions != nil ||
		i.Owner != (AdmissionOwner{}) || i.Buffers != (ResourceReference{}) || i.Invocation != (ResourceReference{}) ||
		i.Config.Application == nil || !i.Config.Core.Native || i.Config.Core.MessageCarrier ||
		i.Config.Initial.Role != protocolv4.ServerToClient || i.Config.Initial.Deadline == nil ||
		i.Config.Initial.Deadline != options.Entrance.Initial.Deadline || i.Config.Initial.Profile != options.Entrance.Initial.Profile ||
		i.Config.Initial.ActivationSourceProfile != options.Entrance.Initial.ActivationSourceProfile ||
		i.Config.Initial.Limits != options.Entrance.Initial.Limits || !i.Config.Initial.Deadline.BelongsTo(i.Config.Core.Clock) ||
		len(options.Accounts) == 0 || len(options.Accounts) > resourcev4.MaxAccountsPerCharge {
		return nil, cryptov4.ErrConfiguration
	}
	if err := accepted.inner.ClaimAdmission(i.Root, i.ResourceOwner, i.Environment, options.Accounts, options.Entrance); err != nil {
		return nil, err
	}
	defer accepted.inner.Close()
	ingress, err := h.inner.BeginIngress()
	if err != nil {
		return nil, err
	}
	defer ingress.Release()
	c := sessionv4.AcceptedIngressConfig{Factory: accepted.inner, RuntimeBytes: options.IngressRuntimeBytes, Dependencies: options.Dependencies,
		Intake: sessionv4.AcceptedIntakeConfig{Input: i, Resolver: v4AcceptedMaterialSource{options.Source}, Limits: options.Limits,
			RuntimeBytes: options.IntakeRuntimeBytes, LocalCapabilities: options.LocalCapabilities, Dependencies: options.Dependencies}}
	var charges [6]resourcev4.Vector
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
	if err != nil {
		return nil, err
	}
	var reservations [6]resourcev4.Reference
	var allocations [6]resourcev4.Request
	for index := range allocations {
		allocations[index] = resourcev4.Request{Owner: v4AssemblyOwner(i.ResourceOwner, "accept", uint64(index)), Charge: charges[index], Accounts: options.Accounts}
	}
	if err = i.Root.ReserveBatch(allocations[:], reservations[:]); err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			for _, ref := range reservations {
				ref.Release()
			}
		}
	}()
	c.Reservation, c.Intake.Reservation = reservations[0], reservations[1]
	c.Intake.Establishment, c.Intake.Subscriptions = reservations[2], reservations[3]
	c.Intake.Input.Buffers, c.Intake.Input.Invocation = reservations[4], reservations[5]
	var result *sessionv4.EnvironmentSession
	result, adopted, err = ingress.AcceptOwned(ctx, c)
	if err != nil {
		return nil, err
	}
	return newSessionFromEnvironment(result), nil
}
