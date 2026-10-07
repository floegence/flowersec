package flowersec

import (
	"context"
	"net/http"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// TunnelServerRegistrationOptions captures one original server material and
// independently authenticated Allow service. Construction admits the provider,
// recipient, subscriptions, carrier and complete HOP entrance before publication.
// Reservation covers the composition itself; child charges use Root and Accounts.
// The host retains its separately bounded TLS listener and HTTP provider.
type TunnelServerRegistrationOptions struct {
	Material                  *ConnectionMaterial
	Root                      *ResourceRoot
	Owner                     ResourceOwnerKey
	Accounts                  []ResourceAccount
	Environment, Dependencies ResourceReference
	Reservation               ResourceReference
	RuntimeBytes              uint64
	Entrance                  AcceptedEntranceConfig
	Registration              TunnelServerAllowRegistrationConfig
	Allow                     TunnelServerAllowHTTPSServiceConfig
}

// TunnelServerRegistration composes existing original owners. It never opens a
// listener or starts another preparation, admission or physical cleanup engine.
type TunnelServerRegistration struct {
	mu                         sync.Mutex
	registration               *sessionv4.TunnelServerAllowRegistration
	service                    *controlv4.TunnelServerAllowHTTPSService
	reservation, shared        ResourceReference
	root                       *ResourceRoot
	owner                      ResourceOwnerKey
	environment                ResourceReference
	entrance                   AcceptedEntranceConfig
	scope                      SessionResourceScope
	accounts                   [resourcev4.MaxAccountsPerCharge]ResourceAccount
	accountCount               int
	wake                       chan struct{}
	accepting, started, closed bool
	cleaning, cleaned          bool
}

func tunnelServerRegistrationCharges(c TunnelServerRegistrationOptions) (charges [5]ResourceVector, err error) {
	if c.Material == nil || c.Material.inner == nil || c.Root == nil || c.RuntimeBytes == 0 ||
		len(c.Accounts) == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge ||
		c.Allow.Recipient != nil || c.Allow.Clock != c.Registration.Clock || c.Entrance.Initial.Deadline != nil {
		return charges, cryptov4.ErrConfiguration
	}
	source, err := sessionv4.TunnelServerMaterialSource(c.Material.inner, c.Environment)
	if err != nil {
		return charges, err
	}
	if c.Entrance.Initial.ActivationSourceProfile != source {
		return charges, cryptov4.ErrConfiguration
	}
	charges[0], charges[1], charges[2], charges[3], err = sessionv4.TunnelServerAllowRegistrationCharges(c.Registration, source == "live_authority")
	if err != nil {
		return charges, err
	}
	// The charge validator needs an endpoint, but does not invoke or publish it.
	allow := c.Allow
	allow.Recipient = &sessionv4.TunnelServerAllowRegistration{}
	charges[4], err = controlv4.TunnelServerAllowHTTPSServiceCharge(allow)
	return charges, err
}

// TunnelServerRegistrationCharge reports the composition's own reservation.
// Construction separately preadmits all original child owners, without I/O.
func TunnelServerRegistrationCharge(c TunnelServerRegistrationOptions) (ResourceVector, error) {
	if _, err := tunnelServerRegistrationCharges(c); err != nil {
		return ResourceVector{}, err
	}
	return (ResourceVector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(TunnelServerRegistration{})) + 512,
		resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(ResourceVector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewTunnelServerRegistration(c TunnelServerRegistrationOptions) (_ *TunnelServerRegistration, err error) {
	charges, err := tunnelServerRegistrationCharges(c)
	if err != nil {
		return nil, err
	}
	cost, err := TunnelServerRegistrationCharge(c)
	if err != nil {
		return nil, err
	}
	if err = c.Reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	for _, ref := range [...]ResourceReference{c.Reservation, c.Dependencies} {
		if err = ref.CheckSameEnvironment(c.Environment); err != nil {
			return nil, err
		}
	}
	owned, err := c.Reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	r := &TunnelServerRegistration{reservation: owned, root: c.Root, owner: c.Owner,
		environment: c.Environment, entrance: c.Entrance, scope: c.Registration.Scope, wake: make(chan struct{}, 1)}
	r.accountCount = copy(r.accounts[:], c.Accounts)
	adopted := false
	defer func() {
		if !adopted {
			r.Close()
			_ = r.WaitCleanup(context.Background())
		}
	}()
	if r.shared, err = c.Dependencies.Borrow(); err != nil {
		return nil, err
	}
	var refs [5]ResourceReference
	var requests [5]resourcev4.Request
	for index := range requests {
		requests[index] = resourcev4.Request{Owner: v4AssemblyOwner(c.Owner, "tunnel-server", uint64(index)), Charge: charges[index], Accounts: r.accounts[:r.accountCount]}
	}
	if err = c.Root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	r.registration, err = sessionv4.NewTunnelServerAllowRegistration(c.Material.inner, c.Registration, refs[0], refs[1], refs[2], refs[3], c.Dependencies, c.Environment)
	if err != nil {
		return nil, err
	}
	// The entrance plan must precede ControlReferenceFor, which publishes the
	// registration to its unique Allow service and seals further plan changes.
	if err = r.registration.AdmitAcceptedEntrance(c.Entrance, c.Root, c.Owner, c.Environment, r.accounts[:r.accountCount]...); err != nil {
		return nil, err
	}
	r.entrance, err = r.registration.AcceptedEntranceConfig()
	if err != nil {
		return nil, err
	}
	allow := c.Allow
	allow.Recipient = r.registration
	r.service, err = controlv4.NewTunnelServerAllowHTTPSService(allow, refs[4], c.Dependencies)
	if err != nil {
		return nil, err
	}
	adopted = true
	return r, nil
}

func (r *TunnelServerRegistration) Handler() http.Handler {
	if r == nil || r.service == nil {
		return nil
	}
	return r.service
}

func (r *TunnelServerRegistration) Binding() (TunnelServerAllowRequest, error) {
	if r == nil || r.registration == nil {
		return TunnelServerAllowRequest{}, cryptov4.ErrConfiguration
	}
	return r.registration.Binding()
}

func (r *TunnelServerRegistration) ReserveOriginalLivePublication(attempt [16]byte) error {
	if r == nil || r.registration == nil {
		return cryptov4.ErrConfiguration
	}
	return r.registration.ReserveOriginalLivePublication(attempt)
}

// TunnelAcceptOptions supplies the original intake policy and fresh application
// plan. Empty deadlines adopt the registration's exact original deadline;
// nonempty deadlines must be that same owner. No replacement preauth is created.
type TunnelAcceptOptions struct {
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

// Accept joins the original Allow result inside one Serve ingress. All six
// intake owners are reserved before TakePrepared; HOP_AUTH, ClientHello, FSB,
// durable admission, Noise and READY retain that physical carrier and deadline.
// After Environment adoption, only its existing cleanup task owns the tail.
func (r *TunnelServerRegistration) Accept(ctx context.Context, serve *ServeHandle, options TunnelAcceptOptions) (*Session, error) {
	if r == nil || ctx == nil || serve == nil || serve.inner == nil || options.Source == nil || isNilInterface(options.Source) {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.started || r.accepting || r.registration == nil {
		r.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	r.accepting = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.accepting = false
		select {
		case r.wake <- struct{}{}:
		default:
		}
		r.mu.Unlock()
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	i := options.Input
	entrance := options.Entrance
	deadline := r.entrance.Initial.Deadline
	if i.Config.Initial.Deadline != nil && i.Config.Initial.Deadline != deadline ||
		entrance.Initial.Deadline != nil && entrance.Initial.Deadline != deadline {
		return nil, cryptov4.ErrConfiguration
	}
	i.Config.Initial.Deadline, entrance.Initial.Deadline = deadline, deadline
	if i.Root != r.root || i.Store == nil || i.Authority == nil || i.Entrance != nil || i.Establishment != nil || i.Subscriptions != nil ||
		i.Owner != (AdmissionOwner{}) || i.Buffers != (ResourceReference{}) || i.Invocation != (ResourceReference{}) ||
		i.Config.Application == nil || i.Config.Initial.Role != protocolv4.ServerToClient ||
		!deadline.BelongsTo(i.Config.Core.Clock) || i.Config.Core.Clock == nil || i.Scope != r.scope ||
		i.Config.Initial.Authorization != nil || i.Config.Initial.Reservation != (ResourceReference{}) ||
		entrance.Initial.Authorization != nil || entrance.Initial.Reservation != (ResourceReference{}) ||
		i.Config.Initial.Profile != entrance.Initial.Profile || i.Config.Initial.ActivationSourceProfile != entrance.Initial.ActivationSourceProfile ||
		i.Config.Initial.Limits != entrance.Initial.Limits || entrance.Initial.Role != r.entrance.Initial.Role ||
		entrance.Initial.Profile != r.entrance.Initial.Profile || entrance.Initial.ActivationSourceProfile != r.entrance.Initial.ActivationSourceProfile ||
		entrance.Initial.Limits != r.entrance.Initial.Limits || entrance.RuntimeBytes != r.entrance.RuntimeBytes ||
		entrance.InitialRuntimeBytes != r.entrance.InitialRuntimeBytes || entrance.CarrierRuntimeBytes != r.entrance.CarrierRuntimeBytes {
		return nil, cryptov4.ErrConfiguration
	}
	if err := r.reservation.CheckAllocationScope(i.Root, i.ResourceOwner, options.Accounts); err != nil {
		return nil, err
	}
	if err := r.reservation.CheckSameEnvironment(i.Environment); err != nil {
		return nil, err
	}
	if err := r.reservation.CheckSameEnvironment(options.Dependencies); err != nil {
		return nil, err
	}
	ingress, err := serve.inner.BeginIngress()
	if err != nil {
		return nil, err
	}
	defer ingress.Release()
	c := sessionv4.AcceptedIngressConfig{RuntimeBytes: options.IngressRuntimeBytes, Dependencies: options.Dependencies,
		Intake: sessionv4.AcceptedIntakeConfig{Input: i, Resolver: v4AcceptedMaterialSource{options.Source}, Limits: options.Limits,
			RuntimeBytes: options.IntakeRuntimeBytes, LocalCapabilities: options.LocalCapabilities, Dependencies: options.Dependencies}}
	var charges [6]ResourceVector
	charges[0], err = sessionv4.AcceptedIngressCharge(c)
	if err == nil {
		// The same ingress reservation retains the factory object until its
		// actual preparation and physical cleanup have exited.
		charges[0], err = charges[0].Add(ResourceVector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(sessionv4.TunnelAcceptedIngressFactory{})) +
			uint64(r.accountCount)*uint64(unsafe.Sizeof(ResourceAccount{}))})
	}
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
	var refs [6]ResourceReference
	var requests [6]resourcev4.Request
	for index := range requests {
		requests[index] = resourcev4.Request{Owner: v4AssemblyOwner(i.ResourceOwner, "accept", uint64(index)), Charge: charges[index], Accounts: r.accounts[:r.accountCount]}
	}
	if err = i.Root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			for _, ref := range refs {
				ref.Release()
			}
		}
	}()
	// The Environment may retain the factory after this registration's own
	// cleanup completes. Its charged account snapshot cannot alias r's backing.
	factoryAccounts := make([]ResourceAccount, r.accountCount)
	copy(factoryAccounts, r.accounts[:r.accountCount])
	factory := &sessionv4.TunnelAcceptedIngressFactory{Registration: r.registration, Entrance: r.entrance,
		Root: i.Root, Owner: r.owner, Environment: i.Environment, Accounts: factoryAccounts}
	c.Factory, c.Reservation, c.Intake.Reservation = factory, refs[0], refs[1]
	c.Intake.Establishment, c.Intake.Subscriptions = refs[2], refs[3]
	c.Intake.Input.Buffers, c.Intake.Input.Invocation = refs[4], refs[5]
	var result *sessionv4.EnvironmentSession
	result, adopted, err = ingress.AcceptOwned(ctx, c)
	r.mu.Lock()
	r.started = adopted
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return newSessionFromEnvironment(result), nil
}

func (r *TunnelServerRegistration) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	if r.service != nil {
		r.service.Close()
	}
	if r.registration != nil {
		r.registration.Close()
	}
}

// WaitCleanup joins actual control requests and registration preparation. A
// taken recipient belongs to its original Environment/Serve cleanup owner.
// Canceling this observer never releases backing for a still-running callback.
func (r *TunnelServerRegistration) WaitCleanup(ctx context.Context) error {
	if r == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	for {
		r.mu.Lock()
		if r.cleaned {
			r.mu.Unlock()
			return nil
		}
		if !r.closed || r.cleaning {
			r.mu.Unlock()
			return resourcev4.ErrOwner
		}
		if !r.accepting {
			r.cleaning = true
			r.mu.Unlock()
			break
		}
		r.mu.Unlock()
		select {
		case <-r.wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	defer func() { r.mu.Lock(); r.cleaning = false; r.mu.Unlock() }()
	if r.service != nil {
		if err := r.service.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if r.registration != nil {
		if err := r.registration.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	r.shared.Release()
	r.reservation.Release()
	r.mu.Lock()
	r.cleaned = true
	r.mu.Unlock()
	return nil
}

func (*TunnelServerRegistration) String() string {
	return "TunnelServerRegistration(<redacted>)"
}
