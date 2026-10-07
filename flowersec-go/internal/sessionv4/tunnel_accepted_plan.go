package sessionv4

import (
	"context"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// TunnelAcceptedEntrancePlan admits the complete entrance and HOP scratch before
// the original registration is advertised or its physical preparation starts.
// Build transfers these exact original reservations once; no allocation, queue
// or replacement backing can be introduced after the carrier has been prepared.
type TunnelAcceptedEntrancePlan struct {
	mu                                 sync.Mutex
	config                             AcceptedEntranceConfig
	root                               *resourcev4.Root
	owner                              resourcev4.OwnerKey
	environment                        resourcev4.Reference
	accounts                           [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	count                              int
	refs                               [2]resourcev4.Reference
	recipient                          *TunnelServerAllowRecipient
	done                               chan struct{}
	started, building, closed, cleaned bool
}

// Both preadmission and transfer use the same complete charge. The original
// entrance retains the transferred metadata reservation until physical cleanup.
func tunnelAcceptedEntranceCharges(c AcceptedEntranceConfig) (resourcev4.Vector, resourcev4.Vector, error) {
	metadata, initial, _, err := acceptedEntranceCharges(c)
	if err != nil {
		return resourcev4.Vector{}, resourcev4.Vector{}, err
	}
	scratch, err := hopAuthenticationScratchBytes()
	if err != nil {
		return resourcev4.Vector{}, resourcev4.Vector{}, err
	}
	metadata, err = metadata.Add(resourcev4.Vector{resourcev4.SDKBytes: scratch + uint64(unsafe.Sizeof(TunnelAcceptedEntrancePlan{})) + 512, resourcev4.Items: 1})
	return metadata, initial, err
}

func (r *TunnelServerAllowRegistration) AdmitAcceptedEntrance(c AcceptedEntranceConfig, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts ...resourcev4.Account) (err error) {
	if r == nil || root == nil || len(accounts) == 0 || len(accounts) > resourcev4.MaxAccountsPerCharge {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.busy || r.registered || r.state != tunnelAllowAbsent || r.entrancePlan != nil {
		r.mu.Unlock()
		return resourcev4.ErrOwner
	}
	if c.Initial.Deadline != nil && c.Initial.Deadline != r.deadline {
		r.mu.Unlock()
		return cryptov4.ErrConfiguration
	}
	c.Initial.Deadline = r.deadline
	recipient := r.endpoint
	r.busy = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.busy = false; r.mu.Unlock() }()
	metadata, initial, err := tunnelAcceptedEntranceCharges(c)
	if err != nil {
		return err
	}
	if err = r.reservation.CheckSameEnvironment(environment); err != nil {
		return err
	}
	if c.Initial.Profile != recipient.lease.lease.session.Profile || c.Initial.ActivationSourceProfile != recipient.lease.lease.source {
		return cryptov4.ErrConfiguration
	}
	plan := &TunnelAcceptedEntrancePlan{config: c, root: root, owner: owner, environment: environment, recipient: recipient, done: make(chan struct{})}
	plan.count = copy(plan.accounts[:], accounts)
	plan.config.Initial.Profile = strings.Clone(c.Initial.Profile)
	plan.config.Initial.ActivationSourceProfile = strings.Clone(c.Initial.ActivationSourceProfile)
	requests := [2]resourcev4.Request{
		{Owner: admissionResourceKey(owner, 0), Charge: metadata, Accounts: accounts},
		{Owner: admissionResourceKey(owner, 1), Charge: initial, Accounts: accounts},
	}
	if err = root.ReserveBatch(requests[:], plan.refs[:]); err != nil {
		return err
	}
	attached := false
	defer func() {
		if !attached {
			plan.Close()
		}
	}()
	for i, ref := range plan.refs {
		if err = ref.CheckSameEnvironment(environment); err != nil {
			return err
		}
		if err = ref.CheckAllocationScope(root, requests[i].Owner, accounts); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.state != tunnelAllowAbsent || r.registered {
		return resourcev4.ErrClosed
	}
	recipient.mu.Lock()
	defer recipient.mu.Unlock()
	if recipient.closed || recipient.entrancePlan != nil {
		return resourcev4.ErrClosed
	}
	r.entrancePlan, recipient.entrancePlan = plan, plan
	attached = true
	return nil
}

func (p *TunnelAcceptedEntrancePlan) match(c AcceptedEntranceConfig, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts []resourcev4.Account) error {
	return p.matchAdmission(c, root, &owner, environment, accounts)
}
func (p *TunnelAcceptedEntrancePlan) matchAdmission(c AcceptedEntranceConfig, root *resourcev4.Root, owner *resourcev4.OwnerKey, environment resourcev4.Reference, accounts []resourcev4.Account) error {
	if p == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.started || root != p.root || owner != nil && *owner != p.owner || len(accounts) != p.count {
		return resourcev4.ErrOwner
	}
	if c.Initial.Role != p.config.Initial.Role || c.Initial.Profile != p.config.Initial.Profile || c.Initial.ActivationSourceProfile != p.config.Initial.ActivationSourceProfile || c.Initial.Limits != p.config.Initial.Limits || c.Initial.Deadline != p.config.Initial.Deadline || c.RuntimeBytes != p.config.RuntimeBytes || c.InitialRuntimeBytes != p.config.InitialRuntimeBytes || c.CarrierRuntimeBytes != p.config.CarrierRuntimeBytes {
		return cryptov4.ErrConfiguration
	}
	if _, _, err := tunnelAcceptedEntranceCharges(c); err != nil {
		return err
	}
	if err := p.environment.CheckSameEnvironment(environment); err != nil {
		return err
	}
	for i, account := range accounts {
		for _, previous := range accounts[:i] {
			if previous == account {
				return resourcev4.ErrOwner
			}
		}
		found := false
		for _, expected := range p.accounts[:p.count] {
			if account == expected {
				found = true
				break
			}
		}
		if !found {
			return resourcev4.ErrOwner
		}
	}
	return nil
}
func (p *TunnelAcceptedEntrancePlan) Build(ctx context.Context, recipient *TunnelServerAllowRecipient) (entrance *AcceptedEntrance, err error) {
	if p == nil || ctx == nil || recipient == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed || p.started || recipient != p.recipient {
		p.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	p.started, p.building = true, true
	c, refs, environment := p.config, p.refs, p.environment
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		closed := p.closed
		p.building = false
		p.closed = true
		p.cleanupLocked()
		p.mu.Unlock()
		if closed && entrance != nil {
			entrance.Close()
			if err == nil {
				err = resourcev4.ErrClosed
			}
		}
	}()
	return newAdmittedTunnelAcceptedEntrance(ctx, c, recipient, refs, environment)
}
func (p *TunnelAcceptedEntrancePlan) cleanupLocked() {
	if !p.closed || p.building || p.cleaned {
		return
	}
	for _, ref := range p.refs {
		ref.Release()
	}
	p.refs = [2]resourcev4.Reference{}
	p.config = AcceptedEntranceConfig{}
	p.environment = resourcev4.Reference{}
	p.root = nil
	p.recipient = nil
	clear(p.accounts[:])
	p.cleaned = true
	close(p.done)
}
func (p *TunnelAcceptedEntrancePlan) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cleanupLocked()
}
func (p *TunnelAcceptedEntrancePlan) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// AcceptedEntranceConfig returns the already admitted fixed geometry. It does
// not acquire another position or expose material/provider capabilities.
func (r *TunnelServerAllowRegistration) AcceptedEntranceConfig() (AcceptedEntranceConfig, error) {
	if r == nil {
		return AcceptedEntranceConfig{}, resourcev4.ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.entrancePlan == nil {
		return AcceptedEntranceConfig{}, resourcev4.ErrOwner
	}
	p := r.entrancePlan
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.started {
		return AcceptedEntranceConfig{}, resourcev4.ErrOwner
	}
	return p.config, nil
}
