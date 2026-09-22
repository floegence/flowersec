package protocolv4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"

// DeliveryAuthorization owns the original compact authorization of private
// result/cursor bytes. Its detached closure, activation facts, clock and shared
// namespace references contain no Session/Stream/provider or traffic key. It
// checks the same current authorization algorithm as the original endpoint;
// normal I/O closure does not revoke this separately admitted reference.
type DeliveryAuthorization struct {
	owner             *EndpointAuthorization
	claimed, attached bool // Protected by owner.mu.
}

// ForkDelivery is called at original result/cursor admission, before consuming
// input. The supplied reservation covers CredentialSubscriptionsCharge and
// qualified runtime overhead. It does not extend the original nonrenewable cap
// or recreate an authorization already closed. New namespace references exist
// before the original Session can finish closing.
func (a *EndpointAuthorization) ForkDelivery(reservation resourcev4.Reference) (*DeliveryAuthorization, error) {
	return a.ForkDeliveryWithFloor(reservation, nil)
}

func (a *EndpointAuthorization) ForkDeliveryWithFloor(reservation resourcev4.Reference, floor *DeliverySubscriptionFloor) (*DeliveryAuthorization, error) {
	if a == nil {
		return nil, CBORFailure("credential_authorization_owner")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.checkLocked(false); err != nil {
		return nil, err
	}
	s, err := a.closure.subscribeWithFloor(a.bindings[:a.closure.count], a.hardEnd, reservation, a.hard, floor)
	if err != nil {
		return nil, err
	}
	s.freshness = a.freshness
	child, err := NewEndpointAuthorization(s, a.activation)
	if err != nil {
		s.Close()
		return nil, err
	}
	d := &s.delivery[0]
	d.owner = child
	return d, nil
}

// Take transfers the one original reference into a result/cursor constructor.
// Its stale creator cannot close the attached successor. There is one fixed
// successor slot, no chain of copyable ownership or post-admission allocation.
func (d *DeliveryAuthorization) Take() (*DeliveryAuthorization, error) {
	return d.take(resourcev4.Reference{}, false)
}

// TakeFor also binds the private payload to the same actual Environment budget
// as its verification references. A similarly configured private root cannot
// provide the aggregate bound or the Environment's common close fence.
func (d *DeliveryAuthorization) TakeFor(reservation resourcev4.Reference) (*DeliveryAuthorization, error) {
	return d.take(reservation, true)
}

func (d *DeliveryAuthorization) take(reservation resourcev4.Reference, checkEnvironment bool) (*DeliveryAuthorization, error) {
	if d == nil || d.owner == nil {
		return nil, CBORFailure("credential_authorization_owner")
	}
	a := d.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if d != &a.subscriptions.delivery[0] || d.claimed || d.attached {
		return nil, CBORFailure("credential_authorization_owner")
	}
	if checkEnvironment {
		if err := reservation.CheckSameEnvironment(a.subscriptions.reservation); err != nil {
			return nil, err
		}
	}
	if _, err := a.checkLocked(false); err != nil {
		return nil, err
	}
	result := &a.subscriptions.delivery[1]
	result.owner, result.attached = a, true
	d.claimed = true
	return result, nil
}

func (d *DeliveryAuthorization) Check() error {
	if d == nil || d.owner == nil {
		return CBORFailure("credential_authorization_owner")
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if !d.validLocked() {
		return CBORFailure("credential_authorization_owner")
	}
	_, err := d.owner.checkLocked(false)
	return err
}

// WithCurrentAuthorization orders one finite SDK ownership transfer against
// this independently admitted result's original close and authorization gate.
// The transfer may only update SDK state; it must not invoke an application
// codec, perform I/O, wait or reenter this authorization. A prior Check cannot
// authorize a later disclosure after Close has already won.
func (d *DeliveryAuthorization) WithCurrentAuthorization(transfer func() error) error {
	if d == nil || d.owner == nil || transfer == nil {
		return CBORFailure("credential_authorization_owner")
	}
	a := d.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if !d.validLocked() {
		return CBORFailure("credential_authorization_owner")
	}
	if _, err := a.checkLocked(false); err != nil {
		return err
	}
	return transfer()
}

// DetachSessionScope is called once complete private input has moved to its
// original local result owner. Shared namespace references and the original
// authorization cap remain live under the same Environment and tenant.
func (d *DeliveryAuthorization) DetachSessionScope() error {
	if d == nil || d.owner == nil {
		return CBORFailure("credential_authorization_owner")
	}
	a := d.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if !d.validLocked() {
		return CBORFailure("credential_authorization_owner")
	}
	return a.subscriptions.reservation.DetachSessionScope()
}

func (d *DeliveryAuthorization) RemainingMS() (uint64, error) {
	if d == nil || d.owner == nil {
		return 0, CBORFailure("credential_authorization_owner")
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if !d.validLocked() {
		return 0, CBORFailure("credential_authorization_owner")
	}
	return d.owner.remainingLocked()
}

func (d *DeliveryAuthorization) validLocked() bool {
	return !d.claimed && (d == &d.owner.subscriptions.delivery[0] || d == &d.owner.subscriptions.delivery[1])
}

func (d *DeliveryAuthorization) Wake() <-chan struct{} {
	if d == nil || d.owner == nil {
		return nil
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if !d.validLocked() {
		return nil
	}
	return d.owner.Wake()
}

func (d *DeliveryAuthorization) Notify() {
	if d == nil || d.owner == nil {
		return
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.validLocked() {
		d.owner.Notify()
	}
}

func (d *DeliveryAuthorization) Close(cause error) {
	if d == nil || d.owner == nil {
		return
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.validLocked() {
		d.owner.closeLocked(cause)
	}
}
