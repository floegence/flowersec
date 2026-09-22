package rpcv4

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// ServiceInputsConfig fixes one Session's SDK input admission. The protected
// K+2 discard/hash owners are admitted before the channel is activated. Full
// business input is a try-now allocation in the original root/account scopes;
// allocation pressure never borrows protected input or waits on the reader.
// Captured input still needs current authorization, output, executor and, for
// execution, original registration before any application decoder may run.
type ServiceInputsConfig struct {
	ShortRequestBytes, ShortResponseBytes             uint32
	ShortMethods                                      []uint32
	ShortReservation                                  resourcev4.Reference
	Clock                                             *timev4.Clock
	GeneralOutstanding                                uint16
	MaxCaptureBytes                                   uint32
	InputRuntimeBytes, HashRuntimeBytes, RuntimeBytes uint64
	Root                                              *resourcev4.Root
	Owner                                             resourcev4.OwnerKey
	Accounts                                          []resourcev4.Account
}

// ServiceInputs is the concrete ordinary method input table. Fixed SDK queries
// use the Session's installed protected query owner, or receive a bounded
// service_unavailable response when that service is unavailable. No application
// method can be selected by an internal kind or a matching type alone.
type ServiceInputs struct {
	short                       *resourcev4.ProtectedReservation
	shortRequest, shortResponse uint32
	shortMethods                []uint32
	mu                          sync.Mutex
	network                     *Network
	routes                      *ContractRoutes
	reservation                 resourcev4.Reference
	root                        *resourcev4.Root
	owner                       resourcev4.OwnerKey
	accounts                    [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount                int
	config                      InputConfig
	maxCapture                  uint32
	protected, active           uint16
	serial                      uint64
	closed, cleaned             bool
}

// CheckUnaryBinding verifies a trusted local implementation ordinal
// against the original immutable route set. A matching type alone cannot
// bind another namespace or shape. Execution also requires its Session profile.
func (n *Network) CheckUnaryBinding(method uint32, namespace string, typeID uint32) error {
	return n.checkUnaryBinding(method, namespace, typeID, false, 0)
}

// CheckShortExecutionBinding requires an actual unary volatile execution in
// the original route table. A transient method in the same namespace cannot
// justify a future history promise.
func (n *Network) CheckShortExecutionBinding(method uint32, namespace string, typeID uint32) error {
	return n.checkUnaryBinding(method, namespace, typeID, true, 0)
}

func (n *Network) CheckShortDurableExecutionBinding(method uint32, namespace string, typeID uint32) error {
	return n.checkUnaryBinding(method, namespace, typeID, true, 1)
}

func (n *Network) checkUnaryBinding(method uint32, namespace string, typeID uint32, execution bool, mode uint8) error {
	if n == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return err
	}
	if n.inputs == nil {
		return ErrOwner
	}
	a := n.inputs
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.routes == nil {
		return ErrClosed
	}
	r := a.routes
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	for _, entry := range r.entries {
		p := entry.policy
		if execution && (p.Semantics != 1 || p.ExecutionMode != mode || p.Checkpoint && mode != 1 || p.RetainedContent) {
			continue
		}
		if entry.method == method && entry.registered && p.Namespace == namespace && p.Type == typeID && p.Shape == 0 && (p.Semantics == 0 || p.Semantics == 1 && n.config.Session.Limits().ApplicationProfile == "execution") {
			return nil
		}
	}
	return ErrMethod
}

func ServiceInputsCharge(c ServiceInputsConfig) (resourcev4.Vector, error) {
	if len(c.ShortMethods) > 128 || c.ShortRequestBytes > 1048576 || c.ShortResponseBytes > 1048576 || (c.ShortRequestBytes == 0) != (c.ShortResponseBytes == 0) || c.ShortRequestBytes == 0 && len(c.ShortMethods) != 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	for i, m := range c.ShortMethods {
		for _, other := range c.ShortMethods[:i] {
			if other == m {
				return resourcev4.Vector{}, ErrConfiguration
			}
		}
	}
	if c.GeneralOutstanding == 0 || c.GeneralOutstanding > 1024 || c.MaxCaptureBytes > 1048576 || c.InputRuntimeBytes == 0 || c.RuntimeBytes == 0 || c.Root == nil || len(c.Accounts) > resourcev4.MaxAccountsPerCharge {
		return resourcev4.Vector{}, ErrConfiguration
	}
	hash, err := protocolv4.ExecutionRequestVerifierBackingBytes(c.HashRuntimeBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	per, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RequestInput{})) + hash + 128, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.InputRuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	count := uint64(c.GeneralOutstanding) + queryPositions
	if per[resourcev4.SDKBytes] > math.MaxUint64/count {
		return resourcev4.Vector{}, ErrConfiguration
	}
	total, err := (resourcev4.Vector{resourcev4.SDKBytes: per[resourcev4.SDKBytes] * count, resourcev4.Items: count + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ServiceInputs{}))})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	total, err = total.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return total.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(len(c.ShortMethods)) * 4})
}

func (n *Network) NewServiceInputs(routes *ContractRoutes, c ServiceInputsConfig, reservation resourcev4.Reference) (*ServiceInputs, error) {
	if n == nil || routes == nil {
		return nil, ErrConfiguration
	}
	charge, err := ServiceInputsCharge(c)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return nil, err
	}
	if n.inputs != nil || c.GeneralOutstanding != n.config.Session.Limits().RPCMaxGeneralOutstanding {
		return nil, ErrConfiguration
	}
	if err := reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	routes.mu.Lock()
	defer routes.mu.Unlock()
	if routes.closed || routes.cleaned || routes.captures == math.MaxUint32 {
		return nil, ErrClosed
	}
	if err := reservation.CheckSameEnvironment(routes.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	a := &ServiceInputs{network: n, routes: routes, reservation: owned, root: c.Root, owner: c.Owner, config: InputConfig{Clock: c.Clock, Capture: true, RuntimeBytes: c.InputRuntimeBytes, HashRuntimeBytes: c.HashRuntimeBytes}, maxCapture: c.MaxCaptureBytes, protected: c.GeneralOutstanding + queryPositions, accountCount: len(c.Accounts)}
	if c.ShortRequestBytes != 0 {
		charge, e := RequestInputEnvelopeCharge(c.ShortRequestBytes, a.config)
		if e == nil {
			e = c.ShortReservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts)
		}
		if e == nil {
			a.short, e = resourcev4.NewProtectedReservation(c.ShortReservation, charge)
		}
		if e != nil {
			owned.Release()
			return nil, e
		}
		a.shortRequest, a.shortResponse = c.ShortRequestBytes, c.ShortResponseBytes
		a.shortMethods = append([]uint32(nil), c.ShortMethods...)
	} else if c.ShortReservation != (resourcev4.Reference{}) {
		owned.Release()
		return nil, ErrConfiguration
	}
	copy(a.accounts[:], c.Accounts)
	// This original registry pin is included in a's metadata reservation. Input
	// hashers copy their prefix, and captured policy is a detached scalar view.
	routes.captures++
	n.inputs = a
	return a, nil
}

func (a *ServiceInputs) OpenInput(t Ticket, h protocolv4.ApplicationHeader) (*RequestInput, error) {
	if a == nil || t.network == nil {
		return nil, ErrOwner
	}
	n := t.network
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.cleaned {
		return nil, ErrClosed
	}
	if a.network != n || t.direction != incoming || s.inputAttached || s.header != h || !h.OrdinaryRPC() || h.IsResponse() {
		return nil, ErrAssociation
	}
	if err := a.reservation.Check(); err != nil {
		return nil, err
	}
	// Fixed queries capture only their original bounded pending input. They do
	// not take ordinary root allocation capacity or enter application dispatch.
	if s.class == contractQuery && n.queries != nil && h.Fields().PayloadBytes <= queryRequestBytes {
		if p, err := n.queries.openInputLocked(t, h, s); err == nil {
			return p, nil
		}
	}
	r := a.routes
	r.mu.Lock()
	defer r.mu.Unlock()
	var entry *contractRouteEntry
	code := "service_contract_mismatch"
	// Result reads are a fixed SDK method. They carry a bounded encoded target
	// in their complete input and are handled by the trusted service dispatcher;
	// no user route, type match, or application callback is selected here.
	if h.Kind() == "read_result_request" {
		if !n.resultReadMatches(h) {
			code = "service_contract_mismatch"
		} else if h.Fields().PayloadBytes > 4096 {
			code = "resource_exhausted"
		} else {
			p, captureErr := a.captureLocked(h, nil)
			if captureErr == nil {
				p.ticket = t
				s.inputAttached = true
				return p, nil
			}
			code = "resource_exhausted"
			if errors.Is(captureErr, timev4.ErrExpired) {
				code = "deadline_exceeded"
			} else if !errors.Is(captureErr, resourcev4.ErrCapacity) {
				code = "service_unavailable"
			}
		}
	}
	// An internal fixed read can never dispatch a user registration.
	if h.Kind() == "execution_unary_request" || h.Kind() == "transient_unary_request" {
		for i := range r.entries {
			if r.entries[i].policy.Digest == h.Fields().ServiceContractDigest {
				entry = &r.entries[i]
				break
			}
		}
	} else if h.Kind() != "read_result_request" {
		code = "service_unavailable"
	}
	if entry != nil {
		err = entry.contract.CheckRequest(h)
		switch {
		case errors.Is(err, protocolv4.CBORFailure("application_response_limit")):
			code = "response_limit_unsupported"
		case err != nil:
			code = "service_contract_mismatch"
		case r.closed || !entry.registered || h.HasExecutionIdentity() && n.config.Session.Limits().ApplicationProfile != "execution":
			code = "service_unavailable"
		case h.Fields().PayloadBytes > a.maxCapture:
			code = "resource_exhausted"
		default:
			p, captureErr := a.captureLocked(h, entry)
			if captureErr == nil {
				p.ticket = t
				s.inputAttached = true
				return p, nil
			}
			code = "resource_exhausted"
			if errors.Is(captureErr, timev4.ErrExpired) {
				code = "deadline_exceeded"
			} else if !errors.Is(captureErr, resourcev4.ErrCapacity) {
				code = "service_unavailable"
			}
		}
	}
	// The exact signed network gate already bounds concurrent collectors. Full
	// captures use their separate reservation, so they never occupy this reserve.
	if a.active >= a.protected {
		return nil, ErrCapacity
	}
	p := &RequestInput{header: h, reservation: a.reservation, pool: a, refusal: code, ticket: t}
	if h.HasExecutionIdentity() {
		if entry == nil {
			p.unverifiable = true
		} else {
			p.verifier, err = protocolv4.NewExecutionRejectionVerifier(h, entry.contract)
			if err != nil {
				return nil, err
			}
		}
	}
	a.active++
	s.inputAttached = true
	return p, nil
}

func (a *ServiceInputs) captureLocked(h protocolv4.ApplicationHeader, entry *contractRouteEntry) (*RequestInput, error) {
	if a.serial == math.MaxUint64 {
		return nil, ErrClosed
	}
	charge, err := RequestInputCharge(h, a.config)
	if err != nil {
		return nil, err
	}
	a.serial++
	var identity [64]byte
	copy(identity[:], "flowersec/rpc/input/")
	copy(identity[24:40], a.owner.Instance[:])
	copy(identity[40:56], a.owner.Backing[:])
	binary.BigEndian.PutUint64(identity[56:], a.serial)
	digest := sha256.Sum256(identity[:])
	owner := a.owner
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	var ref resourcev4.Reference
	if entry != nil && a.short != nil && h.Fields().PayloadBytes <= a.shortRequest && h.Fields().ResponseLimitBytes <= a.shortResponse {
		for _, method := range a.shortMethods {
			if method == entry.method {
				ref, _ = a.short.Checkout()
				break
			}
		}
	}
	if ref == (resourcev4.Reference{}) {
		ref, err = a.root.Reserve(owner, charge, a.accounts[:a.accountCount]...)
	}
	if err != nil {
		return nil, err
	}
	if err := ref.CheckSameEnvironment(a.reservation); err != nil {
		ref.Release()
		return nil, err
	}
	var p *RequestInput
	if entry == nil {
		p, err = NewReadResultInput(h, a.config, ref)
	} else {
		p, err = NewRequestInput(h, entry.contract, a.config, ref)
	}
	if err != nil {
		ref.Release()
		return nil, err
	}
	if entry != nil {
		p.method, p.policy, p.methodBound = entry.method, entry.policy, true
	}
	return p, nil
}

func (a *ServiceInputs) releaseInput() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active--
	a.cleanupLocked()
}
func (a *ServiceInputs) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.short.Close()
	a.cleanupLocked()
}
func (a *ServiceInputs) cleanupLocked() {
	if a.cleaned || !a.closed || a.active != 0 {
		return
	}
	r := a.routes
	r.mu.Lock()
	r.captures--
	r.cleanupLocked()
	r.mu.Unlock()
	a.routes = nil
	a.network = nil
	a.root = nil
	a.shortMethods = nil
	clear(a.accounts[:])
	a.reservation.Release()
	a.reservation = resourcev4.Reference{}
	a.cleaned = true
}
func (a *ServiceInputs) CleanupComplete() bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cleaned && a.short.CleanupComplete()
}
func (*ServiceInputs) String() string               { return "Flowersec.RPCServiceInputs" }
func (*ServiceInputs) GoString() string             { return "Flowersec.RPCServiceInputs" }
func (*ServiceInputs) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
