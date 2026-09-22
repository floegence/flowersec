package rpcv4

import (
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// MethodRoutes is one local implementation binding's exact contract set. All
// entries must have the same namespace/type, with at most eight distinct
// contracts. The registry's method ordinal binds to the SessionPlan's one
// current implementation; alternate contracts do not install alternate code.
// Authority/audience isolation is supplied by the original registry owner.
type MethodRoutes struct {
	// ContentDefinition is the locally understood application content codec
	// and read/selection definition. Unknown peer definitions are rejected.
	ContentDefinition [32]byte
	Contracts         [][]byte
	// OfferWindowMS is the trusted positive execution window policy. Zero keeps
	// execution contracts as semantic routes without new admission windows.
	OfferWindowMS uint64
}
type ContractRoutesConfig struct {
	Methods       []MethodRoutes
	ContractNodes int
	RuntimeBytes  uint64
	Clock         *timev4.Clock
}

type contractRouteEntry struct {
	contract               *protocolv4.ServiceContract
	policy                 protocolv4.ServiceContractPolicy
	method                 uint32
	offerWindowMS          uint64
	offerCount             uint8
	offers                 [8]protocolv4.AdmissionOfferBounds
	registered, advertised bool
}
type ContractRoutes struct {
	mu              sync.Mutex
	reservation     resourcev4.Reference
	entries         []contractRouteEntry
	captures        uint32
	closed, cleaned bool
	clock           *timev4.Clock
	offerDecoder    *protocolv4.Decoder
	generation      uint64
}
type routeCapture struct {
	mu          sync.Mutex
	registry    *ContractRoutes
	entry       *contractRouteEntry
	reservation resourcev4.Reference
}

// ContractRoute holds one explicitly charged original semantic capture. Copies
// share its release gate. It exposes no arbitrary callback or wire installer.
type ContractRoute struct{ capture *routeCapture }

func ContractRoutesCharge(c ContractRoutesConfig) (resourcev4.Vector, error) {
	if len(c.Methods) > 1024 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	bytes, err := protocolv4.ServiceContractBackingBytes(c.ContractNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	count := uint64(0)
	for _, method := range c.Methods {
		if len(method.Contracts) == 0 || len(method.Contracts) > 8 || method.OfferWindowMS != 0 && c.Clock == nil {
			return resourcev4.Vector{}, ErrConfiguration
		}
		for _, wire := range method.Contracts {
			if len(wire) == 0 || len(wire) > 8192 {
				return resourcev4.Vector{}, ErrConfiguration
			}
			count++
		}
	}
	// Namespace.Text creates one immutable <=128-byte detached projection per
	// entry. Contract decoders own their separate full canonical bytes and nodes.
	offerBytes, err := protocolv4.AdmissionOfferCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	size := uint64(unsafe.Sizeof(ContractRoutes{})) + count*(bytes+uint64(unsafe.Sizeof(contractRouteEntry{}))+128)
	return (resourcev4.Vector{resourcev4.SDKBytes: size + offerBytes, resourcev4.Items: count + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}
func NewContractRoutes(c ContractRoutesConfig, reservation resourcev4.Reference) (_ *ContractRoutes, err error) {
	charge, err := ContractRoutesCharge(c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	count := 0
	for _, m := range c.Methods {
		count += len(m.Contracts)
	}
	r := &ContractRoutes{reservation: owned, entries: make([]contractRouteEntry, 0, count), clock: c.Clock}
	defer func() {
		if err != nil {
			r.Close()
		}
	}()
	r.offerDecoder, err = protocolv4.NewAdmissionOfferDecoder()
	if err != nil {
		return nil, err
	}
	for method, m := range c.Methods {
		var first protocolv4.ServiceContractPolicy
		var firstShape [32]byte
		for i, wire := range m.Contracts {
			codec, e := protocolv4.NewServiceContractCodec(c.ContractNodes)
			if e != nil {
				return nil, e
			}
			contract, e := codec.Decode(wire)
			if e != nil {
				return nil, e
			}
			policy, e := contract.Policy()
			if e != nil {
				contract.Release()
				return nil, e
			}
			if policy.RetainedContent && (m.ContentDefinition == ([32]byte{}) || m.ContentDefinition != policy.Content.Definition) {
				contract.Release()
				return nil, ErrExecutionUnsupported
			}
			if i == 0 {
				first = policy
			} else if first.Namespace != policy.Namespace || first.Type != policy.Type {
				contract.Release()
				return nil, ErrAssociation
			}
			shape, e := contract.MethodShapeDigest()
			if e != nil || i > 0 && shape != firstShape {
				contract.Release()
				return nil, ErrAssociation
			}
			firstShape = shape
			for _, existing := range r.entries {
				if existing.policy.Digest == policy.Digest || existing.method != uint32(method) && existing.policy.Namespace == policy.Namespace && existing.policy.Type == policy.Type {
					contract.Release()
					return nil, ErrAssociation
				}
			}
			r.entries = append(r.entries, contractRouteEntry{contract: contract, policy: policy, method: uint32(method), offerWindowMS: m.OfferWindowMS, registered: true})
		}
	}
	return r, nil
}
func ContractRouteCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(routeCapture{})) + uint64(unsafe.Sizeof(ContractRoute{})), resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// Capture selects by exact digest only. A type ID, payload namespace or peer
// priority never selects another implementation. The caller separately checks
// header shape/limits and current target permission before request admission.
func (r *ContractRoutes) Capture(digest [32]byte, reservation resourcev4.Reference, runtimeBytes uint64) (ContractRoute, error) {
	if r == nil {
		return ContractRoute{}, ErrOwner
	}
	charge, err := ContractRouteCharge(runtimeBytes)
	if err != nil {
		return ContractRoute{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleaned {
		return ContractRoute{}, ErrClosed
	}
	if r.captures == math.MaxUint32 {
		return ContractRoute{}, ErrCapacity
	}
	if err := reservation.CheckSameEnvironment(r.reservation); err != nil {
		return ContractRoute{}, err
	}
	for i := range r.entries {
		entry := &r.entries[i]
		if entry.policy.Digest != digest {
			continue
		}
		owned, err := reservation.Take(charge)
		if err != nil {
			return ContractRoute{}, err
		}
		r.captures++
		return ContractRoute{&routeCapture{registry: r, entry: entry, reservation: owned}}, nil
	}
	return ContractRoute{}, ErrMethod
}
func (c ContractRoute) Policy() (uint32, protocolv4.ServiceContractPolicy, error) {
	if c.capture == nil {
		return 0, protocolv4.ServiceContractPolicy{}, ErrOwner
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return 0, protocolv4.ServiceContractPolicy{}, ErrOwner
	}
	if err := s.reservation.Check(); err != nil {
		return 0, protocolv4.ServiceContractPolicy{}, err
	}
	return s.entry.method, s.entry.policy, nil
}

// RegisteredMethodPolicy is a local installation projection. The caller must
// own any retained namespace bytes; this grants no future registration or
// dispatch right. Actual message admission uses its exact digest capture.
func (r *ContractRoutes) RegisteredMethodPolicy(method uint32) (protocolv4.ServiceContractPolicy, error) {
	if r == nil {
		return protocolv4.ServiceContractPolicy{}, ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return protocolv4.ServiceContractPolicy{}, ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		return protocolv4.ServiceContractPolicy{}, err
	}
	for _, entry := range r.entries {
		if entry.method == method && entry.registered {
			return entry.policy, nil
		}
	}
	return protocolv4.ServiceContractPolicy{}, ErrMethod
}

// WithRegisteredNotify checks the original exact digest and message variant
// at a finite SDK publication gate. The callback must not perform I/O, call
// application code or reenter these routes. The channel's original services
// retain the registry until all notification publication tails have exited.
func (r *ContractRoutes) WithRegisteredNotify(h protocolv4.ApplicationHeader, action func(uint32, protocolv4.ServiceContractPolicy) error) error {
	if r == nil || !h.Notify() || action == nil {
		return ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleaned {
		return ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		return err
	}
	for _, entry := range r.entries {
		if entry.policy.Digest != h.Fields().ServiceContractDigest || !entry.registered {
			continue
		}
		if err := entry.contract.CheckRequest(h); err != nil {
			return err
		}
		return action(entry.method, entry.policy)
	}
	return ErrMethod
}
func (c ContractRoute) CheckRequest(h protocolv4.ApplicationHeader) error {
	if c.capture == nil {
		return ErrOwner
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return ErrOwner
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	return s.entry.contract.CheckRequest(h)
}
func (c ContractRoute) NewIncomingInput(t Ticket, h protocolv4.ApplicationHeader, config InputConfig, reservation resourcev4.Reference) (*RequestInput, error) {
	if c.capture == nil || t.network == nil {
		return nil, ErrOwner
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return nil, ErrOwner
	}
	if err := s.reservation.CheckSameEnvironment(reservation); err != nil {
		return nil, err
	}
	if err := s.entry.contract.CheckRequest(h); err != nil {
		return nil, err
	}
	return t.network.NewIncomingInput(t, s.entry.contract, config, reservation)
}

// NewNotifyInput captures an exact trusted notification input without an RPC
// ticket, ReplySlot, result owner or execution admission. Execution NOTIFY must
// still pass the execution owner's registration and dispatch gates after full
// input verification. A route capture alone never supplies that authority.
func (c ContractRoute) NewNotifyInput(h protocolv4.ApplicationHeader, config InputConfig, reservation resourcev4.Reference) (*RequestInput, error) {
	if c.capture == nil || !h.Notify() || config.Clock == nil {
		return nil, ErrOwner
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return nil, ErrOwner
	}
	if err := s.reservation.CheckSameEnvironment(reservation); err != nil {
		return nil, err
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	if s.registry.closed || !s.entry.registered || config.Clock != s.registry.clock {
		return nil, ErrMethod
	}
	p, err := NewRequestInput(h, s.entry.contract, config, reservation)
	if err == nil {
		p.method, p.methodBound, p.policy = s.entry.method, true, s.entry.policy
	}
	return p, err
}

// WithRegistered orders finite SDK admission with current method registration.
// The action must not run application code, perform I/O or reenter the route.
func (c ContractRoute) WithRegistered(action func() error) error {
	if c.capture == nil || action == nil {
		return ErrOwner
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return ErrOwner
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	if s.registry.closed || !s.entry.registered {
		return ErrMethod
	}
	return action()
}
func (c ContractRoute) CopyCanonical(dst []byte) (int, error) {
	if c.capture == nil {
		return 0, ErrOwner
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return 0, ErrOwner
	}
	if err := s.reservation.Check(); err != nil {
		return 0, err
	}
	return s.entry.contract.CopyCanonical(dst)
}
func (c ContractRoute) Release() {
	if c.capture == nil {
		return
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.registry
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.captures--
	s.registry = nil
	s.entry = nil
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
	r.cleanupLocked()
}
func (r *ContractRoutes) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.cleanupLocked()
}
func (r *ContractRoutes) cleanupLocked() {
	if r.cleaned || !r.closed || r.captures != 0 {
		return
	}
	for i := range r.entries {
		r.entries[i].contract.Release()
	}
	clear(r.entries)
	r.entries = nil
	r.clock = nil
	r.offerDecoder = nil
	r.reservation.Release()
	r.reservation = resourcev4.Reference{}
	r.cleaned = true
}
func (r *ContractRoutes) CleanupComplete() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cleaned
}

func (*ContractRoutes) String() string               { return "Flowersec.ContractRoutes" }
func (*ContractRoutes) GoString() string             { return "Flowersec.ContractRoutes" }
func (*ContractRoutes) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
func (ContractRoute) String() string                 { return "Flowersec.ContractRoute" }
func (ContractRoute) GoString() string               { return "Flowersec.ContractRoute" }
func (ContractRoute) MarshalJSON() ([]byte, error)   { return []byte("{}"), nil }
