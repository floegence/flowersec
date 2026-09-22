package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// RPCServicesConfig is the immutable ordinary RPC assembly for one Session.
// The common root/accounts and signed K apply to every component. Shared
// receive promises, short workload protection and execution stores are separate
// admission obligations; this assembly alone cannot enable a Session profile.
type RPCServicesConfig struct {
	// ReferenceDomain identifies the trusted local application target domain,
	// never a root or endpoint obtained from an imported reference. Required
	// when this caller prepares execution operations.
	ReferenceDomain                                                           string
	StreamMethods                                                             []StreamRegistration
	StreamSlots                                                               uint32
	DurableProviderRuntimeBytes                                               uint64
	ExecutionRegistry                                                         *rpcv4.ServiceRegistry
	ExecutionServices                                                         []rpcv4.ServiceBinding
	ManagementResolver                                                        rpcv4.ExecutionManagementResolver
	NotificationMethods                                                       []NotificationMethod
	NotifyReceivePending, NotifyPublishPending                                uint32
	NotificationWaitMS, NotificationCleanupMS                                 uint64
	CompletionGraceMS                                                         uint64
	ShortRequestBytes, ShortResponseBytes                                     uint32
	ShortTaskCharge                                                           resourcev4.Vector
	ShortCompletionCharge                                                     resourcev4.Vector
	CryptoProfile                                                             string
	Bootstrap                                                                 SessionStreamConfig
	MaxDataPayloadBytes                                                       uint64
	Root                                                                      *resourcev4.Root
	Owner                                                                     resourcev4.OwnerKey
	Accounts                                                                  []resourcev4.Account
	Session                                                                   protocolv4.SessionContract
	Clock                                                                     *timev4.Clock
	Query                                                                     rpcv4.QueryBinding
	ResultRead                                                                rpcv4.QueryBinding
	Routes                                                                    rpcv4.ContractRoutesConfig
	Methods                                                                   []UnaryRegistration
	Slots, ResidentSlots                                                      uint32
	MaxCaptureBytes                                                           uint32
	RuntimeBytes, InputRuntimeBytes, HashRuntimeBytes, InvocationRuntimeBytes uint64
}

const (
	rpcServicesMetadata = iota
	rpcServicesNetwork
	rpcServicesRoutes
	rpcServicesInputs
	rpcServicesQueryServer
	rpcServicesQueryClient
	rpcServicesDispatch
	rpcServicesChannel
	rpcServicesBatchWriter
	rpcServicesPublisher
	rpcServicesReceiver
	rpcServicesStreamMetadata
	rpcServicesStreamSend
	rpcServicesStreamQueue
	rpcServicesStreamOwnership
	rpcServicesShortInput
	rpcServicesShortCalls
	rpcServicesCompletionFloor = rpcServicesShortCalls + 5
	rpcServicesCallerMetadata  = rpcServicesCompletionFloor + 1
	rpcServicesCallerRequest   = rpcServicesCallerMetadata + 1
	rpcServicesCallerResult    = rpcServicesCallerRequest + 1
	rpcServicesCallerRoute     = rpcServicesCallerResult + 1
	rpcServicesCallerOwner     = rpcServicesCallerRoute + 1
	rpcServicesCallerAuthority = rpcServicesCallerOwner + 1
	rpcServicesDeliveryFloor   = rpcServicesCallerAuthority + 1
	rpcServicesNotifyDispatch  = rpcServicesDeliveryFloor + 1
	rpcServicesOwners          = rpcServicesNotifyDispatch + 1
)

// RPCServices retains the common tables and the first channel's preadmitted
// owners through real decoder, callback and provider cleanup. Construction
// does not start a channel or publish readiness. The original SessionPlan owns
// dispatch and fixed query worker registrations on the shared root executor.
type RPCServices struct {
	referenceDomain                       string
	referenceCodec                        *protocolv4.OperationReferenceCodec
	resultReadBinding                     rpcv4.QueryBinding
	deliveryFloor                         *protocolv4.DeliverySubscriptionFloor
	management                            *managementChannelOpening
	managementResolver                    rpcv4.ExecutionManagementResolver
	executionRegistry                     *rpcv4.ServiceRegistry
	executionRegistryBorrow               resourcev4.Reference
	managementChanged                     chan struct{}
	managementCallsDone                   chan struct{}
	managementCalls                       uint32
	managementStopped                     bool
	notifyChannels                        [2]*notifyChannelOpening
	notifications                         *NotificationDispatch
	notifyReceiverConfig                  rpcv4.NotifyReceiverConfig
	notifyPublisherConfig                 rpcv4.NotifyPublisherConfig
	runtimeContext                        context.Context
	runtimeStop                           chan struct{}
	dynamicChannels                       [8]*rpcChannelOpening
	firstFuture                           internalChannelFuture
	firstAllocation                       *internalChannelAllocation
	runtimeStarted                        bool
	publication                           <-chan struct{}
	receivePool                           *ReceivePool
	receiveProtection                     [11]*ReceiveProtection
	futureChannels                        [maxFutureChannels]internalChannelFuture
	plan                                  *SessionPlan
	localCall                             *unaryInvocation
	generalCalls                          []*unaryInvocation
	operations                            []*UnaryOperation
	callSerial                            uint64
	shortCaller                           [6]*resourcev4.ProtectedReservation
	shortRequestBytes, shortResponseBytes uint32
	bootstrap                             *Bootstrap
	stream                                *StreamOwnership
	cryptoProfile                         string
	mu                                    sync.Mutex
	network                               *rpcv4.Network
	routes                                *rpcv4.ContractRoutes
	inputs                                *rpcv4.ServiceInputs
	incoming                              *rpcv4.ContractQueryService
	outgoing                              *rpcv4.ContractQueryClient
	dispatch                              *ServiceDispatch
	completionFloor                       *CompletionFloor
	channel                               *RPCChannel
	refs                                  [rpcServicesOwnerCapacity]resourcev4.Reference
	session                               protocolv4.SessionContract
	clock                                 *timev4.Clock
	root                                  *resourcev4.Root
	owner                                 resourcev4.OwnerKey
	accounts                              [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount                          int
	runtimeBytes                          uint64
	hashRuntimeBytes                      uint64
	completionGraceMS                     uint64
	closed, bound, retired                bool
}

func (c RPCServicesConfig) inputConfig() rpcv4.ServiceInputsConfig {
	var methods []uint32
	for _, m := range c.Methods {
		if m.WorkClass == ApplicationShort {
			methods = append(methods, m.Method)
		}
	}
	return rpcv4.ServiceInputsConfig{ShortRequestBytes: c.ShortRequestBytes, ShortResponseBytes: c.ShortResponseBytes, ShortMethods: methods, Root: c.Root, Owner: c.Owner, Accounts: c.Accounts, Clock: c.Clock,
		GeneralOutstanding: c.Session.Limits().RPCMaxGeneralOutstanding, MaxCaptureBytes: c.MaxCaptureBytes,
		RuntimeBytes: c.RuntimeBytes, InputRuntimeBytes: c.InputRuntimeBytes, HashRuntimeBytes: c.HashRuntimeBytes}
}
func (c RPCServicesConfig) dispatchConfig() ServiceDispatchConfig {
	return ServiceDispatchConfig{Streams: c.StreamMethods, StreamSlots: c.StreamSlots, DurableProviderRuntimeBytes: c.DurableProviderRuntimeBytes, ExecutionRegistry: c.ExecutionRegistry, ExecutionServices: c.ExecutionServices, ShortResponseBytes: c.ShortResponseBytes, Root: c.Root, Owner: c.Owner, Accounts: c.Accounts, Clock: c.Clock,
		Methods: c.Methods, Slots: c.Slots, ResidentSlots: c.ResidentSlots, RuntimeBytes: c.RuntimeBytes, InvocationRuntimeBytes: c.InvocationRuntimeBytes}
}

func (c RPCServicesConfig) notificationConfig() NotificationDispatchConfig {
	var slots uint32
	for _, m := range c.NotificationMethods {
		if m.ExecutionHandler != nil {
			slots = c.Slots
			break
		}
	}
	return NotificationDispatchConfig{ExecutionRegistry: c.ExecutionRegistry, ExecutionSlots: slots, Root: c.Root, Owner: c.Owner, Accounts: c.Accounts, Clock: c.Clock, Methods: c.NotificationMethods, RuntimeBytes: c.RuntimeBytes, DeliveryRuntimeBytes: c.InvocationRuntimeBytes, WaitMS: c.NotificationWaitMS, CleanupMS: c.NotificationCleanupMS}
}
func (c RPCServicesConfig) notifyInputConfig() rpcv4.NotifyReceiverConfig {
	return rpcv4.NotifyReceiverConfig{Root: c.Root, Owner: c.Owner, Accounts: c.Accounts, Clock: c.Clock, Pending: c.NotifyReceivePending, MaxCaptureBytes: c.MaxCaptureBytes, RuntimeBytes: c.RuntimeBytes, InputRuntimeBytes: c.InputRuntimeBytes, HashRuntimeBytes: c.HashRuntimeBytes}
}
func (c RPCServicesConfig) notifyOutputConfig() rpcv4.NotifyPublisherConfig {
	return rpcv4.NotifyPublisherConfig{Pending: c.NotifyPublishPending, RuntimeBytes: c.RuntimeBytes}
}

func rpcServicesCharges(c RPCServicesConfig) (charges [rpcServicesOwnerCapacity]resourcev4.Vector, total resourcev4.Vector, err error) {
	if c.ReferenceDomain != "" && !executionIdentityText(c.ReferenceDomain) {
		return charges, total, cryptov4.ErrConfiguration
	}
	if c.CompletionGraceMS == 0 || c.ShortRequestBytes == 0 || c.ShortResponseBytes == 0 || c.ShortTaskCharge == (resourcev4.Vector{}) || c.ShortCompletionCharge == (resourcev4.Vector{}) || c.Root == nil || c.Clock == nil || c.RuntimeBytes == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || c.Routes.Clock != c.Clock {
		return charges, total, cryptov4.ErrConfiguration
	}
	spec, enabled, e := protocolv4.Bootstrap(c.Session.Limits().ApplicationProfile)
	if e != nil || !enabled || c.Bootstrap.InitialReceiveLimit != spec.ReceiveLimit || c.Bootstrap.QueueBytes < spec.ReceiveLimit || c.Bootstrap.ReceiveBytes < spec.ReceiveLimit {
		return charges, total, cryptov4.ErrConfiguration
	}
	geometry, minimum, e := internalChannelGeometry(c.Session.Limits().ApplicationProfile)
	channels := uint64(geometry.RPC) + uint64(geometry.Notify) + uint64(geometry.Management)
	if e != nil || channels == 0 || c.Session.Limits().MaxCredit < channels*minimum || c.Bootstrap.ReceivePoolBytes < (channels-1)*minimum+c.Bootstrap.ReceiveBytes {
		return charges, total, cryptov4.ErrConfiguration
	}
	charges[rpcServicesMetadata], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RPCServices{})) + uint64(c.Session.Limits().RPCMaxGeneralOutstanding)*(uint64(unsafe.Sizeof((*unaryInvocation)(nil)))+uint64(unsafe.Sizeof((*UnaryOperation)(nil)))), resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return
	}
	if c.ReferenceDomain != "" {
		n, e := protocolv4.OperationReferenceCodecBackingBytes()
		if e != nil {
			err = e
			return
		}
		charges[rpcServicesMetadata], err = charges[rpcServicesMetadata].Add(resourcev4.Vector{resourcev4.SDKBytes: n + 128})
		if err != nil {
			return
		}
	}
	if geometry.Management != 0 {
		// The existing Session supervisor also owns M initialization/rebuild.
		// Two bounded availability waiters remain charged before a channel exists.
		charges[rpcServicesMetadata], err = charges[rpcServicesMetadata].Add(resourcev4.Vector{resourcev4.SDKBytes: 3*c.RuntimeBytes + 2*(512+uint64(unsafe.Sizeof(timev4.Deadline{}))+uint64(unsafe.Sizeof(managementHistoryAuthority{}))), resourcev4.Items: 4, resourcev4.WorkSlots: 2, resourcev4.Timers: 4})
		if err != nil {
			return
		}
	}
	charges[rpcServicesNetwork], err = rpcv4.NetworkCharge(rpcv4.NetworkConfig{ProtectShortCall: true, Session: c.Session, Query: c.Query, ResultRead: c.ResultRead, RuntimeBytes: c.RuntimeBytes})
	if err != nil {
		return
	}
	charges[rpcServicesRoutes], err = rpcv4.ContractRoutesCharge(c.Routes)
	if err != nil {
		return
	}
	charges[rpcServicesInputs], err = rpcv4.ServiceInputsCharge(c.inputConfig())
	if err != nil {
		return
	}
	charges[rpcServicesQueryServer], err = rpcv4.ContractQueryServiceCharge(c.RuntimeBytes)
	if err != nil {
		return
	}
	charges[rpcServicesQueryClient], err = rpcv4.ContractQueryClientCharge(c.RuntimeBytes)
	if err != nil {
		return
	}
	charges[rpcServicesDispatch], err = ServiceDispatchCharge(c.dispatchConfig())
	if err != nil {
		return
	}
	charges[rpcServicesNotifyDispatch], err = NotificationDispatchCharge(c.notificationConfig())
	if err != nil {
		return
	}
	input, e := rpcv4.RequestInputEnvelopeCharge(c.ShortRequestBytes, rpcv4.InputConfig{Clock: c.Clock, Capture: true, RuntimeBytes: c.InputRuntimeBytes, HashRuntimeBytes: c.HashRuntimeBytes})
	if e != nil {
		return charges, total, e
	}
	charges[rpcServicesShortInput], err = resourcev4.ProtectedCharge(input)
	if err != nil {
		return
	}
	calls, e := serviceCallCharges(c.InvocationRuntimeBytes, c.ShortResponseBytes, c.ShortTaskCharge)
	if e != nil {
		return charges, total, e
	}
	for index, v := range calls {
		charges[rpcServicesShortCalls+index], err = resourcev4.ProtectedCharge(v)
		if err != nil {
			return
		}
	}
	charges[rpcServicesDeliveryFloor], err = protocolv4.DeliverySubscriptionFloorCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return
	}
	charges[rpcServicesCompletionFloor] = c.ShortCompletionCharge
	caller, e := shortCallerCharges(c.RuntimeBytes, c.ShortRequestBytes, c.ShortResponseBytes)
	if e != nil {
		return charges, total, e
	}
	for index, v := range caller {
		charges[rpcServicesCallerMetadata+index], err = resourcev4.ProtectedCharge(v)
		if err != nil {
			return
		}
	}
	executionStart, e := appendFutureChannelCharges(c, &charges)
	if e != nil {
		return charges, total, e
	}
	if err = appendExecutionFloorCharges(c, &charges, executionStart); err != nil {
		return
	}
	first, _, e := futureChannelCharges(c, 0)
	if e != nil {
		return charges, total, e
	}
	for i, position := range firstChannelOwners {
		charges[position], err = resourcev4.ProtectedCharge(first[i])
		if err != nil {
			return
		}
	}
	for _, charge := range charges {
		total, err = total.Add(charge)
		if err != nil {
			return
		}
	}
	return
}

func RPCServicesRequirements(c RPCServicesConfig) (resourcev4.Vector, uint32, error) {
	charges, total, err := rpcServicesCharges(c)
	return total, uint32(rpcServicesChargeCount(charges)), err
}

func rpcServicesChargeCount(charges [rpcServicesOwnerCapacity]resourcev4.Vector) int {
	for i, charge := range charges {
		if charge == (resourcev4.Vector{}) {
			return i
		}
	}
	return len(charges)
}

// rpcServicesBatch is one stack-owned preparation in the original Session
// admission. It describes distinct backing owners without reserving any budget.
// The caller combines its requests with core and handshake requests in one
// ReserveBatch, then consumes these exact references before any durable claim.
type rpcServicesBatch struct {
	deliveryFloor   *protocolv4.DeliverySubscriptionFloor
	plan            *SessionPlan
	config          RPCServicesConfig
	executionScopes []rpcExecutionScope
	executionStart  int
	charges         [rpcServicesOwnerCapacity]resourcev4.Vector
	count           int
	prepared, used  bool
}

func prepareRPCServicesBatch(b *rpcServicesBatch, p *SessionPlan, c RPCServicesConfig, host *EnvironmentSession) error {
	if b == nil || b.prepared || b.used || p == nil {
		return cryptov4.ErrConfiguration
	}
	charges, _, err := rpcServicesCharges(c)
	if err != nil {
		return err
	}
	scopes, executionStart, err := prepareExecutionScopes(c)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.executor == nil || p.claimed || p.host != host || p.rpcPreparing || p.rpc != nil || p.services != nil || p.queries != nil || !p.config.Services || !p.config.ContractQueries {
		return cryptov4.ErrTransition
	}
	if c.ShortTaskCharge != p.executor.TaskCharge() || c.ShortCompletionCharge != p.executor.CompletionFloorCharge() {
		return cryptov4.ErrConfiguration
	}
	if err := p.reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return err
	}
	p.rpcPreparing = true
	*b = rpcServicesBatch{plan: p, config: c, executionScopes: scopes, executionStart: executionStart, charges: charges, count: rpcServicesChargeCount(charges), prepared: true}
	return nil
}

func (b *rpcServicesBatch) request(index int) (resourcev4.Request, error) {
	if b == nil || !b.prepared || b.used || index < 0 || index >= b.count {
		return resourcev4.Request{}, resourcev4.ErrOwner
	}
	owner := b.config.Owner
	var input [56]byte
	copy(input[:16], "rpc-services/v4/")
	copy(input[16:32], owner.Instance[:])
	copy(input[32:48], owner.Backing[:])
	binary.BigEndian.PutUint64(input[48:], uint64(index))
	hash := sha256.Sum256(input[:])
	copy(owner.Instance[:], hash[:16])
	copy(owner.Backing[:], hash[16:])
	return resourcev4.Request{Owner: owner, Charge: b.charges[index], Accounts: b.accountsFor(index), ResultOwner: index == rpcServicesCallerOwner}, nil
}

func (b *rpcServicesBatch) release() {
	if b == nil || !b.prepared {
		return
	}
	b.deliveryFloor.Close()
	b.deliveryFloor = nil
	b.plan.mu.Lock()
	b.plan.rpcPreparing = false
	b.plan.mu.Unlock()
	b.prepared, b.used = false, true
	b.executionScopes = nil
}

// InstallRPCServices is a component constructor. Complete Session admission
// uses the same preparation and adoption in its original aggregate batch.
func (p *SessionPlan) InstallRPCServices(c RPCServicesConfig) (*RPCServices, error) {
	var b rpcServicesBatch
	if err := prepareRPCServicesBatch(&b, p, c, nil); err != nil {
		return nil, err
	}
	defer b.release()
	var requests [rpcServicesOwnerCapacity]resourcev4.Request
	var refs [rpcServicesOwnerCapacity]resourcev4.Reference
	for index := range requests[:b.count] {
		var err error
		requests[index], err = b.request(index)
		if err != nil {
			return nil, err
		}
	}
	if err := c.Root.ReserveBatch(requests[:b.count], refs[:b.count]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	return b.adopt(refs[:b.count])
}

func (b *rpcServicesBatch) adopt(refs []resourcev4.Reference) (_ *RPCServices, err error) {
	if b == nil || !b.prepared || b.used || len(refs) != b.count {
		return nil, resourcev4.ErrOwner
	}
	b.used = true
	p, c := b.plan, b.config
	executor := p.executor
	for index, ref := range refs {
		if index == rpcServicesDeliveryFloor && b.deliveryFloor != nil {
			continue
		}
		if err := ref.CheckAllocationScope(c.Root, c.Owner, b.accountsFor(index)); err != nil {
			return nil, err
		}
	}
	shortBorrow, err := refs[rpcServicesShortCalls].Borrow()
	if err != nil {
		return nil, err
	}
	defer shortBorrow.Release()
	r := &RPCServices{resultReadBinding: c.ResultRead, deliveryFloor: b.deliveryFloor, plan: p, shortRequestBytes: c.ShortRequestBytes, shortResponseBytes: c.ShortResponseBytes, cryptoProfile: c.CryptoProfile, session: c.Session, clock: c.Clock, root: c.Root, owner: c.Owner, accountCount: len(c.Accounts), runtimeBytes: c.RuntimeBytes, hashRuntimeBytes: c.HashRuntimeBytes}
	r.generalCalls = make([]*unaryInvocation, c.Session.Limits().RPCMaxGeneralOutstanding)
	r.operations = make([]*UnaryOperation, c.Session.Limits().RPCMaxGeneralOutstanding)
	r.runtimeStop = make(chan struct{})
	if c.Session.Limits().ApplicationProfile == "execution" {
		r.managementResolver = c.ManagementResolver
		if r.managementResolver == nil {
			r.managementResolver = r
		}
		r.managementChanged = make(chan struct{})
		r.managementCallsDone = make(chan struct{})
	}
	r.notifyReceiverConfig, r.notifyPublisherConfig = c.notifyInputConfig(), c.notifyOutputConfig()
	r.notifyReceiverConfig.Accounts = nil
	r.completionGraceMS = c.CompletionGraceMS
	copy(r.accounts[:], c.Accounts)
	attached := false
	defer func() {
		if err == nil {
			return
		}
		r.Close()
		if attached {
			p.Close()
		} else {
			_ = r.retire()
		}
	}()
	for index, ref := range refs {
		if index == rpcServicesDeliveryFloor && b.deliveryFloor != nil {
			continue
		}
		r.refs[index], err = ref.Take(b.charges[index])
		if err != nil {
			return nil, err
		}
	}
	if c.Session.Limits().ApplicationProfile == "execution" && c.ExecutionRegistry != nil {
		r.executionRegistryBorrow, err = c.ExecutionRegistry.Borrow(r.refs[rpcServicesMetadata])
		if err != nil {
			return nil, err
		}
		r.executionRegistry = c.ExecutionRegistry
	}
	if err := r.adoptFutureChannels(c); err != nil {
		return nil, err
	}
	caller, _ := shortCallerCharges(c.RuntimeBytes, c.ShortRequestBytes, c.ShortResponseBytes)
	for index, charge := range caller {
		ref := r.refs[rpcServicesCallerMetadata+index]
		if index == 2 || index == 4 || index == 5 {
			anchor, e := ref.Borrow()
			if e != nil {
				return nil, e
			}
			var aliases []resourcev4.Reference
			if index == 4 {
				alias, e := ref.Borrow()
				if e != nil {
					anchor.Release()
					return nil, e
				}
				aliases = []resourcev4.Reference{alias}
			}
			r.shortCaller[index], err = resourcev4.NewProtectedResultReservation(ref, charge, anchor, aliases...)
			anchor.Release()
			for _, alias := range aliases {
				alias.Release()
			}
		} else {
			r.shortCaller[index], err = resourcev4.NewProtectedReservation(ref, charge)
		}
		if err != nil {
			return nil, err
		}
	}
	r.completionFloor, err = executor.NewCompletionFloor(r.refs[rpcServicesCompletionFloor], r.refs[rpcServicesMetadata])
	if err != nil {
		return nil, err
	}
	if c.ReferenceDomain != "" {
		r.referenceDomain = strings.Clone(c.ReferenceDomain)
		r.referenceCodec, err = protocolv4.NewOperationReferenceCodec()
		if err != nil {
			return nil, err
		}
	}
	r.network, err = rpcv4.NewNetwork(rpcv4.NetworkConfig{ProtectShortCall: true, Session: c.Session, Query: c.Query, ResultRead: c.ResultRead, RuntimeBytes: c.RuntimeBytes}, r.refs[rpcServicesNetwork])
	if err != nil {
		return nil, err
	}
	r.routes, err = rpcv4.NewContractRoutes(c.Routes, r.refs[rpcServicesRoutes])
	if err != nil {
		return nil, err
	}
	if err := checkContentReadRegistrations(c); err != nil {
		return nil, err
	}
	for _, method := range c.Methods {
		if err := r.routes.CheckMethodExecutionSupport(method.Method, c.ExecutionServices); err != nil {
			return nil, err
		}
	}
	for _, method := range c.StreamMethods {
		if err := r.routes.CheckMethodExecutionSupport(method.Method, c.ExecutionServices); err != nil {
			return nil, err
		}
	}
	for _, method := range c.NotificationMethods {
		if err := r.routes.CheckMethodExecutionSupport(method.Method, c.ExecutionServices); err != nil {
			return nil, err
		}
	}
	ic := c.inputConfig()
	ic.ShortReservation = r.refs[rpcServicesShortInput]
	r.inputs, err = r.network.NewServiceInputs(r.routes, ic, r.refs[rpcServicesInputs])
	if err != nil {
		return nil, err
	}
	r.incoming, err = r.network.NewContractQueryService(r.routes, c.Clock, r.refs[rpcServicesQueryServer], c.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	r.outgoing, err = r.network.NewContractQueryClient(c.Clock, r.refs[rpcServicesQueryClient], c.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	// Original execution promises must succeed before the plan is attached.
	// History-capacity failure retires this whole batch and leaves the caller's
	// unclaimed plan available for a later original admission.
	dc := c.dispatchConfig()
	copy(dc.ShortReservations[:], r.refs[rpcServicesShortCalls:rpcServicesShortCalls+5])
	dc.ShortExecutionBorrow = shortBorrow
	b.installExecutionReferences(&dc, r)
	dispatch, err := p.InstallServices(dc, r.network, r.refs[rpcServicesDispatch])
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.dispatch = dispatch
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	p.rpc = r
	attached = true
	p.mu.Unlock()
	if err = p.InstallContractQueries(r.incoming); err != nil {
		return nil, err
	}
	if err = p.InstallOutgoingContractQueries(r.outgoing); err != nil {
		return nil, err
	}
	notifications, err := p.InstallNotifications(c.notificationConfig(), r.routes, r.refs[rpcServicesNotifyDispatch])
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.notifications = notifications
	closed = r.closed
	r.mu.Unlock()
	if closed {
		notifications.Close()
		return nil, cryptov4.ErrClosed
	}
	b.deliveryFloor = nil
	return r, nil
}

// PrepareBootstrap binds the fixed flow before READY using the aggregate's
// original send/queue/ownership reservations and the core's receive pool.
// There is no dynamic OPEN, second shared reader, or post-READY root reserve.
func (r *RPCServices) PrepareBootstrap(g *SharedIngress, pool *ReceivePool, output io.Writer) (*Bootstrap, error) {
	if r == nil || g == nil || pool == nil || output == nil {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired || r.bootstrap != nil {
		return nil, cryptov4.ErrTransition
	}
	a := g.admission
	_, profile := a.engine.SessionBinding()
	if a.engine.SessionParameters().Contract != r.session || a.engine.Clock() != r.clock || profile != r.cryptoProfile {
		return nil, cryptov4.ErrConfiguration
	}
	if err := pool.reservation.CheckAllocationScope(r.root, r.owner, r.accounts[:r.accountCount]); err != nil {
		return nil, err
	}
	if err := g.receiver.reservation.CheckAllocationScope(r.root, r.owner, r.accounts[:r.accountCount]); err != nil {
		return nil, err
	}
	if err := r.prepareReceiveLocked(pool); err != nil {
		return nil, err
	}
	allocation, err := r.checkoutChannelAllocationLocked(&r.firstFuture, 0)
	if err != nil {
		return nil, err
	}
	r.firstAllocation = allocation
	b, err := g.PrepareBootstrap(allocation.stream.reservation, output)
	if err != nil {
		allocation.release()
		r.firstAllocation = nil
		return nil, err
	}
	r.bootstrap = b
	return b, nil
}

// OpenFirstChannel runs after the original fixed prefix has materialized. A
// pending prefix leaves the original reservations untouched. Success transfers
// this exact Stream owner to the channel; a partial failure remains owned here.
func (r *RPCServices) OpenFirstChannel(identity [16]byte) (*RPCChannel, error) {
	if r == nil {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.bound || r.bootstrap == nil || r.dispatch == nil {
		return nil, cryptov4.ErrTransition
	}
	if identity == ([16]byte{}) {
		return nil, cryptov4.ErrConfiguration
	}
	if r.stream == nil {
		stream, err := r.bootstrap.admission.OwnStream(r.bootstrap.handle, r.firstAllocation.stream.refs[streamFactoryOwnership])
		if err != nil {
			return nil, err
		}
		r.stream = stream
	}
	return r.bindFirstChannelLocked(r.stream, identity)
}

// The first fixed channel consumes only its original preadmitted references.
func (r *RPCServices) bindFirstChannelLocked(stream *StreamOwnership, identity [16]byte) (_ *RPCChannel, err error) {
	if r.closed || r.retired || r.bound || r.dispatch == nil {
		return nil, cryptov4.ErrTransition
	}
	a := stream.admission
	if a == nil || a.engine.SessionParameters().Contract != r.session || a.engine.Clock() != r.clock {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	fixed := a.bootstrap != nil && a.bootstrap.handle == stream.handle && a.bootstrap.complete && a.bootstrap.materialized
	a.mu.Unlock()
	if !fixed {
		return nil, ErrOpenAssociation
	}
	if err := stream.reservation.CheckAllocationScope(r.root, r.owner, r.accounts[:r.accountCount]); err != nil {
		return nil, err
	}
	// Attempting construction consumes this first-channel opportunity. Partial
	// constructors close their original pieces; they do not justify new owners.
	r.bound = true
	channel, err := NewRPCChannel(stream, r.network, identity, r.inputs,
		r.firstAllocation.rpc[0], r.firstAllocation.rpc[1], r.firstAllocation.rpc[2], r.firstAllocation.rpc[3], r.runtimeBytes)
	if err != nil {
		return nil, err
	}
	r.channel = channel
	if err := r.dispatch.AttachChannel(channel.Receiver(), channel.Publisher()); err != nil {
		channel.Close()
		return nil, err
	}
	return channel, nil
}

func (r *RPCServices) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		if r.managementChanged != nil {
			r.signalManagementLocked()
			if r.managementCalls == 0 {
				close(r.managementCallsDone)
			}
		}
		if r.runtimeStop != nil {
			close(r.runtimeStop)
		}
	}
	for _, job := range r.dynamicChannels {
		if job != nil {
			job.cancel()
			if job.channel != nil {
				job.channel.Close()
			}
		}
	}
	if job := r.management; job != nil {
		job.cancel()
		if job.channel != nil {
			job.channel.Close()
		}
	}
	channel, network, routes, inputs, incoming, outgoing := r.channel, r.network, r.routes, r.inputs, r.incoming, r.outgoing
	for _, job := range r.notifyChannels {
		if job != nil {
			job.cancel()
			if job.channel != nil {
				job.channel.Close()
			}
		}
	}
	stream, bootstrap := r.stream, r.bootstrap
	floor, deliveryFloor := r.completionFloor, r.deliveryFloor
	notifications := r.notifications
	for _, guard := range r.receiveProtection {
		guard.Close()
	}
	for _, future := range r.futureChannels {
		for _, owner := range future.owners {
			owner.Close()
		}
	}
	for _, owner := range r.firstFuture.owners {
		owner.Close()
	}
	for _, protected := range r.shortCaller {
		protected.CloseAfterUse()
	}
	r.mu.Unlock()
	r.advanceOperations()
	deliveryFloor.Close()
	floor.Close()
	if notifications != nil {
		notifications.Close()
	}
	if channel != nil {
		channel.Close()
	} else if stream != nil {
		_ = stream.Cancel()
	} else if bootstrap != nil {
		_ = bootstrap.admission.Cancel(bootstrap.handle)
	}
	if outgoing != nil {
		outgoing.Close()
	}
	if incoming != nil {
		incoming.Close()
	}
	if inputs != nil {
		inputs.Close()
	}
	if routes != nil {
		routes.Close()
	}
	if network != nil {
		network.Close()
	}
	r.AdvanceCalls()
}
func (r *RPCServices) waitChannel(ctx context.Context) error {
	r.mu.Lock()
	channel, stream := r.channel, r.stream
	jobs := r.dynamicChannels
	notifyJobs := r.notifyChannels
	managementJob, managementCallsDone := r.management, r.managementCallsDone
	r.mu.Unlock()
	if managementCallsDone != nil {
		select {
		case <-managementCallsDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if managementJob != nil {
		select {
		case <-managementJob.done:
			if managementJob.cleanupError != nil {
				return managementJob.cleanupError
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for _, job := range notifyJobs {
		if job != nil {
			select {
			case <-job.done:
				if job.cleanupError != nil {
					return job.cleanupError
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	for _, job := range jobs {
		if job != nil {
			select {
			case <-job.done:
				if job.cleanupError != nil {
					return job.cleanupError
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if channel == nil {
		if stream != nil {
			if err := stream.Cleanup(ctx); err != nil {
				return err
			}
			return stream.Release()
		}
		return nil
	}
	if err := channel.WaitCleanup(ctx); err != nil {
		return err
	}
	return r.waitCalls(ctx)
}

func (p *SessionPlan) waitRPCChannel(ctx context.Context) error {
	p.mu.Lock()
	r, preparing := p.rpc, p.rpcPreparing
	p.mu.Unlock()
	if preparing {
		return cryptov4.ErrCapacity
	}
	if r == nil {
		return nil
	}
	return r.waitChannel(ctx)
}
func (r *RPCServices) retire() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired {
		return nil
	}
	if !r.closed {
		return cryptov4.ErrCapacity
	}
	if r.management != nil || r.managementCalls != 0 {
		return cryptov4.ErrCapacity
	}
	for _, job := range r.notifyChannels {
		if job != nil {
			return cryptov4.ErrCapacity
		}
	}
	if r.notifications != nil {
		select {
		case <-r.notifications.done:
		default:
			return cryptov4.ErrCapacity
		}
	}
	for _, job := range r.dynamicChannels {
		if job != nil {
			return cryptov4.ErrCapacity
		}
	}
	if r.firstAllocation != nil {
		r.firstAllocation.release()
		r.firstAllocation = nil
	}
	for _, owner := range r.firstFuture.owners {
		if !owner.CleanupComplete() {
			return cryptov4.ErrCapacity
		}
	}
	if r.localCall != nil || !r.completionFloor.CleanupComplete() {
		return cryptov4.ErrCapacity
	}
	for _, call := range r.generalCalls {
		if call != nil {
			return cryptov4.ErrCapacity
		}
	}
	for _, operation := range r.operations {
		if operation != nil {
			return cryptov4.ErrCapacity
		}
	}
	for _, future := range r.futureChannels {
		for _, owner := range future.owners {
			if !owner.CleanupComplete() {
				return cryptov4.ErrCapacity
			}
		}
	}
	for _, protected := range r.shortCaller {
		if !protected.CleanupComplete() {
			return cryptov4.ErrCapacity
		}
	}
	if r.bootstrap != nil {
		a := r.bootstrap.admission
		a.mu.Lock()
		retired := a.retired
		a.mu.Unlock()
		if !retired {
			return cryptov4.ErrCapacity
		}
	}
	if r.network != nil && !r.network.Snapshot().CleanupComplete || !r.inputs.CleanupComplete() || !r.routes.CleanupComplete() || !r.incoming.CleanupComplete() || !r.outgoing.CleanupComplete() {
		return cryptov4.ErrCapacity
	}
	for index, ref := range r.refs {
		ref.Release()
		r.refs[index] = resourcev4.Reference{}
	}
	r.channel, r.dispatch, r.network, r.routes, r.inputs, r.incoming, r.outgoing = nil, nil, nil, nil, nil, nil, nil
	r.notifications = nil
	r.executionRegistryBorrow.Release()
	r.executionRegistryBorrow = resourcev4.Reference{}
	r.executionRegistry, r.managementResolver = nil, nil
	r.notifyReceiverConfig = rpcv4.NotifyReceiverConfig{}
	r.notifyPublisherConfig = rpcv4.NotifyPublisherConfig{}
	r.clock, r.root = nil, nil
	r.completionFloor = nil
	r.deliveryFloor = nil
	r.plan = nil
	r.generalCalls = nil
	r.operations = nil
	r.publication = nil
	r.runtimeContext = nil
	r.firstFuture = internalChannelFuture{}
	clear(r.shortCaller[:])
	r.bootstrap, r.stream = nil, nil
	r.receivePool = nil
	clear(r.receiveProtection[:])
	clear(r.futureChannels[:])
	clear(r.accounts[:])
	r.retired = true
	return nil
}
