package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// SessionCoreConfig is the immutable transport part of a complete SessionPlan.
// It admits shared message carriers and shared/native byte carriers. Services
// and execution profiles require the original aggregate application admission.
// Application handlers, Stream payload storage, provider handles,
// trust and durable spend remain separately admitted original owners.
// RuntimeBytes supplies the deployment's non-Engine allocation/channel/stack
// allowance; this source-sized minimum does not qualify a runtime or provider.
type SessionCoreConfig struct {
	applicationServices                    bool
	Session                                protocolv4.ArtifactSessionParameters
	Clock                                  *timev4.Clock
	LocalIdleDurationMS                    uint64
	Open                                   OpenLimits
	MaxScopes, PendingScopes, WorkSlots    uint32
	Datagrams                              bool
	Maintenance                            cryptov4.MaintenanceReserve
	EngineResources                        cryptov4.EngineResourceOptions
	RuntimeBytes                           uint64
	Native, MessageCarrier                 bool
	MessageRuntimeBytes                    uint64
	Streams                                SessionStreamConfig
	Handlers                               SessionStreamHandlerConfig
	DecoderNodes                           int
	MaxDataPayloadBytes                    uint64
	SendWorkers                            [3]uint32
	NativeAuthWorkers                      uint32
	ProbeSlots, PongSlots, RekeyWaitSlots  uint32
	Automatic                              AutomaticLivenessPolicy
	Messages                               MaintenanceMessagePolicy
	Termination                            StreamTerminationPolicy
	Rekey                                  RekeyPhaseBudgets
	SharedDiscard                          SharedDiscardPolicy
	NativeIngress                          MaintenanceIngressPolicy
	DispatchTimeoutMS, RetirementTimeoutMS uint64
	DrainTimeoutMS                         uint64
}

const (
	corePlanOwner = iota
	coreEngineOwner
	coreOpenOwner
	coreLivenessOwner
	coreMessagesOwner
	coreTerminationOwner
	coreRekeyOwner
	coreRetirementOwner
	coreIngressOwner
	coreIngressReceiverOwner
	coreRuntimeOwner
	coreCarrierOwner
	coreReceivePoolOwner
	coreHandlersOwner
	coreSendOwner
	coreNativeAuthOwner
	coreLifecycleOwner
	coreNativeReceiverStart
	coreOwnerCapacity = coreNativeReceiverStart + 128
)

// SessionResourceScope is resolved by trusted local composition from verified
// tenant identity. These exact same-root account handles, including their
// generations, follow every core and dynamic Stream charge. They are local
// capacity fences, not proof of identity, spend or admission authority.
type SessionResourceScope struct {
	Tenant, Session resourcev4.Account
}

// SessionCorePlan owns every original claim from atomic reservation through
// physical retirement. Claim is once-only even if Noise or READY later fails.
// Constructor work and cleanup observation use the caller's original position;
// cancellation never launches another cleanup worker or refunds a live tail.
type SessionCorePlan struct {
	preaccepted                                                                        [maxPreacceptedStreams]*preacceptedStream
	mu                                                                                 sync.Mutex
	config                                                                             SessionCoreConfig
	refs                                                                               [coreOwnerCapacity]resourcev4.Reference
	environment, sharedEnvironment                                                     resourcev4.Reference
	engineEnvironment, carrierEnvironment                                              resourcev4.Reference
	role                                                                               protocolv4.Direction
	claimed, preparing, installing, busy, closed, cleaning, cleaned, retiring, retired bool
	wake, cleanup                                                                      chan struct{}
	engine                                                                             *cryptov4.Engine
	initial                                                                            *InitialExchange
	admission                                                                          *OpenAdmission
	runtime                                                                            *SessionRuntime
	writer                                                                             *RecordWriter
	input                                                                              sessionCoreCarrier
	receivePool                                                                        *ReceivePool
	dispatcher                                                                         *sessionStreamDispatcher
	rpc                                                                                *RPCServices
	application                                                                        *SessionPlan
	root                                                                               *resourcev4.Root
	resourceOwner                                                                      resourcev4.OwnerKey
	accounts                                                                           [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount                                                                       int
	streamMethods                                                                      uint32
	streamCalls                                                                        uint64
	carrier                                                                            CarrierAssociation
	probes                                                                             []ProbeSlot
	pongs                                                                              []PongSlot
	rekeyWait                                                                          []RekeyWaitSlot
	core                                                                               SessionCore
	drain                                                                              *DrainOperation
}

// SessionCore exposes the assembled private transport owner. Authentication
// still decides when dual READY permits its original Engine to run.
type SessionCore struct{ plan *SessionCorePlan }

type sessionCoreCarrier interface {
	RuntimeInput
	io.WriteCloser
	WaitCleanup(context.Context) error
	Retire() error
}

func (c SessionCoreConfig) messageOptions() SessionMessageInputOptions {
	return SessionMessageInputOptions{MaxFrame: c.Session.Contract.Limits().MaxFrame, WriteSlots: c.WorkSlots + 2, RuntimeBytes: c.MessageRuntimeBytes}
}

func (c SessionCoreConfig) records(role protocolv4.Direction) cryptov4.Config {
	signed := c.Session.Contract.Limits()
	return cryptov4.Config{Profile: c.Session.Profile, ApplicationProfile: signed.ApplicationProfile,
		SendDirection: role, MaxFrame: signed.MaxFrame, MaxScopes: c.MaxScopes,
		SignedMaxScopes: signed.MaxStreams, PendingScopes: c.PendingScopes, WorkSlots: c.WorkSlots,
		Datagrams: c.Datagrams, Maintenance: c.Maintenance, Clock: c.Clock, IdleDurationMS: signed.IdleDurationMS, LocalIdleDurationMS: c.LocalIdleDurationMS}
}

func (c SessionCoreConfig) decode() protocolv4.DecodeContext {
	return protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": c.MaxDataPayloadBytes}}
}

type coreKeyLimits struct {
	Seal   uint64 `json:"seal_calls,string"`
	Open   uint64 `json:"open_attempts,string"`
	Blocks uint64 `json:"authentication_blocks,string"`
	Bytes  uint64 `json:"ciphertext_bytes,string"`
}

var coreUsageRegistry = sync.OnceValues(func() (map[string]struct{ Key coreKeyLimits }, error) {
	var registry struct {
		Profiles map[string]struct{ Key coreKeyLimits }
	}
	err := json.Unmarshal([]byte(protocolv4.CryptoUsageRegistryJSON), &registry)
	return registry.Profiles, err
})

func (c SessionCoreConfig) validateTime() error {
	if c.Clock == nil {
		return cryptov4.ErrConfiguration
	}
	signed := c.Session.Contract.Limits()
	if _, err := AdmitRekeyService(c.Session.Profile, signed.Rekey, c.Clock.Profile().Rate, c.Session.IssuedAtMS, c.Session.SessionNotAfterMS); err != nil {
		return err
	}
	deadline, err := timev4.NewDeadline(c.Clock, c.Session.SessionNotAfterMS)
	if err != nil {
		return err
	}
	now, err := deadline.Sample()
	if err != nil {
		return err
	}
	if err := now.LowerBound(c.Session.IssuedAtMS, true); err != nil {
		return err
	}
	if c.Clock.Profile().MaxWidthMS >= min(c.Rekey.ProtocolPrepareMS, c.Rekey.ConfirmationMS) {
		return cryptov4.ErrConfiguration
	}
	_, uncertainty, err := elapsedCredit(c.Clock.Profile().Rate, 0)
	if err != nil || uncertainty >= min(c.Rekey.LocalPrepareMS, c.Rekey.ProtocolPrepareMS, c.Rekey.ConfirmationMS) {
		return cryptov4.ErrConfiguration
	}
	for _, duration := range [...]uint64{c.Automatic.SubmissionMS + c.Automatic.ResponseMS, c.Messages.ReplyTimeoutMS, c.Termination.NormalMS, c.Termination.QuarantineMS, c.Rekey.LocalPrepareMS} {
		if _, err := timev4.NewWindow(c.Clock, duration); err != nil {
			return err
		}
	}
	for _, duration := range [...]uint64{c.Automatic.IntervalMS, c.Messages.IngressRefillMS} {
		if _, err := timev4.NewDelay(c.Clock, duration); err != nil {
			return err
		}
	}
	for _, duration := range [...]uint64{c.DispatchTimeoutMS, c.RetirementTimeoutMS} {
		if _, err := timev4.NewAge(c.Clock, duration, math.MaxUint64); err != nil {
			return err
		}
	}
	if c.DrainTimeoutMS != 0 {
		if _, err := timev4.NewAge(c.Clock, c.DrainTimeoutMS, math.MaxUint64); err != nil {
			return err
		}
	}
	if c.Native {
		if _, err := timev4.NewWindow(c.Clock, c.NativeIngress.FrameTimeoutMS); err != nil {
			return err
		}
		if _, err := timev4.NewDelay(c.Clock, c.NativeIngress.RefillMS); err != nil {
			return err
		}
	} else if _, err := timev4.NewWindow(c.Clock, c.SharedDiscard.DurationMS); err != nil {
		return err
	}
	_, err = timev4.NewIdle(c.Clock, signed.IdleDurationMS, c.LocalIdleDurationMS)
	return err
}

func sessionCoreCharges(c SessionCoreConfig) (charges [coreOwnerCapacity]resourcev4.Vector, total resourcev4.Vector, count uint32, err error) {
	if c.Handlers != (SessionStreamHandlerConfig{}) {
		if c.Native || c.Handlers.Plan != nil && c.Streams == (SessionStreamConfig{}) || uint64(c.Handlers.Concurrency) > uint64(c.Open.Opening)+uint64(c.Open.IngressItems) {
			err = cryptov4.ErrConfiguration
			return
		}
		charges[coreHandlersOwner], err = sessionStreamDispatcherCharge(c.Handlers)
		if err != nil {
			return
		}
	}
	signed := c.Session.Contract.Limits()
	profileSupported := signed.ApplicationProfile == "transport" && !c.applicationServices || c.applicationServices && (signed.ApplicationProfile == "services" || signed.ApplicationProfile == "execution")
	if !c.Session.Contract.Valid() || !profileSupported || c.Session.SessionNotAfterMS <= c.Session.IssuedAtMS || c.Native && c.MessageCarrier ||
		c.RuntimeBytes == 0 || c.DecoderNodes <= 0 || c.MaxDataPayloadBytes == 0 || c.MaxDataPayloadBytes > uint64(signed.MaxFrame) ||
		c.Open.Active > c.MaxScopes || c.Open.IngressItems > c.PendingScopes || c.ProbeSlots == 0 || c.ProbeSlots > 8 || c.PongSlots == 0 || c.PongSlots > c.Messages.IngressBurst ||
		c.DispatchTimeoutMS == 0 || c.RetirementTimeoutMS == 0 || c.Automatic.IntervalMS == 0 || c.Automatic.SubmissionMS == 0 || c.Automatic.ResponseMS == 0 || c.Automatic.MissThreshold == 0 || c.Automatic.SubmissionMS > math.MaxUint64-c.Automatic.ResponseMS ||
		c.Messages.IngressRefillMS == 0 || c.Messages.ReplyTimeoutMS == 0 || c.Termination.NormalMS == 0 || c.Termination.QuarantineMS == 0 || c.Termination.NormalMS > math.MaxUint64-c.Termination.QuarantineMS || c.Termination.QuarantineDirections == 0 || c.Termination.QuarantineDirections > 32 || c.Termination.QuarantineMS > 10000 ||
		c.Rekey.LocalPrepareMS == 0 || c.Rekey.ProtocolPrepareMS == 0 || c.Rekey.ConfirmationMS == 0 {
		err = cryptov4.ErrConfiguration
		return
	}
	var send uint64
	for class, workers := range c.SendWorkers {
		if (c.Open.PerClass[class] == 0) != (workers == 0) {
			err = cryptov4.ErrConfiguration
			return
		}
		send += uint64(workers)
	}
	if c.Open.Active == 0 && (send != 0 || c.NativeAuthWorkers != 0) || c.Open.Active != 0 && send == 0 || send > 128 {
		err = cryptov4.ErrConfiguration
		return
	}
	if c.Native {
		if c.NativeIngress.FrameTimeoutMS == 0 || c.NativeIngress.RefillMS == 0 || c.NativeIngress.Burst == 0 || c.Open.Active != 0 && (c.NativeAuthWorkers == 0 || c.NativeAuthWorkers > 128) || send+uint64(c.NativeAuthWorkers) > uint64(c.WorkSlots) {
			err = cryptov4.ErrConfiguration
			return
		}
	} else if c.NativeAuthWorkers != 0 || c.SharedDiscard.MaxRecords == 0 || c.SharedDiscard.MaxBytes == 0 || c.SharedDiscard.DurationMS == 0 || send+1 > uint64(c.WorkSlots) {
		err = cryptov4.ErrConfiguration
		return
	}
	maxInt := uint64(^uint(0) >> 1)
	if uint64(c.PongSlots) > maxInt/uint64(unsafe.Sizeof(PongSlot{})) || uint64(c.RekeyWaitSlots) > maxInt/uint64(unsafe.Sizeof(RekeyWaitSlot{})) {
		err = cryptov4.ErrConfiguration
		return
	}
	usage, e := coreUsageRegistry()
	if e != nil {
		err = e
		return
	}
	key, ok := usage[c.Session.Profile]
	if !ok || c.Maintenance.Calls == 0 || c.Maintenance.Blocks == 0 || c.Maintenance.Bytes == 0 || c.Maintenance.Calls >= min(key.Key.Seal, key.Key.Open) || c.Maintenance.Blocks >= key.Key.Blocks || c.Maintenance.Bytes >= key.Key.Bytes {
		err = cryptov4.ErrConfiguration
		return
	}
	if err = c.validateTime(); err != nil {
		return
	}
	if c.Streams != (SessionStreamConfig{}) {
		if c.Native || c.Open.Active == 0 || c.Streams.InitialReceiveLimit > signed.MaxCredit {
			err = cryptov4.ErrConfiguration
			return
		}
		if _, err = sessionStreamCharges(c.Streams, c.Session.Profile, uint64(signed.MaxFrame), c.MaxDataPayloadBytes, 0); err != nil {
			return
		}
		charges[coreReceivePoolOwner], err = ReceivePoolCharge(c.Streams.ReceivePoolBytes, c.Open.Active)
		if err != nil {
			return
		}
	}
	// ProbeSlot and PongSlot arrays are already included in their service
	// charges. The remaining original rekey causes/credit and writer belong here.
	metadata := uint64(unsafe.Sizeof(SessionCorePlan{})) + uint64(unsafe.Sizeof(RecordWriter{})) + uint64(unsafe.Sizeof(RekeyCredit{})) + uint64(unsafe.Sizeof(RekeyCauses{})) + uint64(unsafe.Sizeof(RekeyIntent{})) + uint64(unsafe.Sizeof(RekeyCharge{})) + 2*uint64(unsafe.Sizeof(rekeyTiming{})) + 4*uint64(unsafe.Sizeof(timev4.Deadline{})) + 2*uint64(unsafe.Sizeof(timev4.Window{}))
	// Each manual waiter can retain a different completed intent across later
	// rounds. Those original identities and security caps outlive current intent.
	metadata += uint64(c.RekeyWaitSlots) * (uint64(unsafe.Sizeof(RekeyWaitSlot{})) + uint64(unsafe.Sizeof(RekeyIntent{})) + uint64(unsafe.Sizeof(timev4.Deadline{})))
	charges[corePlanOwner], err = (resourcev4.Vector{resourcev4.SDKBytes: metadata, resourcev4.Items: 16 + 3*uint64(c.RekeyWaitSlots), resourcev4.Sessions: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return
	}
	charges[coreEngineOwner], err = cryptov4.EngineCharge(c.records(0), c.EngineResources)
	if err != nil {
		return
	}
	charges[coreOpenOwner], err = OpenAdmissionCharge(c.Open)
	if err != nil {
		return
	}
	charges[coreLivenessOwner], err = LivenessCharge(int(c.ProbeSlots), true)
	if err != nil {
		return
	}
	charges[coreMessagesOwner], err = MaintenanceMessagesCharge(int(c.PongSlots))
	if err != nil {
		return
	}
	charges[coreTerminationOwner], err = StreamTerminationServiceCharge(c.Open.Active)
	if err != nil {
		return
	}
	barriers, e := protocolv4.FieldItemLimit("REKEY_INIT", "client_barrier")
	if e != nil {
		err = e
		return
	}
	charges[coreRekeyOwner] = RekeyServiceCharge(signed.MaxFrame, min(signed.MaxStreams, uint32(barriers)))
	charges[coreRetirementOwner], err = RetirementServiceCharge()
	if err != nil {
		return
	}
	charges[coreRuntimeOwner] = SessionRuntimeCharge()
	charges[coreLifecycleOwner] = SessionLifecycleCharge()
	if c.MessageCarrier {
		charges[coreCarrierOwner], err = SessionMessageInputCharge(c.messageOptions())
	} else {
		charges[coreCarrierOwner], err = sessionStreamInputCharge(c.WorkSlots + 2)
	}
	if err != nil {
		return
	}
	if c.Open.Active != 0 {
		charges[coreSendOwner], err = SendServiceCharge(c.Open.Active, c.SendWorkers)
		if err != nil {
			return
		}
	}
	decode := c.decode()
	if c.Native {
		charges[coreIngressOwner], err = MaintenanceIngressCharge(signed.MaxFrame)
		if err != nil {
			return
		}
		charges[coreIngressReceiverOwner], err = RecordReceiverCharge(signed.MaxFrame, c.DecoderNodes, decode)
		if err != nil {
			return
		}
		if c.Open.Active != 0 {
			charges[coreNativeAuthOwner], err = NativeAuthServiceCharge(c.Open.Active, c.NativeAuthWorkers)
			if err != nil {
				return
			}
			for i := uint32(0); i < c.NativeAuthWorkers; i++ {
				charges[coreNativeReceiverStart+int(i)] = charges[coreIngressReceiverOwner]
			}
		}
	} else {
		charges[coreIngressOwner], err = SharedIngressCharge(signed.MaxFrame, c.DecoderNodes, decode)
		if err != nil {
			return
		}
	}
	for _, charge := range charges {
		if charge != (resourcev4.Vector{}) {
			total, err = total.Add(charge)
			if err != nil {
				return
			}
			count++
		}
	}
	return
}

// SessionCoreRequirements gives the batch's complete vector and distinct owner
// count. The root also needs its own slab charge and two Environment reference
// positions (plan and Engine), plus a third for message carriers, in addition
// to the original Environment owner. All are acquired by the constructor.
func SessionCoreRequirements(c SessionCoreConfig) (resourcev4.Vector, uint32, error) {
	_, total, count, err := sessionCoreCharges(c)
	return total, count, err
}

// sessionCoreBatch is scratch on the original admitted construction stack. It
// is not a reusable configuration or a public adoption capability. Preparation
// freezes every charge/account and acquires the exact Environment borrows;
// the enclosing owner may then include requests in its single ReserveBatch.
// Requests and adoption stay on this original synchronous construction path.
type sessionCoreBatch struct {
	receivePool    *ReceivePool
	config         SessionCoreConfig
	root           *resourcev4.Root
	owner          resourcev4.OwnerKey
	environment    resourcev4.Reference
	scope          SessionResourceScope
	charges        [coreOwnerCapacity]resourcev4.Vector
	positions      [coreOwnerCapacity]int
	accounts       [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	borrows        [3]resourcev4.Reference
	count          int
	accountCount   int
	prepared, used bool
}

func prepareSessionCoreBatch(b *sessionCoreBatch, c SessionCoreConfig, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, scope SessionResourceScope, accounts ...resourcev4.Account) error {
	if b == nil || b.prepared || b.used || owner.Backing == ([16]byte{}) || len(accounts) > resourcev4.MaxAccountsPerCharge-2 {
		return resourcev4.ErrOwner
	}
	charges, _, _, err := sessionCoreCharges(c)
	if err != nil {
		return err
	}
	if c.Handlers.Plan != nil {
		if err := c.Handlers.Plan.CheckEnvironment(environment); err != nil {
			return err
		}
	}
	*b = sessionCoreBatch{config: c, root: root, owner: owner, environment: environment, scope: scope, charges: charges, accountCount: len(accounts) + 2}
	b.accounts[0], b.accounts[1] = scope.Tenant, scope.Session
	copy(b.accounts[2:], accounts)
	borrows := 2
	if c.MessageCarrier {
		borrows++
	}
	for i := 0; i < borrows; i++ {
		b.borrows[i], err = environment.Borrow()
		if err != nil {
			b.release()
			return err
		}
	}
	for position, charge := range charges {
		if charge != (resourcev4.Vector{}) {
			b.positions[b.count] = position
			b.count++
		}
	}
	b.prepared = true
	return nil
}

// request returns one frozen entry for the enclosing stack-owned batch. The
// account slice must not outlive that original ReserveBatch call. Returning an
// entry by value keeps this scratch on the caller's stack; writing its account
// slice through a caller-provided output pointer would make the batch escape.
func (b *sessionCoreBatch) request(index int) (resourcev4.Request, error) {
	if b == nil || !b.prepared || b.used || index < 0 || index >= b.count {
		return resourcev4.Request{}, resourcev4.ErrOwner
	}
	position := b.positions[index]
	key := b.owner
	var identity [20]byte
	copy(identity[:16], b.owner.Backing[:])
	binary.BigEndian.PutUint32(identity[16:], uint32(position))
	digest := sha256.Sum256(identity[:])
	copy(key.Backing[:], digest[:16])
	return resourcev4.Request{Owner: key, Charge: b.charges[position], Accounts: b.accounts[:b.accountCount]}, nil
}

// release ends this construction and returns only its Environment borrows.
// The enclosing owner always releases its original ReserveBatch output after
// adoption, including on error: Take has invalidated the copies that moved.
func (b *sessionCoreBatch) release() {
	if b == nil {
		return
	}
	b.used = true
	if b.receivePool != nil {
		b.receivePool.Close()
		b.receivePool = nil
	}
	for i, ref := range b.borrows {
		ref.Release()
		b.borrows[i] = resourcev4.Reference{}
	}
}

// Receive storage is an original admitted owner before spend, including the
// reference positions needed for future internal-channel reservations.
func (b *sessionCoreBatch) prepareReceivePool(refs []resourcev4.Reference) error {
	if b.config.Streams == (SessionStreamConfig{}) || b.receivePool != nil {
		return nil
	}
	if !b.prepared || b.used || len(refs) != b.count {
		return resourcev4.ErrOwner
	}
	for i, position := range b.positions[:b.count] {
		if position != coreReceivePoolOwner {
			continue
		}
		if err := refs[i].CheckAllocationScope(b.root, b.owner, b.accounts[:b.accountCount]); err != nil {
			return err
		}
		pool, err := NewReceivePool(b.config.Session.Contract.Limits().MaxCredit, b.config.Streams.ReceivePoolBytes, b.config.Open.Active, refs[i])
		if err != nil {
			return err
		}
		b.receivePool = pool
		return nil
	}
	return cryptov4.ErrConfiguration
}

// adopt consumes this preparation once, using only its original core prefix
// from the enclosing ReserveBatch. It admits no charge or reference position.
// On failure it releases the core references already taken and its own borrows;
// the caller still owns every not-yet-taken original output, including all
// non-core aggregate entries. Handler claim is the final fallible operation.
func (b *sessionCoreBatch) adopt(refs []resourcev4.Reference) (_ *SessionCorePlan, err error) {
	if b == nil || !b.prepared || b.used {
		return nil, resourcev4.ErrOwner
	}
	if err := b.prepareReceivePool(refs); err != nil {
		return nil, err
	}
	b.used = true
	defer b.release()
	if len(refs) != b.count {
		return nil, resourcev4.ErrOwner
	}
	var taken [coreOwnerCapacity]resourcev4.Reference
	defer func() {
		if err != nil {
			for _, ref := range taken {
				ref.Release()
			}
		}
	}()
	for i, ref := range refs {
		position := b.positions[i]
		if position == coreReceivePoolOwner && b.receivePool != nil {
			continue
		}
		if err = ref.CheckSameEnvironment(b.environment); err != nil {
			return nil, err
		}
		taken[position], err = ref.Take(b.charges[position])
		if err != nil {
			return nil, err
		}
	}
	if err = taken[corePlanOwner].CheckSessionScope(b.scope.Tenant, b.scope.Session); err != nil {
		return nil, err
	}
	for i, ref := range b.borrows {
		if ref == (resourcev4.Reference{}) {
			continue
		}
		b.borrows[i], err = ref.TakeBorrow()
		if err != nil {
			// A failed move leaves the original borrow owned by this batch.
			b.borrows[i] = ref
			return nil, err
		}
	}
	if b.config.Handlers.Plan != nil {
		if err = b.config.Handlers.Plan.claimSession(); err != nil {
			return nil, err
		}
	}
	p := &SessionCorePlan{config: b.config, refs: taken, environment: b.borrows[0], sharedEnvironment: b.borrows[0], engineEnvironment: b.borrows[1], carrierEnvironment: b.borrows[2], wake: make(chan struct{}, 1), cleanup: make(chan struct{})}
	p.receivePool, b.receivePool = b.receivePool, nil
	p.root, p.resourceOwner, p.accountCount, p.accounts = b.root, b.owner, b.accountCount, b.accounts
	clear(b.borrows[:])
	p.core.plan = p
	return p, nil
}

// NewSessionCorePlan completes one atomic batch before allocating any service.
// Accounts are used only during this call; caller maps, slices and queues never
// become retained plan configuration. Owner must identify this unique Session.
// One root/tenant/Session slot is acquired in the same batch as all core bytes
// and work. Logical close keeps that slot until the final physical retirement.
func NewSessionCorePlan(c SessionCoreConfig, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, scope SessionResourceScope, accounts ...resourcev4.Account) (*SessionCorePlan, error) {
	var batch sessionCoreBatch
	if err := prepareSessionCoreBatch(&batch, c, root, owner, environment, scope, accounts...); err != nil {
		return nil, err
	}
	defer batch.release()
	var requests [coreOwnerCapacity]resourcev4.Request
	var refs [coreOwnerCapacity]resourcev4.Reference
	for i := 0; i < batch.count; i++ {
		request, err := batch.request(i)
		if err != nil {
			return nil, err
		}
		requests[i] = request
	}
	if err := root.ReserveBatch(requests[:batch.count], refs[:batch.count]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs[:batch.count] {
			ref.Release()
		}
	}()
	return batch.adopt(refs[:batch.count])
}

func (p *SessionCorePlan) records() cryptov4.Config {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.config.records(p.role)
}

func (p *SessionCorePlan) CheckEnvironment(ref resourcev4.Reference) error {
	if p == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return cryptov4.ErrClosed
	}
	return p.refs[corePlanOwner].CheckSameEnvironment(ref)
}

func (p *SessionCorePlan) Claim(session protocolv4.ArtifactSessionParameters, role protocolv4.Direction) error {
	if p == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.claimLocked(session, role)
}

func (p *SessionCorePlan) claimLocked(session protocolv4.ArtifactSessionParameters, role protocolv4.Direction) error {
	if p.closed {
		return cryptov4.ErrClosed
	}
	if p.claimed {
		return cryptov4.ErrTransition
	}
	if session != p.config.Session || role > protocolv4.ServerToClient {
		return cryptov4.ErrConfiguration
	}
	if p.config.applicationServices && p.rpc == nil {
		return cryptov4.ErrConfiguration
	}
	if err := p.refs[corePlanOwner].CheckSameEnvironment(p.environment); err != nil {
		return err
	}
	p.claimed, p.role = true, role
	return nil
}

// claimInitial binds cancellation and cleanup to the actual original Noise /
// READY method before consuming the plan. A matching value projection alone
// cannot replace this still-running owner or permit Engine retirement early.
func (p *SessionCorePlan) claimInitial(session protocolv4.ArtifactSessionParameters, role protocolv4.Direction, initial *InitialExchange) error {
	if p == nil || initial == nil {
		return cryptov4.ErrConfiguration
	}
	initial.mu.Lock()
	defer initial.mu.Unlock()
	if err := initial.checkLocked(); err != nil {
		return err
	}
	if initial.corePlan != nil || initial.authenticating || initial.sending || initial.receiving {
		return cryptov4.ErrTransition
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.claimLocked(session, role); err != nil {
		return err
	}
	p.initial = initial
	initial.corePlan = p
	return nil
}

func (p *SessionCorePlan) sameRecords(records cryptov4.Config) bool {
	c := p.config.records(p.role)
	return records.MaxFrame == c.MaxFrame && records.MaxScopes == c.MaxScopes && records.PendingScopes == c.PendingScopes && records.WorkSlots == c.WorkSlots && records.Datagrams == c.Datagrams && records.Maintenance == c.Maintenance &&
		(records.Clock == nil || records.Clock == c.Clock) && records.LocalIdleDurationMS == c.LocalIdleDurationMS &&
		(records.Profile == "" || records.Profile == c.Profile) && (records.ApplicationProfile == "" || records.ApplicationProfile == c.ApplicationProfile) && (records.SignedMaxScopes == 0 || records.SignedMaxScopes == c.SignedMaxScopes)
}

func (p *SessionCorePlan) notifyLocked() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *SessionCorePlan) finishWork() {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		p.closeOwners()
	}
	p.mu.Lock()
	p.busy = false
	p.notifyLocked()
	p.mu.Unlock()
}

// PrepareRecords keeps the claimed Engine opaque until the original finished
// handshake has attached it. No caller can take its reservation independently.
func (p *SessionCorePlan) PrepareRecords(f *cryptov4.FinishedHandshake, records cryptov4.Config) (engine *cryptov4.Engine, err error) {
	if p == nil || f == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if !p.claimed || p.preparing || p.busy {
		p.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	if !p.sameRecords(records) {
		p.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	p.preparing, p.busy = true, true
	options, reservation, environment := p.config.EngineResources, p.refs[coreEngineOwner], p.engineEnvironment
	p.mu.Unlock()
	defer p.finishWork()
	engine, err = f.PrepareReservedRecordsWithEnvironmentBorrow(records, options, reservation, environment)
	p.mu.Lock()
	p.engine = engine
	if err != nil {
		p.closed = true
	}
	if p.closed && err == nil {
		err = cryptov4.ErrClosed
	}
	p.mu.Unlock()
	return engine, err
}

// Install runs the same dependency order for both roles before READY. Each
// constructor takes its original batch claim; it performs no new reservation.
func (p *SessionCorePlan) Install(engine *cryptov4.Engine, input RuntimeInput, output io.Writer) (core *SessionCore, err error) {
	if p == nil || input == nil || output == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if p.busy || p.installing || engine == nil || engine != p.engine || !p.preparing {
		p.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	if engine.SessionParameters() != p.config.Session || engine.Clock() != p.config.Clock {
		p.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	_, _, role := engine.ScopeLimits()
	if role != p.role {
		p.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	p.installing, p.busy = true, true
	c := p.config
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if err != nil {
			p.closed = true
		}
		if p.closed && err == nil {
			core = nil
			err = cryptov4.ErrClosed
		}
		p.mu.Unlock()
		p.finishWork()
	}()
	a, err := NewReservedOpenAdmission(engine, role, c.Open, p.refs[coreOpenOwner], p.environment)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.admission = a
	p.mu.Unlock()
	if c.Streams != (SessionStreamConfig{}) {
		pool := p.receivePool
		if pool == nil {
			return nil, cryptov4.ErrConfiguration
		}
		a.mu.Lock()
		a.receivePool = pool
		a.mu.Unlock()
	}
	w, err := NewRecordWriter(engine, 0, output)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.writer = w
	p.mu.Unlock()
	drainTimeout := c.DrainTimeoutMS
	if drainTimeout == 0 {
		drainTimeout = 30000
	}
	if _, err = NewSessionLifecycle(a, w, drainTimeout, p.refs[coreLifecycleOwner]); err != nil {
		return nil, err
	}
	if c.Open.Active != 0 {
		if _, err = NewSendService(a, c.SendWorkers, p.refs[coreSendOwner]); err != nil {
			return nil, err
		}
	}
	decode := c.decode()
	if c.Native && c.Open.Active != 0 {
		if _, err = NewNativeAuthService(a, c.DecoderNodes, decode, p.refs[coreNativeAuthOwner], p.refs[coreNativeReceiverStart:coreNativeReceiverStart+int(c.NativeAuthWorkers)]); err != nil {
			return nil, err
		}
	}
	p.probes = make([]ProbeSlot, int(c.ProbeSlots))
	liveness, err := NewLivenessWithPolicy(a, w, p.probes, c.Automatic, p.refs[coreLivenessOwner])
	if err != nil {
		return nil, err
	}
	p.pongs = make([]PongSlot, int(c.PongSlots))
	if _, err = NewMaintenanceMessages(liveness, p.pongs, c.Messages, p.refs[coreMessagesOwner]); err != nil {
		return nil, err
	}
	if _, err = NewStreamTerminationService(a, w, c.Termination, p.refs[coreTerminationOwner]); err != nil {
		return nil, err
	}
	original := engine.SessionParameters()
	if _, err = NewRekeyCredit(a, original.Contract.Limits().Rekey, original.IssuedAtMS, original.SessionNotAfterMS, engine.Clock()); err != nil {
		return nil, err
	}
	p.rekeyWait = make([]RekeyWaitSlot, int(c.RekeyWaitSlots))
	if _, err = NewRekeyCauses(a, p.rekeyWait); err != nil {
		return nil, err
	}
	if _, err = NewBarriers(a); err != nil {
		return nil, err
	}
	if _, err = NewRekeyService(a, w, c.Rekey, p.refs[coreRekeyOwner]); err != nil {
		return nil, err
	}
	retirement, err := NewRetirement(a, w)
	if err != nil {
		return nil, err
	}
	if _, err = NewRetirementService(retirement, c.RetirementTimeoutMS, p.refs[coreRetirementOwner]); err != nil {
		return nil, err
	}
	runtimeConfig := SessionRuntimeConfig{Admission: a, Input: input, DispatchTimeoutMS: c.DispatchTimeoutMS, Reservation: p.refs[coreRuntimeOwner]}
	if c.Native {
		runtimeConfig.MaintenanceIngress, err = NewMaintenanceIngress(a, &p.carrier, c.NativeIngress, c.DecoderNodes, decode, p.refs[coreIngressOwner], p.refs[coreIngressReceiverOwner])
	} else {
		runtimeConfig.SharedIngress, err = NewSharedIngress(a, &p.carrier, c.SharedDiscard, c.DecoderNodes, decode, p.refs[coreIngressOwner])
	}
	if err != nil {
		return nil, err
	}
	if p.rpc != nil {
		if runtimeConfig.SharedIngress == nil {
			return nil, cryptov4.ErrConfiguration
		}
		if _, err = p.rpc.PrepareBootstrap(runtimeConfig.SharedIngress, p.receivePool, output); err != nil {
			return nil, err
		}
		runtimeConfig.rpc = p.rpc
	}
	if c.Handlers.Plan != nil || c.Handlers.internal {
		dispatcher, dispatchErr := newSessionStreamDispatcher(&p.core, c.Handlers, p.refs[coreHandlersOwner])
		if dispatchErr != nil {
			return nil, dispatchErr
		}
		p.mu.Lock()
		p.dispatcher = dispatcher
		p.mu.Unlock()
		runtimeConfig.handlers = dispatcher
	}
	runtime, err := NewSessionRuntime(runtimeConfig)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.runtime = runtime
	p.mu.Unlock()
	return &p.core, nil
}

func (p *SessionCorePlan) closeOwners() {
	p.mu.Lock()
	runtime, a, engine, writer, initial, input := p.runtime, p.admission, p.engine, p.writer, p.initial, p.input
	pool := p.receivePool
	preaccepted := p.preaccepted
	dispatcher, handlers := p.dispatcher, p.config.Handlers.Plan
	p.mu.Unlock()
	for _, entry := range preaccepted {
		entry.close()
	}
	if dispatcher != nil {
		dispatcher.Close()
	} else if handlers != nil {
		handlers.Close()
	}
	if initial != nil {
		initial.Close(cryptov4.ErrClosed)
	}
	if input != nil {
		_ = input.Close()
	}
	if pool != nil {
		pool.Close()
	}
	if writer != nil {
		writer.Close()
	}
	if runtime != nil {
		runtime.Close()
	} else if a != nil {
		a.Close()
	} else if engine != nil {
		engine.Close()
	}
}

// Close seals the original plan promptly. A constructor already in progress
// remains charged and seals any owner it returns before ending its method tail.
func (p *SessionCorePlan) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.notifyLocked()
	p.mu.Unlock()
	p.closeOwners()
}

func (p *SessionCorePlan) waitChange(ctx context.Context) error {
	select {
	case <-p.cleanup:
		return nil
	case <-p.wake:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitCleanup joins the original graph on this caller. Concurrent observers
// wait for the same completion; cancellation relinquishes only observation.
// An outstanding manual rekey handle returns ErrCapacity without refunding;
// its original caller must Release it before retrying cleanup.
func (p *SessionCorePlan) WaitCleanup(ctx context.Context) (err error) {
	if p == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	for {
		p.mu.Lock()
		if p.cleaned {
			p.mu.Unlock()
			return nil
		}
		if !p.closed {
			p.mu.Unlock()
			return cryptov4.ErrTransition
		}
		if !p.busy && !p.cleaning && p.streamMethods == 0 {
			p.cleaning = true
			p.mu.Unlock()
			break
		}
		p.mu.Unlock()
		if err = p.waitChange(ctx); err != nil {
			return err
		}
	}
	defer func() {
		p.mu.Lock()
		p.cleaning = false
		if err == nil {
			p.cleaned = true
			close(p.cleanup)
		}
		p.notifyLocked()
		p.mu.Unlock()
	}()
	if err = ctx.Err(); err != nil {
		return err
	}
	p.closeOwners()
	if p.dispatcher != nil {
		if err = p.dispatcher.WaitCleanup(ctx); err != nil {
			return err
		}
	} else if p.config.Handlers.Plan != nil {
		if err = p.config.Handlers.Plan.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if p.initial != nil {
		if err = p.initial.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if p.input != nil {
		if err = p.input.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if p.runtime != nil {
		if err = p.runtime.WaitCleanup(ctx); err != nil {
			return err
		}
	} else if a := p.admission; a != nil {
		var waits [9]func(context.Context) error
		n := 0
		if a.lifecycle != nil {
			waits[n] = a.lifecycle.WaitCleanup
			n++
		}
		if a.sendService != nil {
			waits[n] = a.sendService.WaitCleanup
			n++
		}
		if a.nativeAuth != nil {
			waits[n] = a.nativeAuth.WaitCleanup
			n++
		}
		if a.termination != nil {
			waits[n] = a.termination.WaitCleanup
			n++
		}
		if a.liveness != nil {
			waits[n] = a.liveness.WaitCleanup
			n++
		}
		if a.maintenanceMessages != nil {
			waits[n] = a.maintenanceMessages.WaitCleanup
			n++
		}
		if a.rekeyService != nil {
			waits[n] = a.rekeyService.WaitCleanup
			n++
		}
		if a.retirementService != nil {
			waits[n] = a.retirementService.WaitCleanup
			n++
		}
		if a.maintenanceIngress != nil {
			waits[n] = a.maintenanceIngress.WaitCleanup
			n++
		}
		for _, wait := range waits[:n] {
			if err = wait(ctx); err != nil {
				return err
			}
		}
		if err = a.cleanupClosed(ctx); err != nil {
			return err
		}
		if err = a.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if p.writer != nil {
		if err = p.writer.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if p.engine != nil {
		if err = p.engine.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if p.admission != nil && p.admission.rekeyCauses != nil {
		causes := p.admission.rekeyCauses
		causes.mu.Lock()
		for _, slot := range causes.slots {
			if slot.intent != nil {
				causes.mu.Unlock()
				return cryptov4.ErrCapacity
			}
		}
		causes.mu.Unlock()
	}
	return nil
}

func (p *SessionCorePlan) Retire() (err error) {
	if p == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.retired {
		p.mu.Unlock()
		return nil
	}
	if !p.cleaned || p.cleaning || p.busy || p.retiring || p.streamMethods != 0 {
		p.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	p.retiring = true
	p.mu.Unlock()
	defer func() {
		if err != nil {
			p.mu.Lock()
			p.retiring = false
			p.mu.Unlock()
		}
	}()
	if p.runtime != nil {
		if err = p.runtime.Retire(); err != nil {
			return err
		}
	}
	if p.admission != nil {
		if err = p.admission.Retire(); err != nil {
			return err
		}
	}
	if p.engine != nil {
		if err = p.engine.Retire(); err != nil {
			return err
		}
	}
	if p.input != nil {
		if err = p.input.Retire(); err != nil {
			return err
		}
	}
	if p.dispatcher != nil {
		if err = p.dispatcher.Retire(); err != nil {
			return err
		}
	} else if p.config.Handlers.Plan != nil {
		if err = p.config.Handlers.Plan.Retire(); err != nil {
			return err
		}
	}
	p.mu.Lock()
	p.engine, p.admission, p.runtime, p.writer = nil, nil, nil, nil
	p.initial = nil
	p.input = nil
	p.receivePool, p.root = nil, nil
	p.dispatcher = nil
	p.rpc = nil
	p.application = nil
	p.config.Handlers = SessionStreamHandlerConfig{}
	p.resourceOwner = resourcev4.OwnerKey{}
	clear(p.accounts[:])
	p.accountCount = 0
	p.probes, p.pongs, p.rekeyWait = nil, nil, nil
	p.config.Clock = nil
	p.carrier.mu.Lock()
	p.carrier.bound, p.carrier.shared = nil, nil
	p.carrier.mu.Unlock()
	p.retired, p.retiring = true, false
	metadata := p.refs[corePlanOwner]
	p.refs[corePlanOwner] = resourcev4.Reference{}
	for i, ref := range p.refs {
		ref.Release()
		p.refs[i] = resourcev4.Reference{}
	}
	p.sharedEnvironment.Release()
	p.engineEnvironment.Release()
	p.carrierEnvironment.Release()
	p.sharedEnvironment, p.environment = resourcev4.Reference{}, resourcev4.Reference{}
	p.engineEnvironment, p.carrierEnvironment = resourcev4.Reference{}, resourcev4.Reference{}
	metadata.Release()
	p.mu.Unlock()
	return nil
}

func (p *SessionCorePlan) Abort(ctx context.Context) error {
	if p == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	p.Close()
	if err := p.WaitCleanup(ctx); err != nil {
		return err
	}
	return p.Retire()
}

func (c *SessionCore) Engine() *cryptov4.Engine {
	c.plan.mu.Lock()
	defer c.plan.mu.Unlock()
	return c.plan.engine
}
func (c *SessionCore) Admission() *OpenAdmission {
	c.plan.mu.Lock()
	defer c.plan.mu.Unlock()
	return c.plan.admission
}
func (c *SessionCore) Runtime() *SessionRuntime {
	c.plan.mu.Lock()
	defer c.plan.mu.Unlock()
	return c.plan.runtime
}
func (c *SessionCore) Writer() io.Writer {
	c.plan.mu.Lock()
	defer c.plan.mu.Unlock()
	if c.plan.writer == nil {
		return nil
	}
	return c.plan.writer.writer
}
func (c *SessionCore) Close() {
	if c != nil {
		c.plan.Close()
	}
}

func (c *SessionCore) Drain(timeoutMS, absoluteCap uint64) (*DrainOperation, error) {
	if c == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p := c.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.drain != nil {
		return p.drain, nil
	}
	if p.closed || p.admission == nil || p.admission.lifecycle == nil {
		return nil, cryptov4.ErrClosed
	}
	op, err := p.admission.lifecycle.Drain(timeoutMS, absoluteCap, "normal")
	if err == nil {
		p.drain = op
	}
	return op, err
}
func (c *SessionCore) WaitCleanup(ctx context.Context) error {
	if c == nil {
		return cryptov4.ErrConfiguration
	}
	return c.plan.WaitCleanup(ctx)
}
func (c *SessionCore) Retire() error {
	if c == nil {
		return cryptov4.ErrConfiguration
	}
	return c.plan.Retire()
}
