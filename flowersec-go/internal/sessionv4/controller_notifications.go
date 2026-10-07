package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type NotificationObservationPolicy uint8

const (
	NotificationCurrentOnly NotificationObservationPolicy = iota
	NotificationDrainAware
)

// Gap reasons are a finite local bit set, never provider errors or identifiers.
type NotificationGapReasons uint32

const (
	NotificationGapLateAttachment NotificationGapReasons = 1 << iota
	NotificationGapHandoff
	NotificationGapSourceClosed
	NotificationGapCapacity
	NotificationGapCoalesced
	NotificationGapExpired
	NotificationGapInvalidPayload
	NotificationGapHandler
	NotificationGapContract
)

type ControllerNotificationGap struct {
	FromGeneration, ToGeneration uint64
	Reasons                      NotificationGapReasons
	KnownDropped                 uint64
	PossibleGap                  bool
}

// SourceGeneration is local to one subscription. It grants no identity,
// ordering, replay or authority outside this bounded observation owner.
type ControllerNotificationEvent struct {
	Kind             string
	Value            any
	SourceGeneration uint64
	SourcePhase      string
	Gap              ControllerNotificationGap
}

type ControllerNotificationObserver struct {
	Dependencies []ServiceDependency
	Decode       func(context.Context, []byte) (any, error)
	Handle       func(context.Context, ControllerNotificationEvent) error
}

type ControllerNotificationOptions struct {
	Observation NotificationObservationPolicy
	Pending     NotificationPendingPolicy
	// Zero selects two actual sources, including candidates and cleanup tails.
	MaxObservedSessions uint8
	// Zero uses the Controller's original runtime allowance and finite defaults.
	RuntimeBytes, WaitMS, CleanupMS uint64
}

type NotificationObservationStatus struct {
	Closed, CleanupComplete bool
	AttachedCurrent         bool
	AttachedSources         uint8
	CurrentGeneration       uint64
	Gap                     ControllerNotificationGap
}

// The Controller's existing coordinator owns this root. Child tokens contain
// no delivery queue or callback; all sources share these seventeen positions
// (sixteen pending plus one running) and one protected, coalescing gap slot.
type controllerNotificationRoot struct {
	mu                                                                    sync.Mutex
	controller                                                            *ConnectionController
	client                                                                *UnaryServiceClient
	selector                                                              UnaryMethodSelector
	subscription                                                          *NotificationSubscription
	observer                                                              ControllerNotificationObserver
	options                                                               ControllerNotificationOptions
	executor                                                              *ApplicationExecutor
	group                                                                 *applicationGroup
	services                                                              *invocationServices
	root                                                                  *resourcev4.Root
	owner                                                                 resourcev4.OwnerKey
	accounts                                                              [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount                                                          int
	clock                                                                 *timev4.Clock
	reservation, controllerTail, clientTail                               resourcev4.Reference
	gapBacking, gapTask                                                   *resourcev4.ProtectedReservation
	sources                                                               [2]*controllerNotificationSource
	jobs                                                                  [17]*controllerNotificationDelivery
	active                                                                *controllerNotificationDelivery
	gapPending                                                            ControllerNotificationGap
	gapDirty, lastWasGap                                                  bool
	attachmentFailure                                                     NotificationGapReasons
	serial, generation, currentAttempt                                    uint64
	visits, closingSamples                                                uint32
	closed, cleaned, preparing, advancing, cleaning, declarationPreparing bool
}

type controllerNotificationSource struct {
	root                                                *controllerNotificationRoot
	session                                             *EnvironmentSession
	dispatch                                            *NotificationDispatch
	token                                               *notificationToken
	generation, attempt                                 uint64
	digest                                              [32]byte
	phase                                               string
	preinstalled, eligible, closed, detached, attaching bool
	jobs, visits                                        uint32
	rootTail                                            resourcev4.Reference
}

type controllerNotificationDelivery struct {
	root                                   *controllerNotificationRoot
	source                                 *controllerNotificationSource
	serial                                 uint64
	payload                                []byte
	gap                                    ControllerNotificationGap
	isGap                                  bool
	deadline                               *timev4.Deadline
	ctx                                    context.Context
	cancel                                 context.CancelCauseFunc
	reservation, taskReservation, rootTail resourcev4.Reference
	queued                                 *QueuedApplicationTask
	services                               *invocationServices
	entered, canceled                      bool
}

// SubscribeNotification borrows a notify method from this Controller's exact
// service binding. It performs only local registration, never Acquire, query,
// OPEN or business snapshot recovery. Missing later contracts remain visible.
func (c *ConnectionController) SubscribeNotification(client *UnaryServiceClient, selector UnaryMethodSelector, observer ControllerNotificationObserver, options ControllerNotificationOptions) (_ *NotificationSubscription, err error) {
	if c == nil || client == nil || selector.Type == 0 || selector.Namespace == "" || len(selector.Namespace) > 128 || observer.Decode == nil || observer.Handle == nil || options.Observation > NotificationDrainAware || options.Pending > NotificationLatestPending {
		return nil, cryptov4.ErrConfiguration
	}
	if options.MaxObservedSessions == 0 {
		options.MaxObservedSessions = 2
	}
	if options.MaxObservedSessions > 2 {
		return nil, cryptov4.ErrConfiguration
	}
	if options.WaitMS == 0 {
		options.WaitMS = 30000
	}
	if options.CleanupMS == 0 {
		options.CleanupMS = 5000
	}
	if options.WaitMS > 120000 || options.CleanupMS > 120000 {
		return nil, cryptov4.ErrConfiguration
	}
	client.mu.Lock()
	if client.closed || client.cleaned || client.source.controller != c || client.namespace != selector.Namespace || client.visits == math.MaxUint32 {
		client.mu.Unlock()
		return nil, rpcv4.ErrOwner
	}
	m, err := client.methodLocked(selector.Type)
	if err != nil || m.definition.Shape != 2 {
		client.mu.Unlock()
		return nil, rpcv4.ErrMethod
	}
	if options.Pending == NotificationLatestPending {
		if !m.installed {
			client.mu.Unlock()
			return nil, cryptov4.ErrNotReady
		}
		if m.notificationSemantics != 0 {
			client.mu.Unlock()
			return nil, cryptov4.ErrConfiguration
		}
	}
	client.visits++
	root, clock, executor := client.root, client.clock, client.notificationExecutor
	clientTail, err := client.metadata.Borrow()
	client.mu.Unlock()
	if err != nil {
		client.mu.Lock()
		client.visits--
		client.mu.Unlock()
		return nil, err
	}
	installed := false
	defer func() {
		if !installed {
			clientTail.Release()
			client.mu.Lock()
			client.visits--
			client.mu.Unlock()
		}
	}()
	if executor == nil {
		return nil, cryptov4.ErrNotReady
	}
	dependencyCharge, err := serviceDependenciesCharge(observer.Dependencies)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed || c.notificationSerial == math.MaxUint64 {
		c.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	position := -1
	for i, existing := range c.notifications {
		if existing == nil {
			position = i
			break
		}
	}
	if position < 0 {
		c.mu.Unlock()
		return nil, rpcv4.ErrCapacity
	}
	if options.RuntimeBytes == 0 {
		options.RuntimeBytes = c.config.RuntimeBytes
	}
	var accounts [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	owner, count, err := c.reservation.CopyAllocationScope(root, accounts[:])
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	c.notificationSerial++
	serial := c.notificationSerial
	n := &controllerNotificationRoot{controller: c, client: client, selector: selector, options: options, observer: observer, executor: executor, root: root, owner: owner, accounts: accounts, accountCount: count, clock: clock, preparing: true}
	c.notifications[position] = n
	c.mu.Unlock()
	defer func() {
		if !installed {
			c.mu.Lock()
			if c.notifications[position] == n {
				c.notifications[position] = nil
			}
			c.mu.Unlock()
		}
	}()
	var seed [48]byte
	copy(seed[:16], "controller-notify")
	copy(seed[16:32], owner.Backing[:])
	binary.BigEndian.PutUint64(seed[32:40], serial)
	digest := sha256.Sum256(seed[:])
	copy(n.owner.Instance[:], digest[:16])
	copy(n.owner.Backing[:], digest[16:])
	rootCharge, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(controllerNotificationRoot{})) + uint64(unsafe.Sizeof(applicationGroup{})) + uint64(len(selector.Namespace)), resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: options.RuntimeBytes})
	if err == nil {
		rootCharge, err = rootCharge.Add(dependencyCharge)
	}
	if err != nil {
		return nil, err
	}
	gapMinimum, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(controllerNotificationDelivery{})) + applicationContextBytes() + uint64(unsafe.Sizeof(notificationInvocation{})), resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: options.RuntimeBytes})
	if err != nil {
		return nil, err
	}
	gapCharge, err := resourcev4.ProtectedCharge(gapMinimum)
	if err != nil {
		return nil, err
	}
	gapTaskCharge, err := resourcev4.ProtectedCharge(executor.TaskCharge())
	if err != nil {
		return nil, err
	}
	handleCharge, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NotificationSubscription{})) + uint64(unsafe.Sizeof(timev4.Window{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: options.RuntimeBytes})
	if err != nil {
		return nil, err
	}
	charges := [4]resourcev4.Vector{rootCharge, handleCharge, gapCharge, gapTaskCharge}
	var requests [4]resourcev4.Request
	var refs [4]resourcev4.Reference
	for i, charge := range charges {
		owner := n.owner
		owner.Backing[15] ^= byte(i + 1)
		requests[i] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: accounts[:count]}
	}
	if err = root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, err
	}
	defer func() {
		if !installed {
			for _, ref := range refs {
				ref.Release()
			}
			n.gapBacking.Close()
			n.gapTask.Close()
			n.services.close()
			if n.group != nil {
				executor.cancelApplicationGroup(n.group)
			}
			n.controllerTail.Release()
		}
	}()
	n.reservation = refs[0]
	n.selector.Namespace = strings.Clone(selector.Namespace)
	n.controllerTail, err = c.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	n.services, err = newInvocationServices(observer.Dependencies, refs[0])
	if err != nil {
		return nil, err
	}
	n.observer.Dependencies = nil
	n.gapBacking, err = resourcev4.NewProtectedReservation(refs[2], gapMinimum)
	if err != nil {
		return nil, err
	}
	n.gapTask, err = resourcev4.NewProtectedReservation(refs[3], executor.TaskCharge())
	if err != nil {
		return nil, err
	}
	n.group, err = executor.newApplicationGroup()
	if err != nil {
		return nil, err
	}
	if err = executor.attachApplicationGroup(n.group, refs[0]); err != nil {
		return nil, err
	}
	s := &NotificationSubscription{controller: n, reservation: refs[1], root: root, owner: n.owner, accounts: accounts, accountCount: count, clock: clock, waitMS: options.WaitMS, runtimeBytes: options.RuntimeBytes, identity: serial, done: make(chan struct{}), closing: make(chan struct{})}
	n.subscription, n.clientTail = s, clientTail
	client.mu.Lock()
	c.mu.Lock()
	n.mu.Lock()
	if c.closed || client.closed || client.source.controller != c {
		n.mu.Unlock()
		c.mu.Unlock()
		client.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	n.preparing = false
	n.recordGapLocked(0, 0, NotificationGapLateAttachment, 0, true)
	n.mu.Unlock()
	c.signalLocked()
	c.mu.Unlock()
	client.mu.Unlock()
	installed = true
	return s, nil
}

func (s *NotificationSubscription) ObservationStatus() NotificationObservationStatus {
	if s == nil {
		return NotificationObservationStatus{Closed: true, CleanupComplete: true}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.observation
	out.Closed, out.CleanupComplete = s.status.Closed, s.status.CleanupComplete
	return out
}

func saturatingNotifications(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

func mergeNotificationGap(target *ControllerNotificationGap, from, to uint64, reasons NotificationGapReasons, dropped uint64, possible bool) {
	if target.Reasons == 0 || from != 0 && (target.FromGeneration == 0 || from < target.FromGeneration) {
		target.FromGeneration = from
	}
	if to > target.ToGeneration {
		target.ToGeneration = to
	}
	target.Reasons |= reasons
	target.KnownDropped = saturatingNotifications(target.KnownDropped, dropped)
	target.PossibleGap = target.PossibleGap || possible
}

func (n *controllerNotificationRoot) recordGapLocked(from, to uint64, reasons NotificationGapReasons, dropped uint64, possible bool) {
	mergeNotificationGap(&n.gapPending, from, to, reasons, dropped, possible)
	n.gapDirty = true
	if s := n.subscription; s != nil {
		s.mu.Lock()
		mergeNotificationGap(&s.observation.Gap, from, to, reasons, dropped, possible)
		s.status.KnownDropped = saturatingNotifications(s.status.KnownDropped, dropped)
		s.status.LastGap = "observation_gap"
		s.mu.Unlock()
	}
}

func notificationReason(reason string) NotificationGapReasons {
	switch reason {
	case "coalesced_pending":
		return NotificationGapCoalesced
	case "delivery_expired":
		return NotificationGapExpired
	case "decode_error":
		return NotificationGapInvalidPayload
	case "handler_error":
		return NotificationGapHandler
	case "delivery_unavailable":
		return NotificationGapSourceClosed
	default:
		return NotificationGapCapacity
	}
}
