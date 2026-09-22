package sessionv4

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrOpenAssociation = errors.New("sessionv4: conflicting OPEN association")
	ErrOpenPending     = errors.New("sessionv4: OPEN outcome pending")
	ErrOpenRejected    = errors.New("sessionv4: OPEN rejected")
	ErrOpenWaitBusy    = errors.New("sessionv4: OPEN observer already active")
)

// StreamClass is chosen by the trusted kind/profile registration, never by an
// unauthenticated header or by an application's requested priority.
type StreamClass uint8

const (
	BusinessStream StreamClass = iota
	InternalStream
	ManagementStream
)

// OpenLimits is the admitted, immutable local allocation. Protected positive
// and proof positions are part of these totals, not additional free capacity.
// Provider handles, flow storage and I/O work have their own real reservations.
type OpenLimits struct {
	Active, Opening, Terminal, RejectionReserve, IngressItems uint32
	IngressBytes                                              uint64
	PerClass                                                  [3]uint32
	PerOpener                                                 [2][3]uint32
	Protected                                                 [2][3]uint32
	Lifetime                                                  [2][3]uint64
}

type openPhase uint8

const (
	openFree openPhase = iota
	openPending
	openOpening
	openLive
	openRecent
	openHeld
	openReserved
)

// OpenHandle is meaningful only to its original Session. Scope IDs are never
// reused, so moving an ingress owner to its proof slot cannot cause an ABA.
type OpenHandle struct {
	owner *OpenAdmission
	scope uint64
}

func (h OpenHandle) Scope() uint64 { return h.scope }

// CarrierAssociation is allocated by a provider's bounded create/accept owner.
// Its identity denotes that exact logical carrier object and generation. It is
// not constructed from a peer stream number. WS uses a logical association.
type CarrierAssociation struct {
	// shared identifies the original SDK-owned logical association. Native
	// providers report their own actual CarrierClosed separately.
	shared *SharedIngress
	mu     sync.Mutex
	bound  *OpenAdmission
	scope  uint64
}

type openSlot struct {
	bootstrap                                                                                   bool
	rejectionOrdinary                                                                           bool
	scope                                                                                       uint64
	phase                                                                                       openPhase
	class                                                                                       StreamClass
	local, submitted, cancelled, rejectionToken, carrierDone, accepted, deciding, activeCharged bool
	carrier                                                                                     *CarrierAssociation
	incoming                                                                                    *cryptov4.IncomingScope
	header                                                                                      protocolv4.RecordHeader
	digest                                                                                      [32]byte
	deadline                                                                                    *timev4.Deadline
	peerLimit, localLimit                                                                       uint64
	reason                                                                                      uint64
	metadataStart, metadataSize, kindSize                                                       int
	flow                                                                                        *StreamFlow
	owner                                                                                       *StreamOwnership
	barrierReferences                                                                           uint32
	terminal                                                                                    [2]DrainProof
	contender                                                                                   bool
	drainSubmitted                                                                              bool
	drainComplete                                                                               bool
	terminalPublishing, cleanupBusy, coreCleaned                                                bool
	stopSubmitted, stoppedSubmitted, stoppedDirty                                               bool
	retirementReferences                                                                        uint32
	dispatched, outcomeWaiting                                                                  bool
	preparationTarget                                                                           int // Ordinary proof slot + 1; retained after transfer.
	preparationActive, preparationCaptured                                                      bool
	preparationSnapshot                                                                         []byte
	barrierUnpublished                                                                          uint32
}

// OpenAdmission owns a fixed ingress byte arena and all future/recent/held
// proof slots. There is no allocation per rejected ID and no pending waiter
// queue. The same owner gate orders resource transfer and outcome selection.
type OpenAdmission struct {
	mu                                                        sync.Mutex
	engine                                                    *cryptov4.Engine
	direction                                                 protocolv4.Direction
	limits                                                    OpenLimits
	slots                                                     []openSlot
	index                                                     []int
	metadata                                                  []byte
	metadataUsed                                              []bool
	active, opening, pending, positiveProofs, rejectionProofs uint32
	byOpener                                                  [2][3]uint32
	lifetime                                                  [2][3]uint64
	nextOrdinal                                               uint64
	roleOrdinals                                              [2]uint64
	stable                                                    [2][]uint64
	closed, draining                                          bool
	openGate                                                  localOpenGate
	highestAccepted                                           [2]uint64
	peerGoAway                                                goAwayBoundary
	lifecycle                                                 *SessionLifecycle
	decoder                                                   *protocolv4.Decoder
	encode                                                    []byte
	retirement                                                *Retirement
	retirementService                                         *RetirementService
	barriers                                                  *Barriers
	rekeyCredit                                               *RekeyCredit
	rekeyCauses                                               *RekeyCauses
	rekeyService                                              *RekeyService
	bootstrap                                                 *Bootstrap
	idleWatchdog                                              *IdleWatchdog
	liveness                                                  *Liveness
	maintenanceMessages                                       *MaintenanceMessages
	sendService                                               *SendService
	nativeAuth                                                *NativeAuthService
	termination                                               *StreamTerminationService
	maintenanceIngress                                        *MaintenanceIngress
	sharedIngress                                             *SharedIngress
	exchange                                                  *RekeyExchange
	runtime                                                   *SessionRuntime
	failure                                                   error
	methodTails                                               uint64
	cleaning, cleaned, retired                                bool
	receivePool                                               *ReceivePool
	pendingWaiting                                            bool
	pendingWake                                               chan struct{}
	outcomeWake                                               []chan struct{}
	cleanupWake, cleanupDone                                  chan struct{}
	reservation                                               resourcev4.Reference
}

func NewOpenAdmission(engine *cryptov4.Engine, direction protocolv4.Direction, limits OpenLimits) (*OpenAdmission, error) {
	r, err := openAdmissionRegistry()
	if err != nil {
		return nil, err
	}
	streams, record := r.Streams, r.Records
	if engine == nil || direction > protocolv4.ServerToClient || limits.Opening > min(limits.Active, streams.Pending) || limits.Terminal > streams.Terminal ||
		limits.RejectionReserve == 0 || limits.RejectionReserve > streams.Reject || uint64(limits.Active)+uint64(limits.RejectionReserve) > uint64(limits.Terminal) ||
		limits.IngressItems == 0 || uint64(limits.IngressItems) > record.Caps.Ingress.Items || limits.IngressBytes > record.Caps.Ingress.Bytes {
		return nil, cryptov4.ErrConfiguration
	}
	_, bootstrap := engine.BootstrapSpec()
	if bootstrap && limits.Active == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	engineActive, enginePending, engineDirection := engine.ScopeLimits()
	if limits.Active > engineActive || limits.IngressItems > enginePending || direction != engineDirection {
		return nil, cryptov4.ErrConfiguration
	}
	var protected uint64
	for _, cap := range limits.PerClass {
		if cap > limits.Active {
			return nil, cryptov4.ErrConfiguration
		}
	}
	for role := range 2 {
		for class, cap := range []uint64{streams.Business, streams.Internal, streams.Management} {
			if limits.Lifetime[role][class] > cap || limits.PerOpener[role][class] > limits.PerClass[class] || limits.Protected[role][class] > limits.PerOpener[role][class] {
				return nil, cryptov4.ErrConfiguration
			}
			protected += uint64(limits.Protected[role][class])
		}
	}
	if protected > uint64(limits.Active) {
		return nil, cryptov4.ErrConfiguration
	}
	// Descriptor and fixed index costs are charged before assigning metadata
	// capacity. The byte arena has one occupancy byte per owned byte; this
	// conservative layout makes fragmentation and cleanup accounting explicit.
	ingressOverhead := uint64(limits.IngressItems) * (uint64(unsafe.Sizeof(openSlot{})) + 4*uint64(unsafe.Sizeof(int(0))))
	if limits.IngressBytes <= ingressOverhead {
		return nil, cryptov4.ErrConfiguration
	}
	kind, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil {
		return nil, err
	}
	metadata, err := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
	if err != nil {
		return nil, err
	}
	arenaBytes := int((limits.IngressBytes - ingressOverhead) / 2)
	if arenaBytes < kind+metadata {
		return nil, cryptov4.ErrConfiguration
	}
	// This workspace covers one complete maximum OPEN at uint64 field maxima.
	// Actual frame/route admission still checks the complete encrypted record.
	encodeBytes := kind + metadata + 256
	decoder, err := protocolv4.NewRecordDecoder(encodeBytes, 64)
	if err != nil {
		return nil, err
	}
	indexSize := 1
	for indexSize < 2*int(limits.Terminal+limits.IngressItems) {
		indexSize *= 2
	}
	a := &OpenAdmission{pendingWake: make(chan struct{}, 1), outcomeWake: make([]chan struct{}, int(limits.Terminal+limits.IngressItems)), cleanupWake: make(chan struct{}, 1), cleanupDone: make(chan struct{}), engine: engine, direction: direction, limits: limits, slots: make([]openSlot, int(limits.Terminal+limits.IngressItems)), index: make([]int, indexSize), metadata: make([]byte, arenaBytes), metadataUsed: make([]bool, arenaBytes), nextOrdinal: 1, roleOrdinals: [2]uint64{streams.Client, streams.Server}, stable: [2][]uint64{make([]uint64, (streams.Client+63)/64), make([]uint64, (streams.Server+63)/64)}, decoder: decoder, encode: make([]byte, encodeBytes)}
	for i := range a.outcomeWake {
		a.outcomeWake[i] = make(chan struct{}, 1)
	}
	return a, nil
}

func (a *OpenAdmission) checkDeadline(deadline *timev4.Deadline) error {
	if !deadline.BelongsTo(a.engine.Clock()) {
		return cryptov4.ErrConfiguration
	}
	return rekeyTimeError(deadline.Check())
}

func (a *OpenAdmission) bucket(scope uint64) int {
	return int(scope * 11400714819323198485 & uint64(len(a.index)-1))
}
func (a *OpenAdmission) find(scope uint64) int {
	if len(a.index) == 0 {
		return -1
	}
	for pos, count := a.bucket(scope), 0; count < len(a.index); pos, count = (pos+1)&(len(a.index)-1), count+1 {
		index := a.index[pos]
		if index == 0 {
			return -1
		}
		if index > 0 && a.slots[index-1].scope == scope {
			return index - 1
		}
	}
	return -1
}
func (a *OpenAdmission) insert(scope uint64, slot int) {
	for pos, count := a.bucket(scope), 0; count < len(a.index); pos, count = (pos+1)&(len(a.index)-1), count+1 {
		if a.index[pos] <= 0 {
			a.index[pos] = slot + 1
			return
		}
	}
	panic("sessionv4: fixed OPEN index capacity invariant")
}
func (a *OpenAdmission) remove(scope uint64) {
	for pos, count := a.bucket(scope), 0; count < len(a.index); pos, count = (pos+1)&(len(a.index)-1), count+1 {
		index := a.index[pos]
		if index == 0 {
			return
		}
		if index > 0 && a.slots[index-1].scope == scope {
			a.index[pos] = -1
			return
		}
	}
}
func (a *OpenAdmission) slot(h OpenHandle) (*openSlot, error) {
	if h.owner != a {
		return nil, ErrOpenAssociation
	}
	i := a.find(h.scope)
	if i < 0 {
		return nil, ErrOpenAssociation
	}
	return &a.slots[i], nil
}
func (a *OpenAdmission) metadataReserve(kind string, metadata []byte) (int, bool) {
	size, run := len(kind)+len(metadata), 0
	for i, used := range a.metadataUsed {
		if used {
			run = 0
		} else {
			run++
		}
		if run == size {
			start := i + 1 - size
			for j := start; j <= i; j++ {
				a.metadataUsed[j] = true
			}
			copy(a.metadata[start:], kind)
			copy(a.metadata[start+len(kind):], metadata)
			return start, true
		}
	}
	return 0, false
}
func (a *OpenAdmission) releaseMetadata(s *openSlot) {
	if s.metadataSize == 0 || s.preparationActive {
		return
	}
	clear(a.metadata[s.metadataStart : s.metadataStart+s.metadataSize])
	clear(a.metadataUsed[s.metadataStart : s.metadataStart+s.metadataSize])
	s.metadataSize, s.kindSize = 0, 0
}
func (a *OpenAdmission) freeSlot(ingress bool, rejection bool) int {
	start, end := 0, int(a.limits.Terminal-a.limits.RejectionReserve)
	if ingress {
		start, end = int(a.limits.Terminal), len(a.slots)
	} else if rejection {
		start, end = end, int(a.limits.Terminal)
	}
	for i := start; i < end; i++ {
		if a.slots[i].phase == openFree {
			return i
		}
	}
	return -1
}
func (a *OpenAdmission) unusedProtection(role protocolv4.Direction, class StreamClass) uint32 {
	var reserved uint32
	for r := range 2 {
		for c := range 3 {
			used := a.byOpener[r][c]
			if r == int(role) && c == int(class) {
				used++
			}
			if used < a.limits.Protected[r][c] {
				reserved += a.limits.Protected[r][c] - used
			}
		}
	}
	return reserved
}
func (a *OpenAdmission) positiveAvailable(role protocolv4.Direction, class StreamClass) bool {
	return a.positiveAvailableWithProof(role, class, false)
}

func (a *OpenAdmission) positiveAvailableWithProof(role protocolv4.Direction, class StreamClass, ownsProof bool) bool {
	if class > ManagementStream {
		return false
	}
	proofs := a.positiveProofs
	if ownsProof {
		if proofs == 0 {
			return false
		}
		proofs-- // Transfer this OPEN's original proof without reserving another.
	}
	reserved := a.unusedProtection(role, class)
	return a.active < a.limits.Active && reserved <= a.limits.Active-a.active-1 &&
		a.byOpener[role][class] < a.limits.PerOpener[role][class] && a.byOpener[0][class]+a.byOpener[1][class] < a.limits.PerClass[class] &&
		a.lifetime[role][class] < a.limits.Lifetime[role][class] &&
		proofs+reserved < a.limits.Terminal-a.limits.RejectionReserve
}

func (a *OpenAdmission) businessConflict() bool {
	if a.direction != protocolv4.ServerToClient || a.byOpener[0][BusinessStream]+a.byOpener[1][BusinessStream] < a.limits.PerClass[BusinessStream] && a.active < a.limits.Active {
		return false
	}
	for i := 0; i < int(a.limits.Terminal); i++ {
		s := &a.slots[i]
		if s.local && s.phase == openOpening && s.class == BusinessStream && s.submitted {
			return true
		}
	}
	return false
}

// Hold transfers only an already authenticated OPEN and its exact carrier
// association. Metadata remains opaque: invalid application metadata still
// needs the same bounded owner and explicit rejected proof.
func (a *OpenAdmission) Hold(record *ReceivedRecord, carrier *CarrierAssociation, deadline *timev4.Deadline) (handle OpenHandle, err error) {
	if record == nil || carrier == nil {
		return OpenHandle{}, ErrOpenAssociation
	}
	defer record.acceptOnSuccess(&err)
	frame, err := record.Body()
	if err != nil {
		return OpenHandle{}, err
	}
	if record.receiver.engine != a.engine || record.receiver.direction != 1-a.direction || frame.Type != protocolv4.FrameOpenStream || record.incoming == nil || record.incoming.Header() != frame.Header {
		return OpenHandle{}, ErrOpenAssociation
	}
	kind, ok := frame.Field("kind").Text()
	metadata, yes := frame.Field("metadata").ByteString()
	digest, good := frame.Field("open_digest").ByteString()
	limit, numeric := frame.Field("initial_receive_limit").Uint()
	if !ok || !yes || !good || !numeric || len(digest) != 32 {
		return OpenHandle{}, ErrOpenAssociation
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	if a.closed {
		return OpenHandle{}, cryptov4.ErrClosed
	}
	if err := a.checkDeadline(deadline); err != nil {
		return OpenHandle{}, err
	}
	if carrier.bound != nil || a.find(frame.Header.Scope) >= 0 {
		return OpenHandle{}, ErrOpenAssociation
	}
	i := a.freeSlot(true, false)
	if i < 0 {
		return OpenHandle{}, cryptov4.ErrCapacity
	}
	start, fits := a.metadataReserve(kind, metadata)
	if !fits {
		return OpenHandle{}, cryptov4.ErrCapacity
	}
	s := &a.slots[i]
	*s = openSlot{scope: frame.Header.Scope, phase: openPending, carrier: carrier, incoming: record.incoming, header: frame.Header, deadline: deadline, peerLimit: limit, metadataStart: start, metadataSize: len(kind) + len(metadata), kindSize: len(kind)}
	copy(s.digest[:], digest)
	carrier.bound, carrier.scope = a, s.scope
	a.insert(s.scope, i)
	a.pending++
	a.notifyPendingLocked()
	if a.barriers != nil {
		a.barriers.bind(s)
	}
	if a.termination != nil {
		a.termination.notify()
	}
	return OpenHandle{a, s.scope}, nil
}

// CopyRequest transfers the bounded fields into an already reserved local
// authorization/typed-metadata workspace. No parser or callback runs under the
// outcome gate, and no borrowed decoder is retained by pending admission.
func (a *OpenAdmission) CopyRequest(h OpenHandle, dst []byte) (kind, metadata []byte, peerLimit uint64, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return nil, nil, 0, err
	}
	if a.closed {
		return nil, nil, 0, cryptov4.ErrClosed
	}
	if err := a.engine.ApplicationInputReady(s.header.Epoch); err != nil {
		return nil, nil, 0, err
	}
	if s.phase != openPending || len(dst) < s.metadataSize {
		return nil, nil, 0, cryptov4.ErrCapacity
	}
	copy(dst, a.metadata[s.metadataStart:s.metadataStart+s.metadataSize])
	return dst[:s.kindSize:s.kindSize], dst[s.kindSize:s.metadataSize:s.metadataSize], s.peerLimit, nil
}

type OpenUsage struct{ Active, Opening, Pending, PositiveProofs, RejectionProofs uint32 }

func (a *OpenAdmission) Usage() OpenUsage {
	a.mu.Lock()
	defer a.mu.Unlock()
	return OpenUsage{a.active, a.opening, a.pending, a.positiveProofs, a.rejectionProofs}
}

// CarrierClosed is reported by the original provider cleanup owner after its
// callbacks and aliases really exit. It does not create a terminal proof or
// retire an ID; rejected local openings retain active charge until this event.
func (a *OpenAdmission) CarrierClosed(h OpenHandle) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return err
	}
	if s.carrierDone {
		return nil
	}
	s.carrierDone = true
	a.notifyCleanup()
	if (s.phase == openRecent || s.phase == openHeld) && s.activeCharged {
		a.active--
		a.byOpener[(s.scope+1)%2][s.class]--
		s.activeCharged = false
		a.notifyDecisionOpportunityLocked()
	}
	a.collect(s)
	return nil
}

func (a *OpenAdmission) isStable(scope uint64) bool {
	if scope == 0 || scope >= uint64(1)<<63 {
		return false
	}
	role, ordinal := (scope+1)%2, (scope-1)/2
	return ordinal < a.roleOrdinals[role] && a.stable[role][ordinal/64]&(uint64(1)<<(ordinal%64)) != 0
}
func (a *OpenAdmission) makeStable(s *openSlot) {
	role, ordinal := (s.scope+1)%2, (s.scope-1)/2
	a.stable[role][ordinal/64] |= uint64(1) << (ordinal % 64)
	s.phase = openHeld
	// The detail index is retained privately while real references exist; the
	// stable bitmap already rejects every new barrier/OPEN association.
	a.collect(s)
}
func (a *OpenAdmission) collect(s *openSlot) {
	if a.closed {
		a.notifyCleanup()
		return
	}
	if s.phase != openHeld || !s.carrierDone || s.activeCharged || s.barrierReferences != 0 || s.retirementReferences != 0 {
		return
	}
	if s.flow != nil {
		_, _, _, _, sendClean := s.flow.send.Snapshot()
		s.flow.receive.pool.mu.Lock()
		receiveClean := s.flow.receive.cleaned
		s.flow.receive.pool.mu.Unlock()
		if !sendClean || !receiveClean {
			return
		}
		if s.flow.nativeReceive != nil && s.flow.nativeReceive.retire() != nil {
			return
		}
		if s.flow.send.retire() != nil {
			return
		}
	}
	// A rejected prepared OPEN still owns its original ordinary proof share.
	// Only a token actually taken from the rejection reserve returns there.
	if s.rejectionToken && s.preparationTarget == 0 && !s.rejectionOrdinary {
		a.rejectionProofs--
	} else {
		a.positiveProofs--
	}
	a.remove(s.scope)
	*s = openSlot{}
	a.notifyDecisionOpportunityLocked()
}

// Collect revisits completed physical owners after their original callbacks or
// application reads exit. A retirement ACK alone cannot reclaim those charges.
func (a *OpenAdmission) Collect() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.slots {
		a.collect(&a.slots[i])
	}
}

func (a *OpenAdmission) Drain() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.drainLocked()
}

func (a *OpenAdmission) drainLocked() {
	a.draining = true
	a.openGate.close()
	a.notifyDecisionOpportunityLocked()
	if a.bootstrap != nil && a.direction == a.bootstrap.spec.Opener {
		if s, err := a.slot(a.bootstrap.handle); err == nil && !s.submitted {
			s.cancelled = true
			s.flow.send.Stop()
			s.flow.receive.Abandon()
		}
	}
}

// CheckDeadlines preserves every submitted/pending fact. The Session closes on this
// result; it must not forget an unresolved OPEN and continue with the same ID.
func (a *OpenAdmission) CheckDeadlines() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.slots {
		s := &a.slots[i]
		if s.phase == openOpening || s.phase == openPending || s.pendingRejection() || s.rejectionToken && s.deciding {
			if err := a.checkDeadline(s.deadline); err != nil {
				return err
			}
		}
	}
	return nil
}
