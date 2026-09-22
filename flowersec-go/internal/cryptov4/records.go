// Package cryptov4 owns Flowersec v4 key lifetimes and record cryptography.
package cryptov4

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrConfiguration   = errors.New("cryptov4: configuration capacity")
	ErrClosed          = errors.New("cryptov4: closed")
	ErrNotReady        = errors.New("cryptov4: not ready")
	ErrExpired         = errors.New("cryptov4: security deadline")
	ErrCapacity        = errors.New("cryptov4: resource exhausted")
	ErrUsage           = errors.New("cryptov4: crypto usage exhausted")
	ErrSequence        = errors.New("cryptov4: unexpected reliable sequence")
	ErrReplay          = errors.New("cryptov4: duplicate or old datagram")
	ErrEpoch           = errors.New("cryptov4: unexpected epoch")
	ErrAuthentication  = errors.New("cryptov4: record authentication failed")
	ErrScope           = errors.New("cryptov4: unowned or retired scope")
	ErrTransition      = errors.New("cryptov4: epoch transition unavailable")
	ErrReceiveBlocked  = errors.New("cryptov4: datagram receive temporarily blocked")
	ErrReceiveDisabled = errors.New("cryptov4: datagram receive disabled")
)

type usageLimits struct {
	Seal   uint64 `json:"seal_calls,string"`
	Open   uint64 `json:"open_attempts,string"`
	Blocks uint64 `json:"authentication_blocks,string"`
	Bytes  uint64 `json:"ciphertext_bytes,string"`
}
type usageProfile struct {
	Key, Epoch, Session usageLimits
	RootAge             uint64 `json:"root_max_age_ms,string"`
	Epochs              uint64 `json:"max_epochs,string"`
	Derivations         uint64 `json:"max_record_key_derivations,string"`
}
type usage struct{ calls, blocks, bytes uint64 }

// MaintenanceReserve is the precomputed remaining REKEY responsibility for one
// direction. Ordinary maintenance cannot consume it. It never raises L0 limits.
type MaintenanceReserve struct{ Calls, Blocks, Bytes uint64 }

// TicketGuard joins a bounded Session cause/cancellation gate to the original
// crypto ticket. LockTicket must unlock itself on error. A successful lock is
// held through accounting and sequence advancement; UnlockTicket records the
// actual submission fact. No crypto, I/O or application callback is permitted.
type TicketGuard interface {
	LockTicket() error
	UnlockTicket(submitted bool)
}

// Config is assembled by the admitted handshake owner, never from a peer's
// unauthenticated record. Deadlines must already use the trusted time adapter's
// conservative local projection. RootBorn is sampled before the actual KDF.
type Config struct {
	Profile                             string
	ApplicationProfile                  string
	Root, HandshakeHash, ContextDigest  [32]byte
	SendDirection                       protocolv4.Direction
	MaxFrame                            uint32
	MaxScopes, SignedMaxScopes          uint32
	PendingScopes                       uint32
	WorkSlots                           uint32
	Datagrams                           bool
	Features                            uint64
	RootBorn                            timev4.Sample
	AuthorizationDeadlineMS             uint64
	Authorization                       protocolv4.AuthorizationGuard
	Clock                               *timev4.Clock
	IdleDurationMS, LocalIdleDurationMS uint64
	Maintenance                         MaintenanceReserve
}

// TicketError preserves the irreversible precharge fact if crypto or its final
// publication gate fails. It must not be projected as an unsubmitted operation.
type TicketError struct {
	Cause  error
	Header protocolv4.RecordHeader
}

func (e *TicketError) Error() string { return e.Cause.Error() }
func (e *TicketError) Unwrap() error { return e.Cause }

type recordKey struct {
	aead      cipher.AEAD
	usage     usage
	next      uint64
	exhausted bool
	replay    replayWindow
	busy      bool
	good      usage
}
type scopeKeys struct {
	bootstrap     bool
	deriving      [2]bool
	keys          [2]*recordKey
	opening       bool
	openSubmitted bool
	incoming      *IncomingScope
}
type epochState struct {
	number   uint32
	root     [32]byte
	deadline *timev4.Deadline
	keys     scopeTable
	usage    [2]usage
}
type workspace struct {
	input, output []byte
	maintenance   bool
	sharedInput   bool
	direction     protocolv4.Direction
}

type epochKeyJob struct {
	scope     uint64
	direction protocolv4.Direction
	owner     *scopeKeys
}

// Engine serializes only short ownership/accounting gates. AEAD runs outside
// the gate; completion rechecks the original key, scope, epoch and lifecycle.
type Engine struct {
	reservation, environment              resourcev4.Reference
	retired                               bool
	clock                                 atomic.Pointer[timev4.Clock]
	authorizationWake                     <-chan struct{}
	mu                                    sync.Mutex
	config                                Config
	session                               protocolv4.ArtifactSessionParameters
	profile                               protocolv4.RecordProfile
	limits                                usageProfile
	current, staged                       *epochState
	spareScopes                           scopeTable
	stageJobs                             []epochKeyJob
	freeze                                *ApplicationFreeze
	rekey                                 *RekeyRound
	switching                             *epochSwitch
	staging                               bool
	used                                  [2][]uint64
	ordinal                               [2]uint64
	counts                                [2]usage
	derivations                           uint64
	ready, closed                         bool
	initial                               *FinishedHandshake
	initialSubmitted                      bool
	initialSigning                        bool
	bootstrap                             protocolv4.BootstrapSpec
	bootstrapEnabled, bootstrapReserved   bool
	active                                uint32
	pending                               uint32
	flight                                uint32
	borrowedWork                          uint32
	cleanupComplete                       bool
	cleanup                               chan struct{}
	free                                  []*workspace
	maintenance                           [2]*workspace
	sharedInput                           *workspace
	sharedInputReserved                   bool
	reliableFlight                        uint32
	outgoingPackets                       uint32
	invalidTotal, possibleFailures        uint32
	pause                                 *timev4.Delay
	receiveDisabled                       bool
	idle                                  *timev4.Idle
	idleWake, sendWake, receiveWake, done chan struct{}
	maintenanceReceiveWake                chan struct{}
}

func NewEngine(config Config) (*Engine, error) {
	if config.ApplicationProfile == "" {
		config.ApplicationProfile = "transport"
	}
	bootstrap, enabled, err := protocolv4.Bootstrap(config.ApplicationProfile)
	if err != nil {
		return nil, err
	}
	p, err := protocolv4.Profile(config.Profile)
	if err != nil {
		return nil, err
	}
	registry, err := engineRegistry()
	if err != nil {
		return nil, err
	}
	streams := registry.streams
	signedMaximum, err := protocolv4.SessionMaxStreams()
	if err != nil {
		return nil, err
	}
	limits, ok := registry.profiles[config.Profile]
	if !ok || config.SendDirection > protocolv4.ServerToClient || config.MaxFrame < uint32(protocolv4.RecordHeaderSize()+p.TagBytes) || config.MaxFrame > protocolv4.MaxPayloadLength ||
		config.MaxScopes > config.SignedMaxScopes || config.SignedMaxScopes > signedMaximum || (enabled && config.MaxScopes == 0) || config.PendingScopes > streams.Pending || config.WorkSlots == 0 || config.WorkSlots > 128 ||
		config.Clock == nil || config.AuthorizationDeadlineMS == 0 || config.Authorization == nil ||
		config.Maintenance.Calls == 0 || config.Maintenance.Blocks == 0 || config.Maintenance.Bytes == 0 ||
		config.Maintenance.Calls >= min(limits.Key.Seal, limits.Key.Open) || config.Maintenance.Blocks >= limits.Key.Blocks || config.Maintenance.Bytes >= limits.Key.Bytes {
		return nil, ErrConfiguration
	}
	if err := config.Authorization.Check(); err != nil {
		return nil, err
	}
	scopeCapacity, err := scopeTableCapacity(config)
	if err != nil {
		return nil, err
	}
	if _, err := scopeTableSlots(scopeCapacity); err != nil || uint64(scopeCapacity) > uint64(math.MaxInt)/2/uint64(unsafe.Sizeof(epochKeyJob{})) {
		return nil, ErrConfiguration
	}
	idle, err := timev4.NewIdle(config.Clock, config.IdleDurationMS, config.LocalIdleDurationMS)
	if err != nil {
		return nil, err
	}
	e := &Engine{config: config, profile: p, limits: limits, ordinal: [2]uint64{streams.Client, streams.Server}, bootstrap: bootstrap, bootstrapEnabled: enabled, idle: idle, idleWake: make(chan struct{}, 1), sendWake: make(chan struct{}, 1), receiveWake: make(chan struct{}, 1), maintenanceReceiveWake: make(chan struct{}, 1), done: make(chan struct{}), cleanup: make(chan struct{}), free: make([]*workspace, 0, config.WorkSlots)}
	e.clock.Store(config.Clock)
	e.authorizationWake = config.Authorization.Wake()
	deadline, err := e.rootDeadline(config.RootBorn)
	if err != nil {
		return nil, err
	}
	e.used[0] = make([]uint64, (streams.Client+63)/64)
	e.used[1] = make([]uint64, (streams.Server+63)/64)
	for i := uint32(0); i < config.WorkSlots+2; i++ {
		w := &workspace{input: make([]byte, int(config.MaxFrame)+protocolv4.EnvelopePrefixSize), output: make([]byte, int(config.MaxFrame)+protocolv4.EnvelopePrefixSize), maintenance: i >= config.WorkSlots}
		if w.maintenance {
			w.direction = protocolv4.Direction(i - config.WorkSlots)
			e.maintenance[w.direction] = w
		} else {
			e.free = append(e.free, w)
		}
	}
	currentScopes, _ := newScopeTable(scopeCapacity) // Shape checked before allocation.
	e.spareScopes, _ = newScopeTable(scopeCapacity)
	e.stageJobs = make([]epochKeyJob, 2*scopeCapacity)
	e.current = &epochState{root: config.Root, deadline: deadline, keys: currentScopes}
	clear(e.config.Root[:])
	if err := e.current.deadline.Check(); err != nil {
		e.Close()
		return nil, securityTimeError(err)
	}
	for _, scope := range []uint64{0, protocolv4.DatagramScope()} {
		if scope != 0 && !config.Datagrams {
			continue
		}
		keys, err := e.derive(e.current, scope)
		if err != nil {
			e.Close()
			return nil, err
		}
		if err := e.current.keys.insert(scope, keys); err != nil {
			e.Close()
			return nil, err
		}
	}
	if enabled {
		keys, err := e.derive(e.current, bootstrap.Scope)
		if err != nil {
			e.Close()
			return nil, err
		}
		keys.bootstrap = true
		if err := e.current.keys.insert(bootstrap.Scope, keys); err != nil {
			e.Close()
			return nil, err
		}
		e.consumeScope(bootstrap.Scope)
		e.active++
	}
	return e, nil
}

func (e *Engine) derive(epoch *epochState, scope uint64) (*scopeKeys, error) {
	result := new(scopeKeys)
	for direction := protocolv4.ClientToServer; direction <= protocolv4.ServerToClient; direction++ {
		key, err := e.deriveKey(epoch, scope, direction)
		if err != nil {
			return nil, err
		}
		result.keys[direction] = key
	}
	return result, nil
}

func (e *Engine) deriveKey(epoch *epochState, scope uint64, direction protocolv4.Direction) (*recordKey, error) {
	if e.derivations >= e.limits.Derivations {
		return nil, ErrUsage
	}
	e.derivations++ // A failed or cancelled derivation is never refunded.
	return e.constructKey(epoch.root, epoch.number, scope, direction)
}

// constructKey has no owner mutations. Callers reserve the actual job and KDF
// charge first, retain this private root copy, then recheck original ownership.
func (e *Engine) constructKey(root [32]byte, epoch uint32, scope uint64, direction protocolv4.Direction) (*recordKey, error) {
	defer clear(root[:])
	info, err := protocolv4.RecordKeyInfo(e.config.Profile, e.config.HandshakeHash, epoch, direction, scope)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Expand(sha256.New, root[:], string(info), e.profile.KeyBytes)
	if err != nil {
		return nil, err
	}
	var aead cipher.AEAD
	switch e.profile.Algorithm {
	case "chacha20-poly1305":
		aead, err = chacha20poly1305.New(key)
	case "aes-256-gcm":
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	default:
		err = ErrConfiguration
	}
	clear(key)
	if err != nil {
		return nil, err
	}
	return &recordKey{aead: aead}, nil
}

// Activate is called once at the dual-READY publication gate. It does not
// authenticate READY or substitute for that caller-owned handshake transition.
func (e *Engine) Activate() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	if err := e.resourceLive(); err != nil {
		return err
	}
	if e.ready || e.initial != nil || e.bootstrapEnabled && !e.bootstrapReserved {
		return ErrNotReady
	}
	if err := e.config.Authorization.Check(); err != nil {
		return err
	}
	if err := e.current.deadline.Check(); err != nil {
		return securityTimeError(err)
	}
	if err := e.startIdle(); err != nil {
		return err
	}
	e.ready = true
	return nil
}

// OpenScope consumes the lifetime bitmap before deriving keys. A failed
// derivation cannot make the ID reusable. Only the admitted OPEN owner calls it.
func (e *Engine) OpenScope(scope uint64) error {
	return e.openScope(scope, false)
}

func (e *Engine) openScope(scope uint64, opening bool) error {
	e.mu.Lock()
	if err := e.live(); err != nil {
		e.mu.Unlock()
		return err
	}
	if e.staged != nil || e.freeze != nil {
		e.mu.Unlock()
		return ErrTransition
	}
	if scope == 0 || scope == protocolv4.DatagramScope() {
		e.mu.Unlock()
		return ErrScope
	}
	role := (scope + 1) % 2
	ordinal := (scope - 1) / 2
	if scope > math.MaxInt64 || ordinal >= e.ordinal[role] {
		e.mu.Unlock()
		return ErrScope
	}
	word, bit := ordinal/64, uint64(1)<<(ordinal%64)
	if e.used[role][word]&bit != 0 || e.current.keys.get(scope) != nil {
		e.mu.Unlock()
		return ErrScope
	}
	if e.active >= e.config.MaxScopes {
		e.mu.Unlock()
		return ErrCapacity
	}
	epoch := e.current
	keys := &scopeKeys{opening: opening}
	if err := epoch.keys.insert(scope, keys); err != nil {
		e.mu.Unlock()
		return err
	}
	job, err := e.reserveKeyWork(false,
		scopeKeyJob{epoch: epoch, owner: keys, scope: scope, direction: protocolv4.ClientToServer},
		scopeKeyJob{epoch: epoch, owner: keys, scope: scope, direction: protocolv4.ServerToClient})
	if err != nil {
		epoch.keys.remove(scope)
		e.mu.Unlock()
		return err
	}
	e.used[role][word] |= bit
	e.active++
	e.mu.Unlock()
	defer job.release()
	err = job.run()
	e.mu.Lock()
	if err == nil {
		err = e.live()
	}
	if err == nil && (e.current != epoch || epoch.keys.get(scope) != keys || e.freeze != nil || e.staged != nil) {
		err = ErrTransition
	}
	if err != nil {
		// Only this allocated scope is discarded; its lifetime bit and actual
		// work/derivation charges are never restored by a failed preparation.
		if e.current.keys.get(scope) != nil {
			e.current.keys.remove(scope)
			e.active--
		}
		if e.staged != nil {
			e.staged.keys.remove(scope)
		}
	}
	e.mu.Unlock()
	if err != nil {
		return err
	}
	return nil
}

// RetireScope drops only live key references. The permanent used-ID bit and
// Session usage remain until this Engine closes. In-flight jobs retain their
// own key/workspace until real completion and cannot pass the final scope gate.
func (e *Engine) RetireScope(scope uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if scope == 0 || scope == protocolv4.DatagramScope() {
		return
	}
	if e.current.keys.get(scope) != nil {
		if e.current.keys.get(scope).incoming != nil {
			// A pending OPEN cannot be retired without selecting its outcome.
			return
		}
		e.current.keys.remove(scope)
		e.active--
	}
	if e.staged != nil {
		e.staged.keys.remove(scope)
	}
}

func (e *Engine) live() error {
	if e.closed {
		return ErrClosed
	}
	if err := e.resourceLive(); err != nil {
		return err
	}
	if !e.ready {
		return ErrNotReady
	}
	if err := e.checkIdle(); err != nil {
		return err
	}
	if err := e.current.deadline.Check(); err != nil {
		return securityTimeError(err)
	}
	if err := e.config.Authorization.Check(); err != nil {
		return err
	}
	return nil
}

func (e *Engine) initialLive(owner *FinishedHandshake) error {
	if e.closed || owner == nil || e.initial != owner || owner.closed.Load() {
		return ErrClosed
	}
	if err := e.resourceLive(); err != nil {
		return err
	}
	if err := e.current.deadline.Check(); err != nil {
		return securityTimeError(err)
	}
	if err := owner.config.Deadline.Check(); err != nil {
		return securityTimeError(err)
	}
	if err := e.config.Authorization.Check(); err != nil {
		return err
	}
	return nil
}

// inputLive admits private authentication only after this endpoint's actual
// READY submission. Public delivery, new outgoing work and outcome selection
// still require live(), which opens at the original dual-READY transition.
func (e *Engine) inputLive() error {
	if e.ready {
		return e.live()
	}
	if e.initial == nil || !e.initialSubmitted {
		return e.live()
	}
	return e.initialLive(e.initial)
}

func (e *Engine) workspace(maintenance bool, direction protocolv4.Direction) (*workspace, error) {
	if maintenance {
		if e.maintenance[direction] == nil {
			return nil, ErrCapacity
		}
		w := e.maintenance[direction]
		e.maintenance[direction] = nil
		e.borrowedWork++
		return w, nil
	}
	if len(e.free) == 0 {
		return nil, ErrCapacity
	}
	last := len(e.free) - 1
	w := e.free[last]
	e.free[last] = nil
	e.free = e.free[:last]
	e.borrowedWork++
	return w, nil
}

// ReserveSharedInput assigns one already admitted ordinary position to the
// shared reader for its full lifetime. Blocked outgoing provider packets can
// never consume it and prevent later maintenance envelopes from progressing.
// No capacity is added; at least one ordinary send/KDF position remains.
func (e *Engine) ReserveSharedInput() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.serviceInitializationLive(); err != nil {
		return err
	}
	if e.sharedInputReserved || e.config.WorkSlots < 2 || len(e.free) == 0 {
		return ErrConfiguration
	}
	w, err := e.workspace(false, 1-e.config.SendDirection)
	if err != nil {
		return err
	}
	w.sharedInput = true
	e.borrowedWork-- // Assignment to the idle shared lane is not an active borrow.
	e.sharedInput, e.sharedInputReserved = w, true
	return nil
}

// serviceInitializationLive permits only attachment of already reserved core
// services before this engine's original READY signature. It does not permit
// records, probes, rekey rounds, application input or scope creation.
func (e *Engine) serviceInitializationLive() error {
	if e.ready || e.initial == nil {
		return e.live()
	}
	if err := e.initialLive(e.initial); err != nil {
		return err
	}
	if e.initialSigning || e.initialSubmitted {
		return ErrTransition
	}
	return nil
}

// ServiceInitializationEpoch supplies the original epoch to the private
// maintenance constructors without borrowing a record frontier or opening I/O.
// The same gate as ReserveSharedInput closes when READY signing begins.
func (e *Engine) ServiceInitializationEpoch() (uint32, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.serviceInitializationLive(); err != nil {
		return 0, err
	}
	return e.current.number, nil
}

func (e *Engine) inputWorkspace(maintenance, datagram bool) (*workspace, error) {
	if e.sharedInputReserved && !maintenance && !datagram {
		if e.sharedInput == nil {
			return nil, ErrCapacity
		}
		w := e.sharedInput
		e.sharedInput = nil
		e.borrowedWork++
		return w, nil
	}
	return e.workspace(maintenance, 1-e.config.SendDirection)
}
func (e *Engine) release(w *workspace) {
	clear(w.input)
	clear(w.output)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.borrowedWork--
	if e.closed {
		w.input, w.output = nil, nil
		e.finishCleanupLocked()
		return
	}
	if w.sharedInput {
		e.sharedInput = w
		select {
		case e.receiveWake <- struct{}{}:
		default:
		}
	} else if w.maintenance {
		e.maintenance[w.direction] = w
		if w.direction != e.config.SendDirection {
			select {
			case e.maintenanceReceiveWake <- struct{}{}:
			default:
			}
		}
	} else {
		e.free = append(e.free, w)
		e.signalSend()
		select {
		case e.receiveWake <- struct{}{}:
		default:
		}
	}
}

func canCharge(current usage, cost usage, limits usageLimits, open bool, reserve MaintenanceReserve) bool {
	calls := limits.Seal
	if open {
		calls = limits.Open
	}
	return reserve.Calls <= calls && reserve.Blocks <= limits.Blocks && reserve.Bytes <= limits.Bytes &&
		current.calls <= calls-reserve.Calls && cost.calls <= calls-reserve.Calls-current.calls &&
		current.blocks <= limits.Blocks-reserve.Blocks && cost.blocks <= limits.Blocks-reserve.Blocks-current.blocks &&
		current.bytes <= limits.Bytes-reserve.Bytes && cost.bytes <= limits.Bytes-reserve.Bytes-current.bytes
}
func addUsage(value *usage, cost usage) {
	value.calls += cost.calls
	value.blocks += cost.blocks
	value.bytes += cost.bytes
}
func (e *Engine) charge(epoch *epochState, key *recordKey, direction protocolv4.Direction, frame protocolv4.FrameType, aadBytes, payloadBytes int, open bool) error {
	blocks := func(n int) uint64 { return uint64(n/16) + uint64((n%16+15)/16) }
	cost := usage{calls: 1, blocks: blocks(aadBytes) + blocks(payloadBytes) + 1, bytes: uint64(payloadBytes + e.profile.TagBytes)}
	reserve := MaintenanceReserve{}
	if frame != protocolv4.FrameRekey {
		reserve = e.config.Maintenance
	}
	keyReserve := MaintenanceReserve{}
	if key == epoch.keys.get(0).keys[direction] {
		keyReserve = reserve
	}
	if !canCharge(key.usage, cost, e.limits.Key, open, keyReserve) || !canCharge(epoch.usage[direction], cost, e.limits.Epoch, open, reserve) || !canCharge(e.counts[direction], cost, e.limits.Session, open, reserve) {
		return ErrUsage
	}
	addUsage(&key.usage, cost)
	addUsage(&epoch.usage[direction], cost)
	addUsage(&e.counts[direction], cost)
	return nil
}

// Packet retains the preallocated workspace until Release. Bytes are borrowed
// only while this unique owner is live; callers must finish using them before
// Release and must not retain aliases afterward.
type Packet struct {
	engine    *Engine
	workspace *workspace
	data      []byte
	epoch     *epochState
	datagram  bool
	outgoing  bool
	scope     uint64
	key       *recordKey
	mu        sync.Mutex
	released  bool
	activity  bool
}

func (p *Packet) Bytes() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.released {
		return nil, ErrClosed
	}
	p.engine.mu.Lock()
	defer p.engine.mu.Unlock()
	var err error
	if p.outgoing {
		err = p.engine.live()
	} else {
		err = p.engine.inputLive()
	}
	if err != nil {
		return nil, err
	}
	if p.datagram && p.epoch != p.engine.current {
		return nil, ErrEpoch
	}
	if p.datagram && p.outgoing && p.engine.freeze != nil && p.engine.freeze.committed {
		return nil, ErrTransition
	}
	if p.datagram && !p.outgoing {
		if err := p.engine.datagramGate(); err != nil {
			return nil, err
		}
	}
	if p.outgoing {
		keys := p.epoch.keys.get(p.scope)
		if p.epoch != p.engine.sendEpoch(p.scope) || keys == nil || keys.keys[p.engine.config.SendDirection] != p.key {
			return nil, ErrScope
		}
	}
	return p.data, nil
}
func (p *Packet) Release() {
	p.mu.Lock()
	if p.released {
		p.mu.Unlock()
		return
	}
	p.released = true
	p.data = nil
	w := p.workspace
	p.workspace = nil
	e := p.engine
	p.engine, p.epoch, p.key = nil, nil, nil
	reliable := p.outgoing && !p.datagram
	p.mu.Unlock()
	if reliable {
		e.mu.Lock()
		e.outgoingPackets--
		e.mu.Unlock()
	}
	e.release(w)
}

// Seal's successful precharge is the irreversible record ticket. Sequence and
// cryptographic usage remain spent if the caller cancels or discards its packet.
func (e *Engine) Seal(frame protocolv4.FrameType, scope uint64, plaintext []byte) (*Packet, error) {
	return e.SealBuild(frame, scope, len(plaintext), func(_ protocolv4.RecordHeader, dst []byte) (int, error) { return copy(dst, plaintext), nil })
}

// SealBuild gives a bounded internal frame encoder the original ticket's
// epoch/scope/sequence. The maximum encoded size is precharged before the ticket;
// encoding failure spends that ticket. build is never application code and may
// neither retain dst nor call this engine. It runs outside the owner lock.
func (e *Engine) SealBuild(frame protocolv4.FrameType, scope uint64, maxPlaintext int, build func(protocolv4.RecordHeader, []byte) (int, error)) (*Packet, error) {
	return e.sealBuild(frame, scope, maxPlaintext, build, nil, nil, nil)
}

// SealBuildTicket adds a bounded internal accounting hook at the exact ticket
// gate, before sequence advancement. It may only sample the admitted clock and
// update its original ledger; no crypto, I/O, application callback or engine
// reentry is permitted. Hook failure still consumes this irreversible ticket.
func (e *Engine) SealBuildTicket(frame protocolv4.FrameType, scope uint64, maxPlaintext int, build func(protocolv4.RecordHeader, []byte) (int, error), ticket func() error) (*Packet, error) {
	return e.sealBuild(frame, scope, maxPlaintext, build, nil, ticket, nil)
}

func (e *Engine) SealBuildGuard(frame protocolv4.FrameType, scope uint64, maxPlaintext int, build func(protocolv4.RecordHeader, []byte) (int, error), ticket func() error, guard TicketGuard) (*Packet, error) {
	return e.sealBuild(frame, scope, maxPlaintext, build, nil, ticket, guard)
}

func (e *Engine) sealBuild(frame protocolv4.FrameType, scope uint64, maxPlaintext int, build func(protocolv4.RecordHeader, []byte) (int, error), marker *RekeyRound, ticket func() error, guard TicketGuard) (*Packet, error) {
	if build == nil || maxPlaintext < 0 {
		return nil, ErrConfiguration
	}
	e.mu.Lock()
	if err := e.live(); err != nil {
		e.mu.Unlock()
		return nil, err
	}
	epoch := e.sendEpoch(scope)
	if marker != nil {
		if e.switching == nil || e.switching.round != marker || e.switching.sent || !e.switching.markerPreparing || e.staged == nil {
			e.mu.Unlock()
			return nil, ErrTransition
		}
		epoch = e.staged
	} else if scope == 0 && e.switching != nil && e.switching.markerPreparing {
		e.mu.Unlock()
		return nil, ErrTransition
	}
	if e.freeze != nil && (scope != 0 && scope != protocolv4.DatagramScope() || scope == protocolv4.DatagramScope() && e.freeze.committed) {
		e.mu.Unlock()
		return nil, ErrTransition
	}
	keys := epoch.keys.get(scope)
	if keys == nil {
		e.mu.Unlock()
		return nil, ErrScope
	}
	if keys.keys[e.config.SendDirection] == nil || keys.deriving[e.config.SendDirection] {
		e.mu.Unlock()
		return nil, ErrNotReady
	}
	if keys.bootstrap && !keys.openSubmitted && (e.config.SendDirection != e.bootstrap.Opener || frame != protocolv4.FrameOpenStream) {
		e.mu.Unlock()
		return nil, ErrNotReady
	}
	if keys.incoming != nil || frame == protocolv4.FrameOpenStream && keys.openSubmitted || keys.opening && (frame != protocolv4.FrameOpenStream || keys.keys[e.config.SendDirection].next != 0) {
		e.mu.Unlock()
		return nil, ErrNotReady
	}
	key := keys.keys[e.config.SendDirection]
	if key.exhausted {
		e.mu.Unlock()
		return nil, ErrUsage
	}
	header := protocolv4.RecordHeader{Epoch: epoch.number, Scope: scope, Sequence: key.next}
	prefix, err := protocolv4.RecordPrefix(frame, header, maxPlaintext, e.config.Profile, e.config.MaxFrame)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	aad, err := protocolv4.RecordAAD(e.config.Profile, e.config.SendDirection, prefix)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	w, err := e.workspace(scope == 0, e.config.SendDirection)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	if guard != nil {
		if err = guard.LockTicket(); err != nil {
			e.mu.Unlock()
			e.release(w)
			return nil, err
		}
	}
	// The original cancellation/cause gate may have been contended. Recheck
	// the same security owner at the actual ticket, before spending its nonce.
	err = e.live()
	if err == nil {
		err = securityTimeError(epoch.deadline.Check())
	}
	if err == nil {
		err = e.charge(epoch, key, e.config.SendDirection, frame, len(aad), maxPlaintext, false)
	}
	if err != nil {
		if guard != nil {
			guard.UnlockTicket(false)
		}
		e.mu.Unlock()
		e.release(w)
		return nil, err
	}
	var ticketErr error
	if ticket != nil {
		ticketErr = ticket()
	}
	if key.next == math.MaxUint64 {
		key.exhausted = true
	} else {
		key.next++
	}
	if frame == protocolv4.FrameOpenStream {
		keys.openSubmitted = true
	}
	if marker != nil {
		e.switching.sent = true
		e.switching.markerPreparing = false
	}
	if guard != nil {
		guard.UnlockTicket(true)
	}
	e.flight++
	if scope != protocolv4.DatagramScope() {
		e.reliableFlight++
	}
	e.mu.Unlock()
	if ticketErr != nil {
		return e.finish(w, epoch, key, header, nil, ticketErr)
	}
	size, err := build(header, w.input[:maxPlaintext:maxPlaintext])
	if err != nil {
		return e.finish(w, epoch, key, header, nil, err)
	}
	if size < 0 || size > maxPlaintext {
		return e.finish(w, epoch, key, header, nil, ErrConfiguration)
	}
	prefix, err = protocolv4.RecordPrefix(frame, header, size, e.config.Profile, e.config.MaxFrame)
	if err != nil {
		return e.finish(w, epoch, key, header, nil, err)
	}
	aad, err = protocolv4.RecordAAD(e.config.Profile, e.config.SendDirection, prefix)
	if err != nil {
		return e.finish(w, epoch, key, header, nil, err)
	}
	copy(w.output, prefix)
	// Recheck time at actual crypto start, after any queue/scheduler delay.
	e.mu.Lock()
	err = e.live()
	if err == nil {
		current := e.sendEpoch(scope).keys.get(scope)
		if epoch != e.sendEpoch(scope) || current == nil || current.keys[e.config.SendDirection] != key {
			err = ErrScope
		}
	}
	e.mu.Unlock()
	if err != nil {
		return e.finish(w, epoch, key, header, nil, err)
	}
	nonce, err := protocolv4.RecordNonce(header)
	if err != nil {
		return e.finish(w, epoch, key, header, nil, err)
	}
	sealed := key.aead.Seal(w.output[:len(prefix)], nonce[:], w.input[:size], aad)
	return e.finish(w, epoch, key, header, sealed, nil)
}

func (e *Engine) finish(w *workspace, epoch *epochState, key *recordKey, header protocolv4.RecordHeader, data []byte, err error) (*Packet, error) {
	scope := header.Scope
	e.mu.Lock()
	e.flight--
	if scope != protocolv4.DatagramScope() {
		e.reliableFlight--
	}
	if err == nil {
		err = e.live()
	}
	if err == nil && epoch != e.sendEpoch(scope) {
		err = ErrEpoch
	}
	if err == nil {
		keys := epoch.keys.get(scope)
		if keys == nil || keys.keys[e.config.SendDirection] != key {
			err = ErrScope
		}
	}
	if err == nil && scope != protocolv4.DatagramScope() {
		e.outgoingPackets++
	}
	e.mu.Unlock()
	if err != nil {
		e.release(w)
		return nil, &TicketError{Cause: err, Header: header}
	}
	return &Packet{engine: e, workspace: w, data: data, epoch: epoch, datagram: scope == protocolv4.DatagramScope(), outgoing: true, scope: scope, key: key}, nil
}

// Open accepts only a pre-owned scope/key. No untrusted header allocates a scope,
// derives another key or selects another Session. Reliable callers serialize a
// direction; datagram jobs may overlap and compete at the final replay gate.
func (e *Engine) Open(input []byte, validate func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error) (*Packet, protocolv4.FrameType, protocolv4.RecordHeader, error) {
	return e.open(input, validate, nil)
}

func (e *Engine) open(input []byte, validate func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error, marker *RekeyRound) (*Packet, protocolv4.FrameType, protocolv4.RecordHeader, error) {
	return e.openReserved(input, validate, marker, nil)
}

func (e *Engine) openReserved(input []byte, validate func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error, marker *RekeyRound, reserved *workspace) (*Packet, protocolv4.FrameType, protocolv4.RecordHeader, error) {
	defer func() {
		if reserved != nil {
			e.release(reserved)
		}
	}()
	if validate == nil {
		return nil, 0, protocolv4.RecordHeader{}, ErrConfiguration
	}
	frame, header, ciphertext, err := protocolv4.ParseRecord(input, e.config.Profile, e.config.MaxFrame)
	if err != nil {
		return nil, 0, header, err
	}
	e.mu.Lock()
	if err = e.inputLive(); err != nil {
		e.mu.Unlock()
		return nil, frame, header, err
	}
	epoch, epochErr := e.receiveEpoch(frame, header, marker)
	if epochErr != nil {
		e.mu.Unlock()
		return nil, frame, header, epochErr
	}
	keys := epoch.keys.get(header.Scope)
	if keys == nil {
		e.mu.Unlock()
		return nil, frame, header, ErrScope
	}
	if keys.bootstrap && ((!keys.openSubmitted && (1-e.config.SendDirection != e.bootstrap.Opener || frame != protocolv4.FrameOpenStream)) || keys.openSubmitted && frame == protocolv4.FrameOpenStream) {
		e.mu.Unlock()
		return nil, frame, header, ErrNotReady
	}
	if keys.opening && (!keys.openSubmitted || frame != protocolv4.FrameStreamData) || keys.incoming != nil && (frame != protocolv4.FrameOpenStream || keys.incoming.authenticated || header != keys.incoming.header) {
		e.mu.Unlock()
		return nil, frame, header, ErrNotReady
	}
	direction := protocolv4.Direction(1 - e.config.SendDirection)
	key := keys.keys[direction]
	if key == nil || keys.deriving[direction] {
		e.mu.Unlock()
		return nil, frame, header, ErrNotReady
	}
	datagram := frame == protocolv4.FrameDatagram
	if datagram {
		if err = e.datagramGate(); err != nil {
			e.mu.Unlock()
			return nil, frame, header, err
		}
		if e.invalidTotal+e.possibleFailures >= 32 {
			e.mu.Unlock()
			return nil, frame, header, ErrReceiveBlocked
		}
		if !key.replay.admits(header.Sequence) {
			e.mu.Unlock()
			return nil, frame, header, ErrReplay
		}
	} else if key.busy || key.exhausted || header.Sequence != key.next {
		e.mu.Unlock()
		return nil, frame, header, ErrSequence
	}
	prefixSize := protocolv4.EnvelopePrefixSize + protocolv4.RecordHeaderSize()
	aad, err := protocolv4.RecordAAD(e.config.Profile, direction, input[:prefixSize])
	if err != nil {
		e.mu.Unlock()
		return nil, frame, header, err
	}
	w := reserved
	if w == nil {
		w, err = e.inputWorkspace(header.Scope == 0, datagram)
	} else {
		reserved = nil // This call now owns the original KDF position.
	}
	if err != nil {
		e.mu.Unlock()
		return nil, frame, header, err
	}
	if err = e.charge(epoch, key, direction, frame, len(aad), len(ciphertext)-e.profile.TagBytes, true); err != nil {
		e.mu.Unlock()
		e.release(w)
		return nil, frame, header, err
	}
	copy(w.input, input)
	if datagram {
		e.possibleFailures++
	}
	if !datagram {
		key.busy = true
	}
	e.flight++
	if !datagram {
		e.reliableFlight++
	}
	e.mu.Unlock()
	var plaintext []byte
	authFailed := false
	e.mu.Lock()
	err = e.inputLive()
	if err == nil {
		selected, selectErr := e.receiveEpoch(frame, header, marker)
		current := epoch.keys.get(header.Scope)
		if selectErr != nil || epoch != selected || current == nil || current.keys[direction] != key {
			err = ErrScope
		}
	}
	e.mu.Unlock()
	if err == nil {
		var nonce [12]byte
		nonce, err = protocolv4.RecordNonce(header)
		if err == nil {
			plaintext, err = key.aead.Open(w.output[:0], nonce[:], w.input[prefixSize:len(input)], aad)
			if err != nil {
				authFailed = true
				err = ErrAuthentication
			}
		}
	}
	if err == nil {
		err = validate(frame, header, plaintext)
	}
	e.mu.Lock()
	e.flight--
	if !datagram {
		e.reliableFlight--
	}
	if datagram {
		e.possibleFailures--
		if authFailed {
			e.invalidTotal++
			if e.invalidTotal >= 32 {
				e.receiveDisabled = true
			} else if !e.closed && e.invalidTotal%8 == 0 {
				var pauseErr error
				e.pause, pauseErr = timev4.NewDelay(e.config.Clock, 1000)
				if pauseErr != nil {
					e.receiveDisabled = true
				}
			}
		}
	}
	if !datagram {
		key.busy = false
	}
	if err == nil {
		err = e.inputLive()
	}
	if err == nil {
		selected, selectErr := e.receiveEpoch(frame, header, marker)
		if selectErr != nil {
			err = selectErr
		} else if epoch != selected {
			err = ErrEpoch
		}
	}
	if err == nil {
		current := epoch.keys.get(header.Scope)
		if current == nil || current.keys[direction] != key {
			err = ErrScope
		}
	}
	if err == nil && marker != nil && marker.receiveTicket != nil {
		err = marker.receiveTicket()
	}
	if err == nil {
		if datagram {
			if gateErr := e.datagramGate(); gateErr != nil {
				err = gateErr
			} else if !key.replay.admits(header.Sequence) {
				err = ErrReplay
			} else {
				key.replay.accept(header.Sequence)
				blocks := func(n int) uint64 { return uint64(n/16) + uint64((n%16+15)/16) }
				addUsage(&key.good, usage{calls: 1, blocks: blocks(len(aad)) + blocks(len(plaintext)) + 1, bytes: uint64(len(ciphertext))})
			}
		} else if key.next != header.Sequence {
			err = ErrSequence
		} else if key.next == math.MaxUint64 {
			key.exhausted = true
		} else {
			key.next++
			if keys.incoming != nil {
				keys.incoming.authenticated = true
			}
			if keys.bootstrap && frame == protocolv4.FrameOpenStream {
				keys.openSubmitted = true
			}
			if marker != nil {
				e.switching.received = true
			}
		}
	}
	e.mu.Unlock()
	if err != nil {
		e.release(w)
		return nil, frame, header, err
	}
	return &Packet{engine: e, workspace: w, data: plaintext, epoch: epoch, datagram: datagram}, frame, header, nil
}

// StageEpoch does not enable new-epoch receive or send. The rekey owner commits
// only at its protocol completion point after resolving every old reliable job.
func (e *Engine) StageEpoch(root [32]byte, born timev4.Sample) error {
	return e.stageEpoch(root, born, nil)
}

func (e *Engine) stageEpoch(root [32]byte, born timev4.Sample, round *RekeyRound) error {
	defer clear(root[:])
	e.mu.Lock()
	if err := e.live(); err != nil {
		e.mu.Unlock()
		return err
	}
	if e.rekey != round || e.staged != nil || uint64(e.current.number)+1 >= e.limits.Epochs {
		e.mu.Unlock()
		return ErrTransition
	}
	var deadline *timev4.Deadline
	var err error
	if round != nil {
		deadline = round.rootAge
	} else {
		deadline, err = e.rootDeadline(born)
	}
	if err == nil && deadline == nil {
		err = ErrConfiguration
	}
	if err == nil {
		err = deadline.Check()
	}
	if err != nil {
		e.mu.Unlock()
		return securityTimeError(err)
	}
	if len(e.spareScopes.slots) == 0 {
		e.mu.Unlock()
		return ErrTransition
	}
	var derivations uint64
	for _, previous := range e.current.keys.all() {
		for direction, key := range previous.keys {
			if key != nil || previous.deriving[direction] {
				derivations++
			}
		}
	}
	if e.derivations > e.limits.Derivations || derivations > e.limits.Derivations-e.derivations {
		e.mu.Unlock()
		return ErrUsage
	}
	staged := &epochState{number: e.current.number + 1, root: root, deadline: deadline, keys: e.spareScopes}
	e.spareScopes = scopeTable{}
	// The sole staging owner is the reserved rekey work position. Ordinary
	// record jobs cannot borrow it or block its response with held output bytes.
	jobs := e.stageJobs[:0]
	for scope, previous := range e.current.keys.all() {
		keys := &scopeKeys{bootstrap: previous.bootstrap, opening: previous.opening, openSubmitted: previous.openSubmitted, incoming: previous.incoming}
		for direction, key := range previous.keys {
			if key == nil && !previous.deriving[direction] {
				continue
			}
			keys.deriving[direction] = true
			jobs = append(jobs, epochKeyJob{scope, protocolv4.Direction(direction), keys})
		}
		if err := staged.keys.insert(scope, keys); err != nil {
			clear(staged.root[:])
			clear(jobs)
			e.recycleScopeTable(&staged.keys)
			e.mu.Unlock()
			return err
		}
	}
	e.derivations += derivations
	e.staged = staged
	e.staging = true
	e.flight++
	e.mu.Unlock()
	for _, job := range jobs {
		e.mu.Lock()
		err = e.live()
		if err == nil && e.staged != staged {
			err = ErrTransition
		}
		if err == nil {
			err = securityTimeError(staged.deadline.Check())
		}
		present := staged.keys.get(job.scope) == job.owner
		e.mu.Unlock()
		if err != nil {
			break
		}
		if !present {
			continue
		}
		key, keyErr := e.constructKey(root, staged.number, job.scope, job.direction)
		if keyErr != nil {
			err = keyErr
			break
		}
		e.mu.Lock()
		err = e.live()
		if err == nil && e.staged != staged {
			err = ErrTransition
		}
		if err == nil {
			err = securityTimeError(staged.deadline.Check())
		}
		if err == nil && staged.keys.get(job.scope) == job.owner {
			job.owner.keys[job.direction] = key
			job.owner.deriving[job.direction] = false
		}
		e.mu.Unlock()
		if err != nil {
			break
		}
	}
	clear(jobs)
	e.mu.Lock()
	e.flight--
	if err == nil {
		err = e.live()
	}
	if err == nil {
		err = securityTimeError(staged.deadline.Check())
	}
	e.staging = false
	if err != nil {
		clear(staged.root[:])
		e.recycleScopeTable(&staged.keys)
		if e.staged == staged {
			e.staged = nil
		}
	}
	if err == nil && round != nil {
		e.switching = &epochSwitch{round: round}
	}
	clear(root[:])
	e.finishCleanupLocked()
	e.mu.Unlock()
	return err
}
func (e *Engine) CommitEpoch() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	if e.rekey != nil || e.staging || e.staged == nil || e.reliableFlight != 0 || e.outgoingPackets != 0 {
		return ErrTransition
	}
	if err := e.staged.deadline.Check(); err != nil {
		return securityTimeError(err)
	}
	old := e.current
	e.current = e.staged
	e.staged = nil
	clear(old.root[:])
	e.recycleScopeTable(&old.keys)

	return nil
}

func (e *Engine) Close() {
	e.mu.Lock()
	defer func() {
		round := e.rekey
		e.mu.Unlock()
		if round != nil {
			round.Close()
		}
	}()
	if e.closed {
		return
	}
	e.closed = true
	e.reservation.Seal()
	e.config.Authorization.Close(ErrClosed)
	e.ready = false
	e.initial = nil
	e.freeze = nil
	e.switching = nil
	close(e.done)
	e.spareScopes.clear()
	for _, epoch := range []*epochState{e.current, e.staged} {
		if epoch != nil {
			clear(epoch.root[:])
			epoch.keys.clear()

		}
	}
	for _, w := range e.free {
		clear(w.input)
		clear(w.output)
		w.input, w.output = nil, nil
	}
	e.free = nil
	if e.sharedInput != nil {
		clear(e.sharedInput.input)
		clear(e.sharedInput.output)
		e.sharedInput.input, e.sharedInput.output = nil, nil
		e.sharedInput = nil
	}
	for i, w := range e.maintenance {
		if w != nil {
			clear(w.input)
			clear(w.output)
			w.input, w.output = nil, nil
			e.maintenance[i] = nil
		}
	}
	// Outstanding workspaces and cipher objects are cleared/released only by
	// their original jobs/packets after real exit. Close never reuses them.
	e.finishCleanupLocked()
}

func (e *Engine) datagramGate() error {
	if e.receiveDisabled {
		return ErrReceiveDisabled
	}
	if e.pause != nil {
		if err := e.pause.Check(); errors.Is(err, timev4.ErrPending) {
			return ErrReceiveBlocked
		} else if err != nil {
			return securityTimeError(err)
		}
		e.pause = nil
	}
	return nil
}

// DatagramReceiveState reports local receive protection without requesting
// rekey or changing reliable service. A zero retry interval is not a timer.
func (e *Engine) DatagramReceiveState() (reason error, retryAfter time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err, 0
	}
	if !e.config.Datagrams {
		return ErrScope, 0
	}
	if e.receiveDisabled {
		return ErrReceiveDisabled, 0
	}
	if e.pause != nil {
		remaining, err := e.pause.RemainingMS()
		if errors.Is(err, timev4.ErrPending) {
			return ErrReceiveBlocked, time.Duration(min(remaining, 1000)) * time.Millisecond
		}
		if err != nil {
			return securityTimeError(err), 0
		}
		e.pause = nil
	}
	key := e.current.keys.get(protocolv4.DatagramScope()).keys[1-e.config.SendDirection]
	if key.usage.calls >= e.limits.Key.Open {
		return ErrUsage, 0
	}
	return nil, 0
}

// Bits record distance behind highest. A gap never allocates memory and an
// unauthenticated value cannot move this window. No sequence+window arithmetic.
type replayWindow struct {
	present bool
	highest uint64
	bits    [4]uint64
}

func (w *replayWindow) admits(sequence uint64) bool {
	if !w.present || sequence > w.highest {
		return true
	}
	delta := w.highest - sequence
	return delta < 256 && w.bits[delta/64]&(uint64(1)<<(delta%64)) == 0
}
func (w *replayWindow) accept(sequence uint64) {
	if !w.present {
		w.present = true
		w.highest = sequence
		w.bits[0] = 1
		return
	}
	if sequence > w.highest {
		delta := sequence - w.highest
		if delta >= 256 {
			clear(w.bits[:])
		} else {
			words, shift := int(delta/64), uint(delta%64)
			var next [4]uint64
			for i := 3; i >= words; i-- {
				next[i] = w.bits[i-words] << shift
				if shift != 0 && i > words {
					next[i] |= w.bits[i-words-1] >> (64 - shift)
				}
			}
			w.bits = next
		}
		w.highest = sequence
		w.bits[0] |= 1
		return
	}
	delta := w.highest - sequence
	w.bits[delta/64] |= uint64(1) << (delta % 64)
}
