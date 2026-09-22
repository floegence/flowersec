package cryptov4

import (
	"crypto/fips140"
	"encoding/json"
	"math"
	"runtime"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// EngineResourceOptions completes the source-sized SDK backing with the
// deployment's channel and allocation overhead allowance. Engine creates no
// goroutines or timers: the Session separately admits the actual crypto callers,
// their stacks and scheduling. Shared registries, clock, authorization and crypto
// caches belong to the Environment whose original reservation is borrowed.
type EngineResourceOptions struct{ RuntimeBytes uint64 }

type engineStreamLimits struct {
	Client  uint64 `json:"client_ordinals"`
	Server  uint64 `json:"server_ordinals"`
	Pending uint32 `json:"pending_per_role"`
}

type engineRegistryData struct {
	profiles map[string]usageProfile
	streams  engineStreamLimits
}

// Immutable registry decoding is shared initialization, never an uncharged
// per-Session constructor scratch graph.
var engineRegistry = sync.OnceValues(func() (*engineRegistryData, error) {
	var usage struct{ Profiles map[string]usageProfile }
	var streams engineStreamLimits
	if json.Unmarshal([]byte(protocolv4.CryptoUsageRegistryJSON), &usage) != nil || json.Unmarshal([]byte(protocolv4.StreamStateRegistryJSON), &streams) != nil || streams.Client > math.MaxUint64-63 || streams.Server > math.MaxUint64-63 {
		return nil, ErrConfiguration
	}
	return &engineRegistryData{usage.Profiles, streams}, nil
})

// These backend allowances were sized from Go 1.27.1 and the module's pinned
// golang.org/x/crypto v0.55.0, with assembly enabled on amd64/arm64. Dependency
// replacements or different crypto sources require a separately qualified bound.
// Runtime FIPS/frozen modules and unsupported build backends fail admission.
func engineResourceBackend() error {
	if !engineResourceAssembly || runtime.Version() != "go1.27.1" || fips140.Enabled() || fips140.Version() != "latest" {
		return ErrConfiguration
	}
	return nil
}

type engineByteCharge struct{ bytes uint64 }

func (c *engineByteCharge) add(count, size uint64) error {
	if size != 0 && count > math.MaxUint64/size {
		return ErrConfiguration
	}
	n := count * size
	if n > math.MaxUint64-c.bytes {
		return ErrConfiguration
	}
	c.bytes += n
	return nil
}

// EngineCharge computes the complete live Engine backing before constructing
// it. Only immutable shape fields of Config are needed; the handshake supplies
// roots, authorization and clock later. RuntimeBytes covers qualified channel
// and allocator overhead. Dead objects awaiting GC, callers' stacks and process
// RSS remain outside this live-backing bound.
func EngineCharge(config Config, options EngineResourceOptions) (resourcev4.Vector, error) {
	if options.RuntimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	if err := engineResourceBackend(); err != nil {
		return resourcev4.Vector{}, err
	}
	if config.ApplicationProfile == "" {
		config.ApplicationProfile = "transport"
	}
	_, bootstrap, err := protocolv4.Bootstrap(config.ApplicationProfile)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	p, err := protocolv4.Profile(config.Profile)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	r, err := engineRegistry()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	maximum, err := protocolv4.SessionMaxStreams()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if _, ok := r.profiles[config.Profile]; !ok || config.SendDirection > protocolv4.ServerToClient || config.MaxFrame < uint32(protocolv4.RecordHeaderSize()+p.TagBytes) || config.MaxFrame > protocolv4.MaxPayloadLength || config.MaxScopes > config.SignedMaxScopes || config.SignedMaxScopes > maximum || bootstrap && config.MaxScopes == 0 || config.PendingScopes > r.streams.Pending || config.WorkSlots == 0 || config.WorkSlots > 128 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	capacity, err := scopeTableCapacity(config)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	slots, err := scopeTableSlots(capacity)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	c, w := uint64(capacity), uint64(config.WorkSlots)
	// Original owners survive index removal and epoch replacement. Count both
	// tables, the stage snapshot, two owners per ordinary job, and maintenance.
	scopes, keys := 3*c+2*w+2, 6*c+4*w+4
	// Every ordinary job can retain two old epochs while subsequent rekeys
	// progress. Current/candidate, maintenance and round metadata are additional.
	epochs := 2*w + 8
	m := uint64(config.MaxFrame) - uint64(protocolv4.RecordHeaderSize()+p.TagBytes)
	charge := engineByteCharge{}
	for _, part := range [...]struct{ count, size uint64 }{
		{1, uint64(unsafe.Sizeof(Engine{}))},
		{w + 2, uint64(unsafe.Sizeof(workspace{}))},
		{2 * (w + 2), uint64(config.MaxFrame) + uint64(protocolv4.EnvelopePrefixSize)},
		{w, uint64(unsafe.Sizeof((*workspace)(nil)))},
		{2 * uint64(slots), uint64(unsafe.Sizeof(scopeBucket{}))},
		{2 * c, uint64(unsafe.Sizeof(epochKeyJob{}))},
		{(r.streams.Client + 63) / 64, 8},
		{(r.streams.Server + 63) / 64, 8},
		{scopes, uint64(unsafe.Sizeof(scopeKeys{}))},
		{keys, uint64(unsafe.Sizeof(recordKey{})) + 1024},
		{epochs, uint64(unsafe.Sizeof(epochState{})) + uint64(unsafe.Sizeof(timev4.Deadline{}))},
		{w, uint64(unsafe.Sizeof(scopeKeyWork{}))},
		{w + 2, uint64(unsafe.Sizeof(Packet{})) + uint64(unsafe.Sizeof(TicketError{}))},
		{c + w + 1, uint64(unsafe.Sizeof(IncomingScope{}))},
		{1, uint64(unsafe.Sizeof(ApplicationFreeze{})) + uint64(unsafe.Sizeof(epochSwitch{})) + uint64(unsafe.Sizeof(RekeyRound{}))},
		{1, uint64(unsafe.Sizeof(timev4.Idle{})) + uint64(unsafe.Sizeof(timev4.Delay{}))},
		{4, uint64(unsafe.Sizeof(timev4.Deadline{}))},
		{w + 1, 4096},      // Sequential constructors per ordinary/stage position.
		{6, m},             // Four round buffers and the exact two-frame transcript.
		{1, 127 + 16*1024}, // Transcript prefix plus DH/HMAC/HKDF/small input scratch.
		{1, options.RuntimeBytes},
	} {
		if err := charge.add(part.count, part.size); err != nil {
			return resourcev4.Vector{}, err
		}
	}
	return resourcev4.Vector{resourcev4.SDKBytes: charge.bytes, resourcev4.Items: 1 + scopes + keys + epochs + c + 4*w + 8, resourcev4.WorkSlots: w + 4}, nil
}

// NewReservedEngine consumes a unique original Engine reservation before any
// Engine allocation and borrows the same Environment's shared dependency owner.
// NewEngine remains the internal unreserved primitive for protocol tests.
func NewReservedEngine(config Config, options EngineResourceOptions, reservation, environment resourcev4.Reference) (*Engine, error) {
	charge, err := EngineCharge(config, options)
	if err != nil {
		return nil, err
	}
	if reservation == environment {
		return nil, resourcev4.ErrOwner
	}
	if err := reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	shared, err := environment.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	return newReservedEngineOwned(config, owned, shared)
}

// NewReservedEngineWithEnvironmentBorrow consumes an Engine claim and moves
// an Environment borrow admitted by the original plan. It acquires no new
// reference slot. Failures before taking the Engine claim leave both handles
// unchanged; later failures release every handle actually taken. An Environment
// handle rejected before its move remains owned by the caller. Stale caller
// copies cannot release an Engine or Environment reference after successful use.
func NewReservedEngineWithEnvironmentBorrow(config Config, options EngineResourceOptions, reservation, environmentBorrow resourcev4.Reference) (*Engine, error) {
	charge, err := EngineCharge(config, options)
	if err != nil {
		return nil, err
	}
	if reservation == environmentBorrow {
		return nil, resourcev4.ErrOwner
	}
	if err := reservation.CheckSameEnvironment(environmentBorrow); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	shared, err := environmentBorrow.TakeBorrow()
	if err != nil {
		owned.Release()
		return nil, err
	}
	return newReservedEngineOwned(config, owned, shared)
}

func newReservedEngineOwned(config Config, owned, shared resourcev4.Reference) (*Engine, error) {
	e, err := NewEngine(config)
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	e.reservation, e.environment = owned, shared
	if err := e.resourceLive(); err != nil {
		e.Close()
		_ = e.Retire()
		return nil, err
	}
	return e, nil
}

func (e *Engine) resourceLive() error {
	if e.reservation == (resourcev4.Reference{}) {
		return nil // Internal unreserved protocol primitive.
	}
	if err := e.reservation.Check(); err != nil {
		return err
	}
	return e.environment.Check()
}

// CheckEnvironment binds another admitted component to this original Engine's
// live budget root and Environment before that component takes its reservation.
func (e *Engine) CheckEnvironment(reservation resourcev4.Reference) error {
	if e == nil {
		return ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	if err := e.resourceLive(); err != nil {
		return err
	}
	return e.reservation.CheckSameEnvironment(reservation)
}

// Retire follows the Session's actual component/handshake joins and Engine
// cleanup. Wait cancellation and logical Close never refund this reservation.
// Closed aliases retain immutable identity and channels, but no authorization,
// clock, idle owner or epoch deadline graph. Detached round observations must
// already have been released by their separate Session coordinator.
func (e *Engine) Retire() error {
	if e == nil {
		return ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retired {
		return nil
	}
	if !e.cleanupComplete {
		return ErrTransition
	}
	e.config.Authorization, e.config.Clock = nil, nil
	e.clock.Store(nil)
	e.config.RootBorn = timev4.Sample{}
	e.idle = nil
	if e.current != nil {
		e.current.deadline = nil
	}
	e.reservation.Release()
	e.environment.Release()
	e.reservation, e.environment = resourcev4.Reference{}, resourcev4.Reference{}
	e.retired = true
	return nil
}
