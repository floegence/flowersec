package sessionv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// PoolLeaseDecoder is the explicitly configured application material format.
// It returns sole ownership of a fully verified pool lease, using independent
// issuer/activation trust. The original call owns all decoder/provider tails;
// it must not return while they still borrow input. This is not a core wire map.
type PoolLeaseDecoder interface {
	DecodePoolLease(context.Context, []byte) (*ArtifactLease, error)
}

// PoolIdentityRestorer resolves only the persisted provider locator and exact
// original certificate. It returns a newly owned advertisement for the same
// key identity, never the provider's current identity. No key bytes are stored.
type PoolIdentityRestorer interface {
	RestorePoolIdentity(context.Context, []byte, []byte) (*ApplicationIdentity, error)
}

type MaterialPoolConfig struct {
	Tenant                                          string
	Generation                                      MaterialGeneration
	Capacity                                        uint32
	OperationMS, RuntimeBytes, MaterialRuntimeBytes uint64
	Journal                                         *ledgerv4.SQLiteTopUpJournal
	Decoder                                         PoolLeaseDecoder
	Identities                                      PoolIdentityRestorer
	Root                                            *resourcev4.Root
	Owner                                           resourcev4.OwnerKey
	Accounts                                        []resourcev4.Account
}

type poolMaterialSlot struct {
	material              *ConnectionMaterial
	entry                 protocolv4.TopUpEntryFacts
	occupied, ready, busy bool
}

// MaterialPool owns the local, complete-material part of a pool source. TopUp
// control I/O and history-only Ack are separate original operations. All local
// material operations have fixed admission and lifetime; Acquire does no I/O to
// an issuer and never joins a refill or replays a control operation.
type MaterialPool struct {
	mu, db                                    sync.Mutex
	environment                               *Environment
	journal                                   *ledgerv4.SQLiteTopUpJournal
	source                                    *PreauthorizedPoolSource
	decoder                                   PoolLeaseDecoder
	identities                                PoolIdentityRestorer
	tenant                                    string
	generation                                MaterialGeneration
	root                                      *resourcev4.Root
	owner                                     resourcev4.OwnerKey
	accounts                                  [8]resourcev4.Account
	accountCount                              int
	reservation, shared                       resourcev4.Reference
	slots                                     []poolMaterialSlot
	certificate                               []byte
	keyReference                              []byte
	material                                  []byte
	serial, operationMS, materialRuntimeBytes uint64
	writer, acquiring                         bool
	writerCancel, acquireCancel               context.CancelFunc
	closed, cleaned                           bool
	done                                      chan struct{}
}

func (*MaterialPool) String() string               { return "Flowersec.MaterialPool" }
func (*MaterialPool) GoString() string             { return "Flowersec.MaterialPool" }
func (*MaterialPool) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func MaterialPoolCharge(c MaterialPoolConfig) (resourcev4.Vector, error) {
	if len(c.Tenant) == 0 || len(c.Tenant) > 128 || c.Generation.Source == ([16]byte{}) || c.Generation.Generation == 0 || c.Capacity == 0 || c.Capacity > 256 || c.OperationMS == 0 || c.OperationMS > 90000 || c.RuntimeBytes == 0 || c.MaterialRuntimeBytes == 0 || len(c.Accounts) > 8 || c.Journal == nil || c.Decoder == nil || c.Identities == nil || c.Root == nil {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if _, err := ConnectionMaterialCharge(c.MaterialRuntimeBytes); err != nil {
		return resourcev4.Vector{}, err
	}
	size := uint64(unsafe.Sizeof(MaterialPool{})) + 65536 + 512 + 65536 + uint64(c.Capacity)*uint64(unsafe.Sizeof(poolMaterialSlot{})) + uint64(len(c.Tenant))
	return (resourcev4.Vector{resourcev4.SDKBytes: size, resourcev4.Items: 1 + uint64(c.Capacity), resourcev4.WorkSlots: 2, resourcev4.Tasks: 2, resourcev4.Timers: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// NewMaterialPool registers its real tails with the existing Environment. The
// journal, roots and key providers are borrowed, and are not closed by the pool.
func (e *Environment) NewMaterialPool(c MaterialPoolConfig, reservation resourcev4.Reference) (*MaterialPool, error) {
	charge, err := MaterialPoolCharge(c)
	if err != nil || e == nil {
		if err == nil {
			err = cryptov4.ErrConfiguration
		}
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err = c.Journal.CheckBinding(c.Tenant, c.Generation.Source, c.Generation.Generation, c.Capacity, reservation); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, cryptov4.ErrClosed
	}
	if int(c.Capacity) > len(e.materials) {
		return nil, cryptov4.ErrCapacity
	}
	index := -1
	for i, p := range e.pools {
		if p == nil {
			if index < 0 {
				index = i
			}
			continue
		}
		if p.tenant == c.Tenant && p.generation.Source == c.Generation.Source {
			return nil, cryptov4.ErrTransition
		}
	}
	if index < 0 {
		return nil, cryptov4.ErrCapacity
	}
	if err = reservation.CheckSameEnvironment(e.reservation); err != nil {
		return nil, err
	}
	shared, err := e.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	p := &MaterialPool{environment: e, journal: c.Journal, decoder: c.Decoder, identities: c.Identities, tenant: strings.Clone(c.Tenant), generation: c.Generation, root: c.Root, owner: c.Owner, reservation: owned, shared: shared, slots: make([]poolMaterialSlot, c.Capacity), certificate: make([]byte, 65536), keyReference: make([]byte, 512), material: make([]byte, 65536), operationMS: c.OperationMS, materialRuntimeBytes: c.MaterialRuntimeBytes, done: make(chan struct{})}
	p.accountCount = copy(p.accounts[:], c.Accounts)
	e.pools[index] = p
	e.poolActive++
	e.signalMaterials()
	return p, nil
}

func poolError(code protocolv4.V4TopUpErrorCode) error {
	fact, ok := protocolv4.TopUpErrorProjection(code, protocolv4.V4TopUpWriteActionNone)
	if !ok {
		return cryptov4.ErrConfiguration
	}
	return ledgerv4.TopUpFailure{Fact: fact}
}

func (p *MaterialPool) begin(ctx context.Context, writer bool) (context.Context, error) {
	if p == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.reservation.Check(); err != nil {
		return nil, err
	}
	if err := p.shared.Check(); err != nil {
		return nil, err
	}
	if writer && p.writer || !writer && p.acquiring {
		return nil, poolError(protocolv4.V4TopUpErrorCodeCapacityExhausted)
	}
	call, cancel := context.WithTimeout(ctx, time.Duration(p.operationMS)*time.Millisecond)
	if writer {
		p.writer, p.writerCancel = true, cancel
	} else {
		p.acquiring, p.acquireCancel = true, cancel
	}
	return call, nil
}
func (p *MaterialPool) end(writer bool) {
	p.mu.Lock()
	if writer {
		p.writerCancel()
		p.writerCancel = nil
		p.writer = false
	} else {
		p.acquireCancel()
		p.acquireCancel = nil
		p.acquiring = false
	}
	environment := p.environment
	p.mu.Unlock()
	if environment != nil {
		environment.signalMaterials()
	}
}
func (p *MaterialPool) reserveSlots(count int) ([4]int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var indices [4]int
	if count < 1 || count > 4 {
		return indices, cryptov4.ErrConfiguration
	}
	if p.closed {
		return indices, poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	found := 0
	for i := range p.slots {
		if !p.slots[i].occupied {
			indices[found] = i
			found++
			if found == count {
				break
			}
		}
	}
	if count < 1 || count > 4 || found != count {
		return indices, poolError(protocolv4.V4TopUpErrorCodeCapacityExhausted)
	}
	for _, i := range indices[:count] {
		p.slots[i].occupied, p.slots[i].busy = true, true
	}
	return indices, nil
}
func (p *MaterialPool) reserveMaterial() (resourcev4.Reference, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.serial == math.MaxUint64 {
		return resourcev4.Reference{}, cryptov4.ErrClosed
	}
	p.serial++
	var seed [56]byte
	copy(seed[:16], "pool-material/v4")
	copy(seed[16:32], p.owner.Instance[:])
	copy(seed[32:48], p.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], p.serial)
	digest := sha256.Sum256(seed[:])
	owner := p.owner
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	charge, err := ConnectionMaterialCharge(p.materialRuntimeBytes)
	if err != nil {
		return resourcev4.Reference{}, err
	}
	return p.root.Reserve(owner, charge, p.accounts[:p.accountCount]...)
}

// construct keeps the original identity use pinned across actual provider work.
// Environment hosts the factory before it runs and retains late failed results.
func (p *MaterialPool) construct(ctx context.Context, wire []byte, identity identityUse, entry protocolv4.TopUpEntryFacts) (*ConnectionMaterial, error) {
	if entry.Generation == 0 || entry.Generation > p.generation.Generation || identity.identity == nil || identity.identity.role != protocolv4.ClientToServer || identity.identity.credential.Scope().Tenant != p.tenant || identity.identity.credential.Facts().Digest != entry.Identity {
		return nil, ErrSourceContractInvalid
	}
	return p.environment.CreateMaterial(ctx, func(call context.Context) (*ConnectionMaterial, error) {
		reservation, err := p.reserveMaterial()
		if err != nil {
			return nil, err
		}
		defer reservation.Release()
		pin, err := identity.borrow(reservation)
		if err != nil {
			return nil, err
		}
		defer pin.release()
		lease, err := p.decoder.DecodePoolLease(call, wire)
		if lease != nil {
			defer lease.Close()
		}
		if err != nil {
			return nil, err
		}
		if lease == nil || lease.source != "preauthorized_pool" {
			return nil, ErrSourceContractInvalid
		}
		if err = call.Err(); err != nil {
			return nil, err
		}
		charge, _ := ConnectionMaterialCharge(p.materialRuntimeBytes)
		owned := pin
		pin = identityUse{}
		m, err := newConnectionMaterialCaptured(lease, owned, MaterialGeneration{Source: p.generation.Source, Generation: entry.Generation}, charge, reservation)
		if err != nil {
			return nil, err
		}
		if entry.ExpiryMS > m.materialEnd() {
			return m, ErrSourceContractInvalid
		}
		return m, nil
	})
}

// claim pins an unused complete owner while it belongs to the pool. Environment
// expiry may close it, but cannot release keys under ongoing pool validation.
func (p *MaterialPool) claim(index int, m *ConnectionMaterial, entry protocolv4.TopUpEntryFacts) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.used || m.building || m.attached {
		return cryptov4.ErrClosed
	}
	m.building = true
	p.slots[index].material, p.slots[index].entry = m, entry
	return nil
}
func (p *MaterialPool) discard(indices []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, index := range indices {
		s := &p.slots[index]
		if s.material != nil {
			m := s.material
			m.mu.Lock()
			m.closed = true
			m.building = false
			m.cleanupLocked()
			m.mu.Unlock()
		}
		*s = poolMaterialSlot{}
	}
}
func (p *MaterialPool) publish(ctx context.Context, indices []int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	// Lock each immutable material only to check its local close gate. No I/O
	// or provider work runs under the pool publication gate.
	for _, index := range indices {
		m := p.slots[index].material
		m.mu.Lock()
		closed := m.closed
		m.mu.Unlock()
		if closed {
			return ErrSourceContractInvalid
		}
	}
	for _, index := range indices {
		p.slots[index].ready = true
		p.slots[index].busy = false
	}
	return nil
}

// Install validates every complete material before one durable batch install.
// Already-Applied history is compared without decoding or requiring old keys.
// The caller is the original TopUp worker, never its cancelable waiting handle.
func (p *MaterialPool) Install(ctx context.Context, request protocolv4.TopUpRequestFacts, batch *protocolv4.TopUpBatch, identity *ApplicationIdentity) error {
	return p.installBatch(ctx, request, batch, identity, identityUse{}, false)
}

// RecoverInstall restores the persisted original certificate and provider key
// identity only when this operation has not reached Applied. A history replay
// takes the same no-key, no-decoding path as Install.
func (p *MaterialPool) RecoverInstall(ctx context.Context, request protocolv4.TopUpRequestFacts, batch *protocolv4.TopUpBatch) error {
	return p.installBatch(ctx, request, batch, nil, identityUse{}, true)
}

// installOriginal is used by the source worker holding the identity captured
// before Begin. Advertisement retirement cannot force a current-key lookup.
func (p *MaterialPool) installOriginal(ctx context.Context, request protocolv4.TopUpRequestFacts, batch *protocolv4.TopUpBatch, original identityUse) error {
	return p.installBatch(ctx, request, batch, nil, original, false)
}

func (p *MaterialPool) installBatch(ctx context.Context, request protocolv4.TopUpRequestFacts, batch *protocolv4.TopUpBatch, identity *ApplicationIdentity, original identityUse, restore bool) (err error) {
	call, err := p.begin(ctx, true)
	if err != nil {
		return err
	}
	defer p.end(true)
	if batch == nil || !batch.MatchesRequest(request) {
		return ErrSourceContractInvalid
	}
	if !p.db.TryLock() {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	recovered, err := p.journal.Recover(call)
	p.db.Unlock()
	if err != nil {
		return err
	}
	if recovered.Request != request {
		return ErrSourceContractInvalid
	}
	facts, err := batch.Facts()
	if err != nil {
		return err
	}
	if recovered.State == ledgerv4.TopUpJournalInstalled || recovered.State == ledgerv4.TopUpJournalAcked {
		if recovered.Response != facts {
			return poolError(protocolv4.V4TopUpErrorCodeOperationConflict)
		}
		return nil
	}
	if recovered.State != ledgerv4.TopUpJournalPending {
		return poolError(protocolv4.V4TopUpErrorCodeOperationConflict)
	}
	if restore {
		if !p.db.TryLock() {
			return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
		}
		certN, keyN, e := p.journal.ReadPendingIdentity(call, request, p.certificate[:], p.keyReference[:])
		p.db.Unlock()
		defer clear(p.certificate[:])
		defer clear(p.keyReference[:])
		if e != nil {
			return e
		}
		identity, err = p.identities.RestorePoolIdentity(call, p.certificate[:certN], p.keyReference[:keyN])
		if identity != nil {
			defer identity.Close()
		}
		if err != nil {
			return err
		}
	}
	var pin identityUse
	if original.identity != nil {
		pin, err = original.borrow(p.reservation)
	} else {
		pin, err = identity.capture(p.reservation)
	}
	if err != nil {
		return ErrSourceContractInvalid
	}
	defer pin.release()
	return p.install(call, request, batch, facts, pin)
}
func (p *MaterialPool) install(call context.Context, request protocolv4.TopUpRequestFacts, batch *protocolv4.TopUpBatch, facts protocolv4.TopUpResponseFacts, pin identityUse) (err error) {
	if pin.identity.credential.Facts().Digest != request.Identity || pin.identity.credential.Scope().Tenant != p.tenant {
		return ErrSourceContractInvalid
	}
	if !p.db.TryLock() {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	n, _, err := p.journal.ReadPendingIdentity(call, request, p.certificate[:], p.keyReference[:])
	p.db.Unlock()
	defer clear(p.certificate[:])
	defer clear(p.keyReference[:])
	if err != nil {
		return err
	}
	original, err := pin.identity.certificate.Bytes()
	if err != nil || !bytes.Equal(original, p.certificate[:n]) {
		return ErrSourceContractInvalid
	}
	indices, err := p.reserveSlots(int(facts.Count))
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			p.discard(indices[:facts.Count])
		}
	}()
	for i, index := range indices[:facts.Count] {
		wire, e := batch.Material(uint32(i))
		if e != nil {
			return e
		}
		m, e := p.construct(call, wire, pin, facts.Entries[i])
		if e != nil {
			return e
		}
		if e = p.claim(index, m, facts.Entries[i]); e != nil {
			m.Close()
			return e
		}
	}
	// Recheck actual keys and complete credentials after the last decoder tail.
	for _, index := range indices[:facts.Count] {
		if err = p.slots[index].material.check(); err != nil {
			return err
		}
	}
	if !p.db.TryLock() {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	err = p.journal.Install(call, request, batch)
	p.db.Unlock()
	if err != nil {
		return err
	}
	if err = p.publish(call, indices[:facts.Count]); err != nil {
		return err
	}
	published = true
	return nil
}

// RestoreInstalled is explicit local material restoration, separate from
// RecoverPendingTopUps/Ack. It never issues, installs, takes or advances history.
// A missing key fails this call; history-only confirmation remains available.
func (p *MaterialPool) RestoreInstalled(ctx context.Context) (err error) {
	call, err := p.begin(ctx, true)
	if err != nil {
		return err
	}
	defer p.end(true)
	defer clear(p.certificate[:])
	defer clear(p.keyReference[:])
	defer clear(p.material[:])
	after := uint64(0)
	for visited := 0; visited <= len(p.slots); visited++ {
		if !p.db.TryLock() {
			return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
		}
		row, e := p.journal.ReadPoolNext(call, after, p.certificate[:], p.keyReference[:], p.material[:])
		p.db.Unlock()
		if e != nil {
			return e
		}
		if !row.Found {
			return nil
		}
		if visited == len(p.slots) {
			return poolError(protocolv4.V4TopUpErrorCodeCapacityExhausted)
		}
		after = row.Entry.Sequence
		p.mu.Lock()
		exists := false
		for _, slot := range p.slots {
			if slot.occupied && slot.entry.Sequence == after {
				exists = true
				if slot.entry != row.Entry {
					p.mu.Unlock()
					return ErrSourceContractInvalid
				}
				break
			}
		}
		p.mu.Unlock()
		if exists {
			continue
		}
		if err = p.restoreOne(call, row); err != nil {
			return err
		}
	}
	return nil
}
func (p *MaterialPool) restoreOne(ctx context.Context, row ledgerv4.TopUpPoolRead) (err error) {
	indices, err := p.reserveSlots(1)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			p.discard(indices[:1])
		}
	}()
	identity, err := p.identities.RestorePoolIdentity(ctx, p.certificate[:row.CertificateBytes], p.keyReference[:row.KeyReferenceBytes])
	if identity != nil {
		defer identity.Close()
	}
	if err != nil {
		return err
	}
	pin, err := identity.capture(p.reservation)
	if err != nil {
		return ErrSourceContractInvalid
	}
	defer pin.release()
	certificate, err := pin.identity.certificate.Bytes()
	if err != nil || !bytes.Equal(certificate, p.certificate[:row.CertificateBytes]) {
		return ErrSourceContractInvalid
	}
	m, err := p.construct(ctx, p.material[:row.MaterialBytes], pin, row.Entry)
	if err != nil {
		return err
	}
	if err = p.claim(indices[0], m, row.Entry); err != nil {
		m.Close()
		return err
	}
	if err = p.publish(ctx, indices[:1]); err != nil {
		return err
	}
	published = true
	return nil
}

// Acquire selects only an already local complete material. The durable take
// precedes handoff, and unknown/late commits cannot be interpreted as delivery.
func (p *MaterialPool) Acquire(ctx context.Context, requirements MaterialRequirements) (*ConnectionMaterial, error) {
	return p.acquirePrepared(ctx, requirements, nil)
}

func (p *MaterialPool) acquirePrepared(ctx context.Context, requirements MaterialRequirements, subscriptions *protocolv4.CredentialSubscriptions) (result *ConnectionMaterial, err error) {
	if !requirements.valid() {
		return nil, ErrSourceContractInvalid
	}
	if requirements, err = requirements.capture(); err != nil {
		return nil, err
	}
	call, err := p.begin(ctx, false)
	if err != nil {
		return nil, err
	}
	defer p.end(false)
	p.mu.Lock()
	index := -1
	for i, slot := range p.slots {
		if slot.ready && !slot.busy {
			index = i
			break
		}
	}
	if index < 0 {
		p.mu.Unlock()
		return nil, poolError(protocolv4.V4TopUpErrorCodeSourceExhausted)
	}
	slot := &p.slots[index]
	slot.ready = false
	slot.busy = true
	m, entry := slot.material, slot.entry
	p.mu.Unlock()
	delivered, takeAttempted := false, false
	defer func() {
		if !delivered {
			if !takeAttempted {
				p.mu.Lock()
				m.mu.Lock()
				keep := !p.closed && !m.closed
				if keep {
					slot.ready, slot.busy = true, false
				}
				m.mu.Unlock()
				p.mu.Unlock()
				if keep {
					return
				}
			}
			p.discard([]int{index})
		}
	}()
	if err = m.check(); err != nil {
		return nil, err
	}
	limits := m.lease.lease.session.Contract.Limits()
	if limits.ApplicationProfile != requirements.ApplicationProfile || limits.RPCMaxGeneralOutstanding != requirements.RPCMaxGeneralOutstanding {
		return nil, ErrSourceContractInvalid
	}
	if subscriptions != nil {
		if err = subscriptions.CheckSourceNamespaces(m.lease.lease.allCredentialBindings()); err != nil {
			return nil, err
		}
	}
	if !p.db.TryLock() {
		return nil, poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	takeAttempted = true
	err = p.journal.TakePool(call, entry)
	p.db.Unlock()
	if err != nil {
		return nil, err
	}
	if err = m.check(); err != nil {
		return nil, err
	}
	if err = p.journal.CheckCurrentOwner(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.closed || m.closed {
		return nil, poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	if err = call.Err(); err != nil {
		return nil, err
	}
	if err = p.reservation.Check(); err != nil {
		return nil, err
	}
	m.building = false
	*slot = poolMaterialSlot{}
	delivered = true
	return m, nil
}

func (p *MaterialPool) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	if p.source != nil {
		p.source.stop()
	}
	if p.writerCancel != nil {
		p.writerCancel()
	}
	if p.acquireCancel != nil {
		p.acquireCancel()
	}
	environment := p.environment
	p.mu.Unlock()
	if environment != nil {
		environment.signalMaterials()
	}
}
func (p *MaterialPool) WaitCleanup(ctx context.Context) error {
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

// advance runs on the Environment's existing coordinator, not a per-pool
// watcher. It performs only local lifetime transitions and no provider work.
func (p *MaterialPool) advance() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cleaned {
		return true
	}
	if p.reservation.Check() != nil || p.shared.Check() != nil {
		p.closed = true
		if p.writerCancel != nil {
			p.writerCancel()
		}
		if p.acquireCancel != nil {
			p.acquireCancel()
		}
	}
	for i := range p.slots {
		s := &p.slots[i]
		if !s.occupied || s.busy || s.material == nil {
			continue
		}
		m := s.material
		m.mu.Lock()
		if p.closed || m.closed {
			m.closed = true
			m.building = false
			m.cleanupLocked()
			*s = poolMaterialSlot{}
		}
		m.mu.Unlock()
	}
	if p.source != nil {
		if p.closed {
			p.source.stop()
		}
		select {
		case <-p.source.done:
			p.source = nil
		default:
			return false
		}
	}
	if p.closed && !p.writer && !p.acquiring {
		for _, s := range p.slots {
			if s.occupied {
				return false
			}
		}
		clear(p.certificate[:])
		clear(p.keyReference[:])
		clear(p.material[:])
		p.certificate, p.keyReference, p.material = nil, nil, nil
		p.decoder, p.identities, p.journal = nil, nil, nil
		p.slots = nil
		p.accounts = [8]resourcev4.Account{}
		p.root = nil
		p.reservation.Release()
		p.shared.Release()
		p.reservation, p.shared = resourcev4.Reference{}, resourcev4.Reference{}
		p.cleaned = true
		p.environment = nil
		close(p.done)
	}
	return p.cleaned
}

// restorePendingIdentity is the source worker's original recovery step before
// sending an unapplied request. It owns the pool's single restoration position
// and returns only a validated original pin, with no borrowed scratch bytes.
func (p *MaterialPool) restorePendingIdentity(ctx context.Context, request protocolv4.TopUpRequestFacts) (identityUse, error) {
	call, err := p.begin(ctx, true)
	if err != nil {
		return identityUse{}, err
	}
	defer p.end(true)
	if !p.db.TryLock() {
		return identityUse{}, poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	n, k, err := p.journal.ReadPendingIdentity(call, request, p.certificate, p.keyReference)
	p.db.Unlock()
	defer clear(p.certificate)
	defer clear(p.keyReference)
	if err != nil {
		return identityUse{}, err
	}
	identity, err := p.identities.RestorePoolIdentity(call, p.certificate[:n], p.keyReference[:k])
	if identity != nil {
		defer identity.Close()
	}
	if err != nil {
		return identityUse{}, err
	}
	pin, err := identity.capture(p.reservation)
	if err != nil {
		return identityUse{}, ErrSourceContractInvalid
	}
	original, err := pin.identity.certificate.Bytes()
	if err != nil || !bytes.Equal(original, p.certificate[:n]) || pin.identity.credential.Facts().Digest != request.Identity || pin.identity.role != protocolv4.ClientToServer {
		pin.release()
		return identityUse{}, ErrSourceContractInvalid
	}
	if err = pin.identity.check(); err == nil {
		err = call.Err()
	}
	if err != nil {
		pin.release()
		return identityUse{}, err
	}
	return pin, nil
}
