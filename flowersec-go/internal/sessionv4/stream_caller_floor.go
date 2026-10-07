package sessionv4

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// A caller floor supplies the original stream factory's complete transport
// vector. It never borrows a delegated server floor or creates a preaccepted
// stream. The composing operation owns request/result/Completion separately.
const (
	streamCallerPreaccepted = streamFactoryOwners + iota
	streamCallerRoute
	streamCallerOwners
)

type streamCallerFloor struct {
	workload      *unaryWorkload
	preaccepted   *preacceptedStream
	provider      native.StreamProtection
	connection    native.Connection
	geometry      streamCallerGeometry
	plan          *SessionCorePlan
	owner         resourcev4.OwnerKey
	metadata      resourcev4.Reference
	owners        [streamCallerOwners]*resourcev4.ProtectedReservation
	receive       *ReceiveProtection
	open          localOpenProtection
	native        *nativeStreamProtection
	openHandle    OpenHandle
	generation    uint64
	snapshotBytes int
	used, closed  bool // guarded by the original Session plan
	registered    bool
}

func streamCallerFloorCharges(c SessionCoreConfig, snapshotBytes int) (charges [streamCallerOwners]resourcev4.Vector, metadata resourcev4.Vector, err error) {
	stream, err := sessionStreamCharges(c.Streams, c.Session.Profile, uint64(c.Session.Contract.Limits().MaxFrame), c.MaxDataPayloadBytes, snapshotBytes)
	if err != nil {
		return
	}
	copy(charges[:], stream[:])
	if c.Native || c.MixedCarrier {
		charges[streamFactoryNativeReceive], err = NativeDataAssemblyCharge(math.MaxInt64, 0, c.Session.Profile, c.Session.Contract.Limits().MaxFrame)
		if err != nil {
			return
		}
	}
	preaccepted, err := preacceptedStreamCharges(c.Streams.RuntimeBytes, snapshotBytes)
	if err != nil {
		return
	}
	copy(charges[streamCallerPreaccepted:], preaccepted[:])
	metadata = resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(streamCallerFloor{})) +
		(streamCallerOwners+1)*(uint64(unsafe.Sizeof(resourcev4.Request{}))+uint64(unsafe.Sizeof(resourcev4.Reference{}))), resourcev4.Items: 1}
	return
}

// All protection is acquired before returning the declaration. A failure
// unwinds this unpublished vector without OPEN, provider creation or a task.
func (p *SessionCorePlan) reserveStreamCallerFloor(snapshotBytes int) (_ *streamCallerFloor, err error) {
	if p == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.streamCalls == math.MaxUint64 {
		return nil, cryptov4.ErrClosed
	}
	if p.receivePool == nil || p.admission == nil || p.rpc == nil || p.rpc.plan == nil || p.config.Native && p.nativeStreams == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if p.streamMethods-p.streamServices+p.streamCallerProtected-p.streamCallerUsed >= p.config.Open.Opening+p.config.Open.IngressItems {
		return nil, cryptov4.ErrCapacity
	}
	p.streamCalls++
	var seed [40]byte
	copy(seed[:16], "stream-floor/v4")
	copy(seed[16:32], p.resourceOwner.Backing[:])
	binary.BigEndian.PutUint64(seed[32:], p.streamCalls)
	digest := sha256.Sum256(seed[:])
	owner := p.resourceOwner
	copy(owner.Backing[:], digest[:16])
	f, err := reserveStreamCallerBacking(p.config, p.root, owner, p.accounts[:p.accountCount], p.receivePool, snapshotBytes)
	if err != nil {
		return nil, err
	}
	if err := p.adoptStreamCallerFloorLocked(f); err != nil {
		f.closeLocked()
		return nil, err
	}
	return f, nil
}

// Geometry is frozen with the pre-Acquire backing. Adoption cannot trade a
// cheaper ring, queue, frame or runtime envelope for a different live factory.
type streamCallerGeometry struct {
	streams SessionStreamConfig
	profile string
	frame   uint32
	maxData uint64
	native  bool
	mixed   bool
}

func callerStreamGeometry(c SessionCoreConfig) streamCallerGeometry {
	return streamCallerGeometry{streams: c.Streams, profile: c.Session.Profile, frame: c.Session.Contract.Limits().MaxFrame, maxData: c.MaxDataPayloadBytes, native: c.Native && !c.MixedCarrier, mixed: c.MixedCarrier}
}

// Original admission can construct this backing before it has an authenticated
// core or a native connection. The actual shared receive pool already owns its
// ring/credit and the retained alias. No OPEN, task or provider call occurs.
func reserveStreamCallerBacking(c SessionCoreConfig, root *resourcev4.Root, owner resourcev4.OwnerKey, accounts []resourcev4.Account, pool *ReceivePool, snapshotBytes int) (_ *streamCallerFloor, err error) {
	if root == nil || pool == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err := pool.reservation.CheckAllocationScope(root, owner, accounts); err != nil {
		return nil, err
	}
	charges, metadata, err := streamCallerFloorCharges(c, snapshotBytes)
	if err != nil {
		return nil, err
	}
	var requests [streamCallerOwners + 1]resourcev4.Request
	var refs [streamCallerOwners + 1]resourcev4.Reference
	var positions [streamCallerOwners + 1]int
	requests[0] = resourcev4.Request{Owner: owner, Charge: metadata, Accounts: accounts}
	count := 1
	for i, charge := range charges {
		if charge == (resourcev4.Vector{}) {
			continue
		}
		protected, e := resourcev4.ProtectedCharge(charge)
		if e != nil {
			return nil, e
		}
		key := owner
		key.Backing[0] ^= byte(i + 1)
		requests[count] = resourcev4.Request{Owner: key, Charge: protected, Accounts: accounts}
		positions[count] = i
		count++
	}
	if err = root.ReserveBatch(requests[:count], refs[:count]); err != nil {
		return nil, err
	}
	f := &streamCallerFloor{geometry: callerStreamGeometry(c), owner: owner, metadata: refs[0], snapshotBytes: snapshotBytes}
	defer func() {
		for _, ref := range refs[1:count] {
			ref.Release()
		}
		if err != nil {
			f.closeLocked()
		}
	}()
	for i := 1; i < count; i++ {
		position := positions[i]
		var alias resourcev4.Reference
		if position == streamFactoryMetadata || position == streamCallerPreaccepted {
			alias, err = refs[i].Borrow()
			if err == nil {
				f.owners[position], err = resourcev4.NewProtectedReservation(refs[i], charges[position], alias)
			}
			alias.Release()
		} else {
			f.owners[position], err = resourcev4.NewProtectedReservation(refs[i], charges[position])
		}
		if err != nil {
			return nil, err
		}
	}
	f.receive, err = pool.Protect(c.Streams.ReceiveBytes, c.Streams.InitialReceiveLimit)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// This bounded adoption precedes publication of the Session factory. It joins
// the original proof/native slots to the exact preadmitted backing and does
// not request another root reservation or receive alias.
func (p *SessionCorePlan) adoptStreamCallerFloorLocked(f *streamCallerFloor) (err error) {
	if f == nil || f.plan != nil || f.closed || f.geometry != callerStreamGeometry(p.config) || f.receive == nil || f.receive.pool != p.receivePool {
		return cryptov4.ErrConfiguration
	}
	if p.closed {
		return cryptov4.ErrClosed
	}
	if p.admission == nil || p.config.Native && p.nativeStreams == nil {
		return cryptov4.ErrNotReady
	}
	if err := f.metadata.CheckAllocationScope(p.root, p.resourceOwner, p.accounts[:p.accountCount]); err != nil {
		return err
	}
	if p.streamMethods-p.streamServices+p.streamCallerProtected-p.streamCallerUsed >= p.config.Open.Opening+p.config.Open.IngressItems {
		return cryptov4.ErrCapacity
	}
	var opening [1]localOpenProtection
	if err = p.admission.protectLocal(BusinessStream, opening[:]); err != nil {
		return err
	}
	f.open = opening[0]
	if p.config.Native {
		if f.provider != nil {
			if f.connection != p.nativeStreams.connection {
				err = cryptov4.ErrConfiguration
			} else {
				f.native, err = p.nativeStreams.adoptLocalProvider(f.provider)
			}
			if err == nil {
				f.provider, f.connection = nil, nil
			}
		} else {
			var positions [1]*nativeStreamProtection
			err = p.nativeStreams.protectLocal(positions[:])
			f.native = positions[0]
		}
		if err != nil {
			f.open.close()
			f.open = localOpenProtection{}
			return err
		}
	}
	f.plan, f.registered = p, true
	p.streamCallerProtected++
	return nil
}

func (f *streamCallerFloor) checkAvailable() error {
	if f == nil {
		return nil
	}
	if f.plan == nil {
		return cryptov4.ErrNotReady
	}
	f.plan.mu.Lock()
	defer f.plan.mu.Unlock()
	return f.checkAvailableLocked()
}

func (f *streamCallerFloor) checkAvailableLocked() error {
	if f.closed || f.plan.closed {
		return cryptov4.ErrClosed
	}
	if f.used || f.generation == math.MaxUint64 {
		return cryptov4.ErrCapacity
	}
	for _, owner := range f.owners {
		if owner != nil {
			if err := owner.CheckAvailable(); err != nil {
				return err
			}
		}
	}
	f.receive.pool.mu.Lock()
	received := f.receive.flow != nil || f.receive.closed || f.receive.pool.closed
	f.receive.pool.mu.Unlock()
	if received {
		return cryptov4.ErrCapacity
	}
	if f.native != nil {
		if err := f.native.checkAvailable(); err != nil {
			return err
		}
	}
	if f.openHandle != (OpenHandle{}) {
		if err := f.open.releaseUse(f.openHandle); err != nil {
			return err
		}
		f.openHandle = OpenHandle{}
	}
	a := f.open.admission
	a.mu.Lock()
	_, err := f.open.availableLocked(a, BusinessStream)
	a.mu.Unlock()
	return err
}

func (p *SessionCorePlan) prepareCallerStreamLocked(snapshotBytes int, f *streamCallerFloor) (*sessionStreamAllocation, *OpenAdmission, error) {
	if f.plan != p || snapshotBytes < 0 || snapshotBytes > f.snapshotBytes {
		return nil, nil, cryptov4.ErrConfiguration
	}
	if err := f.checkAvailableLocked(); err != nil {
		return nil, nil, err
	}
	var owners [streamFactoryOwners]*resourcev4.ProtectedReservation
	var refs [streamFactoryOwners]resourcev4.Reference
	var positions [streamFactoryOwners]int
	count := 0
	for i, owner := range f.owners[:streamFactoryOwners] {
		if owner != nil {
			owners[count], positions[count] = owner, i
			count++
		}
	}
	if err := resourcev4.CheckoutProtectedBatch(owners[:count], refs[:count]); err != nil {
		return nil, nil, err
	}
	f.generation++
	var seed [24]byte
	copy(seed[:16], f.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[16:], f.generation)
	digest := sha256.Sum256(seed[:])
	allocation := &sessionStreamAllocation{callerFloor: f}
	copy(allocation.identity[:], digest[:16])
	for i, ref := range refs[:count] {
		allocation.refs[positions[i]] = ref
	}
	if err := p.buildStreamAllocationLocked(allocation, f.owner, snapshotBytes); err != nil {
		allocation.releaseReferences()
		return nil, nil, err
	}
	f.used = true
	p.streamCallerUsed++
	p.streamMethods++
	return allocation, p.admission, nil
}

func (f *streamCallerFloor) closeLocked() {
	if !f.closed {
		f.closed = true
		if f.registered && !f.used {
			f.plan.streamCallerProtected--
			f.registered = false
		}
		f.preaccepted.close()
		f.open.close()
		f.native.close()
		if f.provider != nil {
			f.provider.Close()
			f.provider, f.connection = nil, nil
		}
		f.receive.Close()
		for _, owner := range f.owners {
			owner.CloseAfterUse()
		}
	}
	f.cleanupLocked()
}

func (f *streamCallerFloor) close() {
	if f == nil {
		return
	}
	if f.plan == nil {
		// The unpublished construction has one original owner. After plan
		// adoption, every access is serialized by that plan's existing gate.
		f.closeLocked()
		return
	}
	f.plan.mu.Lock()
	defer f.plan.mu.Unlock()
	f.closeLocked()
}

// The composing workload calls this from its existing cleanup coordinator.
// No callback, waiter or timer is added for a declared transport opportunity.
func (f *streamCallerFloor) cleanupLocked() bool {
	if !f.closed || f.used || f.registered {
		return false
	}
	for _, owner := range f.owners {
		if !owner.CleanupComplete() {
			return false
		}
	}
	if f.receive != nil {
		f.receive.pool.mu.Lock()
		busy := f.receive.flow != nil
		f.receive.pool.mu.Unlock()
		if busy {
			return false
		}
	}
	if f.native != nil {
		n := f.native.transport
		n.mu.Lock()
		busy := f.native.index < len(n.slots) && n.slots[f.native.index].protection == f.native && n.slots[f.native.index].used
		n.mu.Unlock()
		if busy {
			return false
		}
	}
	if f.openHandle != (OpenHandle{}) {
		a := f.open.admission
		a.mu.Lock()
		cleaned := a.cleaned
		a.mu.Unlock()
		if !cleaned {
			if err := f.open.releaseUse(f.openHandle); err != nil {
				return false
			}
		}
		f.openHandle = OpenHandle{}
	}
	f.metadata.Release()
	f.metadata = resourcev4.Reference{}
	return true
}

func (f *streamCallerFloor) cleanupComplete() bool {
	if f == nil {
		return true
	}
	if f.plan == nil {
		return f.cleanupLocked()
	}
	f.plan.mu.Lock()
	defer f.plan.mu.Unlock()
	return f.cleanupLocked()
}

// An idle preaccepted Stream is the same transport opportunity as its dormant
// floor. A failed unsubmitted operation may return the result vector while
// this original transport remains in the explicit pool.
func (f *streamCallerFloor) checkWorkloadAvailable() error {
	if f == nil {
		return nil
	}
	if f.plan == nil {
		return cryptov4.ErrNotReady
	}
	f.plan.mu.Lock()
	defer f.plan.mu.Unlock()
	if f.closed || f.plan.closed {
		return cryptov4.ErrClosed
	}
	if e := f.preaccepted; e != nil {
		e.mu.Lock()
		defer e.mu.Unlock()
		if !e.closed && !e.claimed && !e.transferred {
			return nil
		}
	}
	return f.checkAvailableLocked()
}
