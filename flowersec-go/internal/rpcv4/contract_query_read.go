package rpcv4

import (
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// QueryTargetAccess is the result of the original authenticated query owner's
// current per-target authorization. It must never be derived from the request's
// namespace, digest, known selector or refresh claim. A user authorization hook
// runs under its own real permit outside the reader/registry/fixed SDK worker.
type QueryTargetAccess uint8

const (
	QueryTargetUnavailable QueryTargetAccess = iota
	QueryTargetDenied
	QueryTargetAllowed
)

// ContractQueryRead retains bounded semantic references for one complete fixed
// query. Resolve reads one target per service opportunity; unrelated targets do
// not form an atomic advertisement transaction. Only private SDK code calls it,
// after the original current authorization step, under the fixed query service.
// It owns no worker, response buffer, ReplySlot or authority to dispatch.
type ContractQueryRead struct {
	mu          sync.Mutex
	registry    *ContractRoutes
	reservation resourcev4.Reference
	targets     protocolv4.ContractQueryTargets
	choices     [8]protocolv4.ContractSnapshotChoice
	offers      [8][256]byte
	resolved    uint8
	closed      bool
	shared      bool
	writer      *protocolv4.ContractSnapshotWriter
	output      []byte
	written     int
	encoded     bool
}

func ContractQueryReadCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ContractQueryRead{})) + 8*128 + protocolv4.ContractSnapshotWriterBackingBytes(), resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func (r *ContractRoutes) NewQueryRead(targets protocolv4.ContractQueryTargets, reservation resourcev4.Reference, runtimeBytes uint64) (*ContractQueryRead, error) {
	if r == nil || targets.Count() == 0 {
		return nil, ErrConfiguration
	}
	charge, err := ContractQueryReadCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleaned {
		return nil, ErrClosed
	}
	if r.captures == math.MaxUint32 {
		return nil, ErrCapacity
	}
	if err := reservation.CheckSameEnvironment(r.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	r.captures++
	return &ContractQueryRead{registry: r, targets: targets, reservation: owned}, nil
}

// Resolve fixes the next original target exactly once. Denied and unavailable
// authorization results never inspect a contract or expose an Offer. Authorized
// reads select only wanted, or the one current advertisement when wanted is
// absent. Known is strictly a conditional-body selector, never a route selector.
func (q *ContractQueryRead) Resolve(index int, access QueryTargetAccess) error {
	if q == nil {
		return ErrOwner
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.registry == nil {
		return ErrClosed
	}
	if index != int(q.resolved) || index >= q.targets.Count() || access > QueryTargetAllowed {
		return ErrAssociation
	}
	if err := q.reservation.Check(); err != nil {
		return err
	}
	choice := &q.choices[index]
	choice.Status = "unavailable"
	if access != QueryTargetAllowed {
		if access == QueryTargetDenied {
			choice.Status = "denied"
		}
		q.resolved++
		return nil
	}
	r := q.registry
	target, err := q.targets.Target(index)
	if err != nil {
		return err
	}
	// Only execution selection needs the bounded original clock. After sampling
	// outside the registry gate, recheck the selected entry's availability and
	// advertisement before taking the snapshot. No retry can substitute a digest.
	r.mu.Lock()
	var selected *contractRouteEntry
	if !r.closed && !r.cleaned {
		for i := range r.entries {
			entry := &r.entries[i]
			if entry.registered && entry.policy.Namespace == target.Namespace && entry.policy.Type == target.Type && (target.HasWanted && entry.policy.Digest == target.Wanted || !target.HasWanted && entry.advertised) {
				selected = entry
				break
			}
		}
	}
	r.mu.Unlock()
	var now timev4.Sample
	var clockErr error
	if selected != nil && selected.policy.Semantics == 1 {
		now, clockErr = r.offerSample()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed && !r.cleaned && r.reservation.Check() == nil && selected != nil && selected.registered && (target.HasWanted || selected.advertised) {
		func() {
			entry := selected
			if entry.policy.Semantics == 1 {
				if clockErr != nil {
					return
				}
				offer, ok := usableOffer(entry, now, 0, true)
				if !ok {
					return
				}
				var wire []byte
				wire, err = protocolv4.EncodeMap(q.offers[index][:], "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: offer.Digest[:]}, {Name: "not_before_ms", Number: offer.NotBeforeMS}, {Name: "not_after_ms", Number: offer.NotAfterMS}})
				if err != nil {
					return
				}
				choice.Offer, choice.MaxOfferWindowMS = wire, entry.offerWindowMS
			}
			choice.Status, choice.Contract = "available_full", entry.contract
			if target.HasKnown && target.Known == entry.policy.Digest {
				choice.Status = "available_unchanged"
			}
		}()
	}
	if err != nil {
		return err
	}
	q.resolved++
	return nil
}

// Encode copies a fully resolved snapshot to the original admitted full output.
// The fixed codec belongs to the protected SDK service. Neither route withdrawal
// nor registry Close can erase bodies already captured by this finite read.
func (q *ContractQueryRead) Encode(codec *protocolv4.ContractSnapshotEncoder, dst []byte) (int, error) {
	if q == nil {
		return 0, ErrOwner
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || int(q.resolved) != q.targets.Count() || q.writer != nil {
		return 0, ErrOwner
	}
	if err := q.reservation.Check(); err != nil {
		return 0, err
	}
	return codec.Encode(dst, q.targets, q.choices[:q.resolved])
}

// EncodeStep advances at most 4 KiB into this read's one original complete
// output backing. Every step uses the same buffer; no shared codec lock or body
// scratch is retained across scheduler opportunities. The caller owns that full
// output reservation until publication and actual source cleanup.
func (q *ContractQueryRead) EncodeStep(codec *protocolv4.ContractSnapshotEncoder, dst []byte) (written int, done bool, err error) {
	if q == nil {
		return 0, false, ErrOwner
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || int(q.resolved) != q.targets.Count() || len(dst) == 0 {
		return 0, false, ErrOwner
	}
	if err := q.reservation.Check(); err != nil {
		return 0, false, err
	}
	if q.writer == nil {
		writer, err := codec.NewWriter(q.targets, q.choices[:q.resolved])
		if err != nil {
			return 0, false, err
		}
		if len(dst) < writer.Size() {
			writer.Close()
			return 0, false, ErrCapacity
		}
		q.writer, q.output = writer, dst
	} else if len(dst) != len(q.output) || &dst[0] != &q.output[0] {
		return 0, false, ErrAssociation
	}
	n, done, err := q.writer.Next(q.output[q.written:])
	if err != nil {
		clear(q.output)
		return 0, false, err
	}
	q.written += n
	q.encoded = done
	return q.written, done, nil
}

func (q *ContractQueryRead) Close() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	if q.writer != nil {
		q.writer.Close()
		q.writer = nil
	}
	if !q.encoded {
		clear(q.output)
	}
	q.output = nil
	r := q.registry
	q.registry = nil
	clear(q.choices[:])
	clear(q.offers[:])
	q.targets = protocolv4.ContractQueryTargets{}
	if q.shared {
		// A fixed query service pins the original registry and complete read
		// metadata through the real last step/source use. No new root reference.
		q.reservation = resourcev4.Reference{}
		return
	}
	q.reservation.Release()
	q.reservation = resourcev4.Reference{}
	r.mu.Lock()
	r.captures--
	r.cleanupLocked()
	r.mu.Unlock()
}

func (*ContractQueryRead) String() string               { return "Flowersec.ContractQueryRead" }
func (*ContractQueryRead) GoString() string             { return "Flowersec.ContractQueryRead" }
func (*ContractQueryRead) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
