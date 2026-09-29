package ledgerv4

import (
	"context"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// SQLiteCommittedRelayLeg contains only public facts matched to an original
// committed issuer outbox or complete live TxB for one logical leg. Its retained
// original proof and Grants are public and never exposed as dispatch rights.
// It carries no Artifact, secret, store connection, callback or native handle.
// Its private origin
// cannot be supplied by peer Grants or by relay claim readback.
type SQLiteCommittedRelayLeg struct {
	mu                  sync.Mutex
	identity            SQLiteIdentity
	projection          *protocolv4.RelayParentProjection
	role                protocolv4.Direction
	reservation, shared resourcev4.Reference
	closed              bool
}

func SQLiteCommittedRelayLegCharge() (resourcev4.Vector, error) {
	projection, err := protocolv4.RelayParentProjectionBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	decoder, err := protocolv4.DecoderBackingBytes(65536, 166)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteCommittedRelayLeg{})) + projection + decoder + 1024,
		resourcev4.Items: 1, resourcev4.WorkSlots: 1}, nil
}

// CaptureRelayLeg must run at the issuer, before retiring the original
// outbox. It reads only durable original issuance, never request-supplied bytes.
// The expected store identity is independent deployment configuration. A lost
// or retired original outbox is history_unknown; no replacement is issued.
func (j *SQLiteTopUpServer) CaptureRelayLeg(ctx context.Context, access TopUpAccess, expected SQLiteIdentity, operationSequence, artifactSequence uint64,
	projection *protocolv4.RelayParentProjection, role protocolv4.Direction, reservation, dependencies resourcev4.Reference) (_ *SQLiteCommittedRelayLeg, err error) {
	if role > protocolv4.ServerToClient || ctx == nil || j == nil || j.store == nil || projection == nil || !validSQLiteIdentity(expected) || operationSequence == 0 || artifactSequence == 0 {
		return nil, ErrConfiguration
	}
	if err = j.authorize(access); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	storeRef, identity, _, _, err := j.store.admissionReference(dependencies)
	if err != nil {
		return nil, err
	}
	defer storeRef.Release()
	if identity != expected {
		return nil, ErrOwner
	}
	charge, err := SQLiteCommittedRelayLegCharge()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	adopted := false
	var shared resourcev4.Reference
	defer func() {
		if !adopted {
			shared.Release()
			owned.Release()
		}
	}()
	shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	decoder, err := protocolv4.NewDecoder(65536, 166)
	if err != nil {
		return nil, err
	}
	if err = j.store.begin(ctx); err != nil {
		return nil, err
	}
	defer j.store.end()
	defer clear(j.wire)
	if err = j.store.checkFence(); err != nil {
		return nil, err
	}
	snapshot, err := j.readState()
	if err != nil {
		return nil, err
	}
	if snapshot.State != TopUpServerCommitted || snapshot.Permanent || snapshot.Request.Sequence() != operationSequence {
		return nil, ErrRelayHistoryUnknown
	}
	fence, err := j.fence()
	if err != nil {
		return nil, err
	}
	if fence.Permanent {
		return nil, ErrFenced
	}
	n, err := j.readWire()
	if err != nil {
		return nil, err
	}
	batch, err := j.codec.ParseResponse(j.wire[:n], snapshot.Request)
	if err != nil {
		return nil, err
	}
	defer batch.Release()
	facts, err := batch.Facts()
	if err != nil {
		return nil, err
	}
	if facts != snapshot.Response {
		return nil, ErrStorageFormat
	}
	index := -1
	for i, entry := range facts.Entries[:facts.Count] {
		if entry.Sequence == artifactSequence {
			index = i
		}
	}
	if index < 0 {
		return nil, ErrRelayHistoryUnknown
	}
	wire, err := batch.Material(uint32(index))
	if err != nil {
		return nil, err
	}
	doc, err := decoder.DecodeShape(wire, "", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer doc.Release()
	original, err := projection.CloneIssuedPoolMaterial(doc, role)
	if err != nil {
		return nil, err
	}
	if err = j.authorize(access); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	identity.Authority = strings.Clone(identity.Authority)
	result := &SQLiteCommittedRelayLeg{identity: identity, role: role, projection: original, reservation: owned, shared: shared}
	adopted = true
	return result, nil
}

// CaptureRelayLeg runs at the live authority's authenticated, admitted read
// boundary. It verifies the entire original TxB and its TxA projections before
// detaching public registration facts. No policy, signature, allow or carrier
// dispatch can be recovered from this receipt. Its separate reservation must
// already be admitted before this physical read begins.
func (r *SQLiteLiveSpendRead) CaptureRelayLeg(expected SQLiteIdentity, projection *protocolv4.RelayParentProjection, role protocolv4.Direction, reservation, dependencies resourcev4.Reference) (_ *SQLiteCommittedRelayLeg, err error) {
	if r == nil || r.sqliteLiveSpendRead == nil || projection == nil || role > protocolv4.ServerToClient || !validSQLiteIdentity(expected) || expected != r.identity {
		return nil, ErrConfiguration
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(r.reservation); err != nil {
		return nil, err
	}
	charge, err := SQLiteCommittedRelayLegCharge()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	adopted := false
	var shared resourcev4.Reference
	defer func() {
		if !adopted {
			shared.Release()
			owned.Release()
		}
	}()
	shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	if err = r.begin(); err != nil {
		return nil, err
	}
	defer r.finish()
	v, err := r.read()
	if err != nil {
		return nil, err
	}
	if err = r.verifyClientMaterial(v, true); err != nil {
		return nil, err
	}
	original, err := projection.CloneCommittedLiveMaterial(v.proof, v.grants)
	if err != nil {
		return nil, err
	}
	now, err := r.clock.Sample()
	if err != nil {
		return nil, err
	}
	if !now.ValidBefore(v.materialEnd) {
		return nil, timev4.ErrExpired
	}
	if err = r.check(); err != nil {
		return nil, err
	}
	if err = owned.Check(); err != nil {
		return nil, err
	}
	if err = shared.Check(); err != nil {
		return nil, err
	}
	expected.Authority = strings.Clone(expected.Authority)
	result := &SQLiteCommittedRelayLeg{identity: expected, role: role, projection: original, reservation: owned, shared: shared}
	adopted = true
	return result, nil
}

// The authority table owns separate charged backing for the detached clone.
func (p *SQLiteCommittedRelayLeg) copyProjection(expected SQLiteIdentity, role protocolv4.Direction, environment resourcev4.Reference) (*protocolv4.RelayParentProjection, error) {
	if p == nil {
		return nil, ErrRelayHistoryUnknown
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(expected, role, environment); err != nil {
		return nil, err
	}
	return p.projection.Clone(), nil
}

func (p *SQLiteCommittedRelayLeg) checkLocked(expected SQLiteIdentity, role protocolv4.Direction, environment resourcev4.Reference) error {
	if p.closed || p.identity != expected || p.role != role {
		return ErrOwner
	}
	if err := p.reservation.CheckSameEnvironment(environment); err != nil {
		return err
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	return p.shared.Check()
}

func (p *SQLiteCommittedRelayLeg) matchProjection(expected SQLiteIdentity, role protocolv4.Direction, environment resourcev4.Reference, projection *protocolv4.RelayParentProjection) error {
	if p == nil {
		return ErrRelayHistoryUnknown
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(expected, role, environment); err != nil {
		return err
	}
	return p.projection.MatchOriginalProjection(projection)
}

func (p *SQLiteCommittedRelayLeg) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		p.projection = nil
		p.shared.Release()
		p.reservation.Release()
	}
}
