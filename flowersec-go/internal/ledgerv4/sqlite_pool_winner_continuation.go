package ledgerv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// SQLitePoolWinnerContinuation is retained only by an original successful pool
// publication. Its nonce and exact selection are never restored from a row.
// Continue only matches the winner already fixed by the relay's real HOP claim.
type SQLitePoolWinnerContinuation struct {
	originalRemoteMatcher                               func(context.Context, []byte, []byte, func() error) error
	mu                                                  sync.Mutex
	store                                               *SQLiteStore
	reservation, shared, storeRef                       resourcev4.Reference
	nonce                                               [32]byte
	lease                                               [161]byte
	projection, controlProjection, scratch              [8192]byte
	leaseBytes, projectionBytes, controlProjectionBytes int
	published, acknowledged, consumed, active, closed   bool
}

func SQLitePoolWinnerContinuationCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLitePoolWinnerContinuation{})), resourcev4.Items: 1, resourcev4.WorkSlots: 1}
}

// CheckOriginalMaterial can be used only while the first committed publication
// is still retained. A publication reconstructed for replay fails this check.
func (p *SQLitePoolRelayPublication) CheckOriginalMaterial(request protocolv4.TopUpRequestFacts, response []byte) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return err
	}
	if !p.original || !p.committed || p.active || p.closed || p.request != request || p.wireDigest != sha256.Sum256(response) {
		return ErrOwner
	}
	return nil
}

func (p *SQLitePoolRelayPublication) CaptureOriginalWinner(key protocolv4.RelayParentKey, reservation, environment resourcev4.Reference) (*SQLitePoolWinnerContinuation, error) {
	return p.captureOriginalWinner(key, reservation, environment, nil)
}

// CaptureOriginalRemoteWinner retains the independently installed native
// relay's original matcher before publication. It is never reconstructed from
// a public row or supplied by a registering endpoint.
func (p *SQLitePoolRelayPublication) CaptureOriginalRemoteWinner(key protocolv4.RelayParentKey, reservation, environment resourcev4.Reference, match func(context.Context, []byte, []byte, func() error) error) (*SQLitePoolWinnerContinuation, error) {
	if match == nil {
		return nil, ErrConfiguration
	}
	return p.captureOriginalWinner(key, reservation, environment, match)
}
func (p *SQLitePoolRelayPublication) captureOriginalWinner(key protocolv4.RelayParentKey, reservation, environment resourcev4.Reference, match func(context.Context, []byte, []byte, func() error) error) (_ *SQLitePoolWinnerContinuation, err error) {
	if p == nil {
		return nil, ErrConfiguration
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err = p.checkLocked(); err != nil {
		return nil, err
	}
	if p.closed || p.active || !p.original || !p.committed || p.winnerTaken {
		return nil, ErrOwner
	}
	if err = p.reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	var fields protocolv4.AdmissionFields
	found := false
	for index := range p.entries {
		entry := &p.entries[index]
		if entry.key == key {
			fields, err = entry.projection.PoolWinnerFields()
			found = true
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if !found || fields.WinnerAuthority != p.table.identity.Authority {
		return nil, ErrOwner
	}
	p.winnerTaken = true
	owned, err := reservation.Take(SQLitePoolWinnerContinuationCharge())
	if err != nil {
		return nil, err
	}
	c := &SQLitePoolWinnerContinuation{store: p.table.store, reservation: owned, originalRemoteMatcher: match}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	c.shared, err = environment.Borrow()
	if err != nil {
		return nil, err
	}
	c.storeRef, _, _, _, err = c.store.admissionReference(environment)
	if err != nil {
		return nil, err
	}
	record := admissionRecord{fields: fields}
	c.leaseBytes, err = record.key(c.lease[:])
	if err != nil {
		return nil, err
	}
	c.projectionBytes, err = encodeParentSelection(c.projection[:], fields)
	if err != nil {
		return nil, err
	}
	c.controlProjectionBytes, err = protocolv4.EncodePoolWinnerControlProjection(c.controlProjection[:], fields)
	if err != nil {
		return nil, err
	}
	if _, err = rand.Read(c.nonce[:]); err != nil {
		return nil, err
	}
	if c.nonce == ([32]byte{}) {
		return nil, ErrConfiguration
	}
	return c, nil
}

func (c *SQLitePoolWinnerContinuation) checkLocked() error {
	if c.closed {
		return ErrOwner
	}
	for _, ref := range []resourcev4.Reference{c.reservation, c.shared, c.storeRef} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}

// Publication lends bytes to its original control writer; the continuation
// owns them until joined cleanup. Only this once-only method may expose them.
func (c *SQLitePoolWinnerContinuation) Publication() (nonce, lease, projection []byte, err error) {
	if c == nil {
		return nil, nil, nil, ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err = c.checkLocked(); err != nil {
		return
	}
	if c.published {
		err = ErrOwner
		return
	}
	c.published = true
	return c.nonce[:], c.lease[:c.leaseBytes], c.controlProjection[:c.controlProjectionBytes], nil
}

func (c *SQLitePoolWinnerContinuation) Acknowledge(nonce []byte) error {
	if c == nil {
		return ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkLocked(); err != nil {
		return err
	}
	if !c.published || c.acknowledged || !bytes.Equal(nonce, c.nonce[:]) {
		return ErrOwner
	}
	c.acknowledged = true
	return nil
}

func (c *SQLitePoolWinnerContinuation) Continue(ctx context.Context, nonce []byte, guard func() error) (err error) {
	if c == nil || ctx == nil || guard == nil {
		return ErrConfiguration
	}
	c.mu.Lock()
	if err = c.checkLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	if !c.acknowledged || c.consumed || !bytes.Equal(nonce, c.nonce[:]) {
		c.mu.Unlock()
		return ErrOwner
	}
	c.consumed, c.active = true, true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.active, c.closed = false, true; c.cleanupLocked(); c.mu.Unlock() }()
	check := func() error {
		if err := guard(); err != nil {
			return err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.checkLocked()
	}
	if err = check(); err != nil {
		return err
	}
	if c.originalRemoteMatcher != nil {
		if err = c.originalRemoteMatcher(ctx, c.lease[:c.leaseBytes], c.controlProjection[:c.controlProjectionBytes], check); err != nil {
			return err
		}
		return check()
	}
	s := c.store.sqliteStore
	if err = s.begin(ctx); err != nil {
		return err
	}
	defer s.end()
	if err = s.checkFence(); err != nil {
		return err
	}
	n, found, err := s.readParentWinnerContext(ctx, c.lease[:c.leaseBytes], c.scratch[:])
	if err != nil {
		return err
	}
	if !found || !bytes.Equal(c.scratch[:n], c.projection[:c.projectionBytes]) {
		return ErrConflict
	}
	return check()
}

func (c *SQLitePoolWinnerContinuation) cleanupLocked() {
	if !c.closed || c.active {
		return
	}
	clear(c.nonce[:])
	clear(c.lease[:])
	clear(c.projection[:])
	clear(c.controlProjection[:])
	clear(c.scratch[:])
	c.store = nil
	c.originalRemoteMatcher = nil
	c.shared.Release()
	c.storeRef.Release()
	c.reservation.Release()
	c.shared, c.storeRef, c.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
}

func (c *SQLitePoolWinnerContinuation) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.cleanupLocked()
}
