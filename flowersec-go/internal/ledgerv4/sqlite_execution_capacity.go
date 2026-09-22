package ledgerv4

import (
	"database/sql/driver"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// Capacity is an original live admission promise, not persisted history or a
// dispatch capability. All state below is protected by the original store gate.
type SQLiteExecutionCapacity struct{ *sqliteExecutionCapacity }
type sqliteExecutionCapacity struct {
	store                                    *SQLiteExecutions
	metadata, backing                        resourcev4.Reference
	claimed, using, working, closed, cleaned bool
}

func SQLiteExecutionCapacityCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteExecutionCapacity{})) + uint64(unsafe.Sizeof(sqliteExecutionCapacity{})), resourcev4.Items: 1}
}

// refreshCapacity runs only while the original connection is exclusively
// owned. It records detached counts for finite pre-Session admission; a failed
// read never leaves old free-space observations eligible for a new promise.
func (e *SQLiteExecutions) refreshCapacity() {
	s := e.store.sqliteStore
	var values [2]driver.Value
	err := s.checkFence()
	if err == nil {
		err = s.one("SELECT record_count,active_count FROM manifest WHERE id=1", values[:])
	}
	records, rok := values[0].(int64)
	active, aok := values[1].(int64)
	s.mu.Lock()
	e.capacityKnown = err == nil && rok && aok && records >= 0 && active >= 0 && active <= records
	if e.capacityKnown {
		e.capacityRecords, e.capacityActive = uint64(records), uint64(active)
	}
	s.mu.Unlock()
}

func (e *SQLiteExecutions) capacityAvailableLocked() bool {
	s := e.store.sqliteStore
	return !s.closed && !s.complete && !s.active && e.capacityKnown && e.capacityRecords+uint64(e.capacityReserved) < uint64(s.backing.limits.MaxRecords) && e.capacityActive+uint64(e.capacityReserved) < uint64(e.config.Active)
}

// ReserveCapacity performs no I/O and is safe before irreversible Session
// admission. The original complete store already reserved all maximum result
// pages. This call protects one free record and active position from other work.
func (e *SQLiteExecutions) ReserveCapacity(metadata resourcev4.Reference) (*SQLiteExecutionCapacity, error) {
	if e == nil || e.store == nil {
		return nil, ErrOwner
	}
	s := e.store.sqliteStore
	s.mu.Lock()
	defer s.mu.Unlock()
	if !e.capacityAvailableLocked() {
		return nil, ErrCapacity
	}
	if err := metadata.CheckAllocationScope(e.config.Root, e.config.Owner, e.config.Accounts); err != nil {
		return nil, err
	}
	owned, err := metadata.Take(SQLiteExecutionCapacityCharge())
	if err != nil {
		return nil, err
	}
	backing, err := s.reservation.Borrow()
	if err != nil {
		owned.Release()
		return nil, err
	}
	e.capacityReserved++
	return &SQLiteExecutionCapacity{&sqliteExecutionCapacity{store: e, metadata: owned, backing: backing, claimed: true}}, nil
}

func (c *SQLiteExecutionCapacity) CheckReady() error {
	if c == nil || c.sqliteExecutionCapacity == nil {
		return ErrOwner
	}
	s := c.store.store.sqliteStore
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.closed || s.closed {
		return ErrOwner
	}
	if c.using || c.working {
		return ErrCapacity
	}
	if !c.claimed {
		if !c.store.capacityAvailableLocked() {
			return ErrCapacity
		}
		c.claimed = true
		c.store.capacityReserved++
	}
	return c.backing.Check()
}

func (c *SQLiteExecutionCapacity) begin(e *SQLiteExecutions) error {
	if c == nil || c.sqliteExecutionCapacity == nil || c.store != e {
		return ErrOwner
	}
	s := e.store.sqliteStore
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.closed || c.using || c.working || !c.claimed {
		return ErrCapacity
	}
	c.using = true
	return nil
}
func (c *SQLiteExecutionCapacity) finish() {
	s := c.store.store.sqliteStore
	s.mu.Lock()
	defer s.mu.Unlock()
	c.using = false
	c.cleanupLocked()
}

// consume runs only after the new work owner has acquired all of its original
// resources. An uncertain transaction keeps working true until actual Exit.
func (c *SQLiteExecutionCapacity) consumeLocked() {
	c.claimed = false
	c.working = true
	c.store.capacityReserved--
}
func (c *SQLiteExecutionCapacity) releaseWork() {
	s := c.store.store.sqliteStore
	s.mu.Lock()
	defer s.mu.Unlock()
	c.working = false
	c.cleanupLocked()
}
func (c *SQLiteExecutionCapacity) Close() {
	if c == nil || c.sqliteExecutionCapacity == nil {
		return
	}
	s := c.store.store.sqliteStore
	s.mu.Lock()
	defer s.mu.Unlock()
	c.closed = true
	// An in-flight registration still owns this capacity until it either
	// transfers it to a work owner or completes its original attempt.
	if !c.using && c.claimed {
		c.claimed = false
		c.store.capacityReserved--
	}
	c.cleanupLocked()
}
func (c *SQLiteExecutionCapacity) cleanupLocked() {
	if !c.closed || c.using || c.working || c.cleaned {
		return
	}
	if c.claimed {
		c.claimed = false
		c.store.capacityReserved--
	}
	c.cleaned = true
	c.backing.Release()
	c.metadata.Release()
	c.backing, c.metadata = resourcev4.Reference{}, resourcev4.Reference{}
}
