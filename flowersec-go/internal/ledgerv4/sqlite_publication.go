package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PublicationAuthority is independently installed control-plane authorization.
// Checks are bounded local work and must not call the store. Mutation permission
// and complete-namespace visibility are distinct; tenant equality is not ACL.
// The host must retain its policy backing in the supplied dependency reservation.
type PublicationAuthority interface {
	CheckPublicationMutation(protocolv4.NamespacePublicationScope) error
	CheckPublicationRead(protocolv4.NamespacePublicationScope, []byte) error
}

type SQLitePublicationConfig struct {
	Scope  protocolv4.NamespacePublicationScope
	Clock  *timev4.Clock
	Trust  *protocolv4.NamespaceTrustStore
	Access PublicationAuthority
	// HistorySlots includes the current published pair. Each position reserves
	// a complete maximum State and Head; no unexpired version is evicted.
	// Unchanged State content reuses its position across freshness publications.
	HistorySlots           uint32
	MaxAuthenticationBytes uint32
	stateReservations      [2]resourcev4.Reference
}

// SQLitePublicationStore is one fixed namespace authority and publication
// transaction group. State mutation and publication metadata are separate.
// Ordinary mutations remain possible while the sole publisher is signing and
// while all retained publication positions are occupied.
type SQLitePublicationStore struct {
	store                              *SQLiteStore
	config                             SQLitePublicationConfig
	rules                              *protocolv4.NamespaceRules
	maximum, headMaximum               uint64
	configuration                      [512]byte
	configurationBytes                 int
	workspaces                         [2]*protocolv4.RevocationWorkspace
	codec                              *protocolv4.SignedMapCodec
	decoder                            *protocolv4.Decoder
	trust                              resourcev4.Reference
	current, snapshot, candidate, head []byte
	claim                              protocolv4.NamespacePublicationSnapshot
	claimSlot                          uint32
	nextOwner                          uint64
	claimInUse, releasePending         bool
}

func SQLitePublicationStoreCharges(l SQLiteLimits, c SQLitePublicationConfig) (owner, first, second resourcev4.Vector, err error) {
	if c.Clock == nil || c.Trust == nil || c.Access == nil || c.HistorySlots < 2 || c.HistorySlots > 64 || c.MaxAuthenticationBytes == 0 || c.MaxAuthenticationBytes > 16384 || c.Scope.Generation == 0 {
		return owner, first, second, ErrConfiguration
	}
	r, err := c.Trust.Rules()
	if err != nil {
		return owner, first, second, err
	}
	if r.PublicationScope(c.Scope.Generation) != c.Scope {
		return owner, first, second, ErrConfiguration
	}
	maximum, head := r.PublicationCapacity()
	chunks := (maximum + namespaceChunkBytes - 1) / namespaceChunkBytes
	pages := uint64(c.HistorySlots+2)*((maximum+head+sqlitePageBytes-1)/sqlitePageBytes+2*chunks+4) + 32
	if l.MaxRecordBytes < namespaceChunkBytes || uint64(l.MaxRecords) < uint64(c.HistorySlots+1)*chunks || uint64(l.MaxPages) < pages {
		return owner, first, second, ErrCapacity
	}
	base, err := SQLiteStoreCharge(l)
	if err != nil {
		return owner, first, second, err
	}
	h, err := protocolv4.SchemaByteLimit("FreshnessHead")
	if err != nil {
		return owner, first, second, err
	}
	codec, err := protocolv4.SignedMapBackingBytes("FreshnessHead", h, h)
	if err != nil {
		return owner, first, second, err
	}
	decoder, err := protocolv4.DecoderBackingBytes(h, h)
	if err != nil {
		return owner, first, second, err
	}
	headOwner, err := protocolv4.NamespaceHeadBackingBytes()
	if err != nil {
		return owner, first, second, err
	}
	first, err = r.StateCharge()
	if err != nil {
		return owner, first, second, err
	}
	second = first
	owner, err = base.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLitePublicationStore{})) + 3*maximum + head + codec + decoder + headOwner + uint64(c.MaxAuthenticationBytes), resourcev4.Items: 1})
	return
}

func newSQLitePublicationStore(s *sqliteStore, c SQLitePublicationConfig) (_ *SQLitePublicationStore, err error) {
	r, err := c.Trust.Rules()
	if err != nil {
		return nil, err
	}
	p := &SQLitePublicationStore{store: &SQLiteStore{s}, config: c, rules: r}
	defer func() {
		if err != nil {
			p.clear()
		}
	}()
	p.maximum, p.headMaximum = r.PublicationCapacity()
	w := admissionWriter{dst: p.configuration[:]}
	w.text(c.Scope.Tenant)
	w.text(c.Scope.Authority)
	w.bytes(c.Scope.Capacity[:])
	w.uint(c.Scope.Generation)
	w.uint(uint64(c.HistorySlots))
	w.uint(uint64(c.MaxAuthenticationBytes))
	w.uint(p.maximum)
	w.uint(p.headMaximum)
	p.configurationBytes = w.n
	if w.err != nil {
		return nil, w.err
	}
	// These same bounded arenas inspect both open snapshots and subsequently
	// serve mutations. No second maximum State decoder is created for reopen.
	for i, reference := range c.stateReservations {
		p.workspaces[i], err = protocolv4.NewRevocationWorkspace(r, reference)
		if err != nil {
			return nil, err
		}
	}
	p.config.stateReservations = [2]resourcev4.Reference{}
	h, err := protocolv4.SchemaByteLimit("FreshnessHead")
	if err != nil {
		return nil, err
	}
	p.codec, err = protocolv4.NewSignedMapCodec("FreshnessHead", h, h)
	if err != nil {
		return nil, err
	}
	p.decoder, err = protocolv4.NewDecoder(h, h)
	if err != nil {
		return nil, err
	}
	p.current = make([]byte, int(p.maximum))
	p.snapshot = make([]byte, int(p.maximum))
	p.candidate = make([]byte, int(p.maximum))
	p.head = make([]byte, int(p.headMaximum))
	return p, nil
}

func CreateSQLitePublicationStore(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLitePublicationConfig, owner, first, second, dependencies resourcev4.Reference) (*SQLitePublicationStore, error) {
	return openSQLitePublicationStore(ctx, backing, identity, continuity, c, owner, first, second, dependencies, true)
}
func OpenSQLitePublicationStore(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLitePublicationConfig, owner, first, second, dependencies resourcev4.Reference) (*SQLitePublicationStore, error) {
	return openSQLitePublicationStore(ctx, backing, identity, continuity, c, owner, first, second, dependencies, false)
}
func openSQLitePublicationStore(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLitePublicationConfig, owner, first, second, dependencies resourcev4.Reference, create bool) (_ *SQLitePublicationStore, err error) {
	if backing == nil || backing.sqliteBacking == nil {
		return nil, ErrConfiguration
	}
	ownerCharge, firstCharge, secondCharge, err := SQLitePublicationStoreCharges(backing.limits, c)
	if err != nil {
		return nil, err
	}
	for _, entry := range []struct {
		reference resourcev4.Reference
		minimum   resourcev4.Vector
	}{{owner, ownerCharge}, {first, firstCharge}, {second, secondCharge}} {
		if err = entry.reference.CheckMinimum(entry.minimum); err != nil {
			return nil, err
		}
	}
	if err = owner.CheckSameEnvironment(first); err != nil {
		return nil, err
	}
	if err = owner.CheckSameEnvironment(second); err != nil {
		return nil, err
	}
	c.stateReservations = [2]resourcev4.Reference{first, second}
	s, err := openSQLitePurpose(ctx, backing, identity, continuity, owner, dependencies, create, nil, nil, nil, nil, nil, nil, &c)
	if s == nil {
		return nil, err
	}
	p := s.publication
	if err != nil {
		return p, err
	}
	defer func() {
		if err != nil {
			s.Close()
			if s.WaitCleanup(context.Background()) == nil {
				_ = s.Retire()
			}
		}
	}()
	p.trust, err = c.Trust.ReferenceFor(c.Clock, s.reservation)
	if err != nil {
		return p, err
	}
	return p, nil
}

func (p *SQLitePublicationStore) ReferencePublicationStore(scope protocolv4.NamespacePublicationScope, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if p == nil || p.store == nil {
		return resourcev4.Reference{}, ErrConfiguration
	}
	s := p.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || scope != p.config.Scope {
		return resourcev4.Reference{}, ErrOwner
	}
	if err := s.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	return s.reservation.Borrow()
}

func (p *SQLitePublicationStore) guard() error {
	if err := p.trust.Check(); err != nil {
		return err
	}
	if err := p.config.Trust.CheckPublicationScope(p.config.Scope); err != nil {
		return err
	}
	if err := p.config.Access.CheckPublicationMutation(p.config.Scope); err != nil {
		return err
	}
	return p.store.continuity.Check(p.store.identity, p.store.epoch, false)
}

// ReplaceState commits a complete authority snapshot under the exact previous
// internal version. It preserves known revocations and immutable cohort policy;
// callers must already hold trusted issuance/revocation transaction authority.
func (p *SQLitePublicationStore) ReplaceState(ctx context.Context, expected uint64, wire []byte) (version uint64, err error) {
	if p == nil || p.store == nil || expected == math.MaxUint64 || len(wire) == 0 || uint64(len(wire)) > p.maximum {
		return 0, ErrConfiguration
	}
	s := p.store
	if err = s.begin(ctx); err != nil {
		return 0, err
	}
	defer s.end()
	copy(p.candidate, wire)
	defer clear(p.candidate)
	err = s.writeTransactionCommit(ctx, p.guard, func() error {
		old, oldDigest, size, e := p.readCurrent()
		if e != nil {
			return e
		}
		if old != expected {
			return ErrConflict
		}
		now, e := p.config.Clock.Sample()
		if e != nil {
			return e
		}
		next, e := p.workspaces[1].BindPublicationState(p.candidate[:len(wire)], p.config.Scope.Generation, expected+1, now.Interval)
		if e != nil {
			return e
		}
		defer next.Release()
		if e = p.config.Trust.StateHistory(next); e != nil {
			return e
		}
		if old != 0 {
			if e = p.readChunks(0, p.current[:size]); e != nil {
				return e
			}
			defer clear(p.current)
			previous, e := p.workspaces[0].BindPublicationState(p.current[:size], p.config.Scope.Generation, old, now.Interval)
			if e != nil {
				return e
			}
			defer previous.Release()
			if previous.PublicationDigest() != oldDigest {
				return ErrStorageFormat
			}
			if e = previous.CheckPublicationSuccessor(next, p.config.Trust); e != nil {
				return e
			}
		}
		digest := next.PublicationDigest()
		if e = p.writeChunks(0, p.candidate[:len(wire)]); e != nil {
			return e
		}
		return s.exec("UPDATE current_state SET version=?1,digest=?2,encoded_bytes=?3 WHERE id=1", named(1, sqliteUint(expected+1)), named(2, digest[:]), named(3, int64(len(wire))))
	}, false, func() error {
		return p.config.Trust.CommitPublication(p.config.Scope, nil, func() error { return s.exec("COMMIT") })
	})
	if err != nil {
		return 0, err
	}
	return expected + 1, nil
}

func (p *SQLitePublicationStore) ReadPublicationSnapshot(ctx context.Context, dst []byte) (out protocolv4.NamespacePublicationSnapshot, err error) {
	if p == nil || p.store == nil {
		return out, ErrConfiguration
	}
	s := p.store
	if err = s.begin(ctx); err != nil {
		return out, err
	}
	defer s.end()
	s.mu.Lock()
	if p.claim.Owner != 0 || p.nextOwner == math.MaxUint64 {
		s.mu.Unlock()
		return out, ErrCapacity
	}
	s.mu.Unlock()
	var slot, currentSlot uint32
	err = s.writeTransaction(ctx, p.guard, func() error {
		version, digest, size, e := p.readCurrent()
		if e != nil {
			return e
		}
		if version == 0 || size == 0 {
			return ErrStorageUnavailable
		}
		if uint64(len(dst)) < size {
			return ErrCapacity
		}
		previous, e := p.readPublicationVersion()
		if e != nil {
			return e
		}
		now, e := p.config.Clock.Sample()
		if e != nil {
			return e
		}
		// Removal uses the conservative lower bound and never erases the sole
		// durable high-water mark or any still-promised readable version.
		for i := uint32(1); i <= p.config.HistorySlots; i++ {
			var end, seq uint64
			var same bool
			e = s.readOne("SELECT next_update,sequence,state_digest=?2 FROM publications WHERE slot=?1", 3, func(v []driver.Value) error {
				var e error
				end, e = readSQLiteUint(v[0])
				if e == nil {
					seq, e = readSQLiteUint(v[1])
				}
				same = v[2] == int64(1)
				return e
			}, named(1, int64(i)), named(2, digest[:]))
			if e == nil && same && seq == previous.Sequence {
				currentSlot = i
			}
			if e == nil && seq != previous.Sequence && now.Interval.LowerMS >= end {
				if e = s.exec("DELETE FROM publications WHERE slot=?1", named(1, int64(i))); e != nil {
					return e
				}
				if e = s.exec("DELETE FROM chunks WHERE slot=?1", named(1, int64(i))); e != nil {
					return e
				}
				e = errNoPublicationRow
			}
			if isNoPublicationRow(e) {
				if slot == 0 {
					slot = i
				}
			} else if e != nil {
				return e
			}
		}
		// The same current State needs no additional immutable content position.
		// Its old read promise is preserved by a nondecreasing next_update.
		if currentSlot != 0 {
			slot = currentSlot
		}
		if slot == 0 {
			return ErrCapacity
		}
		if e = p.readChunks(0, p.snapshot[:size]); e != nil {
			return e
		}
		state, e := p.workspaces[0].BindPublicationState(p.snapshot[:size], p.config.Scope.Generation, version, now.Interval)
		if e != nil {
			return e
		}
		defer state.Release()
		if state.PublicationDigest() != digest {
			return ErrStorageFormat
		}
		if e = p.config.Trust.StateHistory(state); e != nil {
			return e
		}
		out = protocolv4.NamespacePublicationSnapshot{Fence: s.epoch, Owner: p.nextOwner + 1, Version: version, Previous: previous, StateBytes: size}
		return nil
	})
	if err != nil {
		clear(p.snapshot)
		return protocolv4.NamespacePublicationSnapshot{}, err
	}
	s.mu.Lock()
	p.nextOwner = out.Owner
	p.claim = out
	p.claimSlot = slot
	s.workPins++
	s.mu.Unlock()
	copy(dst, p.snapshot[:out.StateBytes])
	return out, nil
}

func (p *SQLitePublicationStore) ReleasePublicationSnapshot(claim protocolv4.NamespacePublicationSnapshot) {
	if p == nil || p.store == nil {
		return
	}
	s := p.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.claim == claim && claim.Owner != 0 {
		if p.claimInUse {
			p.releasePending = true
			return
		}
		clear(p.snapshot)
		p.claim = protocolv4.NamespacePublicationSnapshot{}
		p.claimSlot = 0
		s.workPins--
		s.signalLocked()
	}
}

func (p *SQLitePublicationStore) CommitNamespacePublication(ctx context.Context, claim protocolv4.NamespacePublicationSnapshot, version protocolv4.NamespacePublicationVersion, state, head []byte, guard func() error, commitGate func(func() error) error) (err error) {
	if p == nil || p.store == nil || guard == nil || commitGate == nil {
		return ErrConfiguration
	}
	s := p.store
	if err = s.begin(ctx); err != nil {
		return err
	}
	defer s.end()
	s.mu.Lock()
	valid := p.claim == claim && claim.Owner != 0 && claim.Fence == s.epoch
	slot := p.claimSlot
	if valid {
		p.claimInUse = true
	}
	s.mu.Unlock()
	if valid {
		defer func() {
			s.mu.Lock()
			p.claimInUse = false
			if p.releasePending {
				clear(p.snapshot)
				p.claim = protocolv4.NamespacePublicationSnapshot{}
				p.claimSlot = 0
				p.releasePending = false
				s.workPins--
				s.signalLocked()
			}
			s.mu.Unlock()
		}()
	}
	if !valid || claim.StateBytes != uint64(len(state)) || !bytes.Equal(state, p.snapshot[:claim.StateBytes]) || len(head) == 0 || uint64(len(head)) > p.headMaximum || claim.Previous.Sequence == math.MaxUint64 || version.Sequence != claim.Previous.Sequence+1 || version.Snapshot != claim.Version || version.Snapshot < claim.Previous.Snapshot || version.ThisUpdateMS < claim.Previous.ThisUpdateMS || version.NextUpdateMS <= version.ThisUpdateMS {
		return ErrConflict
	}
	if version.Snapshot == claim.Previous.Snapshot && version.StateDigest != claim.Previous.StateDigest {
		return ErrConflict
	}
	if err = p.config.Trust.ValidatePublicationPair(p.codec, p.decoder, p.workspaces[0], state, head, version); err != nil {
		return err
	}
	err = s.writeTransactionCommit(ctx, func() error {
		if e := p.guard(); e != nil {
			return e
		}
		return guard()
	}, func() error {
		previous, e := p.readPublicationVersion()
		if e != nil {
			return e
		}
		if previous != claim.Previous {
			return ErrConflict
		}
		if version.StateDigest == previous.StateDigest {
			if version.NextUpdateMS < previous.NextUpdateMS {
				return ErrConflict
			}
			if e = p.readChunks(slot, p.current[:len(state)]); e != nil {
				return e
			}
			defer clear(p.current)
			if !bytes.Equal(p.current[:len(state)], state) {
				return ErrStorageFormat
			}
			if e = s.exec("DELETE FROM publications WHERE slot=?1 AND sequence=?2", named(1, int64(slot)), named(2, sqliteUint(previous.Sequence))); e != nil {
				return e
			}
			if e = s.changedOne(); e != nil {
				return e
			}
		} else {
			if e = p.writeChunks(slot, state); e != nil {
				return e
			}
		}
		return s.exec("INSERT INTO publications VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", named(1, int64(slot)), named(2, sqliteUint(version.Snapshot)), named(3, sqliteUint(version.Sequence)), named(4, version.StateDigest[:]), named(5, version.HeadDigest[:]), named(6, sqliteUint(version.ThisUpdateMS)), named(7, sqliteUint(version.NextUpdateMS)), named(8, int64(len(state))), named(9, head))
	}, false, func() error {
		return p.config.Trust.CommitPublication(p.config.Scope, head, func() error { return commitGate(func() error { return s.exec("COMMIT") }) })
	})
	if err != nil {
		// A lost COMMIT result is reconciled only by an exact durable read.
		// Any inability to prove the original outcome fences this connection;
		// a later Open requires independent continuity and a new fencing epoch.
		if reconcile := p.reconcilePublication(claim, version, head); reconcile != nil {
			s.poison()
			return errors.Join(ErrUnknown, err, reconcile)
		}
	}
	return err
}

func (p *SQLitePublicationStore) reconcilePublication(claim protocolv4.NamespacePublicationSnapshot, version protocolv4.NamespacePublicationVersion, head []byte) (err error) {
	s := p.store
	if err = s.exec("BEGIN DEFERRED"); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, s.exec("ROLLBACK")) }()
	if err = s.checkFence(); err != nil {
		return err
	}
	if err = s.continuity.Check(s.identity, s.epoch, false); err != nil {
		return err
	}
	observed, err := p.readPublicationVersion()
	if err != nil {
		return err
	}
	if observed == claim.Previous {
		return nil
	}
	if observed != version {
		return ErrConflict
	}
	return s.readOne("SELECT CASE WHEN length(head)<=?1 THEN head ELSE NULL END FROM publications WHERE sequence=?2", 1, func(v []driver.Value) error {
		wire, ok := v[0].([]byte)
		if !ok || !bytes.Equal(wire, head) {
			return ErrStorageFormat
		}
		return nil
	}, named(1, int64(p.headMaximum)), named(2, sqliteUint(version.Sequence)))
}

var ErrMissingPublication = errors.New("ledgerv4: publication not available")

// ReadPublished checks full-namespace visibility on every access, including
// exact-digest cache reads. Zero digest selects the current published pair.
// It never invokes signing or treats unknown versions as an empty State.
func (p *SQLitePublicationStore) ReadPublished(ctx context.Context, authentication []byte, digest [32]byte, state, head []byte) (out protocolv4.NamespacePublicationVersion, stateBytes, headBytes int, err error) {
	if p == nil || p.store == nil || len(authentication) == 0 || len(authentication) > int(p.config.MaxAuthenticationBytes) {
		return out, 0, 0, ErrConfiguration
	}
	s := p.store
	if err = s.begin(ctx); err != nil {
		return out, 0, 0, err
	}
	defer s.end()
	defer func() {
		if err != nil {
			clear(state[:stateBytes])
			clear(head[:headBytes])
			out = protocolv4.NamespacePublicationVersion{}
			stateBytes = 0
			headBytes = 0
		}
	}()
	if err = p.config.Access.CheckPublicationRead(p.config.Scope, authentication); err != nil {
		return
	}
	if err = s.exec("BEGIN DEFERRED"); err != nil {
		return
	}
	defer func() { err = errors.Join(err, s.exec("ROLLBACK")) }()
	if err = s.checkFence(); err != nil {
		return
	}
	if err = s.continuity.Check(s.identity, s.epoch, false); err != nil {
		return
	}
	var slot uint32
	query := "SELECT slot,snapshot,sequence,state_digest,head_digest,this_update,next_update,encoded_bytes,CASE WHEN length(head)<=?1 THEN head ELSE NULL END FROM publications"
	args := []driver.NamedValue{named(1, int64(p.headMaximum))}
	if digest != ([32]byte{}) {
		query += " WHERE state_digest=?2"
		args = append(args, named(2, digest[:]))
	}
	query += " ORDER BY sequence DESC LIMIT 1"
	err = s.readOne(query, 9, func(v []driver.Value) error {
		var e error
		slot, out, e = publicationRow(v[:7])
		if e != nil {
			return e
		}
		size, ok := v[7].(int64)
		wire, wok := v[8].([]byte)
		if !ok || size <= 0 || uint64(size) > p.maximum || !wok || len(wire) == 0 || uint64(len(wire)) > p.headMaximum {
			return ErrStorageFormat
		}
		if int64(len(state)) < size || len(head) < len(wire) {
			return ErrCapacity
		}
		stateBytes, headBytes = int(size), len(wire)
		copy(head, wire)
		return nil
	}, args...)
	if isNoPublicationRow(err) {
		err = ErrMissingPublication
	}
	if err != nil {
		return
	}
	now, e := p.config.Clock.Sample()
	if e != nil {
		err = e
		return
	}
	if !now.Interval.ValidBefore(out.NextUpdateMS) {
		err = ErrMissingPublication
		return
	}
	if err = p.readChunks(slot, state[:stateBytes]); err != nil {
		return
	}
	if err = p.config.Trust.ValidatePublicationPair(p.codec, p.decoder, p.workspaces[0], state[:stateBytes], head[:headBytes], out); err != nil {
		return
	}
	if err = p.config.Access.CheckPublicationRead(p.config.Scope, authentication); err != nil {
		return
	}
	err = ctx.Err()
	return
}

// CheckReadAccess is the service's final disclosure check. Its installed policy
// must authorize the full namespace, including trust dependencies, on every call.
func (p *SQLitePublicationStore) CheckReadAccess(scope protocolv4.NamespacePublicationScope, authentication []byte) error {
	if p == nil || p.store == nil || scope != p.config.Scope || len(authentication) == 0 || len(authentication) > int(p.config.MaxAuthenticationBytes) {
		return ErrConfiguration
	}
	s := p.store
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrOwner
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	return p.config.Access.CheckPublicationRead(scope, authentication)
}

func (p *SQLitePublicationStore) Close() {
	if p != nil && p.store != nil {
		p.store.Close()
	}
}
func (p *SQLitePublicationStore) WaitCleanup(ctx context.Context) error {
	if p == nil || p.store == nil {
		return ErrConfiguration
	}
	return p.store.WaitCleanup(ctx)
}
func (p *SQLitePublicationStore) Retire() error {
	if p == nil || p.store == nil {
		return ErrConfiguration
	}
	return p.store.Retire()
}
func (p *SQLitePublicationStore) clear() {
	for _, w := range p.workspaces {
		if w != nil {
			_ = w.Close()
		}
	}
	clear(p.current)
	clear(p.snapshot)
	clear(p.candidate)
	clear(p.head)
	p.current, p.snapshot, p.candidate, p.head = nil, nil, nil, nil
	p.trust.Release()
	p.config = SQLitePublicationConfig{}
	p.rules = nil
	p.workspaces = [2]*protocolv4.RevocationWorkspace{}
	clear(p.configuration[:])
	p.codec = nil
	p.decoder = nil
}
func (*SQLitePublicationStore) String() string               { return "Flowersec.SQLitePublicationStore" }
func (*SQLitePublicationStore) GoString() string             { return "Flowersec.SQLitePublicationStore" }
func (*SQLitePublicationStore) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
