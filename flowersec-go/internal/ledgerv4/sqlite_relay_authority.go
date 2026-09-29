package ledgerv4

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

var ErrRelayHistoryUnknown = errors.New("ledgerv4: original relay issuance history unknown")

type SQLiteRelayParentRegistration struct {
	// RestoreKey selects an already retained original registration. When set,
	// Committed must be empty; the same independent source identities, issuer
	// mapping and current parent validation remain mandatory.
	RestoreKey *protocolv4.RelayParentKey
	Committed  [2]*SQLiteCommittedRelayLeg
	// IssuanceIdentity and Mapping come from independent deployment trust.
	// A verified projection alone does not prove original durable issuance.
	IssuanceIdentity [2]SQLiteIdentity
	Mapping          protocolv4.RelayIssuerMapping
	Parent           protocolv4.CredentialValidation
}

type SQLiteRelayAuthorityConfig struct {
	Identity SQLiteIdentity
	Parents  []SQLiteRelayParentRegistration
	// MaxParents reserves the lifetime registration capacity. Zero fixes it to
	// the initial list; a larger value admits subsequent original publications.
	MaxParents      uint32
	ParallelLookups uint32
	RuntimeBytes    uint64
}

type sqliteRelayParentEntry struct {
	projection *protocolv4.RelayParentProjection
	parent     protocolv4.CredentialValidation
}

// SQLiteRelayAuthorityTable is a bounded original-issuance public index.
// It cannot install facts from a claim, fetch a parent using an untrusted URI,
// sign a replacement Grant or recover any handle/dispatch right. Absence is
// history_unknown, never authorization to accept an otherwise valid Grant.
// Parent registrations must come from committed original issuance/TxB records.
type SQLiteRelayAuthorityTable struct {
	mu                            sync.Mutex
	identity                      SQLiteIdentity
	store                         *SQLiteStore
	maxRecordBytes                uint32
	wire, original                []byte
	installing                    bool
	publication                   sqliteRelayPublication
	entries                       []sqliteRelayParentEntry
	index                         map[protocolv4.RelayParentKey]int
	reservation, shared, storeRef resourcev4.Reference
	parallel, active              uint32
	closed, cleaned               bool
	done                          chan struct{}
}

func SQLiteRelayAuthorityCharge(c SQLiteRelayAuthorityConfig) (resourcev4.Vector, error) {
	capacity := c.MaxParents
	if capacity == 0 {
		capacity = uint32(len(c.Parents))
	}
	if !validSQLiteIdentity(c.Identity) || capacity == 0 || capacity > 4096 || len(c.Parents) > int(capacity) || c.ParallelLookups == 0 || c.ParallelLookups > 65536 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	for _, parent := range c.Parents {
		for role := range parent.Committed {
			if (parent.RestoreKey == nil) != (parent.Committed[role] != nil) || !validSQLiteIdentity(parent.IssuanceIdentity[role]) {
				return resourcev4.Vector{}, ErrConfiguration
			}
		}
	}
	entry, err := protocolv4.RelayParentProjectionBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	record, err := protocolv4.RelayParentRecordBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	// One additional detached candidate belongs to the serialized installation
	// method, including duplicate comparison when every resident slot is full.
	fixed := record + entry + 2*protocolv4.RelayParentRecordMaxBytes + uint64(unsafe.Sizeof(SQLiteRelayAuthorityTable{})) + uint64(capacity)*(entry+uint64(unsafe.Sizeof(sqliteRelayParentEntry{}))+1024) + 512
	return (resourcev4.Vector{resourcev4.SDKBytes: fixed, resourcev4.Items: uint64(capacity) + 1, resourcev4.WorkSlots: uint64(c.ParallelLookups) + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// dependencies retains the independently configured namespace/trust owners.
// Each copied entry is additionally checked against those live owners on every
// resolution, including forwarding after the initiation window has ended.
func NewSQLiteRelayAuthorityTable(store *SQLiteStore, c SQLiteRelayAuthorityConfig, reservation, dependencies resourcev4.Reference) (*SQLiteRelayAuthorityTable, error) {
	return NewSQLiteRelayAuthorityTableContext(context.Background(), store, c, reservation, dependencies)
}

// NewSQLiteRelayAuthorityTableContext retains new original registrations before
// exposing a lookup table, or restores exact public rows from the same fenced
// store. No claim, winner, server allow or signing work is replayed.
func NewSQLiteRelayAuthorityTableContext(ctx context.Context, store *SQLiteStore, c SQLiteRelayAuthorityConfig, reservation, dependencies resourcev4.Reference) (_ *SQLiteRelayAuthorityTable, err error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	charge, err := SQLiteRelayAuthorityCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	storeRef, identity, _, maxRecordBytes, err := store.admissionReference(dependencies)
	if err != nil {
		return nil, err
	}
	adopted, refOwned := false, false
	defer func() {
		if !refOwned {
			storeRef.Release()
		}
	}()
	if identity != c.Identity {
		return nil, ErrOwner
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	capacity := c.MaxParents
	if capacity == 0 {
		capacity = uint32(len(c.Parents))
	}
	a := &SQLiteRelayAuthorityTable{identity: identity, store: store, maxRecordBytes: maxRecordBytes, reservation: owned, storeRef: storeRef, parallel: c.ParallelLookups,
		entries: make([]sqliteRelayParentEntry, 0, capacity), index: make(map[protocolv4.RelayParentKey]int, capacity),
		wire: make([]byte, protocolv4.RelayParentRecordMaxBytes), original: make([]byte, protocolv4.RelayParentRecordMaxBytes), done: make(chan struct{})}
	refOwned = true
	defer func() {
		if !adopted {
			a.Close()
		}
	}()
	a.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	a.identity.Authority = strings.Clone(identity.Authority)
	for _, input := range c.Parents {
		if err = a.Install(ctx, input); err != nil {
			return nil, err
		}
	}
	adopted = true
	return a, nil
}

// Install admits one original publication into the preallocated index. It
// holds its sole method position through storage and verification return;
// duplicates confirm the same original row and never replace its trust owner.
// New registrations require BOTH original committed receipts. RestoreKey reads
// an already retained public row and cannot recover any dispatch capability.
func (a *SQLiteRelayAuthorityTable) Install(ctx context.Context, input SQLiteRelayParentRegistration) error {
	return a.install(ctx, input, nil)
}

func (a *SQLiteRelayAuthorityTable) install(ctx context.Context, input SQLiteRelayParentRegistration, publication sqliteRelayPublication) (err error) {
	if a == nil || ctx == nil {
		return ErrConfiguration
	}
	for side, receipt := range input.Committed {
		if (input.RestoreKey == nil) != (receipt != nil) || !validSQLiteIdentity(input.IssuanceIdentity[side]) {
			return ErrConfiguration
		}
	}
	if input.RestoreKey != nil {
		key := *input.RestoreKey
		input.RestoreKey = &key
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return ErrOwner
	}
	if publication != nil && (a.publication != publication || !a.installing) {
		a.mu.Unlock()
		return ErrOwner
	}
	if a.installing && (publication == nil || a.publication != publication) {
		a.mu.Unlock()
		return ErrCapacity
	}
	for _, ref := range []resourcev4.Reference{a.reservation, a.shared, a.storeRef} {
		if err = ref.Check(); err != nil {
			a.mu.Unlock()
			return err
		}
	}
	a.installing = true
	a.mu.Unlock()
	defer func() {
		clear(a.wire)
		clear(a.original)
		a.mu.Lock()
		if publication == nil {
			a.installing = false
		}
		if a.closed && err == nil {
			err = ErrOwner
		}
		a.cleanupLocked()
		a.mu.Unlock()
	}()
	var p *protocolv4.RelayParentProjection
	if input.RestoreKey != nil {
		p, err = a.store.restoreRelayRegistration(ctx, input, a.wire, a.reservation)
	} else {
		p, err = input.Committed[0].copyProjection(input.IssuanceIdentity[0], protocolv4.ClientToServer, a.reservation)
		if err == nil {
			err = input.Committed[1].matchProjection(input.IssuanceIdentity[1], protocolv4.ServerToClient, a.reservation, p)
		}
	}
	if err != nil {
		return err
	}
	if err = p.MatchMapping(input.Mapping); err != nil {
		return err
	}
	if input.Mapping.Activation.WinnerAuthority != a.identity.Authority {
		return ErrConflict
	}
	key, err := p.Key()
	if err != nil {
		return err
	}
	input.Parent.Issuer.Schema = strings.Clone(input.Parent.Issuer.Schema)
	if err = p.CheckCurrent(input.Parent, a.reservation); err != nil {
		return err
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return ErrOwner
	}
	existing, duplicate := a.index[key]
	if duplicate {
		entry := a.entries[existing]
		if entry.parent != input.Parent {
			a.mu.Unlock()
			return ErrConflict
		}
		if err = entry.projection.MatchOriginalProjection(p); err != nil {
			a.mu.Unlock()
			return err
		}
	} else if len(a.entries) == cap(a.entries) {
		a.mu.Unlock()
		return ErrCapacity
	}
	a.mu.Unlock()
	if input.RestoreKey == nil {
		if err = a.store.persistRelayRegistration(ctx, input, p, a.wire, a.original, a.reservation, publication); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = p.CheckCurrent(input.Parent, a.reservation); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrOwner
	}
	for _, ref := range []resourcev4.Reference{a.reservation, a.shared, a.storeRef} {
		if err = ref.Check(); err != nil {
			return err
		}
	}
	if !duplicate {
		a.index[key] = len(a.entries)
		a.entries = append(a.entries, sqliteRelayParentEntry{projection: p, parent: input.Parent})
	}
	return nil
}

func (a *SQLiteRelayAuthorityTable) ResolveRelayParent(identity SQLiteIdentity, facts protocolv4.RelayClaimFacts) (_ RelayParentSelection, err error) {
	if a == nil {
		return RelayParentSelection{}, ErrOwner
	}
	key, err := protocolv4.RelayClaimKey(facts)
	if err != nil {
		return RelayParentSelection{}, err
	}
	a.mu.Lock()
	if a.closed || identity != a.identity {
		a.mu.Unlock()
		return RelayParentSelection{}, ErrOwner
	}
	if a.active >= a.parallel {
		a.mu.Unlock()
		return RelayParentSelection{}, ErrCapacity
	}
	for _, ref := range []resourcev4.Reference{a.reservation, a.shared, a.storeRef} {
		if err = ref.Check(); err != nil {
			a.mu.Unlock()
			return RelayParentSelection{}, err
		}
	}
	index, ok := a.index[key]
	if !ok {
		a.mu.Unlock()
		return RelayParentSelection{}, ErrRelayHistoryUnknown
	}
	entry := a.entries[index]
	a.active++
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.active--
		if a.closed {
			err = ErrOwner
		}
		a.cleanupLocked()
		a.mu.Unlock()
	}()
	selection, err := entry.projection.Resolve(facts)
	if err != nil {
		return RelayParentSelection{}, err
	}
	if err = entry.projection.CheckCurrent(entry.parent, a.reservation); err != nil {
		return RelayParentSelection{}, err
	}
	return RelayParentSelection{Source: selection.Source, WinnerAuthority: selection.WinnerAuthority, ActivationDigest: selection.ActivationDigest, CandidateSet: selection.CandidateSet, IssuedAt: selection.IssuedAt, ActivationEnd: selection.ActivationEnd, SessionEnd: selection.SessionEnd}, nil
}

func (a *SQLiteRelayAuthorityTable) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.reservation.Seal()
	a.cleanupLocked()
}
func (a *SQLiteRelayAuthorityTable) cleanupLocked() {
	if !a.closed || a.cleaned || a.active != 0 || a.installing {
		return
	}
	clear(a.entries)
	clear(a.index)
	a.entries, a.index = nil, nil
	clear(a.wire)
	clear(a.original)
	a.wire, a.original, a.store = nil, nil, nil
	a.shared.Release()
	a.storeRef.Release()
	a.reservation.Release()
	a.cleaned = true
	close(a.done)
}
func (a *SQLiteRelayAuthorityTable) WaitCleanup(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrConfiguration
	}
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ SQLiteRelayAuthority = (*SQLiteRelayAuthorityTable)(nil)
