package ledgerv4

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// RelayParentSelection is resolved from independently authenticated original
// issuance/activation records. It is never taken from peer hints or readback
// rows. Pool resolution proves membership in the complete signed selection,
// including direct candidates, and the single common parent once authority.
type RelayParentSelection struct {
	Source, WinnerAuthority             string
	ActivationDigest, CandidateSet      [32]byte
	IssuedAt, ActivationEnd, SessionEnd uint64
}

// SQLiteRelayAuthority is trusted immutable deployment configuration. It must
// authenticate the grant issuer's parent authority, exact original parent
// reference and activation, route/service/audience/identities, SessionContract
// digest and envelope bound. For pool, every selectable relay and direct
// acceptor must resolve to this same store and ParentWinner projection. The
// actual namespace/revocation/time gates additionally remain in guard.
// This bounded local operation performs no I/O and retains no borrowed facts.
type SQLiteRelayAuthority interface {
	ResolveRelayParent(SQLiteIdentity, protocolv4.RelayClaimFacts) (RelayParentSelection, error)
}

type RelayActivationOwner struct {
	Relay, Invocation, Carrier [16]byte
	Generation                 uint64
}

// SQLiteRelayActivation is one original claim invocation. Only Claim's
// confirmed once-only continuation can publish the relay proof or attach the
// actual original handle to a pairing. Queries never return this capability.
type SQLiteRelayActivation struct{ *sqliteRelayActivation }
type sqliteRelayActivation struct {
	authority                         SQLiteRelayAuthority
	facts                             protocolv4.RelayClaimFacts
	resolving                         uint32
	mu                                sync.Mutex
	store                             *sqliteStore
	invocation                        *Invocation
	guard                             func() error
	fields                            protocolv4.RelayClaimFields
	selection                         RelayParentSelection
	owner                             RelayActivationOwner
	identity                          SQLiteIdentity
	fence, deadline                   uint64
	key                               [admissionKeyBytes + 1]byte
	keySize                           int
	root, winner, target, scratch     []byte
	rootSize, winnerSize, targetSize  int
	reservation, storeReference       resourcev4.Reference
	started, running, closed, cleaned bool
}

func SQLiteRelayActivationCharges(maxRecordBytes uint32) (owner, invocation resourcev4.Vector, err error) {
	if maxRecordBytes < 16384 || maxRecordBytes > 1<<20 {
		return owner, invocation, ErrConfiguration
	}
	factsBytes, err := protocolv4.RelayClaimFactsBackingBytes()
	if err != nil {
		return owner, invocation, err
	}
	owner = resourcev4.Vector{resourcev4.SDKBytes: 5*uint64(maxRecordBytes) + factsBytes + uint64(unsafe.Sizeof(SQLiteRelayActivation{})) + uint64(unsafe.Sizeof(sqliteRelayActivation{})), resourcev4.Items: 1, resourcev4.WorkSlots: 1}
	invocation, err = InvocationCharge(admissionKeyBytes+1, int(maxRecordBytes))
	return
}

func NewSQLiteRelayActivation(ctx context.Context, store *SQLiteStore, authority SQLiteRelayAuthority, facts protocolv4.RelayClaimFacts, owner RelayActivationOwner, clock *timev4.Clock, deadline *timev4.Deadline, guard func() error, buffers, invocation, environment resourcev4.Reference) (_ *SQLiteRelayActivation, err error) {
	if ctx == nil || authority == nil || guard == nil || !deadline.BelongsTo(clock) || owner.Relay == ([16]byte{}) || owner.Invocation == ([16]byte{}) || owner.Carrier == ([16]byte{}) || owner.Generation == 0 {
		return nil, ErrConfiguration
	}
	f, err := facts.Fields()
	if err != nil {
		return nil, err
	}
	if f.RelayIncarnation != owner.Carrier {
		return nil, ErrOwner
	}
	if err = buffers.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if err = invocation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	ref, identity, fence, limit, err := store.admissionReference(environment)
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			ref.Release()
		}
	}()
	charge, _, err := SQLiteRelayActivationCharges(limit)
	if err != nil {
		return nil, err
	}
	held, err := buffers.Take(charge)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			held.Release()
		}
	}()
	selection, err := authority.ResolveRelayParent(identity, facts)
	if err != nil {
		return nil, err
	}
	if selection.Source != "live_authority" && selection.Source != "preauthorized_pool" || selection.ActivationDigest == ([32]byte{}) || selection.IssuedAt < f.ParentIssuedAt || selection.IssuedAt >= selection.ActivationEnd || selection.ActivationEnd > f.ParentInitiationEnd || selection.ActivationEnd > selection.SessionEnd || selection.SessionEnd > f.ParentSessionEnd {
		return nil, ErrConfiguration
	}
	if selection.Source == "preauthorized_pool" {
		if selection.WinnerAuthority != identity.Authority || selection.CandidateSet == ([32]byte{}) {
			return nil, ErrConfiguration
		}
	} else if selection.WinnerAuthority != "" || selection.CandidateSet != ([32]byte{}) {
		return nil, ErrConfiguration
	}
	if err = deadline.Tighten(min(selection.ActivationEnd, selection.SessionEnd, f.NotAfter)); err != nil {
		return nil, err
	}
	if err = guard(); err != nil {
		return nil, err
	}
	sample, err := deadline.Sample()
	if err != nil {
		return nil, err
	}
	if err = sample.LowerBound(max(f.ParentIssuedAt, f.IssuedAt, selection.IssuedAt), true); err != nil {
		return nil, err
	}
	i, err := NewInvocation(ctx, clock, deadline, fence, admissionKeyBytes+1, int(limit), invocation)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			_ = i.Cleanup()
		}
	}()
	for _, value := range []*string{&f.Tenant, &f.Audience, &f.EndpointAudience, &f.Profile, &f.Service, &f.ParentAuthority, &f.ParentPolicy, &selection.Source, &selection.WinnerAuthority, &identity.Authority} {
		*value = strings.Clone(*value)
	}
	a := &sqliteRelayActivation{authority: authority, facts: facts.Clone(), store: store.sqliteStore, invocation: i, guard: guard, fields: f, selection: selection, owner: owner, identity: identity, fence: fence, deadline: deadline.Cap(), reservation: held, storeReference: ref,
		root: make([]byte, limit), winner: make([]byte, limit), target: make([]byte, limit), scratch: make([]byte, limit)}
	parent := admissionRecord{fields: protocolv4.AdmissionFields{Source: selection.Source, Tenant: f.Tenant, Audience: f.EndpointAudience, WinnerAuthority: selection.WinnerAuthority, Issuer: f.Issuer, Lease: f.Lease, Artifact: f.Artifact, Proof: selection.ActivationDigest, CandidateSet: selection.CandidateSet, Candidate: f.Candidate, Route: f.Route, Attempt: f.Attempt, ClientIdentity: f.ClientIdentity, ServerIdentity: f.ServerIdentity, IssuedAt: selection.IssuedAt, ActivationEnd: selection.ActivationEnd, SessionEnd: selection.SessionEnd}}
	n, err := parent.key(a.key[:])
	if err != nil {
		return nil, err
	}
	a.key[n], a.keySize = byte(f.EndpointRole), n+1
	a.winnerSize, err = encodeParentSelection(a.winner, parent.fields)
	if err != nil {
		return nil, err
	}
	if err = a.encode(facts); err != nil {
		return nil, err
	}
	adopted = true
	return &SQLiteRelayActivation{a}, nil
}

func (a *sqliteRelayActivation) encode(facts protocolv4.RelayClaimFacts) error {
	w := admissionWriter{dst: a.root}
	w.text("flowersec/relay-parent/1")
	w.uint(uint64(a.winnerSize))
	w.bytes(a.winner[:a.winnerSize])
	for _, value := range []string{a.fields.Service, a.fields.Audience, a.fields.Profile} {
		w.text(value)
	}
	for _, value := range [][]byte{a.fields.Pairing[:], a.fields.RelayIdentity[:], a.fields.Contract[:]} {
		w.bytes(value)
	}
	n, err := facts.CopyParentReference(a.scratch)
	if err != nil {
		return err
	}
	w.uint(uint64(n))
	w.bytes(a.scratch[:n])
	if w.err != nil {
		return w.err
	}
	a.rootSize = w.n
	w = admissionWriter{dst: a.target}
	w.text("flowersec/relay-leg/1")
	w.uint(uint64(a.rootSize))
	w.bytes(a.root[:a.rootSize])
	w.text(a.identity.Authority)
	for _, value := range [][]byte{a.identity.StoreID[:], a.owner.Relay[:], a.owner.Invocation[:], a.owner.Carrier[:], a.fields.Possession[:], a.fields.Challenge[:]} {
		w.bytes(value)
	}
	for _, value := range []uint64{a.identity.Generation, a.fence, 1, a.owner.Generation, uint64(a.fields.EndpointRole), a.deadline} {
		w.uint(value)
	}
	n, err = facts.CopyGrant(a.scratch)
	if err != nil {
		return err
	}
	w.uint(uint64(n))
	w.bytes(a.scratch[:n])
	clear(a.scratch)
	a.targetSize = w.n
	return w.err
}

func (a *sqliteRelayActivation) check() error {
	if err := a.reservation.Check(); err != nil {
		return err
	}
	if err := a.storeReference.Check(); err != nil {
		return err
	}
	if err := (&SQLiteRelayActivation{a}).CheckResolvedAuthority(); err != nil {
		return err
	}
	return a.guard()
}

func (a *SQLiteRelayActivation) Claim(action func(context.Context) error) (err error) {
	if a == nil || a.sqliteRelayActivation == nil || action == nil {
		return ErrConfiguration
	}
	a.mu.Lock()
	if a.closed || a.started {
		a.mu.Unlock()
		return ErrOwner
	}
	a.started, a.running = true, true
	a.mu.Unlock()
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrOwner
		}
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		if err != nil {
			a.Close(err)
		}
	}()
	tx := Transaction{Kind: RelayClaim, Authority: a.identity.Authority, Key: a.key[:a.keySize], CommitVersion: 1, FencingEpoch: a.fence, Projection: a.target[:a.targetSize]}
	original, err := a.invocation.Begin(tx)
	if err == nil {
		err = original.Run(relayCommitStore{a.sqliteRelayActivation})
	}
	if err == nil {
		err = original.Dispatch(func(ctx context.Context) error {
			if err := a.check(); err != nil {
				return err
			}
			return action(ctx)
		})
	}
	returned = true
	return err
}

func (a *SQLiteRelayActivation) Close(cause error) {
	if a == nil || a.sqliteRelayActivation == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	a.reservation.Seal()
	i := a.invocation
	a.mu.Unlock()
	i.Cancel(cause)
}

// SessionNotAfterMS is an immutable cap, never a dispatch capability. The
// original hop intersects it with its already projected forwarding deadline
// before claim; the shorter activation deadline is not reused as Session age.
func (a *SQLiteRelayActivation) SessionNotAfterMS() (uint64, error) {
	if a == nil || a.sqliteRelayActivation == nil {
		return 0, ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.cleaned {
		return 0, ErrOwner
	}
	return min(a.selection.SessionEnd, a.fields.NotAfter, a.fields.ParentSessionEnd), nil
}

func (a *SQLiteRelayActivation) Cleanup() error {
	if a == nil || a.sqliteRelayActivation == nil {
		return ErrConfiguration
	}
	a.Close(ErrOwner)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cleaned {
		return nil
	}
	if a.running || a.resolving != 0 {
		return ErrCapacity
	}
	if err := a.invocation.Cleanup(); err != nil {
		return err
	}
	clear(a.root)
	clear(a.winner)
	clear(a.target)
	clear(a.scratch)
	clear(a.key[:])
	a.root, a.winner, a.target, a.scratch = nil, nil, nil, nil
	a.fields, a.selection = protocolv4.RelayClaimFields{}, RelayParentSelection{}
	a.authority, a.facts = nil, protocolv4.RelayClaimFacts{}
	a.guard, a.store = nil, nil
	a.storeReference.Release()
	a.reservation.Release()
	a.cleaned = true
	return nil
}

// MatchPeer is a local original-owner check, not a query or recovery path.
// Callers must also hold both live authenticated carrier owners. The exact
// immutable root includes pairing, identities, service and original activation.
func (a *SQLiteRelayActivation) MatchPeer(other *SQLiteRelayActivation) error {
	if a == nil || other == nil || a.sqliteRelayActivation == nil || other.sqliteRelayActivation == nil || a.sqliteRelayActivation == other.sqliteRelayActivation {
		return ErrOwner
	}
	a.mu.Lock()
	side := a.fields.EndpointRole
	invalid := a.closed || a.cleaned || !a.started || a.running
	a.mu.Unlock()
	if invalid {
		return ErrOwner
	}
	other.mu.Lock()
	peerSide := other.fields.EndpointRole
	peerInvalid := other.closed || other.cleaned || !other.started || other.running
	other.mu.Unlock()
	if peerInvalid || side == peerSide {
		return ErrConflict
	}
	first, second := a.sqliteRelayActivation, other.sqliteRelayActivation
	if side == protocolv4.ServerToClient {
		first, second = second, first
	}
	first.mu.Lock()
	defer first.mu.Unlock()
	second.mu.Lock()
	defer second.mu.Unlock()
	if first.closed || second.closed || first.cleaned || second.cleaned || !first.started || !second.started || first.running || second.running || first.fields.EndpointRole != protocolv4.ClientToServer || second.fields.EndpointRole != protocolv4.ServerToClient || first.store != second.store || first.fence != second.fence || first.identity != second.identity || !bytes.Equal(first.root[:first.rootSize], second.root[:second.rootSize]) {
		return ErrConflict
	}
	return nil
}

// CheckResolvedAuthority revalidates the same original public activation and
// issuer/once mapping. It is independent of the claim deadline and dispatch
// machinery, so forwarding can use the original Session horizon. It never
// resolves another selection or grants a later invocation any local right.
func (a *SQLiteRelayActivation) CheckResolvedAuthority() (err error) {
	if a == nil || a.sqliteRelayActivation == nil {
		return ErrOwner
	}
	a.mu.Lock()
	if a.closed || a.cleaned || a.resolving >= 65536 {
		a.mu.Unlock()
		return ErrOwner
	}
	a.resolving++
	authority, identity, facts, expected := a.authority, a.identity, a.facts, a.selection
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.resolving--
		if a.closed {
			err = ErrOwner
		}
		a.mu.Unlock()
	}()
	actual, err := authority.ResolveRelayParent(identity, facts)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrConflict
	}
	return nil
}

func (a *SQLiteRelayActivation) MatchActivationSource(source string) error {
	if a == nil || a.sqliteRelayActivation == nil {
		return ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.cleaned || a.selection.Source != source {
		return ErrConflict
	}
	return nil
}
