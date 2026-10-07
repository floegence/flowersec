package ledgerv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// SQLiteDirectIssueHost binds this exact physical history to one independently
// allocated finite namespace share. Other stores must receive disjoint shares;
// recreating an adapter or database cannot allocate the same share twice. The
// authentication hook authorizes both identities and complete-State read ACLs
// for the entire fixed direct route closure. Hooks are bounded local host work.
// Authentication is borrowed only until AuthorizeDirectIssue returns; an
// access handle retains its own pre-admitted principal/session binding.
type SQLiteDirectIssueHost interface {
	CheckDirectIssueShare(SQLiteIdentity, protocolv4.DirectIssuePolicyLimits, uint32, uint64) error
	AuthorizeDirectIssue(context.Context, SQLiteIdentity, protocolv4.DirectIssueRequest, protocolv4.DirectIssueFacts) (SQLiteDirectIssueAccess, error)
}

type SQLiteDirectIssueAccess interface {
	Check(context.Context) error
	Close()
}

type SQLiteDirectIssueConfig struct {
	Policy                   protocolv4.DirectIssuePolicyConfig
	Host                     SQLiteDirectIssueHost
	MaxOutstanding           uint32
	StateBytes               uint64
	RequestsPerMinute, Burst uint16
	WorkMS, RuntimeBytes     uint64
}

type SQLiteDirectIssueStatus struct {
	Outstanding        uint32
	ReservedStateBytes uint64
	RetainedRequests   uint32
}

// SQLiteDirectIssueAuthority implements the original issuer permit against
// the same physical admission/spend transaction group. It owns one work slot;
// repeated instances share the durable rate/outstanding/configuration row.
// There is intentionally no TTL, automatic GC or row-to-signing reconstruction.
// Authority publication must consume these obligations as described by the
// original namespace publisher integration; this adapter never publishes Head.
type SQLiteDirectIssueAuthority struct {
	mu                                      sync.Mutex
	store                                   *sqliteStore
	config                                  SQLiteDirectIssueConfig
	policy                                  *protocolv4.DirectIssuePolicy
	reservation, shared, storeRef, trustRef resourcev4.Reference
	configuration                           [8192]byte
	configurationSize                       int
	fence                                   uint64
	active                                  *sqliteDirectIssuePermit
	running, closed, cleaned                bool
	done                                    chan struct{}
}

type sqliteDirectIssuePermit struct {
	owner                                     *SQLiteDirectIssueAuthority
	facts                                     protocolv4.DirectIssueFacts
	request                                   [32]byte
	invocation                                [16]byte
	key                                       [admissionKeyBytes]byte
	keySize                                   int
	projection                                [4096]byte
	projectionSize                            int
	access                                    SQLiteDirectIssueAccess
	ctx                                       context.Context
	cancel                                    context.CancelFunc
	window                                    *timev4.Window
	digest                                    [32]byte
	commitStarted, committed, closed, cleaned bool
}

// Each outstanding lease reserves a maximum canonical RevokedLeaseEntry and
// one complete original CohortPolicySegment. The fixed share also pays the
// State header, list headers and one maximum issuer authorization impact.
const directIssueFixedStateBytes uint64 = 1024 + 128
const directIssuePerLeaseStateBytes uint64 = 92 + 41

// SQLiteDirectIssueStateShareBytes is the minimum original State allocation
// required for one fixed physical issuance share. Deployment manifests use the
// same worst-case lease, cohort and header sizes as the durable authority.
func SQLiteDirectIssueStateShareBytes(outstanding uint32) (uint64, error) {
	if outstanding == 0 || outstanding > 1<<20 {
		return 0, ErrConfiguration
	}
	return directIssueFixedStateBytes + uint64(outstanding)*directIssuePerLeaseStateBytes, nil
}

func SQLiteDirectIssueCharge(c SQLiteDirectIssueConfig) (resourcev4.Vector, error) {
	if c.Policy.Trust == nil || c.Policy.Clock == nil || c.Host == nil || c.MaxOutstanding == 0 || c.MaxOutstanding > 1<<20 || c.StateBytes < directIssueFixedStateBytes+uint64(c.MaxOutstanding)*directIssuePerLeaseStateBytes || c.StateBytes > 1<<32 || c.RequestsPerMinute == 0 || c.RequestsPerMinute > 6000 || c.Burst == 0 || c.Burst > c.RequestsPerMinute || c.WorkMS == 0 || c.WorkMS > 2000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteDirectIssueAuthority{})) + uint64(unsafe.Sizeof(sqliteDirectIssuePermit{})) + protocolv4.DirectIssuePolicyBackingBytes() + uint64(unsafe.Sizeof(timev4.Window{})) + 16384, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewSQLiteDirectIssueAuthority(ctx context.Context, store *SQLiteStore, c SQLiteDirectIssueConfig, reservation, dependencies resourcev4.Reference) (_ *SQLiteDirectIssueAuthority, err error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	charge, err := SQLiteDirectIssueCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	ref, _, fence, limit, err := store.admissionReference(dependencies)
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			ref.Release()
		}
	}()
	s := store.sqliteStore
	s.mu.Lock()
	if s.closed || s.retired || s.backing == nil {
		s.mu.Unlock()
		return nil, ErrOwner
	}
	limits := s.backing.limits
	otherPurpose := s.business != nil || s.references != nil || s.topUps != nil || s.topUpServer != nil || s.namespace != nil || s.archive != nil
	s.mu.Unlock()
	if otherPurpose || limit < 4096 || c.MaxOutstanding > limits.MaxRecords {
		return nil, ErrConfiguration
	}
	// Pre-admit physical room for every maximum-sized purpose row, B-tree split,
	// configuration and same-size digest commit; no future revoke needs new disk.
	pages := uint64(32) + (uint64(limits.MaxRecords)+1)*(8+2*((uint64(limit)+4095)/4096))
	if pages > uint64(limits.MaxPages) {
		return nil, ErrCapacity
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	a := &SQLiteDirectIssueAuthority{store: s, config: c, reservation: owned, storeRef: ref, fence: fence, done: make(chan struct{})}
	defer func() {
		if !adopted {
			a.trustRef.Release()
			a.shared.Release()
			owned.Release()
		}
	}()
	a.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	a.policy, a.trustRef, err = protocolv4.NewDirectIssuePolicy(c.Policy, dependencies)
	if err != nil {
		return nil, err
	}
	a.config.Policy.Namespaces = nil
	l := a.policy.Limits()
	if uint64(c.MaxOutstanding) > l.MaxLeases || uint64(c.MaxOutstanding) > l.MaxSegments || l.MaxIssuers < 1 || l.MaxAuthorizations < 1 || c.StateBytes > l.MaxStateBytes {
		return nil, ErrCapacity
	}
	if err = c.Host.CheckDirectIssueShare(s.identity, l, c.MaxOutstanding, c.StateBytes); err != nil {
		return nil, err
	}
	w := admissionWriter{dst: a.configuration[:]}
	w.text("flowersec/direct-issuer/1")
	for _, value := range []uint64{uint64(c.MaxOutstanding), c.StateBytes, uint64(c.RequestsPerMinute), uint64(c.Burst), c.WorkMS, directIssueFixedStateBytes, directIssuePerLeaseStateBytes} {
		w.uint(value)
	}
	n, err := a.policy.CopyConfiguration(a.configuration[w.n:])
	if err != nil {
		return nil, err
	}
	a.configurationSize = w.n + n
	if err = s.begin(ctx); err != nil {
		return nil, err
	}
	defer s.end()
	err = s.writeTransaction(ctx, func() error { return a.checkBase(ctx) }, func() error {
		var old [8192]byte
		size := 0
		err := s.readOne("SELECT configuration,rows,state_bytes,credit,last_upper FROM direct_issue_config WHERE id=1", 5, func(v []driver.Value) error {
			b, ok := v[0].([]byte)
			if !ok || len(b) > len(old) {
				return ErrStorageFormat
			}
			size = copy(old[:], b)
			rows, ok := v[1].(int64)
			state, sok := v[2].(int64)
			credit, ce := readSQLiteUint(v[3])
			_, te := readSQLiteUint(v[4])
			if !ok || rows < 0 || rows > int64(c.MaxOutstanding) || !sok || state != int64(directIssueFixedStateBytes)+rows*int64(directIssuePerLeaseStateBytes) || uint64(state) > c.StateBytes || ce != nil || credit > uint64(c.Burst)*60000 || te != nil {
				return ErrStorageFormat
			}
			return nil
		})
		if err == nil {
			if !bytes.Equal(old[:size], a.configuration[:a.configurationSize]) {
				return ErrConfiguration
			}
			return nil
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
		now, err := c.Policy.Clock.Sample()
		if err != nil {
			return err
		}
		return s.exec("INSERT INTO direct_issue_config VALUES(1,?1,0,?2,?3,?4)", named(1, a.configuration[:a.configurationSize]), named(2, int64(directIssueFixedStateBytes)), named(3, sqliteUint(uint64(c.Burst)*60000)), named(4, sqliteUint(now.UpperMS)))
	})
	if err != nil {
		return nil, err
	}
	adopted = true
	return a, nil
}

func (a *SQLiteDirectIssueAuthority) checkBase(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		return ErrOwner
	}
	for _, ref := range []resourcev4.Reference{a.reservation, a.shared, a.storeRef, a.trustRef} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	if a.store.epoch != a.fence {
		return ErrFenced
	}
	return a.config.Host.CheckDirectIssueShare(a.store.identity, a.policy.Limits(), a.config.MaxOutstanding, a.config.StateBytes)
}

func (p *sqliteDirectIssuePermit) guard(ctx context.Context) error {
	if err := p.owner.checkBase(ctx); err != nil {
		return err
	}
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if err := p.window.Check(); err != nil {
		return err
	}
	p.owner.mu.Lock()
	closed := p.closed
	p.owner.mu.Unlock()
	if closed {
		return ErrOwner
	}
	if err := p.owner.policy.CheckFacts(p.facts); err != nil {
		return err
	}
	if p.access == nil {
		return ErrDenied
	}
	if err := p.access.Check(p.ctx); err != nil {
		return err
	}
	return p.ctx.Err()
}

func (a *SQLiteDirectIssueAuthority) BeginDirectIssue(ctx context.Context, request protocolv4.DirectIssueRequest, facts protocolv4.DirectIssueFacts) (_ protocolv4.DirectIssuePermit, err error) {
	if a == nil || ctx == nil || request.RequestID == ([32]byte{}) || len(request.Authentication) == 0 || len(request.Authentication) > 16384 {
		return nil, ErrConfiguration
	}
	if !a.mu.TryLock() {
		return nil, ErrCapacity
	}
	if a.closed || a.running || a.active != nil {
		a.mu.Unlock()
		return nil, ErrCapacity
	}
	p := &sqliteDirectIssuePermit{owner: a, facts: facts, request: request.RequestID}
	p.ctx, p.cancel = context.WithTimeout(ctx, time.Duration(a.config.WorkMS)*time.Millisecond)
	a.active = p
	a.running = true
	a.mu.Unlock()
	defer func() {
		if err != nil {
			a.mu.Lock()
			p.closed = true
			p.cancel()
			a.mu.Unlock()
		}
		a.finishWork(p)
	}()
	p.window, err = timev4.NewWindow(a.config.Policy.Clock, a.config.WorkMS)
	if err != nil {
		return nil, err
	}
	if err = a.checkBase(p.ctx); err != nil {
		return nil, err
	}
	if err = a.policy.CheckFacts(facts); err != nil {
		return nil, err
	}
	p.access, err = a.config.Host.AuthorizeDirectIssue(p.ctx, a.store.identity, request, facts)
	if err != nil {
		return nil, err
	}
	if p.access == nil {
		return nil, ErrDenied
	}
	if _, err = io.ReadFull(rand.Reader, p.invocation[:]); err != nil || p.invocation == ([16]byte{}) {
		return nil, ErrConfiguration
	}
	p.keySize, err = (&admissionRecord{fields: protocolv4.AdmissionFields{Tenant: facts.Scope.Tenant, Issuer: facts.Scope.Issuer, Lease: facts.LeaseID}}).key(p.key[:])
	if err != nil {
		return nil, err
	}
	var cohort [41]byte
	n, err := a.policy.CopyCohortEvidence(facts, cohort[:])
	if err != nil {
		return nil, err
	}
	p.projectionSize, err = encodeDirectIssue(p.projection[:], a.store.identity, a.fence, p.request, p.invocation, facts, cohort[:n])
	if err != nil {
		return nil, err
	}
	s := a.store
	if err = s.begin(p.ctx); err != nil {
		return nil, err
	}
	defer s.end()
	err = s.writeTransaction(p.ctx, func() error { return p.guard(p.ctx) }, func() error {
		count, err := s.scalar("SELECT count(*) FROM issuance WHERE lease=?1 OR request=?2", named(1, p.key[:p.keySize]), named(2, p.request[:]))
		if err != nil {
			return err
		}
		if count != int64(0) {
			return ErrConflict
		}
		var rows, stateBytes int64
		var credit, last uint64
		err = s.readOne("SELECT rows,state_bytes,credit,last_upper FROM direct_issue_config WHERE id=1", 4, func(v []driver.Value) error {
			var ok, sok bool
			var ce, te error
			rows, ok = v[0].(int64)
			stateBytes, sok = v[1].(int64)
			credit, ce = readSQLiteUint(v[2])
			last, te = readSQLiteUint(v[3])
			if !ok || !sok || rows < 0 || rows > int64(a.config.MaxOutstanding) || stateBytes != int64(directIssueFixedStateBytes)+rows*int64(directIssuePerLeaseStateBytes) || credit > uint64(a.config.Burst)*60000 || ce != nil || te != nil {
				return ErrStorageFormat
			}
			return nil
		})
		if err != nil {
			return err
		}
		if rows >= int64(a.config.MaxOutstanding) || uint64(stateBytes)+directIssuePerLeaseStateBytes > a.config.StateBytes {
			return ErrCapacity
		}
		total, err := s.scalar("SELECT admission_rows+spend_rows+winner_rows+issuance_rows+relay_rows FROM manifest WHERE id=1")
		if err != nil {
			return err
		}
		actual, ok := total.(int64)
		if !ok || actual < 0 {
			return ErrStorageFormat
		}
		if actual >= int64(s.backing.limits.MaxRecords) {
			return ErrCapacity
		}
		now, err := a.config.Policy.Clock.Sample()
		if err != nil {
			return err
		}
		if now.LowerMS > last {
			elapsed := min(now.LowerMS-last, uint64(60000))
			credit = min(uint64(a.config.Burst)*60000, credit+elapsed*uint64(a.config.RequestsPerMinute))
		}
		if credit < 60000 {
			return ErrCapacity
		}
		credit -= 60000
		var empty [32]byte
		if err = s.exec("INSERT INTO issuance(lease,request,invocation,fence,state,version,artifact,projection) VALUES(?1,?2,?3,?4,0,?5,?6,?7)", named(1, p.key[:p.keySize]), named(2, p.request[:]), named(3, p.invocation[:]), named(4, sqliteUint(a.fence)), named(5, sqliteUint(1)), named(6, empty[:]), named(7, p.projection[:p.projectionSize])); err != nil {
			return err
		}
		if err = s.exec("UPDATE direct_issue_config SET rows=rows+1,state_bytes=state_bytes+?1,credit=?2,last_upper=?3 WHERE id=1", named(1, int64(directIssuePerLeaseStateBytes)), named(2, sqliteUint(credit)), named(3, sqliteUint(max(last, now.UpperMS)))); err != nil {
			return err
		}
		return s.exec("UPDATE manifest SET issuance_rows=issuance_rows+1 WHERE id=1")
	})
	if err != nil {
		return nil, err
	}
	if err = p.guard(p.ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// The same original lease obligation supports general Artifact issuance. Its
// immutable policy must already fix the complete actual dependency union;
// this entry does not infer or expand namespace permissions from request data.
func (a *SQLiteDirectIssueAuthority) BeginArtifactIssue(ctx context.Context, request protocolv4.ArtifactIssueRequest, facts protocolv4.ArtifactIssueFacts) (protocolv4.ArtifactIssuePermit, error) {
	return a.BeginDirectIssue(ctx, request, facts)
}

func (p *sqliteDirectIssuePermit) enter(ctx context.Context) error {
	if p == nil || p.owner == nil || ctx == nil {
		return ErrConfiguration
	}
	a := p.owner
	if !a.mu.TryLock() {
		return ErrCapacity
	}
	defer a.mu.Unlock()
	if a.closed || p.closed || p.cleaned || a.active != p {
		return ErrOwner
	}
	if a.running {
		return ErrCapacity
	}
	a.running = true
	return nil
}

func (p *sqliteDirectIssuePermit) checkRow() error {
	s := p.owner.store
	return s.readOne("SELECT invocation,fence,state,version,artifact,projection FROM issuance WHERE lease=?1 AND request=?2", 6, func(v []driver.Value) error {
		inv, ok := v[0].([]byte)
		fence, fe := readSQLiteUint(v[1])
		state, sok := v[2].(int64)
		version, ve := readSQLiteUint(v[3])
		digest, dok := v[4].([]byte)
		projection, pok := v[5].([]byte)
		expectedState := int64(0)
		expectedVersion := uint64(1)
		if p.committed {
			expectedState = 1
			expectedVersion = 2
		}
		if !ok || !bytes.Equal(inv, p.invocation[:]) || fe != nil || fence != p.owner.fence || !sok || state != expectedState || ve != nil || version != expectedVersion || !dok || !bytes.Equal(digest, p.digest[:]) || !pok || !bytes.Equal(projection, p.projection[:p.projectionSize]) {
			return ErrConflict
		}
		return nil
	}, named(1, p.key[:p.keySize]), named(2, p.request[:]))
}

func (p *sqliteDirectIssuePermit) Check(ctx context.Context) (err error) {
	if err = p.enter(ctx); err != nil {
		return err
	}
	defer p.owner.finishWork(p)
	if err = p.guard(ctx); err != nil {
		return err
	}
	s := p.owner.store
	if err = s.begin(ctx); err != nil {
		return err
	}
	defer s.end()
	if err = s.checkFence(); err != nil {
		return err
	}
	if err = p.checkRow(); err != nil {
		return err
	}
	return p.guard(ctx)
}

func (p *sqliteDirectIssuePermit) Commit(ctx context.Context, digest [32]byte) (err error) {
	if digest == ([32]byte{}) {
		return ErrConfiguration
	}
	if err = p.enter(ctx); err != nil {
		return err
	}
	defer p.owner.finishWork(p)
	if p.commitStarted {
		return ErrOwner
	}
	p.commitStarted = true
	if err = p.guard(ctx); err != nil {
		return err
	}
	s := p.owner.store
	if err = s.begin(ctx); err != nil {
		return err
	}
	defer s.end()
	err = s.writeTransaction(ctx, func() error { return p.guard(ctx) }, func() error {
		if err := p.checkRow(); err != nil {
			return err
		}
		if err := s.exec("UPDATE issuance SET state=1,version=?1,artifact=?2 WHERE lease=?3 AND request=?4 AND invocation=?5 AND fence=?6 AND state=0 AND version=?7 AND projection=?8", named(1, sqliteUint(2)), named(2, digest[:]), named(3, p.key[:p.keySize]), named(4, p.request[:]), named(5, p.invocation[:]), named(6, sqliteUint(p.owner.fence)), named(7, sqliteUint(1)), named(8, p.projection[:p.projectionSize])); err != nil {
			return err
		}
		return s.changedOne()
	})
	if err != nil {
		p.owner.mu.Lock()
		p.closed = true
		p.cancel()
		p.owner.mu.Unlock()
		return err
	}
	p.digest = digest
	p.committed = true
	return p.guard(ctx)
}

func (a *SQLiteDirectIssueAuthority) finishWork(p *sqliteDirectIssuePermit) {
	a.mu.Lock()
	if (a.closed || p.closed) && !p.cleaned {
		// Keep running set until actual host cleanup returns.
		p.cleaned = true
		p.cancel()
		access := p.access
		a.mu.Unlock()
		if access != nil {
			access.Close()
		}
		clear(p.projection[:])
		p.access = nil
		p.facts = protocolv4.DirectIssueFacts{}
		p.ctx, p.cancel, p.window = nil, nil, nil
		a.mu.Lock()
		a.active = nil
	}
	a.running = false
	if a.closed && a.active == nil {
		a.cleanupLocked()
	}
	a.mu.Unlock()
}

func (p *sqliteDirectIssuePermit) Close() {
	if p == nil || p.owner == nil {
		return
	}
	a := p.owner
	a.mu.Lock()
	if p.cleaned {
		a.mu.Unlock()
		return
	}
	p.closed = true
	p.cancel()
	run := !a.running
	if run {
		a.running = true
	}
	a.mu.Unlock()
	if run {
		a.finishWork(p)
	}
}

func (a *SQLiteDirectIssueAuthority) cleanupLocked() {
	if a.cleaned {
		return
	}
	a.cleaned = true
	clear(a.configuration[:])
	a.trustRef.Release()
	a.storeRef.Release()
	a.shared.Release()
	a.reservation.Release()
	a.policy = nil
	a.config = SQLiteDirectIssueConfig{}
	a.store = nil
	a.trustRef, a.storeRef, a.shared, a.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	close(a.done)
}

func (a *SQLiteDirectIssueAuthority) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	p := a.active
	if p != nil && !p.cleaned {
		p.closed = true
		p.cancel()
	}
	run := !a.running && p != nil
	if run {
		a.running = true
	}
	if p == nil && !a.running {
		a.cleanupLocked()
	}
	a.mu.Unlock()
	if run {
		a.finishWork(p)
	}
}

func (a *SQLiteDirectIssueAuthority) WaitCleanup(ctx context.Context) error {
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

// Status observes the shared durable responsibility, including reservations
// whose signing or delivery failed. It cannot recreate an original permit.
func (a *SQLiteDirectIssueAuthority) Status(ctx context.Context) (status SQLiteDirectIssueStatus, err error) {
	if a == nil || ctx == nil {
		return status, ErrConfiguration
	}
	if !a.mu.TryLock() {
		return status, ErrCapacity
	}
	if a.closed || a.running || a.active != nil {
		a.mu.Unlock()
		return status, ErrCapacity
	}
	a.running = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.running = false
		if a.closed {
			a.cleanupLocked()
		}
		a.mu.Unlock()
	}()
	if err = a.checkBase(ctx); err != nil {
		return status, err
	}
	s := a.store
	if err = s.begin(ctx); err != nil {
		return status, err
	}
	defer s.end()
	if err = s.checkFence(); err != nil {
		return status, err
	}
	err = s.readOne("SELECT rows,state_bytes,(SELECT issuance_rows FROM manifest WHERE id=1) FROM direct_issue_config WHERE id=1", 3, func(v []driver.Value) error {
		rows, ok := v[0].(int64)
		size, sok := v[1].(int64)
		if !ok || !sok || rows < 0 || rows > int64(a.config.MaxOutstanding) || size != int64(directIssueFixedStateBytes)+rows*int64(directIssuePerLeaseStateBytes) || uint64(size) > a.config.StateBytes {
			return ErrStorageFormat
		}
		total, tok := v[2].(int64)
		if !tok || total < rows || total > int64(s.backing.limits.MaxRecords) {
			return ErrStorageFormat
		}
		status = SQLiteDirectIssueStatus{Outstanding: uint32(rows), ReservedStateBytes: uint64(size), RetainedRequests: uint32(total)}
		return nil
	})
	if err != nil {
		return SQLiteDirectIssueStatus{}, err
	}
	if err = a.checkBase(ctx); err != nil {
		return SQLiteDirectIssueStatus{}, err
	}
	return status, nil
}

func (*SQLiteDirectIssueAuthority) String() string   { return "SQLiteDirectIssueAuthority(<redacted>)" }
func (*SQLiteDirectIssueAuthority) GoString() string { return "SQLiteDirectIssueAuthority(<redacted>)" }

func encodeDirectIssue(dst []byte, identity SQLiteIdentity, fence uint64, request [32]byte, invocation [16]byte, f protocolv4.DirectIssueFacts, cohort []byte) (int, error) {
	w := admissionWriter{dst: dst}
	w.text("flowersec/direct-issue/1")
	for _, v := range []uint64{identity.Generation, fence, f.Scope.Generation, f.Scope.Cohort, f.Scope.IssuedMS, f.InitiationNotAfterMS, f.Scope.ExpiresMS, f.RevocationPolicyRevision} {
		w.uint(v)
	}
	for _, v := range []string{identity.Authority, f.Scope.Tenant, f.Scope.Authority, f.Scope.Audience, f.Scope.Profile, f.RevocationPolicyID} {
		w.text(v)
	}
	for _, v := range [][]byte{identity.StoreID[:], request[:], invocation[:], f.Scope.CapacityDigest[:], f.Scope.Issuer[:], f.LeaseID[:], f.ClientIdentity[:], f.ServerIdentity[:]} {
		w.bytes(v)
	}
	w.uint(uint64(len(cohort)))
	w.bytes(cohort)
	return w.n, w.err
}
