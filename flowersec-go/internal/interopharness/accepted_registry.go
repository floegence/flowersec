package interopharness

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"math"
	"net"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// AcceptedRegistry is a finite trusted material index. Peer HELLO selects only
// a once-owned installed record; it cannot create material, policy or authority.
// Original normal verification and durable admission follow every lookup.
type AcceptedRegistry struct {
	mu       sync.Mutex
	capacity int
	records  []*AcceptedRecord
	// Physical acceptance positions already bound the waiting callbacks. The
	// original SQLite connection admits only one transaction owner at a time.
	admissionGate chan struct{}
}
type AcceptedRecord struct {
	Authority                    *sessionv4.PublicQUICTestHarness
	original                     ledgerv4.SQLiteAdmissionAuthority
	registry                     *AcceptedRegistry
	runtime                      *Runtime
	session                      *fs.Session
	ready                        chan struct{}
	acceptErr                    error
	withdrawn                    chan struct{}
	claimed, completed, canceled bool
	closeOnce                    sync.Once
	closeErr                     error
}

func NewAcceptedRegistry(capacity int) (*AcceptedRegistry, error) {
	if capacity < 1 || capacity > 4096 {
		return nil, errors.New("invalid accepted material capacity")
	}
	return &AcceptedRegistry{capacity: capacity, records: make([]*AcceptedRecord, 0, capacity), admissionGate: make(chan struct{}, 1)}, nil
}
func (r *AcceptedRegistry) Install(authority *sessionv4.PublicQUICTestHarness) (*AcceptedRecord, error) {
	if authority == nil {
		return nil, errors.New("original signed material is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.records) == r.capacity {
		return nil, errors.New("accepted material registry is full")
	}
	for _, record := range r.records {
		if record.Authority.ArtifactDigest == authority.ArtifactDigest {
			return nil, errors.New("original material is already installed")
		}
	}
	record := &AcceptedRecord{Authority: authority, original: authority.Authority, registry: r, ready: make(chan struct{}), withdrawn: make(chan struct{})}
	r.records = append(r.records, record)
	return record, nil
}
func (r *AcceptedRecord) WaitSession(ctx context.Context) (*fs.Session, error) {
	if r == nil || ctx == nil {
		return nil, errors.New("original accepted record and context are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	select {
	case <-r.ready:
		r.registry.mu.Lock()
		canceled, session, err := r.canceled, r.session, r.acceptErr
		r.registry.mu.Unlock()
		if canceled {
			return nil, errors.New("original accepted material was withdrawn")
		}
		return session, err
	case <-r.withdrawn:
		return nil, errors.New("original accepted material was withdrawn")
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}
func (r *AcceptedRecord) Claimed() bool {
	if r == nil {
		return false
	}
	r.registry.mu.Lock()
	defer r.registry.mu.Unlock()
	return r.claimed
}

// Close withdraws every still-owned record and joins each accepted runtime.
// The registry is a second owner beside the listener reporter; closing the
// listener alone cannot retire material that was issued but never claimed.
func (r *AcceptedRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	records := append([]*AcceptedRecord(nil), r.records...)
	r.mu.Unlock()
	var joined error
	for _, record := range records {
		joined = errors.Join(joined, record.Close())
	}
	return joined
}

func (r *AcceptedRegistry) PendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, record := range r.records {
		if !record.claimed && !record.canceled {
			count++
		}
	}
	return count
}
func (r *AcceptedRegistry) Source(runtime *Runtime) *AcceptedRegistrySource {
	pool, _ := runtime.Authority.Authority.(ledgerv4.SQLitePoolAdmissionAuthority)
	return &AcceptedRegistrySource{registry: r, runtime: runtime, pool: pool}
}

type AcceptedRegistrySource struct {
	mu        sync.Mutex
	registry  *AcceptedRegistry
	runtime   *Runtime
	selected  *AcceptedRecord
	pool      ledgerv4.SQLitePoolAdmissionAuthority
	scheduler *Server
}

func (s *AcceptedRegistrySource) ResolveAcceptedMaterial(ctx context.Context, hello []byte) (*fs.ConnectionMaterial, fs.InitialHello, error) {
	if err := ctx.Err(); err != nil {
		return nil, fs.InitialHello{}, err
	}
	decoder, err := protocolv4.NewInitialDecoder(16384, 1024)
	if err != nil {
		return nil, fs.InitialHello{}, err
	}
	document, err := decoder.DecodeShape(hello, "ClientHello", protocolv4.DecodeContext{})
	if err != nil {
		return nil, fs.InitialHello{}, err
	}
	defer document.Release()
	digest, _ := document.Root().Named("ClientHello", "artifact_digest").ByteString()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selected != nil {
		return nil, fs.InitialHello{}, errors.New("original accepted position was already selected")
	}
	s.registry.mu.Lock()
	var selected *AcceptedRecord
	for _, record := range s.registry.records {
		if !record.claimed && !record.canceled && bytes.Equal(digest, record.Authority.ArtifactDigest[:]) {
			record.claimed = true
			record.runtime = s.runtime
			selected = record
			break
		}
	}
	s.registry.mu.Unlock()
	if selected == nil {
		return nil, fs.InitialHello{}, errors.New("unknown or already claimed signed material")
	}
	s.selected = selected
	authority := selected.Authority
	material, err := s.runtime.admitAcceptedMaterial(authority.Lease, authority.Identity[1], authority.Generation)
	return material, authority.Hello, err
}

func (s *AcceptedRegistrySource) ScheduleAdmission(ctx context.Context) (func(), error) {
	if s.scheduler == nil {
		return func() {}, nil
	}
	if err := s.scheduler.acquireAdmission(ctx); err != nil {
		return nil, err
	}
	return s.scheduler.releaseAdmission, nil
}
func (s *AcceptedRegistrySource) CheckAdmission(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	s.mu.Lock()
	selected := s.selected
	s.mu.Unlock()
	if selected == nil {
		return ledgerv4.ErrFenced
	}
	s.registry.mu.Lock()
	canceled := selected.canceled
	s.registry.mu.Unlock()
	if canceled {
		return ledgerv4.ErrFenced
	}
	return selected.original.CheckAdmission(identity, facts)
}

// The accepting host owns winner persistence; detached issuance contributes
// only its immutable signed authority facts.
func (s *AcceptedRegistrySource) ParentWinnerStore() *ledgerv4.SQLiteStore {
	if s.pool == nil {
		return nil
	}
	return s.pool.ParentWinnerStore()
}
func (s *AcceptedRegistrySource) CheckParentWinner(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	s.mu.Lock()
	selected := s.selected
	s.mu.Unlock()
	if selected == nil {
		return ledgerv4.ErrFenced
	}
	s.registry.mu.Lock()
	canceled := selected.canceled
	s.registry.mu.Unlock()
	if canceled {
		return ledgerv4.ErrFenced
	}
	pool, ok := selected.original.(ledgerv4.SQLitePoolAdmissionAuthority)
	if !ok {
		return ledgerv4.ErrConfiguration
	}
	return pool.CheckParentWinner(identity, facts)
}

func (s *AcceptedRegistrySource) Deliver(_ *Server, session *fs.Session, err error) {
	s.mu.Lock()
	selected := s.selected
	s.mu.Unlock()
	if selected == nil {
		if session != nil {
			s.closeUndelivered(session)
		}
		return
	}
	s.registry.mu.Lock()
	if selected.completed || selected.canceled {
		original := selected.session
		s.registry.mu.Unlock()
		if session != nil && session != original {
			s.closeUndelivered(session)
		}
		return
	}
	selected.completed = true
	selected.session = session
	selected.acceptErr = err
	close(selected.ready)
	s.registry.mu.Unlock()
}

// An acceptance callback may finish after its record is withdrawn. Join the
// actual Session cleanup before releasing that callback's ownership.
func (s *AcceptedRegistrySource) closeUndelivered(session *fs.Session) {
	err := session.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = errors.Join(err, session.WaitCleanup(ctx))
	cancel()
	s.runtime.Reporter.ErrorIf(err)
}

// forkAcceptedAuthority captures one original position beneath the listener.
// All position allocations retire with its own reporter, including failures
// before a native entrance or Session is installed.
func (s *Server) forkAcceptedAuthority() (*Reporter, *sessionv4.PublicQUICTestHarness, error) {
	reporter, err := s.Runtime.Reporter.ForkAuthority()
	if err != nil {
		return nil, nil, err
	}
	if reporter.Capacity != nil {
		// This accepted position owns one Environment and borrows the original
		// host executor/root. Closing it must not close those shared owners.
		capacity := *reporter.Capacity
		capacity.Sessions, capacity.Materials, capacity.Parents, capacity.Legs = 1, 1, 0, 0
		reporter.Capacity = &capacity
	}
	h := *s.Runtime.Authority
	deadline, err := timev4.NewAge(h.Clock, reporter.operationMS(10000), math.MaxUint64)
	if err != nil {
		return nil, nil, errors.Join(err, reporter.Close())
	}
	h.Admission[1].Initial.Deadline = deadline
	h.Reserve = func(v resourcev4.Vector, accounts ...resourcev4.Account) resourcev4.Reference {
		reference, err := h.Root.Reserve(h.Owner(), v, accounts...)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(reference.Release)
		return reference
	}
	var sessionID [16]byte
	if _, err = rand.Read(sessionID[:]); err != nil {
		return nil, nil, errors.Join(err, reporter.Close())
	}
	limit := h.SessionLimit
	if limit == (resourcev4.Vector{}) {
		limit = h.Root.Snapshot().Limit
	}
	limit[resourcev4.Sessions] = 1
	scope, err := h.Root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: sessionID}, limit)
	if err != nil {
		return nil, nil, errors.Join(err, reporter.Close())
	}
	reporter.Cleanup(scope.Close)
	h.Scope[1].Session = scope
	return reporter, &h, nil
}

func (s *Server) NewAcceptedPosition(registry *AcceptedRegistry, handlers HandlerConfig) (result *Server, err error) {
	if registry == nil {
		return nil, errors.New("original bounded material registry is required")
	}
	reporter, h, err := s.forkAcceptedAuthority()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, reporter.Close())
		}
	}()
	runtime := &Runtime{Reporter: reporter, Authority: h, Role: 1, Executor: s.Runtime.Executor}
	reporter.Owner(runtime.CloseOwners, runtime.WaitOwners)
	err = runtime.initialize(s.context, []uint8{1}, handlers)
	if err != nil {
		return nil, err
	}
	source := registry.Source(runtime)
	h.Authority = source
	position := &Server{Runtime: runtime, Carrier: s.Carrier, Origin: s.Origin, TrustPEM: s.TrustPEM, Address: s.Address, Namespace: s.Namespace, certificate: s.certificate, roots: s.roots, context: s.context, onTransportError: s.onTransportError, positionOnly: true, admissionGate: registry.admissionGate, results: make(chan SessionResult, 2), acceptedSource: source, onSession: source.Deliver}
	source.scheduler = position
	if err = position.startTransport(reporter); err != nil {
		return nil, err
	}
	return position, nil
}

// Close withdraws an unused record or closes its actual Session and waits for
// the original position's cleanup. Removing an entry never unspends its lease;
// the original SQLite store retains that once-only decision.
func (r *AcceptedRecord) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		registry := r.registry
		registry.mu.Lock()
		r.canceled = true
		close(r.withdrawn)
		for index, entry := range registry.records {
			if entry == r {
				copy(registry.records[index:], registry.records[index+1:])
				last := len(registry.records) - 1
				registry.records[last] = nil
				registry.records = registry.records[:last]
				break
			}
		}
		session, runtime := r.session, r.runtime
		registry.mu.Unlock()
		closedAndCleaned := false
		if session != nil {
			closeErr := session.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cause := session.WaitTermination(ctx)
			observed := ctx.Err() == nil
			cleanupErr := session.WaitCleanup(ctx)
			closedAndCleaned = observed && filterAcceptedClosedErrors(cause) == nil && session.CleanupStatus().Complete
			if closedAndCleaned {
				closeErr = filterAcceptedClosedErrors(closeErr)
			}
			r.closeErr = errors.Join(r.closeErr, closeErr, cleanupErr)
			if !observed {
				r.closeErr = errors.Join(r.closeErr, cause)
			}
			cancel()
		}
		if runtime != nil {
			cleanupErr := runtime.Reporter.Close()
			if closedAndCleaned {
				cleanupErr = filterAcceptedClosedErrors(cleanupErr)
			}
			r.closeErr = errors.Join(r.closeErr, cleanupErr)
		}
	})
	return r.closeErr
}

// These errors retire only under this record's observed terminal and physical
// cleanup facts. Connection interruption and protocol failures remain visible.
func filterAcceptedClosedErrors(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var remaining error
		for _, child := range joined.Unwrap() {
			remaining = errors.Join(remaining, filterAcceptedClosedErrors(child))
		}
		return remaining
	}
	if failure, ok := err.(*fs.SessionError); ok && failure.Code() == fs.SessionClosed {
		return nil
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok && wrapped.Unwrap() != nil {
		if filterAcceptedClosedErrors(wrapped.Unwrap()) == nil {
			return nil
		}
		return err
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, cryptov4.ErrClosed) || errors.Is(err, resourcev4.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) retireUnused() {
	if !s.positionOnly {
		return
	}
	source, ok := s.acceptedSource.(*AcceptedRegistrySource)
	if !ok {
		return
	}
	source.mu.Lock()
	selected := source.selected
	source.mu.Unlock()
	if selected == nil {
		s.Runtime.Reporter.ErrorIf(s.Runtime.Reporter.Close())
	}
}

func (r *AcceptedRecord) IsSession(session *fs.Session) bool {
	if r == nil || session == nil {
		return false
	}
	r.registry.mu.Lock()
	defer r.registry.mu.Unlock()
	return r.session == session && r.completed && !r.canceled
}

func (r *AcceptedRecord) Runtime() *Runtime {
	if r == nil {
		return nil
	}
	r.registry.mu.Lock()
	defer r.registry.mu.Unlock()
	return r.runtime
}
