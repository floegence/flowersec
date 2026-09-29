package ledgerv4

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

const liveSpendRetentionMS uint64 = 7 * 24 * 60 * 60 * 1000

// LiveSpendRetirement identifies the complete original consumed responsibility.
// Proof bytes are borrowed only during the trusted local retirement check.
type LiveSpendRetirement struct {
	Tenant, Audience                          string
	Issuer, Lease, Attempt                    [16]byte
	Artifact, ClientIdentity, RequestDigest   [32]byte
	ParentInitiationEndMS, ParentSessionEndMS uint64
	TerminalAtMS, MaterialNotAfterMS          uint64
	Outcome                                   AuthorizationOutcome
}

// LiveSpendRetirementPolicy is an independently configured nonblocking gate.
// It must prove audit, signer/delegation and all actual material references no
// longer require this row. Time eligibility alone never supplies that proof.
// Implementations may conservatively retain any row. No default permits GC.
type LiveSpendRetirementPolicy interface {
	CanRetireLiveSpend(SQLiteIdentity, LiveSpendRetirement, []byte) (bool, error)
}

type LiveMaintenanceConfig struct {
	BatchRows    uint32
	RuntimeBytes uint64
	Retirement   LiveSpendRetirementPolicy
}

type LiveMaintenanceStatus struct {
	Scanned, Recovered, Removed uint64
	RecoveryLagMS               uint64
	RecoveryLagAlert            bool
	Unavailable, Closed         bool
}

// SQLiteLiveMaintenance owns one keyset scan, two bounded row buffers, one
// worker and a separately admitted batch cancellation observer. It never
// invokes policy authorization, signs, dispatches or
// publishes connection material. A complete failed batch keeps its cursor so
// repeating it cannot create new original work or skip an unconfirmed row.
type SQLiteLiveMaintenance struct {
	mu                                        sync.Mutex
	store                                     *sqliteStore
	clock                                     *timev4.Clock
	config                                    LiveMaintenanceConfig
	reservation, dependencies, storeReference resourcev4.Reference
	ctx, call                                 *ledgerTaskContext
	window                                    *timev4.Window
	last, key                                 [admissionKeyBytes]byte
	lastSize, keySize                         int
	row, output                               []byte
	sweepLag                                  uint64
	status                                    LiveMaintenanceStatus
	active, started, worker, closed, cleaned  bool
}

func SQLiteLiveMaintenanceCharge(maxRecordBytes uint32, c LiveMaintenanceConfig) (resourcev4.Vector, error) {
	if c.BatchRows == 0 || c.BatchRows > 128 || c.RuntimeBytes == 0 || c.RuntimeBytes > math.MaxUint64/2 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	if _, _, err := SQLiteLiveSpendCharges(maxRecordBytes); err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteLiveMaintenance{})) + 2*uint64(maxRecordBytes) + uint64(unsafe.Sizeof(timev4.Window{})) + 2*ledgerTaskContextBytes, resourcev4.Items: 7, resourcev4.WorkSlots: 2, resourcev4.Tasks: 2, resourcev4.Timers: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: 2 * c.RuntimeBytes})
}

func NewSQLiteLiveMaintenance(ctx context.Context, store *SQLiteStore, clock *timev4.Clock, c LiveMaintenanceConfig, reservation, dependencies resourcev4.Reference) (*SQLiteLiveMaintenance, error) {
	if ctx == nil || clock == nil {
		return nil, ErrConfiguration
	}
	if err := reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	ref, _, _, limit, err := store.admissionReference(dependencies)
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			ref.Release()
		}
	}()
	cost, err := SQLiteLiveMaintenanceCharge(limit, c)
	if err != nil {
		return nil, err
	}
	dep, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			dep.Release()
		}
	}()
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			owned.Release()
		}
	}()
	call := newLedgerTaskContext(ctx)
	defer func() {
		if !adopted {
			call.cancel(ErrOwner)
		}
	}()
	if err := call.Err(); err != nil {
		return nil, err
	}
	m := &SQLiteLiveMaintenance{store: store.sqliteStore, clock: clock, config: c, reservation: owned, dependencies: dep, storeReference: ref, ctx: call, row: make([]byte, limit), output: make([]byte, limit)}
	adopted = true
	return m, nil
}

func (m *SQLiteLiveMaintenance) check() error {
	// The admitted batch retains window and buffers while this trusted clock
	// callback runs. Close and Status never wait behind that adapter.
	m.mu.Lock()
	window := m.window
	err := m.checkLocalLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if window != nil {
		if err := window.Check(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.checkLocalLocked()
}

func (m *SQLiteLiveMaintenance) checkLocalLocked() error {
	if m.closed {
		return ErrOwner
	}
	if err := m.ctx.Err(); err != nil {
		return err
	}
	if m.call != nil {
		if err := m.call.Err(); err != nil {
			return err
		}
	}
	for _, ref := range []resourcev4.Reference{m.reservation, m.dependencies, m.storeReference} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (m *SQLiteLiveMaintenance) RunBatch(ctx context.Context) (LiveMaintenanceStatus, error) {
	return m.runBatch(ctx, false)
}

func (m *SQLiteLiveMaintenance) runBatch(ctx context.Context, worker bool) (status LiveMaintenanceStatus, err error) {
	if m == nil || ctx == nil {
		return LiveMaintenanceStatus{}, ErrConfiguration
	}
	m.mu.Lock()
	if m.closed || m.active || m.worker != worker {
		status := m.status
		m.mu.Unlock()
		return status, ErrCapacity
	}
	m.active = true
	m.mu.Unlock()
	var call *ledgerTaskContext
	observing, returned := false, false
	defer func() {
		if !returned {
			err = ErrOwner
		}
		if observing {
			close(call.stop)
			<-call.exited
		}
		if call != nil {
			call.cancel(ErrOwner)
		}
		m.mu.Lock()
		clear(m.row)
		clear(m.output)
		clear(m.key[:])
		m.active, m.window, m.call = false, nil, nil
		m.status.Unavailable = err != nil
		status = m.status
		status.Closed = m.closed
		m.mu.Unlock()
	}()
	call = newLedgerTaskContext(ctx)
	call.owner = m.ctx
	m.mu.Lock()
	m.call = call
	err = m.checkLocalLocked()
	m.mu.Unlock()
	if err != nil {
		returned = true
		return m.Status(), err
	}
	window, err := timev4.NewWindow(m.clock, 2000)
	if err != nil {
		returned = true
		return m.Status(), err
	}
	m.mu.Lock()
	m.window = window
	m.mu.Unlock()
	go call.observe(window, nil, timev4.Mark{})
	observing = true
	err = m.scanBatch(call)
	returned = true
	return m.Status(), err
}

func (m *SQLiteLiveMaintenance) scanBatch(ctx context.Context) (err error) {
	for range m.config.BatchRows {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = m.check(); err != nil {
			return err
		}
		var found bool
		found, err = m.scanOne(ctx)
		if err != nil {
			return err
		}
		if !found {
			clear(m.last[:])
			m.lastSize = 0
			m.mu.Lock()
			m.status.RecoveryLagMS = m.sweepLag
			m.status.RecoveryLagAlert = m.sweepLag > 5*60*1000
			m.sweepLag = 0
			m.mu.Unlock()
			return nil
		}
		m.lastSize = copy(m.last[:], m.key[:m.keySize])
	}
	return nil
}

func (m *SQLiteLiveMaintenance) scanOne(ctx context.Context) (found bool, err error) {
	s := m.store
	if err = s.begin(ctx); err != nil {
		return false, err
	}
	defer s.end()
	if err = s.checkFence(); err != nil {
		return false, err
	}
	rows, err := s.querier.QueryContext(ctx, "SELECT lease FROM spend WHERE source=0 AND lease>?1 ORDER BY lease LIMIT 1", []driver.NamedValue{named(1, m.last[:m.lastSize])})
	if err != nil {
		return false, err
	}
	var value [1]driver.Value
	err = rows.Next(value[:])
	if err == io.EOF {
		return false, rows.Close()
	}
	if err != nil {
		return false, errors.Join(err, rows.Close())
	}
	key, ok := value[0].([]byte)
	if !ok || len(key) < 34 || len(key) > len(m.key) {
		_ = rows.Close()
		return false, ErrStorageFormat
	}
	m.keySize = copy(m.key[:], key)
	if err = rows.Close(); err != nil {
		return false, err
	}
	v, err := s.readLiveSpend(m.key[:m.keySize], m.row)
	if err != nil {
		return false, err
	}
	if !v.found {
		return false, ErrConflict
	}
	now, err := m.clock.Sample()
	if err != nil {
		return false, err
	}
	if err = m.check(); err != nil {
		return false, err
	}
	recovered, removed := false, false
	lag := uint64(0)
	if !v.consumed && now.LowerMS >= v.claimEnd {
		lag = now.LowerMS - v.claimEnd
		n, encodeErr := encodeLiveConsumed(m.output, v.spending, nil, s.epoch, 0, now.UpperMS)
		if encodeErr != nil {
			return false, encodeErr
		}
		err = s.writeTransaction(ctx, m.check, func() error {
			if err := s.exec("UPDATE spend SET state=1,version=?1,fence=?2,projection=?3 WHERE lease=?4 AND source=0 AND state=0 AND version=?5 AND fence=?6 AND projection=?7", named(1, sqliteUint(2)), named(2, sqliteUint(s.epoch)), named(3, m.output[:n]), named(4, m.key[:m.keySize]), named(5, sqliteUint(1)), named(6, sqliteUint(v.originalFence)), named(7, v.spending)); err != nil {
				return err
			}
			return s.changedOne()
		})
		if err != nil {
			return false, err
		}
		recovered = true
	} else if v.consumed && m.config.Retirement != nil {
		base := max(v.parentInitiationEnd, v.terminalAt)
		if base <= math.MaxUint64-liveSpendRetentionMS && now.LowerMS >= max(base+liveSpendRetentionMS, v.parentSessionEnd, v.materialEnd) {
			retirement := LiveSpendRetirement{Tenant: v.tenant, Audience: v.audience, Issuer: v.issuer, Lease: v.lease, Attempt: v.attempt, Artifact: v.artifact, ClientIdentity: v.client, RequestDigest: v.request, ParentInitiationEndMS: v.parentInitiationEnd, ParentSessionEndMS: v.parentSessionEnd, TerminalAtMS: v.terminalAt, MaterialNotAfterMS: v.materialEnd, Outcome: liveSpendReceipt(v).AuthorizationOutcome}
			eligible := func() error {
				if err := m.check(); err != nil {
					return err
				}
				allowed, err := m.config.Retirement.CanRetireLiveSpend(s.identity, retirement, v.proof)
				if err != nil {
					return err
				}
				if !allowed {
					return ErrCapacity
				}
				return nil
			}
			if err = eligible(); err == ErrCapacity {
				err = nil
			} else if err == nil {
				err = s.writeTransaction(ctx, eligible, func() error {
					if err := s.exec("DELETE FROM spend WHERE lease=?1 AND source=0 AND state=1 AND version=?2 AND fence=?3", named(1, m.key[:m.keySize]), named(2, sqliteUint(v.version)), named(3, sqliteUint(v.fence))); err != nil {
						return err
					}
					if err := s.changedOne(); err != nil {
						return err
					}
					if err := s.exec("UPDATE manifest SET spend_rows=spend_rows-1 WHERE id=1 AND spend_rows>0"); err != nil {
						return err
					}
					return s.changedOne()
				})
				removed = err == nil
			}
			if err != nil {
				return false, err
			}
		}
	}
	m.mu.Lock()
	if m.status.Scanned < math.MaxUint64 {
		m.status.Scanned++
	}
	if recovered && m.status.Recovered < math.MaxUint64 {
		m.status.Recovered++
	}
	if removed && m.status.Removed < math.MaxUint64 {
		m.status.Removed++
	}
	m.sweepLag = max(m.sweepLag, lag)
	m.status.RecoveryLagMS = max(m.status.RecoveryLagMS, m.sweepLag)
	m.status.RecoveryLagAlert = m.status.RecoveryLagMS > 5*60*1000
	m.mu.Unlock()
	return true, nil
}

// Run keeps one actual worker. Its one-second scan interval backs off to at
// most sixty seconds after failure; neither timer nor retry creates a new
// authority invocation. Close requests cancellation and Cleanup joins reality.
func (m *SQLiteLiveMaintenance) Run(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrConfiguration
	}
	m.mu.Lock()
	if m.closed || m.started || m.active {
		m.mu.Unlock()
		return ErrOwner
	}
	m.started, m.worker = true, true
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.worker = false; m.mu.Unlock() }()
	// Snapshot the caller's methods once on this already admitted worker.
	// The lifetime context is SDK-owned; no implicit forwarding task exists.
	callerDeadline, hasDeadline := ctx.Deadline()
	callerDone := ctx.Done()
	if err := ctx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			return context.DeadlineExceeded
		}
		return context.Canceled
	}
	delay := time.Second
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-callerDone:
			if hasDeadline && !time.Now().Before(callerDeadline) {
				return context.DeadlineExceeded
			}
			return context.Canceled
		case <-m.ctx.Done():
			return m.ctx.Err()
		case <-m.ctx.parentDone:
			return m.ctx.Err()
		case <-timer.C:
		}
		if hasDeadline && !time.Now().Before(callerDeadline) {
			return context.DeadlineExceeded
		}
		if err := m.ctx.Err(); err != nil {
			return err
		}
		_, err := m.runBatch(ctx, true)
		if err == nil {
			delay = time.Second
		} else {
			delay = min(60*time.Second, 2*delay)
		}
		timer.Reset(delay)
	}
}

func (m *SQLiteLiveMaintenance) Status() LiveMaintenanceStatus {
	if m == nil {
		return LiveMaintenanceStatus{Closed: true, Unavailable: true}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.status
	status.Closed = m.closed
	return status
}

func (m *SQLiteLiveMaintenance) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		m.ctx.cancel(ErrOwner)
		if m.call != nil {
			m.call.cancel(ErrOwner)
		}
		m.reservation.Seal()
	}
}

func (m *SQLiteLiveMaintenance) Cleanup() error {
	if m == nil {
		return ErrConfiguration
	}
	m.Close()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cleaned {
		return nil
	}
	if m.active || m.worker {
		return ErrCapacity
	}
	clear(m.row)
	clear(m.output)
	clear(m.key[:])
	clear(m.last[:])
	m.row, m.output, m.store, m.clock, m.config.Retirement = nil, nil, nil, nil, nil
	m.storeReference.Release()
	m.dependencies.Release()
	m.reservation.Release()
	m.cleaned = true
	return nil
}
