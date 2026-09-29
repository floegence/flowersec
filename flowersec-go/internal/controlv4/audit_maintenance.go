package controlv4

import (
	"context"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type AuditMaintenanceConfig struct {
	Source                                  *ledgerv4.SQLiteTopUpServer
	Archive                                 *ledgerv4.SQLiteAuditArchive
	SourceAccess, ArchiveAccess             ledgerv4.AuditAccess
	Clock                                   *timev4.Clock
	ExportEveryMS, RetentionEveryMS, CallMS uint64
	RuntimeBytes, RuntimeBytesPerTask       uint64
}

// AuditMaintenance owns three original maintenance workers: export, source
// retention and destination retention. Each has one scheduling timer, one
// synchronous operation and one admitted deadline/cancellation observer.
// Blocking storage never spawns replacement tasks or shares another
// worker's position. Store concurrency/rate gates still apply independently.
type AuditMaintenance struct {
	mu                        sync.Mutex
	config                    AuditMaintenanceConfig
	reservation, dependencies resourcev4.Reference
	binding                   *ledgerv4.AuditMaintenanceBinding
	retention                 uint64
	ctx                       context.Context
	cancel                    context.CancelFunc
	done                      chan struct{}
	remaining                 uint8
	state                     AuditMaintenanceSnapshot
}

type AuditMaintenanceSnapshot struct {
	ExportRunning, SourceRetentionRunning, ArchiveRetentionRunning bool
	ExportCalls, ExportFailures, PagesPersisted, PagesAcknowledged uint64
	SourceRetentionCalls, SourceRetentionFailures                  uint64
	ArchiveRetentionCalls, ArchiveRetentionFailures                uint64
	LastExport, LastSourceRetention, LastArchiveRetention          string
	Closed, CleanupComplete                                        bool
}

func AuditMaintenanceCharge(c AuditMaintenanceConfig) (resourcev4.Vector, error) {
	if c.Source == nil || c.Archive == nil || c.SourceAccess == nil || c.ArchiveAccess == nil || c.Clock == nil || c.ExportEveryMS < 2000 || c.ExportEveryMS > 60000 || c.RetentionEveryMS < 1000 || c.RetentionEveryMS > 60000 || c.CallMS == 0 || c.CallMS > 10000 || c.RuntimeBytes == 0 || c.RuntimeBytesPerTask == 0 || c.RuntimeBytesPerTask > math.MaxUint64/3 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	base, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(AuditMaintenance{})) + 3*controlCallContextBytes + ledgerv4.AuditMaintenanceBindingBytes(), resourcev4.Items: 1, resourcev4.Tasks: 6, resourcev4.WorkSlots: 3, resourcev4.Timers: 6}).Add(resourcev4.Vector{resourcev4.SDKBytes: 3 * c.RuntimeBytesPerTask})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	base, err = base.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	return base, err
}

func NewAuditMaintenance(c AuditMaintenanceConfig, reservation, dependencies resourcev4.Reference) (*AuditMaintenance, error) {
	cost, err := AuditMaintenanceCharge(c)
	if err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		shared.Release()
		return nil, err
	}
	adopted := false
	var binding *ledgerv4.AuditMaintenanceBinding
	defer func() {
		if !adopted {
			if binding != nil {
				binding.Release()
			}
			shared.Release()
			owned.Release()
		}
	}()
	var retention uint64
	binding, retention, err = c.Archive.BindMaintenance(owned, c.Clock, c.Source, c.ArchiveAccess, c.SourceAccess)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &AuditMaintenance{config: c, reservation: owned, dependencies: shared, binding: binding, retention: retention, ctx: ctx, cancel: cancel, done: make(chan struct{}), remaining: 3,
		state: AuditMaintenanceSnapshot{LastExport: "not_started", LastSourceRetention: "not_started", LastArchiveRetention: "not_started"}}
	adopted = true
	for lane := uint8(0); lane < 3; lane++ {
		go p.run(lane)
	}
	return p, nil
}

type auditExportCursor struct {
	query  ledgerv4.AuditQuery
	until  uint64
	active bool
}

func (p *AuditMaintenance) export(ctx context.Context, cursor *auditExportCursor) (ledgerv4.AuditTransferResult, error) {
	c := p.config
	if !cursor.active {
		now, err := c.Clock.Sample()
		if err != nil || now.UpperMS == math.MaxUint64 {
			return ledgerv4.AuditTransferResult{}, ledgerv4.ErrAuditUnavailable
		}
		from := uint64(0)
		if now.LowerMS > p.retention {
			from = now.LowerMS - p.retention
		}
		cursor.until = now.UpperMS + 1
		cursor.query = ledgerv4.AuditQuery{FromMS: from, UntilMS: min(cursor.until, from+min(uint64(24*60*60*1000), math.MaxUint64-from)), Limit: ledgerv4.AuditPageRecords, OutputBytes: ledgerv4.AuditPageBytes}
		cursor.active = true
	}
	result, err := c.Archive.TransferAuditPage(ctx, c.ArchiveAccess, c.Source, c.SourceAccess, cursor.query)
	if err != nil {
		return result, err
	}
	if !result.Complete {
		cursor.query.AfterSequence = result.NextSequence
		cursor.query.ThroughSequence = result.ThroughSequence
		return result, nil
	}
	if cursor.query.UntilMS == cursor.until {
		*cursor = auditExportCursor{}
		return result, nil
	}
	from := cursor.query.UntilMS
	cursor.query = ledgerv4.AuditQuery{FromMS: from, UntilMS: min(cursor.until, from+min(uint64(24*60*60*1000), math.MaxUint64-from)), ThroughSequence: result.ThroughSequence, Limit: ledgerv4.AuditPageRecords, OutputBytes: ledgerv4.AuditPageBytes}
	return result, nil
}

func (p *AuditMaintenance) run(lane uint8) {
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			p.Close()
		}
		p.exit()
	}()
	c := p.config
	interval := c.RetentionEveryMS
	if lane == 0 {
		interval = c.ExportEveryMS
	}
	// Spread the original maintenance turns across their period. Starting all
	// lanes at zero can repeatedly put expiry in the sole SQLite position at
	// every export tick, despite all calls being short and separately bounded.
	initial := uint64(lane) * c.RetentionEveryMS / 3
	timer := time.NewTimer(time.Duration(initial) * time.Millisecond)
	defer timer.Stop()
	var cursor auditExportCursor
	for {
		select {
		case <-p.ctx.Done():
			returned = true
			return
		case <-timer.C:
		}
		if p.ctx.Err() != nil {
			returned = true
			return
		}
		if !p.runTurn(lane, c, &cursor) {
			returned = true
			return
		}
		timer.Reset(time.Duration(interval) * time.Millisecond)
	}
}

func (p *AuditMaintenance) runTurn(lane uint8, c AuditMaintenanceConfig, cursor *auditExportCursor) (keep bool) {
	call := newControlCallContext(time.Duration(c.CallMS) * time.Millisecond)
	var result ledgerv4.AuditTransferResult
	var err error
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err, keep = ErrControlTaskExit, false
			call.cancel(err)
			p.Close()
		}
		call.finish()
		if err == nil {
			err = call.cause()
		}
		call.stopCall()
		p.record(lane, result, err)
	}()
	p.started(lane)
	if p.reservation.Check() != nil || p.dependencies.Check() != nil {
		err = resourcev4.ErrClosed
		p.Close()
		returned = true
		return false
	}
	if err = call.start(p.ctx); err == nil {
		switch lane {
		case 0:
			result, err = p.export(call, cursor)
		case 1:
			err = c.Source.ExpireAudit(call, c.SourceAccess)
		case 2:
			err = c.Archive.ExpireAuditArchive(call, c.ArchiveAccess)
		}
	}
	returned = true
	return true
}

func auditAdd(v *uint64) {
	if *v != math.MaxUint64 {
		*v++
	}
}

func (p *AuditMaintenance) record(lane uint8, result ledgerv4.AuditTransferResult, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := "complete"
	switch err {
	case nil:
	case ledgerv4.ErrAuditCapacity:
		state = "capacity"
	case ledgerv4.ErrAuditDenied:
		state = "denied"
	case ledgerv4.ErrAuditUnknown:
		state = "unknown"
	case context.Canceled:
		state = "cancelled"
	case context.DeadlineExceeded:
		state = "timeout"
	default:
		state = "unavailable"
	}
	s := &p.state
	switch lane {
	case 0:
		s.ExportRunning = false
		s.LastExport = state
		if err != nil {
			auditAdd(&s.ExportFailures)
		}
		if result.Persistence == "committed" {
			auditAdd(&s.PagesPersisted)
		}
		if result.Acknowledgement == "committed" {
			auditAdd(&s.PagesAcknowledged)
		}
	case 1:
		s.SourceRetentionRunning = false
		s.LastSourceRetention = state
		if err != nil {
			auditAdd(&s.SourceRetentionFailures)
		}
	case 2:
		s.ArchiveRetentionRunning = false
		s.LastArchiveRetention = state
		if err != nil {
			auditAdd(&s.ArchiveRetentionFailures)
		}
	}
}

func (p *AuditMaintenance) exit() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.remaining--
	if p.remaining != 0 {
		return
	}
	p.state.CleanupComplete = true
	p.config = AuditMaintenanceConfig{}
	p.binding.Release()
	p.binding = nil
	p.dependencies.Release()
	p.reservation.Release()
	p.dependencies, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	p.ctx, p.cancel = nil, nil
	close(p.done)
}
func (p *AuditMaintenance) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state.Closed = true
	if p.cancel != nil {
		p.cancel()
	}
}
func (p *AuditMaintenance) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *AuditMaintenance) Snapshot() AuditMaintenanceSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}
func (*AuditMaintenance) String() string               { return "Flowersec.AuditMaintenance" }
func (*AuditMaintenance) GoString() string             { return "Flowersec.AuditMaintenance" }
func (*AuditMaintenance) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (p *AuditMaintenance) started(lane uint8) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch lane {
	case 0:
		p.state.ExportRunning = true
		p.state.LastExport = "running"
		auditAdd(&p.state.ExportCalls)
	case 1:
		p.state.SourceRetentionRunning = true
		p.state.LastSourceRetention = "running"
		auditAdd(&p.state.SourceRetentionCalls)
	case 2:
		p.state.ArchiveRetentionRunning = true
		p.state.LastArchiveRetention = "running"
		auditAdd(&p.state.ArchiveRetentionCalls)
	}
}

// BorrowOperations preserves aggregate metadata through the management read;
// it cannot extend store authorization or restart a closed maintenance worker.
func (p *AuditMaintenance) BorrowOperations(ref resourcev4.Reference) (resourcev4.Reference, error) {
	if p == nil {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state.Closed {
		return resourcev4.Reference{}, resourcev4.ErrClosed
	}
	if err := p.reservation.CheckSameEnvironment(ref); err != nil {
		return resourcev4.Reference{}, err
	}
	return p.reservation.Borrow()
}
