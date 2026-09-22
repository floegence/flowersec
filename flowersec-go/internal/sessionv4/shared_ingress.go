package sessionv4

import (
	"context"
	"errors"
	"io"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrSharedIngress       = errors.New("sessionv4: shared carrier ingress failed")
	ErrSharedDiscardBudget = errors.New("sessionv4: shared carrier discard budget exhausted")
	errSharedDiscarded     = errors.New("sessionv4: permanently closed DATA direction discarded")
)

// SharedDiscardPolicy is an explicit finite carrier allowance. Its one window
// begins with the first discard and never restarts for a stream, epoch or retry.
// The ordinary ingress/provider profile also bounds all received input work.
type SharedDiscardPolicy struct {
	MaxRecords, MaxBytes, DurationMS uint64
}

// SharedIngress is the single bounded reader for a shared carrier (for
// example, one WebSocket connection). It owns one decoder/crypto receiver and
// dispatches only after the complete envelope has authenticated. OPEN uses the
// original unbound temporary key and exact logical association; DATA and
// maintenance use the admission slot established by that prior proof.
type SharedIngress struct {
	mu                           sync.Mutex
	admission                    *OpenAdmission
	carrier                      *CarrierAssociation
	receiver                     *RecordReceiver
	reservation                  resourcev4.Reference
	closed                       bool
	discardPolicy                SharedDiscardPolicy
	discardWindow                *timev4.Window
	discardRecords, discardBytes uint64
}

func SharedIngressCharge(maxFrame uint32, nodes int, decode protocolv4.DecodeContext) (resourcev4.Vector, error) {
	if maxFrame == 0 || nodes <= 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	receiver, err := RecordReceiverCharge(maxFrame, nodes, decode)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: receiver[resourcev4.SDKBytes] + uint64(unsafe.Sizeof(SharedIngress{})) + uint64(unsafe.Sizeof(timev4.Window{})), resourcev4.Items: receiver[resourcev4.Items] + 1, resourcev4.Tasks: receiver[resourcev4.Tasks], resourcev4.WorkSlots: receiver[resourcev4.WorkSlots]}
	return charge, nil
}

// NewSharedIngress must run before dynamic OPENs are admitted. The carrier is
// one exact logical association for this shared reader; individual OPEN slots
// retain their own immutable carrier associations after authentication.
func NewSharedIngress(a *OpenAdmission, carrier *CarrierAssociation, discard SharedDiscardPolicy, nodes int, decode protocolv4.DecodeContext, reservation resourcev4.Reference) (*SharedIngress, error) {
	if a == nil || carrier == nil || nodes <= 0 || discard.MaxRecords == 0 || discard.MaxBytes == 0 || discard.DurationMS == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err := timev4.NewWindow(a.engine.Clock(), discard.DurationMS); err != nil {
		return nil, err
	}
	charge, err := SharedIngressCharge(a.engine.MaxFrame(), nodes, decode)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.maintenanceIngress != nil || a.sharedIngress != nil || a.nativeAuth != nil {
		return nil, cryptov4.ErrConfiguration
	}
	if s := a.sendService; s != nil {
		workers := uint64(s.workers[0]) + uint64(s.workers[1]) + uint64(s.workers[2])
		if workers >= uint64(a.engine.OrdinaryWorkSlots()) {
			return nil, cryptov4.ErrConfiguration
		}
	}
	carrier.mu.Lock()
	if carrier.bound != nil {
		carrier.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		carrier.mu.Unlock()
		return nil, err
	}
	receiver, err := NewRecordReceiver(a.engine, 1-a.direction, a.engine.MaxFrame(), nodes, decode, owned)
	if err != nil {
		carrier.mu.Unlock()
		owned.Release()
		return nil, err
	}
	if err := a.engine.ReserveSharedInput(); err != nil {
		carrier.mu.Unlock()
		receiver.Close()
		_ = receiver.retire()
		owned.Release()
		return nil, err
	}
	carrier.bound, carrier.scope = a, 0
	g := &SharedIngress{admission: a, carrier: carrier, receiver: receiver, reservation: owned, discardPolicy: discard}
	a.sharedIngress = g
	carrier.mu.Unlock()
	return g, nil
}

// Read authenticates one complete shared-carrier envelope. DATA validation,
// crypto frontier and bounded queue transfer share the original direction gate.
// OPEN/control ownership is transferred by Dispatch. No next read is allowed
// while the returned decoder is held.
func (g *SharedIngress) Read(ctx context.Context, reader io.Reader) (*ReceivedRecord, error) {
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	record, err := g.receiver.readShared(ctx, reader, g)
	if err != nil && (errors.Is(err, cryptov4.ErrScope) || errors.Is(err, protocolv4.ErrRecordScope) || errors.Is(err, protocolv4.ErrRecordDirection)) {
		// No authenticated owner exists for these shared-input failures. The
		// carrier cannot safely continue by guessing another scope/key.
		g.admission.closeWithCause(err)
	}
	return record, err
}

// Dispatch transfers the record to its sole original protocol owner, then the
// caller may release its decoder. A full P_ingress stages the same OPEN as one
// protected rejected proof and never drops the authenticated input.
func (g *SharedIngress) Dispatch(ctx context.Context, record *ReceivedRecord, deadline *timev4.Deadline) error {
	if ctx == nil || record == nil || record.receiver != g.receiver {
		return ErrSharedIngress
	}
	body, err := record.Body()
	if err != nil {
		return err
	}
	if record.dataApplied {
		return nil
	}
	if record.incoming != nil {
		if body.Type != protocolv4.FrameOpenStream {
			return ErrSharedIngress
		}
		logical := &CarrierAssociation{shared: g}
		h, err := g.admission.Hold(record, logical, deadline)
		if errors.Is(err, cryptov4.ErrCapacity) {
			h, err = g.admission.HoldRejection(record, logical, deadline)
		}
		if err != nil {
			return err
		}
		_ = h
		return nil
	}
	if body.Header.Scope == 0 {
		return g.admission.dispatchControl(ctx, record, deadline)
	}
	g.admission.mu.Lock()
	s, err := g.admission.slot(OpenHandle{g.admission, body.Header.Scope})
	if err != nil {
		g.admission.mu.Unlock()
		return err
	}
	carrier := s.carrier
	localOpening := s.local && s.phase == openOpening
	bootstrap := g.admission.bootstrap
	fixedPrefix := s.bootstrap && bootstrap != nil && bootstrap.shared == g && body.Type == protocolv4.FrameOpenStream
	g.admission.mu.Unlock()
	if fixedPrefix {
		return bootstrap.BindPeerPrefix(record, &bootstrap.carrier, bootstrap.output)
	}
	if body.Type == protocolv4.FrameStreamAck && localOpening {
		return g.admission.ApplyOutcome(record)
	}
	if body.Type != protocolv4.FrameStreamData || carrier == nil {
		return ErrSharedIngress
	}
	return g.admission.ApplyData(OpenHandle{g.admission, body.Header.Scope}, carrier, record)
}

// ReadDispatch is the common one-record loop used by a shared provider. It
// releases the authenticated decoder only after Dispatch has transferred all
// required ownership and never starts a replacement reader in the background.
func (g *SharedIngress) ReadDispatch(ctx context.Context, reader io.Reader, deadline *timev4.Deadline) error {
	record, err := g.Read(ctx, reader)
	if errors.Is(err, errSharedDiscarded) {
		return nil
	}
	if err != nil {
		return err
	}
	defer record.Release()
	return g.Dispatch(ctx, record, deadline)
}

func (g *SharedIngress) Close() {
	g.mu.Lock()
	if !g.closed {
		g.closed = true
		g.receiver.Close()
	}
	g.mu.Unlock()
}

func (g *SharedIngress) WaitCleanup(ctx context.Context) error { return g.receiver.WaitCleanup(ctx) }

func (g *SharedIngress) Retire() error {
	if err := g.receiver.retire(); err != nil {
		return err
	}
	g.reservation.Release()
	return nil
}

// validateData runs after AEAD and before receive-sequence commit. Only an
// already accepted outer DATA scope permits local isolation. Inner fields can
// never select another owner, and malformed OPEN/maintenance remains fatal.
type sharedDataCommit struct {
	admission *OpenAdmission
	flow      *ReceiveFlow
}

func (c *sharedDataCommit) release() {
	if c.flow != nil {
		c.flow.pool.mu.Unlock()
		c.admission.mu.Unlock()
		c.flow = nil
	}
}

func (g *SharedIngress) validateData(commit *sharedDataCommit, kind protocolv4.FrameType, header protocolv4.RecordHeader, body *protocolv4.Frame, decodeErr error) error {
	if kind != protocolv4.FrameStreamData {
		return decodeErr
	}
	a := g.admission
	if err := a.engine.ApplicationInputReady(header.Epoch); err != nil {
		return err
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return cryptov4.ErrClosed
	}
	s, err := a.slot(OpenHandle{a, header.Scope})
	if err != nil || s.flow == nil || s.phase != openLive && !(s.local && s.submitted && s.phase == openOpening) {
		a.mu.Unlock()
		return ErrOpenAssociation
	}
	f := s.flow.receive
	f.pool.mu.Lock()
	if decodeErr == nil {
		decodeErr = f.applyDataLocked(body, nil, false, true)
	}
	if decodeErr == nil {
		// Keep the original direction gate through Engine's final sequence
		// commit and the bounded plaintext transfer. Reset/Close cannot split
		// those facts or turn a successful validation into a local fatal race.
		commit.flow = f
		return nil
	}
	f.pool.mu.Unlock()
	defer a.mu.Unlock()
	if !s.accepted || !errors.Is(decodeErr, ErrStreamData) && !errors.Is(decodeErr, ErrCredit) && !errors.Is(decodeErr, ErrTerminal) && body != nil {
		return decodeErr
	}
	f.pool.mu.Lock()
	f.sharedInputFailed = true
	f.termination.start(true, decodeErr)
	f.fenceLocked()
	f.pool.mu.Unlock()
	s.flow.send.Stop()
	return errSharedDiscarded
}

// rejectClosedData inspects a complete fixed envelope only to refuse input
// already forbidden by an original permanent gate. It performs no AEAD, body
// decoding or sequence/credit/retirement advancement.
func (g *SharedIngress) rejectClosedData(kind protocolv4.FrameType, header protocolv4.RecordHeader, size uint64) error {
	if kind != protocolv4.FrameStreamData {
		return nil
	}
	a := g.admission
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return cryptov4.ErrClosed
	}
	closed := a.isStable(header.Scope)
	if index := a.find(header.Scope); index >= 0 {
		s := &a.slots[index]
		closed = closed || !s.accepted && s.rejectionToken && (s.phase == openRecent || s.phase == openHeld)
		if s.accepted && s.flow != nil {
			f := s.flow.receive
			f.pool.mu.Lock()
			closed = f.sharedInputFailed || f.hasTerminal && f.observed == f.terminal || s.drainSubmitted && f.fenced
			f.pool.mu.Unlock()
		}
	}
	a.mu.Unlock()
	if !closed {
		return nil
	}
	frontier, err := a.engine.ScopeFrontier(0, 1-a.direction)
	if err != nil {
		return err
	}
	if header.Epoch > frontier.Epoch {
		return cryptov4.ErrEpoch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.discardWindow == nil {
		g.discardWindow, err = timev4.NewWindow(a.engine.Clock(), g.discardPolicy.DurationMS)
	}
	if err == nil {
		err = g.discardWindow.Check()
	}
	if err != nil {
		return err
	}
	if g.discardRecords == g.discardPolicy.MaxRecords || size > g.discardPolicy.MaxBytes-g.discardBytes {
		return ErrSharedDiscardBudget
	}
	g.discardRecords++
	g.discardBytes += size
	return errSharedDiscarded
}
