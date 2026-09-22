// Package ledgerv4 owns the original v4 authorization and admission transactions.
package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrConfiguration = errors.New("ledgerv4: invalid configuration")
	ErrOwner         = errors.New("ledgerv4: original owner unavailable")
	ErrCapacity      = errors.New("ledgerv4: original work slot occupied")
	ErrUnknown       = errors.New("ledgerv4: commit unknown")
	ErrConflict      = errors.New("ledgerv4: original commit conflict")
	ErrFenced        = errors.New("ledgerv4: original authority fenced")
	ErrRolledBack    = errors.New("ledgerv4: original transaction rolled back")
)

// CommitKind is an internal ownership selector, not a wire state or a public
// recovery API. Reserve and pool consume intentionally have no confirmation
// continuation: uncertainty in either cannot create an activation guard.
type CommitKind uint8

const (
	SpendTxA CommitKind = iota + 1
	AuthorizedTxB
	RelayClaim
	AdmissionCommit
)

// Transaction contains the exact complete immutable storage projection retained
// by the trusted ledger adapter before its only write. Projection must include
// all key/intent/owner/incarnation/binding/state/material fields for that kind.
// No digest-only or state-only observation can substitute for those bytes.
// The adapter owns its storage schema; this type does not define another wire
// encoding or certify the backend's durability, history or linearizability.
type Transaction struct {
	Kind                         CommitKind
	Authority                    string
	Key                          []byte
	BeforeVersion, CommitVersion uint64
	FencingEpoch                 uint64
	Projection                   []byte
}

type ObservationState uint8

const (
	NotObserved ObservationState = iota
	DurablyCommitted
	Unavailable
	RolledBack
	Conflicting
)

// Observation keeps a leg's immutable commit version separate from the relay
// root's aggregate version. A different leg may advance only the latter.
type Observation struct {
	State                           ObservationState
	CommitVersion, AggregateVersion uint64
	CommitFence, CurrentFence       uint64
	ProjectionBytes                 int
}

// CommitStore is a trusted, independently qualified durable store adapter.
// Commit is called once. Confirm reads the same stable authority/key using a
// linearizable committed snapshot and never writes, repairs or signs anything.
// Both methods fill only the supplied bounded output, retain no borrowed slices
// after return, and keep actual I/O ownership until their real task exits.
type CommitStore interface {
	Commit(context.Context, Transaction, []byte) (Observation, error)
	Confirm(context.Context, Transaction, []byte) (Observation, error)
}

// Invocation exists only in the original trusted service/Acceptor/relay call.
// Queries, restored rows and caller-supplied receipts must never construct one.
// Its two backing buffers and one actual I/O slot are reserved before TxA or
// the original claim/admit write. TxB reuses them only after TxA's real tail exits.
type Invocation struct {
	mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelCauseFunc
	clock            *timev4.Clock
	origin           timev4.Mark
	deadline         *timev4.Deadline
	fence            uint64
	expected, output []byte
	key              []byte
	current          *OriginalCommit
	commits          [2]OriginalCommit
	commitCount      int
	reservation      resourcev4.Reference
	terminal         error
}

type OriginalCommit struct {
	invocation                              *Invocation
	tx                                      Transaction
	submitted, running, confirmed           bool
	dispatched, dispatching, dispatchedDone bool
	reads                                   uint8
	window                                  *timev4.Window
	terminal                                error
}

// InvocationCharge returns the original invocation's fixed local minimum.
func InvocationCharge(maxKeyBytes, maxProjectionBytes int) (resourcev4.Vector, error) {
	if maxKeyBytes <= 0 || maxKeyBytes > math.MaxInt/3 || maxProjectionBytes <= 0 || maxProjectionBytes > (math.MaxInt-3*maxKeyBytes)/2 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	// Original key, two detached authority names, exact projection and output,
	// and two fixed commit/window positions. The admitted profile additionally
	// charges runtime allocator/context/timer and actual backend work overhead.
	bytes := uint64(3*maxKeyBytes+2*maxProjectionBytes) + uint64(unsafe.Sizeof(Invocation{})) + 2*uint64(unsafe.Sizeof(timev4.Window{}))
	return resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: 3, resourcev4.WorkSlots: 2, resourcev4.Tasks: 2, resourcev4.Timers: 1}, nil
}

// NewInvocation accepts only a deadline already tightened by the trusted
// caller's original control/claim, authorization, handle and protocol owners.
// Known handle, trust or fencing loss must cancel this same invocation. A new
// deadline/object never transfers the old dispatch or publication guard.
func NewInvocation(ctx context.Context, clock *timev4.Clock, deadline *timev4.Deadline, fence uint64, maxKeyBytes, maxProjectionBytes int, reservation resourcev4.Reference) (*Invocation, error) {
	if ctx == nil || clock == nil || !deadline.BelongsTo(clock) {
		return nil, ErrConfiguration
	}
	charge, err := InvocationCharge(maxKeyBytes, maxProjectionBytes)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sample, err := deadline.Sample()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	original, cancel := context.WithCancelCause(ctx)
	return &Invocation{ctx: original, cancel: cancel, clock: clock, origin: sample.Mark, deadline: deadline, fence: fence, reservation: owned, expected: make([]byte, maxProjectionBytes), output: make([]byte, maxProjectionBytes), key: make([]byte, maxKeyBytes)}, nil
}

func (i *Invocation) check() error {
	if i.terminal != nil {
		return i.terminal
	}
	if err := context.Cause(i.ctx); err != nil {
		i.terminal = err
	} else if err := i.reservation.Check(); err != nil {
		i.terminal = err
	} else {
		sample, err := i.deadline.Sample()
		if !sample.Mark.SameEra(i.origin) {
			i.terminal = timev4.ErrContinuity
		} else {
			i.terminal = err
		}
	}
	return i.terminal
}

// Begin captures a complete projection once. The only two-write invocation is
// TxA followed by authorized TxB after the actual original callback dispatch.
// No failed/unknown write can be replaced, retried, or treated as absence.
func (i *Invocation) Begin(tx Transaction) (*OriginalCommit, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.check(); err != nil {
		return nil, err
	}
	if tx.Kind < SpendTxA || tx.Kind > AdmissionCommit || tx.Authority == "" || len(tx.Authority) > len(i.key) || len(tx.Key) == 0 || len(tx.Key) > len(i.key) || len(tx.Projection) == 0 || len(tx.Projection) > len(i.expected) || tx.BeforeVersion == math.MaxUint64 || tx.CommitVersion != tx.BeforeVersion+1 || tx.FencingEpoch != i.fence {
		return nil, ErrConfiguration
	}
	if previous := i.current; previous != nil {
		if previous.running || previous.dispatching {
			return nil, ErrCapacity
		}
		if previous.tx.Kind != SpendTxA || tx.Kind != AuthorizedTxB || !previous.dispatchedDone || previous.terminal != nil || tx.Authority != previous.tx.Authority || !bytes.Equal(tx.Key, previous.tx.Key) || tx.BeforeVersion != previous.tx.CommitVersion {
			return nil, ErrOwner
		}
	} else if tx.Kind == AuthorizedTxB {
		return nil, ErrOwner
	}
	if i.commitCount == len(i.commits) {
		return nil, ErrOwner
	}
	// Originals cannot alias adapter-owned mutable request/configuration bytes.
	clear(i.expected)
	clear(i.output)
	copy(i.expected, tx.Projection)
	copy(i.key, tx.Key)
	tx.Projection = i.expected[:len(tx.Projection):len(tx.Projection)]
	tx.Key = i.key[:len(tx.Key):len(tx.Key)]
	tx.Authority = strings.Clone(tx.Authority)
	c := &i.commits[i.commitCount]
	i.commitCount++
	*c = OriginalCommit{invocation: i, tx: tx}
	i.current = c
	return c, nil
}

func (c *OriginalCommit) check() error {
	i := c.invocation
	if c.terminal != nil {
		return c.terminal
	}
	if i.current != c {
		return ErrOwner
	}
	if err := i.check(); err != nil {
		c.terminal = err
		return err
	}
	// Once confirmation wins, its finite read window does not replace the
	// original invocation/action deadline. It still bounds late confirmation.
	if c.window != nil && !c.confirmed {
		if err := c.window.Check(); err != nil {
			c.terminal = err
			return err
		}
	}
	return nil
}

func (c *OriginalCommit) observe(observation Observation, projection []byte) error {
	if err := c.check(); err != nil {
		return err
	}
	if !c.submitted {
		return ErrOwner
	}
	if c.confirmed {
		return nil
	}
	switch observation.State {
	case NotObserved, Unavailable:
		return c.uncertain()
	case RolledBack:
		c.terminal = ErrRolledBack
	case Conflicting:
		c.terminal = ErrConflict
	case DurablyCommitted:
		if observation.CurrentFence != c.tx.FencingEpoch || observation.CommitFence != c.tx.FencingEpoch {
			c.terminal = ErrFenced
		} else if observation.CommitVersion != c.tx.CommitVersion || observation.AggregateVersion < observation.CommitVersion || c.tx.Kind != RelayClaim && observation.AggregateVersion != observation.CommitVersion || observation.ProjectionBytes != len(c.tx.Projection) || len(projection) != observation.ProjectionBytes || !bytes.Equal(projection, c.tx.Projection) {
			c.terminal = ErrConflict
		} else {
			c.confirmed = true
			return nil
		}
	default:
		c.terminal = ErrConflict
	}
	return c.terminal
}

func (c *OriginalCommit) uncertain() error {
	if c.window == nil {
		var err error
		c.window, err = timev4.NewWindow(c.invocation.clock, 2000)
		if err != nil {
			c.terminal = err
			return err
		}
	}
	return ErrUnknown
}

// ConfirmOriginal accepts an independently delivered original durable receipt.
// It races bounded confirmation reads at the same gate and never releases
// their actual I/O slot early. It is not an entry point for public queries.
func (c *OriginalCommit) ConfirmOriginal(observation Observation, projection []byte) error {
	i := c.invocation
	i.mu.Lock()
	defer i.mu.Unlock()
	return c.observe(observation, projection)
}

func (c *OriginalCommit) acceptOutput(observation Observation, callErr error) error {
	i := c.invocation
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := c.check(); err != nil {
		return err
	}
	if c.confirmed {
		return nil
	}
	if callErr != nil {
		return c.uncertain() // A transport error is never a rollback receipt.
	}
	if observation.ProjectionBytes < 0 || observation.ProjectionBytes > len(i.output) {
		c.terminal = ErrConflict
		return c.terminal
	}
	return c.observe(observation, i.output[:observation.ProjectionBytes])
}

// Run performs exactly one original write and, on uncertainty, at most three
// serial confirmation reads inside the first uncertainty's two-second window.
// No goroutine detaches a cancelled store call: its reserved buffers remain
// occupied until that call actually returns, even when an original ACK wins.
func (c *OriginalCommit) Run(store CommitStore) error {
	if store == nil {
		return ErrConfiguration
	}
	i := c.invocation
	i.mu.Lock()
	if err := c.check(); err != nil {
		i.mu.Unlock()
		return err
	}
	if c.submitted || c.running {
		i.mu.Unlock()
		return ErrOwner
	}
	c.submitted, c.running = true, true
	i.mu.Unlock()
	defer func() {
		i.mu.Lock()
		c.running = false
		clear(i.output)
		i.mu.Unlock()
	}()
	observation, callErr := store.Commit(i.ctx, c.tx, i.output)
	err := c.acceptOutput(observation, callErr)
	if !errors.Is(err, ErrUnknown) {
		return err
	}
	for {
		i.mu.Lock()
		if err = c.check(); err != nil || c.confirmed {
			i.mu.Unlock()
			return err
		}
		if c.reads == 3 {
			c.terminal = ErrUnknown
			i.mu.Unlock()
			return ErrUnknown
		}
		c.reads++
		clear(i.output)
		i.mu.Unlock()
		observation, callErr = store.Confirm(i.ctx, c.tx, i.output)
		err = c.acceptOutput(observation, callErr)
		if !errors.Is(err, ErrUnknown) {
			return err
		}
		i.mu.Lock()
		last := c.reads == 3
		i.mu.Unlock()
		if !last {
			if err = c.backoff(); err != nil {
				return err
			}
		}
	}
}

func (c *OriginalCommit) backoff() error {
	i := c.invocation
	delay, err := timev4.NewDelay(i.clock, 50)
	if err != nil {
		i.mu.Lock()
		c.terminal = err
		i.mu.Unlock()
		return err
	}
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	for {
		i.mu.Lock()
		err = c.check()
		confirmed := c.confirmed
		i.mu.Unlock()
		if err != nil || confirmed {
			return err
		}
		ms, err := delay.RemainingMS()
		if err == nil {
			return nil
		}
		if !errors.Is(err, timev4.ErrPending) {
			i.mu.Lock()
			c.terminal = err
			i.mu.Unlock()
			return err
		}
		// This is a bounded wakeup, never a new work or authorization deadline.
		timer.Reset(time.Duration(min(ms, 50)) * time.Millisecond)
		select {
		case <-timer.C:
		case <-i.ctx.Done():
		}
	}
}

// Dispatch consumes the only next-action guard, then invokes trusted SDK work
// outside the lock. No result/error can refund it. TxA dispatch is the original
// authorization callback; other kinds start their original publication/handle
// activation/FSA4-Noise path. Remote Connect activation remains a separate gate.
func (c *OriginalCommit) Dispatch(action func(context.Context) error) (err error) {
	if action == nil {
		return ErrConfiguration
	}
	i := c.invocation
	i.mu.Lock()
	if err := c.check(); err != nil {
		i.mu.Unlock()
		return err
	}
	if !c.confirmed || c.dispatched {
		i.mu.Unlock()
		return ErrOwner
	}
	c.dispatched, c.dispatching = true, true
	i.mu.Unlock()
	returned := false
	defer func() {
		i.mu.Lock()
		c.dispatching, c.dispatchedDone = false, true
		if c.terminal == nil {
			if !returned {
				c.terminal = ErrOwner
			} else if err != nil {
				c.terminal = err
			}
		}
		i.mu.Unlock()
	}()
	err = action(i.ctx)
	returned = true
	return err
}

// Fence is called by the original trusted authority/handle continuity owner.
// A different generation ends this invocation permanently; reverting to the
// old value cannot revive it. Actual pending store/callback tails stay owned.
func (i *Invocation) Fence(current uint64) {
	i.mu.Lock()
	changed := current != i.fence && i.terminal == nil
	if changed {
		i.terminal = ErrFenced
		i.reservation.Seal()
	}
	i.mu.Unlock()
	if changed {
		i.cancel(ErrFenced)
	}
}

func (i *Invocation) Cancel(cause error) {
	if cause == nil {
		cause = context.Canceled
	}
	i.mu.Lock()
	if i.terminal == nil {
		i.terminal = cause
	}
	i.reservation.Seal()
	i.mu.Unlock()
	i.cancel(cause)
}

// Cleanup seals admission and clears private material only after actual store
// and callback references have exited. An uncooperative tail returns capacity;
// it is never detached or described as completed cleanup.
func (i *Invocation) Cleanup() error {
	i.Cancel(ErrOwner)
	i.mu.Lock()
	defer i.mu.Unlock()
	if c := i.current; c != nil && (c.running || c.dispatching) {
		return ErrCapacity
	}
	clear(i.expected)
	clear(i.output)
	clear(i.key)
	i.expected, i.output, i.key = nil, nil, nil
	for n := range i.commitCount {
		i.commits[n].tx.Key = nil
		i.commits[n].tx.Projection = nil
		i.commits[n].tx.Authority = ""
	}
	i.reservation.Release()
	return nil
}
