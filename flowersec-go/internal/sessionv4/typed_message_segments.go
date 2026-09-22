package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"unicode/utf8"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

const messageSegmentCount = 65
const messageSendEntries = 8
const messageSendBytes = 2*1048576 + 4*messageSendEntries

// This is a private allocation capability, never granted by a user-supplied
// encoder signature or a peer field. Only the SDK byte/UTF-8 encoders and the
// original message publisher access these blocks. Arbitrary encoders reserve
// their complete worst-case output separately before application entry.
type messageSegments struct {
	mu                      sync.Mutex
	budget                  *messageSendBudget
	reservation             resourcev4.Reference
	encoderAlias            resourcev4.Reference
	encoderAliasBytes       uint32
	growth                  [messageSegmentCount]resourcev4.Reference
	blocks                  [messageSegmentCount][]byte
	used                    [messageSegmentCount]uint32
	context                 context.Context
	deadline                *timev4.Deadline
	serial                  uint64
	maximum, size, capacity uint32
	count                   uint8
	failure                 error
	sealed, closed          bool
}

type messageSendBudget struct {
	mu            sync.Mutex
	root          *resourcev4.Root
	owner         resourcev4.OwnerKey
	accounts      [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount  int
	reservation   resourcev4.Reference
	serial, bytes uint64
	entries       uint8
	closed        bool
}

func messageSendBudgetCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(messageSendBudget{})), resourcev4.Items: 1}
}
func messageSegmentsCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(messageSegments{})) + 4096, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func newMessageSendBudget(root *resourcev4.Root, owner resourcev4.OwnerKey, accounts []resourcev4.Account, reservation resourcev4.Reference) (*messageSendBudget, error) {
	if err := reservation.CheckAllocationScope(root, owner, accounts); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(messageSendBudgetCharge())
	if err != nil {
		return nil, err
	}
	b := &messageSendBudget{root: root, owner: owner, accountCount: len(accounts), reservation: owned}
	copy(b.accounts[:], accounts)
	return b, nil
}

func (b *messageSendBudget) entryOwner(serial uint64, part byte) resourcev4.OwnerKey {
	var seed [41]byte
	copy(seed[:16], b.owner.Instance[:])
	copy(seed[16:32], b.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[32:40], serial)
	seed[40] = part
	digest := sha256.Sum256(seed[:])
	owner := b.owner
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	return owner
}

// The caller's original entry gate fixes FIFO before this admission. Empty
// messages own only metadata and their prefix; idle streams own no body pool.
func (b *messageSendBudget) newSegments(ctx context.Context, deadline *timev4.Deadline, maximum uint32, runtimeBytes uint64) (*messageSegments, error) {
	if ctx == nil || deadline == nil || maximum == 0 || maximum > 1048576 {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := messageSegmentsCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, cryptov4.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := deadline.Check(); err != nil {
		return nil, err
	}
	if err := b.reservation.Check(); err != nil {
		return nil, err
	}
	if b.entries == messageSendEntries || b.bytes > messageSendBytes-4 || b.serial == math.MaxUint64 {
		return nil, cryptov4.ErrCapacity
	}
	b.serial++
	ref, err := b.root.Reserve(b.entryOwner(b.serial, 0), charge, b.accounts[:b.accountCount]...)
	if err != nil {
		return nil, err
	}
	b.entries++
	b.bytes += 4
	return &messageSegments{budget: b, reservation: ref, context: ctx, deadline: deadline, serial: b.serial, maximum: maximum}, nil
}

// Arbitrary array encoders preadmit both their worst-case returned view and a
// disjoint SDK-owned copy. A real maximum-size buffer remains charged until
// its publication tail exits; unused bytes are not falsely refunded as slack.
// This private adapter operation grants no writer capability to the callback.
func (w *messageSegments) reserveApplicationOutput() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.sealed || w.capacity != 0 {
		return cryptov4.ErrTransition
	}
	if err := w.context.Err(); err != nil {
		return err
	}
	if err := w.deadline.Check(); err != nil {
		return err
	}
	b := w.budget
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return cryptov4.ErrClosed
	}
	n := uint64(w.maximum)
	if 2*n > messageSendBytes-b.bytes {
		b.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	requests := [2]resourcev4.Request{
		{Owner: b.entryOwner(w.serial, 1), Charge: resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1}, Accounts: b.accounts[:b.accountCount]},
		{Owner: b.entryOwner(w.serial, 66), Charge: resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1}, Accounts: b.accounts[:b.accountCount]},
	}
	var refs [2]resourcev4.Reference
	if err := b.root.ReserveBatch(requests[:], refs[:]); err != nil {
		b.mu.Unlock()
		return err
	}
	b.bytes += 2 * n
	w.growth[0], w.encoderAlias = refs[0], refs[1]
	w.encoderAliasBytes, w.capacity, w.count = w.maximum, w.maximum, 1
	b.mu.Unlock()
	w.blocks[0] = make([]byte, int(w.maximum))
	return nil
}

// Called only after the actual encoder task exits. Cancellation alone cannot
// release an application-returned buffer still referenced by that task.
func (w *messageSegments) releaseEncoderAlias() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.releaseEncoderAliasLocked()
}
func (w *messageSegments) releaseEncoderAliasLocked() {
	if w.encoderAliasBytes == 0 {
		return
	}
	w.encoderAlias.Release()
	w.encoderAlias = resourcev4.Reference{}
	w.budget.mu.Lock()
	w.budget.bytes -= uint64(w.encoderAliasBytes)
	w.budget.mu.Unlock()
	w.encoderAliasBytes = 0
}

// append atomically obtains all growth needed by this call before allocation
// or copying. A failed append poisons Finalize even if its caller ignores it.
// There is no wait, partial append, coalescing copy or early prefix publication.
func (w *messageSegments) append(input []byte) (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.sealed {
		return cryptov4.ErrClosed
	}
	if w.failure != nil {
		return w.failure
	}
	defer func() {
		if err != nil {
			w.failure = err
		}
	}()
	if err = w.context.Err(); err != nil {
		return err
	}
	if err = w.deadline.Check(); err != nil {
		return err
	}
	if uint64(len(input)) > uint64(w.maximum-w.size) {
		return cryptov4.ErrCapacity
	}
	if err = w.reservation.Check(); err != nil {
		return err
	}
	need := w.size + uint32(len(input))
	capacity := w.capacity
	var sizes [messageSegmentCount]uint32
	count := 0
	for capacity < need {
		chunk := uint32(16384)
		if capacity == 0 {
			chunk = 256
		}
		chunk = min(chunk, w.maximum-capacity)
		if int(w.count)+count == messageSegmentCount || chunk == 0 {
			return cryptov4.ErrCapacity
		}
		sizes[count] = chunk
		capacity += chunk
		count++
	}
	b := w.budget
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if count != 0 {
		growth := uint64(capacity - w.capacity)
		if growth > messageSendBytes-b.bytes {
			b.mu.Unlock()
			return cryptov4.ErrCapacity
		}
		charge := resourcev4.Vector{resourcev4.SDKBytes: growth, resourcev4.Items: uint64(count)}
		ref, failure := b.root.Reserve(b.entryOwner(w.serial, byte(w.count)+1), charge, b.accounts[:b.accountCount]...)
		if failure != nil {
			b.mu.Unlock()
			return failure
		}
		w.growth[w.count] = ref
		b.bytes += growth
		w.capacity = capacity
	}
	b.mu.Unlock()
	// Logical close cannot release this writer while its original encoder is
	// still running. Allocation and copying occur outside the shared gate.
	for _, size := range sizes[:count] {
		w.blocks[w.count] = make([]byte, int(size))
		w.count++
	}
	for index := 0; len(input) != 0 && index < int(w.count); index++ {
		block := w.blocks[index]
		if int(w.used[index]) == len(block) {
			continue
		}
		n := copy(block[w.used[index]:], input)
		w.used[index] += uint32(n)
		w.size += uint32(n)
		input = input[n:]
	}
	return nil
}

// finalize permanently ends growth. A canceled/closed owner cannot turn late
// encoder success into publishable bytes; an earlier sticky failure survives.
func (w *messageSegments) finalize() (uint32, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.sealed {
		return 0, cryptov4.ErrClosed
	}
	w.sealed = true
	if w.failure == nil {
		w.failure = w.context.Err()
	}
	if w.failure == nil {
		w.failure = w.deadline.Check()
	}
	if w.failure == nil {
		w.failure = w.reservation.Check()
	}
	w.budget.mu.Lock()
	if w.failure == nil && w.budget.closed {
		w.failure = cryptov4.ErrClosed
	}
	w.budget.mu.Unlock()
	if w.failure != nil {
		return 0, w.failure
	}
	return w.size, nil
}

// encodeBytes and encodeUTF8 are concrete SDK code. They never call marshal
// hooks, getters, arbitrary writers or application-returned buffer methods.
func (w *messageSegments) encodeBytes(input []byte) error { return w.append(input) }
func (w *messageSegments) encodeUTF8(input string) error {
	if !utf8.ValidString(input) {
		return w.fail(cryptov4.ErrConfiguration)
	}
	// Copy in a fixed workspace; converting the complete string to []byte
	// would create an uncharged full-size intermediate allocation.
	var scratch [4096]byte
	for len(input) != 0 {
		n := copy(scratch[:], input)
		if err := w.append(scratch[:n]); err != nil {
			clear(scratch[:])
			return err
		}
		input = input[n:]
	}
	clear(scratch[:])
	return nil
}
func (w *messageSegments) fail(err error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.sealed {
		return cryptov4.ErrClosed
	}
	if w.failure == nil {
		w.failure = err
	}
	return w.failure
}

// Release is called only after encoder and publisher aliases actually exit.
// A logical FIFO removal does not free an entry or any of its blocks early.
func (w *messageSegments) release() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	w.releaseEncoderAliasLocked()
	for i, block := range w.blocks {
		clear(block)
		w.blocks[i] = nil
		w.growth[i].Release()
		w.growth[i] = resourcev4.Reference{}
	}
	b := w.budget
	b.mu.Lock()
	b.entries--
	b.bytes -= uint64(w.capacity) + 4
	b.cleanupLocked()
	b.mu.Unlock()
	w.context, w.deadline, w.budget = nil, nil, nil
	w.reservation.Release()
	w.reservation = resourcev4.Reference{}
}
func (b *messageSendBudget) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.cleanupLocked()
}
func (b *messageSendBudget) cleanupLocked() {
	if b.closed && b.entries == 0 {
		b.reservation.Release()
		b.reservation = resourcev4.Reference{}
	}
}
