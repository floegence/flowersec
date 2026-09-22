package sessionv4

import (
	"context"
	"errors"
	"io"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

const (
	nativeDataPrepared uint8 = iota
	nativeDataIdle
	nativeDataReading
	nativeDataReady
	nativeDataAuthenticating
)

const nativeDataReadQuantum = 16 * 1024

var errNativeDataTerminal = errors.New("sessionv4: native input reached authenticated terminal")

// NativeDataAssembly is the depth-one input owner for one trusted, accepted
// native DATA direction. Its variable ciphertext backing occupies the original
// unused receive ring/promise; only fixed H_DATA and metadata are additional.
// All state gates use the original receive pool. Provider calls, copying and
// authentication run outside it. No shared decoder/crypto slot holds a half frame.
type NativeDataAssembly struct {
	pool                 *ReceivePool
	flow                 *ReceiveFlow
	reservation          resourcev4.Reference
	bounds               protocolv4.StreamDataBounds
	header               []byte
	maxFrame             uint32
	phase                uint8
	closed, cleaned      bool
	length, headerBytes  int
	ringStart, ringBytes int
	claim                uint64
	done                 chan struct{}
	stateWake            chan struct{}
	service              *NativeAuthService
	readerActive         bool
	authenticated        bool
	cause                error
}

func NativeDataAssemblyCharge(scope uint64, direction protocolv4.Direction, profile string, maxFrame uint32) (resourcev4.Vector, error) {
	bounds, err := protocolv4.NewStreamDataBounds(scope, direction, profile, maxFrame)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NativeDataAssembly{})) + uint64(bounds.Overhead()), resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, nil
}

// NativeDataAssembly is called by the provider's actual native association
// owner, not by a peer scope field or the shared WebSocket reader. OPEN must
// already be accepted on this exact original association. The assembly was
// reserved and allocated in the original Stream preparation before acceptance.
// Provider connection,
// native flow-control and runtime service qualification remain separate.
func (a *OpenAdmission) NativeDataAssembly(h OpenHandle, carrier *CarrierAssociation) (*NativeDataAssembly, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return nil, err
	}
	if a.closed || !s.accepted || s.phase != openLive || s.flow == nil || carrier == nil || s.carrier != carrier {
		return nil, ErrOpenAssociation
	}
	x := s.flow.nativeReceive
	if x == nil {
		return nil, cryptov4.ErrConfiguration
	}
	x.pool.mu.Lock()
	defer x.pool.mu.Unlock()
	if err := x.checkLocked(); err != nil {
		return nil, err
	}
	if x.phase != nativeDataPrepared {
		return nil, cryptov4.ErrTransition
	}
	x.phase = nativeDataIdle
	return x, nil
}

func newNativeDataAssembly(flow *ReceiveFlow, reservation resourcev4.Reference) (*NativeDataAssembly, error) {
	if flow == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p := flow.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if flow.engine == nil || flow.assembly != nil || p.closed || flow.cleaned || flow.fenced || flow.hasTerminal && flow.observed == flow.terminal {
		return nil, ErrFlowClosed
	}
	if err := reservation.CheckSameEnvironment(flow.reservation); err != nil {
		return nil, err
	}
	_, profile := flow.engine.SessionBinding()
	maxFrame := flow.engine.MaxFrame()
	charge, err := NativeDataAssemblyCharge(flow.scope, flow.direction, profile, maxFrame)
	if err != nil {
		return nil, err
	}
	bounds, err := protocolv4.NewStreamDataBounds(flow.scope, flow.direction, profile, maxFrame)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	x := &NativeDataAssembly{pool: p, flow: flow, reservation: owned, bounds: bounds, maxFrame: maxFrame, header: make([]byte, bounds.Overhead()), done: make(chan struct{}), stateWake: make(chan struct{}, 1)}
	flow.assembly = x
	return x, nil
}

func (x *NativeDataAssembly) checkLocked() error {
	if x.closed || x.pool.closed || x.flow == nil || x.flow.fenced || x.flow.cleaned {
		return ErrFlowClosed
	}
	if err := x.reservation.Check(); err != nil {
		return err
	}
	return x.flow.reservation.Check()
}

type nativeDataReader struct {
	assembly *NativeDataAssembly
	context  context.Context
	reader   io.Reader
	read     int
}

func (r *nativeDataReader) Read(dst []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	x := r.assembly
	x.pool.mu.Lock()
	err := x.checkLocked()
	if err == nil && x.length != 0 {
		// STOPPED may contract the logical promise while an old call still owns
		// backing. That call retains its physical charge; each NEW call checks
		// the now-current final frontier without trusting ciphertext fields.
		promise := x.flow.limit - x.flow.observed.Offset
		var maximum int
		maximum, err = x.bounds.MaximumEnvelope(promise)
		if err == nil && x.length > maximum {
			err = ErrCredit
		}
		if err == nil {
			x.claim = min(x.claim, promise)
		}
	}
	x.pool.mu.Unlock()
	if err != nil {
		return 0, err
	}
	dst = dst[:min(len(dst), nativeDataReadQuantum)]
	n, err := r.reader.Read(dst)
	if n < 0 || n > len(dst) {
		return 0, io.ErrShortBuffer
	}
	if n == 0 && err == nil && len(dst) != 0 {
		return 0, io.ErrNoProgress
	}
	r.read += n
	return n, err
}

// Read is owned by the original native reader task. Its context is that task's
// lifetime, not an application's temporary read wait. A partial read error ends
// this direction; it never restarts from a newly parsed envelope prefix.
func (x *NativeDataAssembly) Read(ctx context.Context, reader io.Reader) (err error) {
	return x.read(ctx, reader, nil)
}

func (x *NativeDataAssembly) read(ctx context.Context, reader io.Reader, service *NativeAuthService) (err error) {
	if ctx == nil || reader == nil {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	x.pool.mu.Lock()
	if x.service != service {
		x.pool.mu.Unlock()
		return cryptov4.ErrConfiguration
	}
	if err = x.checkLocked(); err == nil && x.phase != nativeDataIdle {
		err = cryptov4.ErrCapacity
	}
	if err == nil && x.flow.hasTerminal && x.flow.observed == x.flow.terminal {
		err = errNativeDataTerminal
	}
	if err != nil {
		x.pool.mu.Unlock()
		return err
	}
	x.phase = nativeDataReading
	x.authenticated = false
	flow := x.flow
	x.pool.mu.Unlock()
	input := nativeDataReader{assembly: x, context: ctx, reader: reader}
	defer func() {
		x.pool.mu.Lock()
		// EOF at a new, empty prefix may follow an independently authenticated
		// STOPPED. It cannot invalidate that proof or reset the reverse direction.
		// Partial input, arbitrary provider errors and earlier failures remain
		// failures; neither an EOF hint nor a peer tuple alone proves drainage.
		if err == io.EOF && input.read == 0 && x.cause == nil && !x.closed && !x.pool.closed && !flow.fenced && flow.hasTerminal && flow.observed == flow.terminal && ctx.Err() == nil {
			err = errNativeDataTerminal
			x.phase, x.closed = nativeDataIdle, true
			x.signalStateLocked()
			x.cleanupLocked()
			x.pool.mu.Unlock()
			return
		}
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = x.checkLocked()
		}
		if err == nil {
			x.phase = nativeDataReady
			if x.service != nil {
				x.service.notify()
			}
		} else {
			x.failLocked(err)
			flow.fenceLocked()
			x.clearInputLocked()
			x.phase, x.closed = nativeDataIdle, true
			x.cleanupLocked()
		}
		x.pool.mu.Unlock()
	}()
	prefix, err := ReadRecordPrefix(&input, x.maxFrame)
	if err != nil {
		return err
	}
	if protocolv4.FrameType(prefix.bytes[4]) != protocolv4.FrameStreamData {
		return protocolv4.ErrRecordScope
	}
	x.pool.mu.Lock()
	if err = x.checkLocked(); err != nil {
		x.pool.mu.Unlock()
		return err
	}
	promise := flow.limit - flow.observed.Offset
	bound, boundErr := x.bounds.MaximumEnvelope(promise)
	upper, upperErr := x.bounds.PayloadUpper(prefix.RequiredBytes())
	if boundErr != nil || upperErr != nil || prefix.RequiredBytes() > bound {
		x.pool.mu.Unlock()
		return ErrCredit
	}
	length, claim := prefix.RequiredBytes(), min(promise, upper)
	headerBytes := min(length, len(x.header))
	ringBytes := length - headerBytes
	if uint64(ringBytes) > claim || ringBytes > len(flow.storage)-flow.size {
		x.pool.mu.Unlock()
		return ErrCredit
	}
	x.length, x.claim, x.headerBytes, x.ringBytes = length, claim, headerBytes, ringBytes
	if x.ringBytes != 0 {
		x.ringStart = (flow.head + flow.size) % len(flow.storage)
	}
	copy(x.header, prefix.bytes[:])
	first, second, third := x.segmentsLocked()
	x.pool.mu.Unlock()
	for _, part := range [][]byte{first[protocolv4.EnvelopePrefixSize:], second, third} {
		if _, err := io.ReadFull(&input, part); err != nil {
			return err
		}
	}
	return nil
}

func (x *NativeDataAssembly) segmentsLocked() ([]byte, []byte, []byte) {
	if x.ringBytes == 0 {
		return x.header[:x.headerBytes], nil, nil
	}
	first := min(x.ringBytes, len(x.flow.storage)-x.ringStart)
	return x.header[:x.headerBytes], x.flow.storage[x.ringStart : x.ringStart+first], x.flow.storage[:x.ringBytes-first]
}

// Authenticate borrows a shared full-frame receiver only after Read completes.
// No-capacity refusal retains the same original candidate for a later service
// turn. Every actual decode/crypto failure ends this owner without key retry.
func (x *NativeDataAssembly) Authenticate(ctx context.Context, receiver *RecordReceiver) (err error) {
	return x.authenticate(ctx, receiver, nil)
}

func (x *NativeDataAssembly) authenticate(ctx context.Context, receiver *RecordReceiver, service *NativeAuthService) (err error) {
	if ctx == nil || receiver == nil {
		return cryptov4.ErrConfiguration
	}
	x.pool.mu.Lock()
	if x.service != service {
		x.pool.mu.Unlock()
		return cryptov4.ErrConfiguration
	}
	if err = x.checkLocked(); err != nil {
		x.pool.mu.Unlock()
		return err
	}
	flow := x.flow
	if x.phase != nativeDataReady || receiver.engine != flow.engine || receiver.direction != flow.direction || receiver.maxFrame != x.maxFrame {
		x.pool.mu.Unlock()
		return cryptov4.ErrConfiguration
	}
	if err = x.reservation.CheckSameEnvironment(receiver.reservation); err != nil {
		x.pool.mu.Unlock()
		return err
	}
	x.phase = nativeDataAuthenticating
	first, second, third := x.segmentsLocked()
	x.pool.mu.Unlock()
	defer func() {
		x.pool.mu.Lock()
		if (errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, cryptov4.ErrInputPending)) && !x.closed && !flow.fenced && !x.pool.closed {
			x.phase = nativeDataReady
			x.pool.mu.Unlock()
			return
		}
		x.clearInputLocked()
		x.phase = nativeDataIdle
		if err != nil {
			x.failLocked(err)
			flow.fenceLocked()
			x.closed = true
		} else {
			x.authenticated = true
		}
		x.signalStateLocked()
		x.cleanupLocked()
		x.pool.mu.Unlock()
	}()
	// The fixed prefix and record header are entirely inside H_DATA. Parsing
	// below uses the receiver's assembled copy; an untrusted foreign scope must
	// never select another direction's key merely because this carrier read it.
	record, err := receiver.receiveNativeSegments(ctx, flow.scope, first, second, third, func(frame *protocolv4.Frame) error {
		// Semantic failure cannot advance the crypto receive sequence. The
		// original flow gate is checked again at the actual plaintext transfer.
		return flow.applyDataMode(frame, x, false)
	})
	if err != nil {
		return err
	}
	defer record.Release()
	frame, err := record.Body()
	if err != nil {
		return err
	}
	if err := flow.engine.ApplicationInputReady(frame.Header.Epoch); err != nil {
		return err
	}
	x.pool.mu.Lock()
	err = x.checkLocked()
	if err == nil {
		x.clearInputLocked()
	}
	x.pool.mu.Unlock()
	if err != nil {
		return err
	}
	if err = flow.applyData(frame, x); err != nil {
		return err
	}
	return record.accepted()
}

func (x *NativeDataAssembly) clearInputLocked() {
	clear(x.header)
	if x.ringBytes != 0 {
		first := min(x.ringBytes, len(x.flow.storage)-x.ringStart)
		clear(x.flow.storage[x.ringStart : x.ringStart+first])
		clear(x.flow.storage[:x.ringBytes-first])
	}
	x.length, x.headerBytes, x.ringStart, x.ringBytes, x.claim = 0, 0, 0, 0, 0
}

func (x *NativeDataAssembly) Close() {
	x.pool.mu.Lock()
	defer x.pool.mu.Unlock()
	x.closed = true
	x.signalStateLocked()
	// Losing an unverified candidate or ending an unfinished native reader
	// cannot allow a replacement owner to restart at a different byte. A clean
	// post-terminal close preserves authenticated data still awaiting Read.
	if x.flow != nil && (!x.flow.hasTerminal || x.flow.observed != x.flow.terminal) {
		x.flow.fenceLocked()
	}
	x.reservation.Seal()
	x.cleanupLocked()
}

func (x *NativeDataAssembly) cleanupLocked() {
	if !x.closed || x.cleaned || x.readerActive || x.phase == nativeDataReading || x.phase == nativeDataAuthenticating {
		return
	}
	x.clearInputLocked()
	x.flow.assembly = nil
	x.flow.notifyCleanupLocked()
	x.flow = nil
	x.header = nil
	x.cleaned = true
	close(x.done)
}

// The enclosing native service retires this owner after its original reader,
// authentication and cleanup wait tasks have returned.
func (x *NativeDataAssembly) retire() error {
	x.pool.mu.Lock()
	service := x.service
	x.pool.mu.Unlock()
	if service != nil {
		if err := service.detach(x); err != nil {
			return err
		}
	}
	x.pool.mu.Lock()
	defer x.pool.mu.Unlock()
	if !x.cleaned {
		return cryptov4.ErrCapacity
	}
	x.reservation.Release()
	return nil
}

func (x *NativeDataAssembly) signalStateLocked() {
	select {
	case x.stateWake <- struct{}{}:
	default:
	}
}

func (x *NativeDataAssembly) failLocked(err error) {
	if x.cause == nil {
		x.cause = err
		if x.flow != nil {
			x.flow.termination.start(true, err)
		}
	}
	x.signalStateLocked()
}

// Only the original native reader task waits here. Application Read waits use
// the independently bounded receive queue and never retain an auth position.
func (x *NativeDataAssembly) waitAuthenticated(ctx context.Context) error {
	for {
		x.pool.mu.Lock()
		authenticated, closed, cause := x.authenticated, x.closed, x.cause
		x.pool.mu.Unlock()
		if authenticated {
			return nil
		}
		if cause != nil {
			return cause
		}
		if closed {
			return ErrFlowClosed
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-x.stateWake:
		}
	}
}

func (x *NativeDataAssembly) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-x.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
