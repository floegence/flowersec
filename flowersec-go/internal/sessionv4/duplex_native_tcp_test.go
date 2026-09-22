package sessionv4

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type nativeBridgeFixture struct {
	*bridgeFixture
	native  *NativeTCP
	peerTCP *net.TCPConn
}

func newNativeBridgeFixture(t *testing.T, capacity, timeout uint64) *nativeBridgeFixture {
	return newNativeBridgeFixtureChunk(t, capacity, timeout, 4)
}

func newNativeBridgeFixtureChunk(t *testing.T, capacity, timeout, chunk uint64) *nativeBridgeFixture {
	t.Helper()
	b := &bridgeFixture{options: DuplexOptions{ChunkBytes: chunk, TimeoutMS: timeout, CleanupTimeoutMS: 35, RuntimeBytes: 256 * 1024}}
	f := &nativeBridgeFixture{bridgeFixture: b}
	nativeOptions := NativeTCPOptions{RuntimeBytes: 64 * 1024, ProviderBytes: 256 * 1024}
	dialOptions := NativeTCPDialOptions{TimeoutMS: 3000, CleanupTimeoutMS: 35, RuntimeBytes: 256 * 1024, Endpoint: nativeOptions}
	bridgeCharge, _ := DuplexBridgeCharge(b.options)
	chunkCharge, _ := CopyCharge(b.options.ChunkBytes)
	socketCharge, _ := NativeTCPCharge(nativeOptions)
	dialCharge, _ := NativeTCPDialCharge(dialOptions)
	extra := []resourcev4.Vector{bridgeCharge, chunkCharge, chunkCharge, StreamOwnershipCharge(), NativeTCPOwnershipCharge(), socketCharge, dialCharge, NativeTCPOwnershipCharge(), {}, {}, {}, {}, {}, {}, {}, {}}
	b.serviceFixture = newServiceFixtureResources(t, 1, [3]uint32{1}, capacity, 2, testAuthorization{}, true, extra)
	b.options.HardDeadline = streamTestDeadline(t, b.local.engine)
	dialOptions.HardDeadline = b.options.HardDeadline
	b.reservation = b.reserve(t, bridgeCharge)
	b.ownership = [2]resourcev4.Reference{b.reserve(t, StreamOwnershipCharge()), b.reserve(t, NativeTCPOwnershipCharge())}
	b.chunks = [2]resourcev4.Reference{b.reserve(t, chunkCharge), b.reserve(t, chunkCharge)}
	for _, ref := range []resourcev4.Reference{b.reservation, b.ownership[0], b.ownership[1], b.chunks[0], b.chunks[1]} {
		t.Cleanup(ref.Release)
	}
	b.writers[0] = &serviceTestWriter{frames: make(chan []byte, 16)}
	b.queues[0], b.peers[0] = b.open(t, BusinessStream, 64, b.writers[0])
	b.h[0] = OpenHandle{b.local.admission, b.flows[0].receive.scope}
	listener := nativeListener(t)
	dial, err := StartNativeTCPDial(context.Background(), b.local.engine.Clock(), listener.Addr().(*net.TCPAddr).AddrPort(), dialOptions, b.reserve(t, dialCharge), b.reserve(t, socketCharge))
	if err != nil {
		t.Fatal(err)
	}
	f.native, err = nativeWait(t, dial)
	if err != nil {
		t.Fatal(err)
	}
	waitNativeDone(t, dial.Done())
	f.peerTCP, err = listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.peerTCP.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() {
		if b.bridge != nil {
			b.bridge.Abort()
			b.local.admission.Close()
			waitNativeDone(t, b.bridge.Done())
			_, _ = b.bridge.Wait(context.Background())
		}
		_ = f.native.Close()
		_ = f.peerTCP.Close()
	})
	return f
}

func (f *nativeBridgeFixture) construct(t *testing.T, ctx context.Context) *DuplexBridge {
	t.Helper()
	var err error
	f.bridge, err = NewNativeDuplexBridge(ctx, f.h[0], f.native, f.options, f.reservation, f.ownership, f.chunks)
	if err != nil {
		t.Fatal(err)
	}
	return f.bridge
}

func TestNativeDuplexBridgeHalfCloseAndDistinctSendGuarantees(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	f.options.CleanupTimeoutMS = 500
	f.run(t)
	d := f.construct(t, context.Background())
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	f.input(t, 0, "request", true)
	request, err := io.ReadAll(f.peerTCP)
	if err != nil || string(request) != "request" {
		t.Fatal(string(request), err)
	}
	if d.Progress().Final {
		t.Fatal("native FIN prematurely ended reverse exchange")
	}
	if _, err := f.peerTCP.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := f.peerTCP.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := f.receiveFIN(t, 0); got != "reply" {
		t.Fatal(got)
	}
	select {
	case <-d.ready:
		t.Fatal("native shutdown replaced authenticated Flowersec drainage")
	default:
	}
	if _, err := f.peer.admission.PublishDrained(context.Background(), OpenHandle{f.peer.admission, f.h[0].scope}, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
	if _, err := f.local.admission.PublishDrained(context.Background(), f.h[0], f.local.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.peer, f.local.control.Bytes())
	f.local.control.Reset()
	r, err := waitBridge(t, d)
	if err != nil || r.Result.Outcome != protocolv4.V4DuplexOutcomeNormal {
		t.Fatal(r, err)
	}
	a, b := r.Result.AToB, r.Result.BToA
	if a.SendResult.EndpointKind != protocolv4.V4DuplexEndpointKindNativeDuplex || a.SendResult.SendDrained != nil || a.SendResult.NativeSendFinished == nil || !*a.SendResult.NativeSendFinished {
		t.Fatal(a)
	}
	if b.SendResult.EndpointKind != protocolv4.V4DuplexEndpointKindFlowersecStream || b.SendResult.NativeSendFinished != nil || b.SendResult.SendDrained == nil || !*b.SendResult.SendDrained {
		t.Fatal(b)
	}
	if a.Progress.SourceReadBytes != 7 || a.Progress.DestinationAcceptedBytes != 7 || b.Progress.SourceReadBytes != 5 || b.Progress.DestinationAcceptedBytes != 5 {
		t.Fatal(a, b)
	}
	waitNativeDone(t, d.Done())
	again, err := d.Wait(context.Background())
	if err != nil || again.Result != r.Result || d.natives[1] != nil || f.native.clock != nil || f.native.conn != nil {
		t.Fatal("native result retained original graph", again, err)
	}
}

func TestNativeDuplexBridgeAbortPreservesExactUnacceptedTail(t *testing.T) {
	f := newNativeBridgeFixture(t, 2, 3000)
	if _, err := f.peerTCP.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	d := f.construct(t, context.Background())
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(3 * time.Second)
	for {
		p := d.Progress().BToA
		if p.DestinationAcceptedBytes == 2 && p.PendingTailBytes > 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("native input did not reach original Stream backpressure", p)
		}
		runtime.Gosched()
	}
	d.Abort()
	r, err := d.Wait(context.Background())
	if !errors.Is(err, ErrDuplexAborted) {
		t.Fatal(r, err)
	}
	if !r.Final {
		f.local.admission.Close()
		waitNativeDone(t, d.Done())
		r, err = d.Wait(context.Background())
	}
	if r.Result == nil || r.Result.Outcome != protocolv4.V4DuplexOutcomeAborted {
		t.Fatal(r, err)
	}
	p := r.Result.BToA.Progress
	if p.DestinationAcceptedBytes != 2 || p.SourceReadBytes != uint64(2+len(p.UnacceptedTail)) || string(p.UnacceptedTail) != "abcd"[2:p.SourceReadBytes] {
		t.Fatal(p)
	}
	waitNativeDone(t, f.native.Done())
	f.local.admission.Close()
	waitNativeDone(t, d.Done())
	again, _ := d.Wait(context.Background())
	if again.Result != r.Result {
		t.Fatal("repeat observation copied result")
	}
}

func TestNativeDuplexBridgeCanonicalValueAliasesCannotOwnOrCloseTwice(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	duplicate := *f.native
	d := f.construct(t, context.Background())
	if _, err := duplicate.own(resourcev4.Reference{}, d.deadline, context.Background()); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("value alias bypassed canonical claim", err)
	}
	if err := duplicate.Close(); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("value alias closed owned socket", err)
	}
	d.Abort()
	waitNativeDone(t, f.native.Done())
	f.local.admission.Close()
	waitNativeDone(t, d.Done())
}

func TestNativeDuplexBridgeUnstartedAndBlockedReadExpire(t *testing.T) {
	for _, start := range []bool{false, true} {
		t.Run(map[bool]string{false: "unstarted", true: "blocked read"}[start], func(t *testing.T) {
			f := newNativeBridgeFixture(t, 8, 50)
			d := f.construct(t, context.Background())
			if start {
				if err := d.Start(); err != nil {
					t.Fatal(err)
				}
			}
			r, err := d.Wait(context.Background())
			if !errors.Is(err, timev4.ErrExpired) || r.Outcome != protocolv4.V4DuplexOutcomeFailed {
				t.Fatal(r, err)
			}
			waitNativeDone(t, f.native.Done())
			f.local.admission.Close()
			waitNativeDone(t, d.Done())
			r, err = d.Wait(context.Background())
			if r.Result == nil || r.Result.BToA.Progress.SourceReadBytes != 0 || !errors.Is(err, timev4.ErrExpired) {
				t.Fatal(r, err)
			}
		})
	}
}

func TestNativeCopyCommitsNonzeroReadFailureAndEOF(t *testing.T) {
	for _, cause := range []error{io.EOF, io.ErrUnexpectedEOF} {
		s := &copyState{storage: []byte("abcd"), sourceRead: 7, targetTaken: 7}
		terminal, err := s.commitNativeRead(4, cause)
		r := s.result(terminal)
		if r.Progress.SourceReadBytes != 11 || r.Progress.DestinationAcceptedBytes != 7 || string(r.Progress.UnacceptedTail) != "abcd" {
			t.Fatal(r)
		}
		if cause == io.EOF && (err != nil || terminal != protocolv4.V4ReadTerminalEof) {
			t.Fatal(terminal, err)
		}
		if cause != io.EOF && !errors.Is(err, ErrNativeTCPFailure) {
			t.Fatal(err)
		}
	}
}

func TestNativeDuplexBridgeFreezesCanonicalCoreDespiteCallerHandleReplacement(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	original := *f.native
	d := f.construct(t, context.Background())
	*f.native = NativeTCP{}
	defer func() { *f.native = original }()
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	d.Abort()
	waitNativeDone(t, original.Done())
	f.local.admission.Close()
	waitNativeDone(t, d.Done())
	if original.owner != nil || original.conn != nil {
		t.Fatal("replacing caller wrapper redirected original cleanup")
	}
}

func TestNativeDuplexBridgeDestinationFailureWakesIdleNativeRead(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	d := f.construct(t, context.Background())
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	waitReadAdmitted(t, f.flows[0].receive)
	f.queues[0].Stop(ErrTerminal)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := d.Wait(ctx)
	if !errors.Is(err, ErrTerminal) || r.Outcome != protocolv4.V4DuplexOutcomeFailed {
		t.Fatal("destination failure became delayed timeout", r, err)
	}
	waitNativeDone(t, f.native.Done())
	f.local.admission.Close()
	waitNativeDone(t, d.Done())
	r, err = d.Wait(context.Background())
	if !errors.Is(err, ErrTerminal) || r.Result == nil || r.Result.BToA.Progress.SourceReadBytes != 0 {
		t.Fatal(r, err)
	}
}

func TestNativeDuplexBridgeCleanupDeadlineDoesNotJoinDelayedPumps(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	d, tasks, err := prepareDuplexBridge(context.Background(), f.h[0], OpenHandle{}, f.native, f.options, f.reservation, f.ownership, f.chunks)
	if err != nil {
		t.Fatal(err)
	}
	f.bridge = d
	var once sync.Once
	launch := func() {
		once.Do(func() {
			for i := range 2 {
				go d.worker(i, tasks.context, tasks.workers[i])
			}
		})
	}
	t.Cleanup(launch)
	d.Abort()
	before := f.root.Snapshot().Charged
	timer := time.NewTimer(2 * time.Duration(f.options.CleanupTimeoutMS) * time.Millisecond)
	<-timer.C
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := d.Wait(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// An expired canceled observer must not consume the supervisor's one
	// incomplete notification before any actual pump has run.
	// The original task reservations exist, but the runtime has not scheduled
	// either pump. The supervisor still owes a bounded cleanup observation.
	go d.supervise(context.Background(), d.clock, d.cleanupMS, tasks.supervisor)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := d.Wait(ctx)
	if !errors.Is(err, ErrDuplexAborted) || r.Final || r.Result != nil || r.CleanupStatus.Status != protocolv4.V4CleanupStateCleanupIncomplete {
		t.Fatal("cleanup observation waited for actual pumps", r, err)
	}
	after := f.root.Snapshot().Charged
	if after[resourcev4.NativeHandles] != before[resourcev4.NativeHandles] || after[resourcev4.Tasks] != before[resourcev4.Tasks] {
		t.Fatal("pending pump refunded its real charge", before, after)
	}
	if d.copies[0].storage == nil || d.copies[1].storage == nil {
		t.Fatal("live chunks detached before actual task exit")
	}
	launch()
	f.local.admission.Close()
	waitNativeDone(t, d.Done())
	r, err = d.Wait(context.Background())
	if !errors.Is(err, ErrDuplexAborted) || !r.Final || r.Result == nil || r.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal("actual late exits did not publish final owner", r, err)
	}
	again, _ := d.Wait(context.Background())
	if again.Result != r.Result {
		t.Fatal("late result was copied")
	}
}

func nativeCopyMechanics(t *testing.T, f *nativeBridgeFixture) (*copyState, *StreamOwnership, *nativeTCPOwnership) {
	t.Helper()
	stream, err := f.h[0].owner.ownStreamContext(f.h[0], f.ownership[0], f.options.HardDeadline, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	native, err := f.native.own(f.ownership[1], f.options.HardDeadline, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state, err := prepareCopy(f.options.ChunkBytes, f.chunks[0])
	if err != nil {
		t.Fatal(err)
	}
	state.sourceOwner, state.nativeOwner = stream, native
	t.Cleanup(func() {
		_ = f.native.closeOwned(native)
		if err := native.release(); err != nil {
			t.Error(err)
		}
		if err := stream.Release(); err != nil {
			t.Error(err)
		}
		state.release()
	})
	return state, stream, native
}

func TestNativeCopyOverflowIsRejectedBeforeConsumingOrWritingSocket(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	state, stream, native := nativeCopyMechanics(t, f)
	conn, err := native.begin()
	if err != nil {
		t.Fatal(err)
	}
	defer native.end()
	state.sourceRead = math.MaxUint64
	if _, err := f.peerTCP.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := state.readNative(context.Background(), conn, stream); !errors.Is(err, ErrStreamData) {
		t.Fatal("overflowing source read was admitted", err)
	}
	var byteRead [1]byte
	if _, err := io.ReadFull(conn, byteRead[:]); err != nil || byteRead[0] != 'x' {
		t.Fatal("overflow consumed source bytes", byteRead, err)
	}
	state.targetTaken, state.filled = math.MaxUint64, 4
	copy(state.storage, "abcd")
	if err := state.writeNative(context.Background(), conn); !errors.Is(err, ErrStreamData) {
		t.Fatal("overflowing native write was admitted", err)
	}
	_ = f.peerTCP.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := f.peerTCP.Read(byteRead[:]); err == nil || !err.(net.Error).Timeout() {
		t.Fatal("overflow wrote destination bytes", byteRead, err)
	}
}

func TestNativeCopyPartialSocketWriteCommitsPrefixBeforeError(t *testing.T) {
	f := newNativeBridgeFixtureChunk(t, 8, 3000, 8*1024*1024)
	state, _, native := nativeCopyMechanics(t, f)
	conn, err := native.begin()
	if err != nil {
		t.Fatal(err)
	}
	defer native.end()
	_ = conn.SetWriteBuffer(1024)
	_ = f.peerTCP.SetReadBuffer(1024)
	for i := range state.storage {
		state.storage[i] = 'x'
	}
	backing := state.storage
	state.filled, state.sourceRead = len(backing), uint64(len(backing))
	finished := make(chan error, 1)
	go func() { finished <- state.writeNative(context.Background(), conn) }()
	// Real receive proves an irreversible prefix before waking the blocked write.
	var prefix [1]byte
	if _, err := io.ReadFull(f.peerTCP, prefix[:]); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Unix(1, 0))
	select {
	case err := <-finished:
		if !errors.Is(err, ErrNativeTCPFailure) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("native write did not leave netpoll")
	}
	r := state.result(protocolv4.V4ReadTerminalOpen)
	accepted := r.Progress.DestinationAcceptedBytes
	if accepted == 0 || accepted >= uint64(len(backing)) || r.Progress.SourceReadBytes != uint64(len(backing)) || len(r.Progress.UnacceptedTail) != len(backing)-int(accepted) {
		t.Fatal(r.Progress)
	}
	if &r.Progress.UnacceptedTail[0] != &backing[accepted] || r.Progress.UnacceptedTail[0] != 'x' {
		t.Fatal("partial native write copied or lost exact suffix")
	}
}

func TestNativeDuplexBusyNativeClaimRollsBackStreamWithoutReset(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	blockerRef := f.reserve(t, NativeTCPOwnershipCharge())
	t.Cleanup(blockerRef.Release)
	blocker, err := f.native.own(blockerRef, f.options.HardDeadline, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.release()
	if _, err := NewNativeDuplexBridge(context.Background(), f.h[0], f.native, f.options, f.reservation, f.ownership, f.chunks); !errors.Is(err, ErrStreamOwned) {
		t.Fatal(err)
	}
	if f.flows[0].receive.readOwner != nil || f.queues[0].writeOwner != nil {
		t.Fatal("failed construction retained canonical Stream claim")
	}
	if n, err := f.queues[0].Write(context.Background(), []byte("x")); n != 1 || err != nil {
		t.Fatal("rollback reset original Stream", n, err)
	}
}

func TestNativeDuplexBridgeCleanupIncludesPausedObserver(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	d := f.construct(t, context.Background())
	ctx := &nativePausedObserver{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	observed := make(chan DuplexObservation, 1)
	go func() { r, _ := d.Wait(ctx); observed <- r }()
	waitNativeDone(t, ctx.entered)
	d.Abort()
	f.local.admission.Close()
	end := time.Now().Add(3 * time.Second)
	for {
		d.mu.Lock()
		finished := d.complete
		d.mu.Unlock()
		if finished {
			break
		}
		if time.Now().After(end) {
			close(ctx.release)
			t.Fatal("actual lifecycle workers did not exit")
		}
		runtime.Gosched()
	}
	if status := d.CleanupStatus(); status.Status == protocolv4.V4CleanupStateComplete || status.Validate() != nil {
		t.Error("invalid cleanup projection while SDK observer still owns original charge", status)
	}
	select {
	case <-d.Done():
		t.Error("Done before observer exit")
	default:
	}
	if r, err := d.Wait(context.Background()); !errors.Is(err, ErrStreamOwnershipBusy) || r.Result != nil {
		t.Error("second observer escaped original bounded handoff", r, err)
	}
	timer := time.NewTimer(2 * time.Duration(f.options.CleanupTimeoutMS) * time.Millisecond)
	<-timer.C
	if status := d.CleanupStatus(); status.Status != protocolv4.V4CleanupStateCleanupIncomplete || status.Validate() != nil {
		t.Error("observer tail lost original cleanup deadline or core pending fact", status)
	}
	close(ctx.release)
	r := <-observed
	waitNativeDone(t, d.Done())
	if r.Result == nil || d.CleanupStatus().Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(r)
	}
}

func TestNativeDuplexBridgeResetRetainsActualReadErrorTerminal(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	d := f.construct(t, context.Background())
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	_ = f.peerTCP.SetLinger(0)
	_ = f.peerTCP.Close()
	r, err := d.Wait(context.Background())
	if !errors.Is(err, ErrNativeTCPFailure) {
		t.Fatal(r, err)
	}
	if !r.Final {
		f.local.admission.Close()
		waitNativeDone(t, d.Done())
		r, err = d.Wait(context.Background())
	}
	if r.Result == nil || r.Result.BToA.SourceStatus != protocolv4.V4StreamStatusError || !errors.Is(err, ErrNativeTCPFailure) {
		t.Fatal("native read error became cleanup abandonment", r, err)
	}
}

func TestNativeCopySessionCloseFencesOriginalSocketAcceptance(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	state, _, native := nativeCopyMechanics(t, f)
	conn, err := native.begin()
	if err != nil {
		t.Fatal(err)
	}
	defer native.end()
	copy(state.storage, "data")
	state.filled, state.sourceRead = 4, 4
	f.local.engine.Close()
	if err := state.writeNative(context.Background(), conn); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("fresh native write after Session authorization closed", err)
	}
	if state.progress().DestinationAcceptedBytes != 0 {
		t.Fatal("failed admission changed progress")
	}
	_ = f.peerTCP.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	var b [1]byte
	if _, err := f.peerTCP.Read(b[:]); err == nil || !err.(net.Error).Timeout() {
		t.Fatal("closed Session published socket bytes", b, err)
	}
}

func TestNativeTCPCleanupIncludesActualMethodAlias(t *testing.T) {
	f := newNativeBridgeFixture(t, 8, 3000)
	_, _, native := nativeCopyMechanics(t, f)
	if _, err := native.begin(); err != nil {
		t.Fatal(err)
	}
	if err := f.native.closeOwned(native); err != nil {
		native.end()
		t.Fatal(err)
	}
	status := f.native.CleanupStatus()
	result, _ := native.closeResult()
	if status.Status == protocolv4.V4CleanupStateComplete || status.Validate() != nil || result.CleanupStatus.Status == protocolv4.V4CleanupStateComplete || result.CleanupStatus.Validate() != nil {
		t.Error("actual method tail projected core complete", status, result.CleanupStatus)
	}
	select {
	case <-f.native.Done():
		t.Error("native Done preceded actual admitted alias exit")
	default:
	}
	native.end()
	waitNativeDone(t, f.native.Done())
	if status := f.native.CleanupStatus(); status.Status != protocolv4.V4CleanupStateComplete || status.Validate() != nil {
		t.Fatal(status)
	}
}
