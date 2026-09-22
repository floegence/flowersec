package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func idleEndpoints(t *testing.T, duration uint64) (*openEndpoint, *openEndpoint, *atomic.Uint64) {
	t.Helper()
	now := new(atomic.Uint64)
	clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: now.Load(), Incarnation: [16]byte{1}}, nil
	})
	return newOpenEndpointIdle(t, protocolv4.ClientToServer, 4, 2, 1, clock, duration), newOpenEndpointIdle(t, protocolv4.ServerToClient, 4, 2, 1, clock, duration), now
}

func idleRemaining(t *testing.T, e *openEndpoint, expected uint64) {
	t.Helper()
	ms, armed, err := e.engine.IdleRemainingMS()
	if err != nil || !armed || ms != expected {
		t.Fatal("idle remaining", ms, armed, err, "want", expected)
	}
}

func pingBody(t *testing.T, nonce byte) []byte {
	t.Helper()
	var storage [32]byte
	value := [16]byte{nonce}
	wire, err := protocolv4.EncodeMap(storage[:], "PING", []protocolv4.Field{{Name: "nonce", Kind: protocolv4.ByteString, Bytes: value[:]}})
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(wire)
}

func TestIdleRequiresProtocolLegalData(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid_offset", true: "valid_held_data"}[valid], func(t *testing.T) {
			client, server, now := idleEndpoints(t, 100)
			local, peer, _, native := startTestOpen(t, client, server, 32)
			if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 32), server.maintenance); err != nil {
				t.Fatal(err)
			}
			applyTestOutcome(t, server, client)
			out, _ := client.admission.Flow(local)
			in, _ := server.admission.Flow(peer)
			now.Store(70)
			offset := uint64(1)
			if valid {
				offset = 0
			}
			if _, err := out.send.writer.WriteData(context.Background(), protocolv4.ClientToServer, offset, false, []byte("data"), 128); err != nil {
				t.Fatal(err)
			}
			r, err := server.receiver.Read(context.Background(), native)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Release()
			idleRemaining(t, server, 30) // AEAD alone is insufficient.
			err = in.Apply(r)
			if !valid {
				if !errors.Is(err, ErrStreamData) {
					t.Fatal(err)
				}
				now.Store(100)
				if _, _, err := server.engine.IdleRemainingMS(); !errors.Is(err, cryptov4.ErrIdle) {
					t.Fatal("invalid DATA kept Session alive", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			idleRemaining(t, server, 100) // App has not consumed its queue.
			now.Store(90)
			if err = r.accepted(); err != nil {
				t.Fatal(err)
			}
			idleRemaining(t, server, 80)
			data := make([]byte, 4)
			if n, _, err := in.receive.TryRead(data); err != nil || n != 4 || string(data) != "data" {
				t.Fatal(n, err)
			}
			idleRemaining(t, server, 80) // App callbacks/reads do not refresh.
			now.Store(170)
			if _, _, err := server.engine.IdleRemainingMS(); !errors.Is(err, cryptov4.ErrIdle) {
				t.Fatal("repeated acceptance refreshed the original packet", err)
			}
		})
	}
}

type idleWriterFunc func([]byte) (int, error)

func (f idleWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestIdleProviderHandoffKeepsPartialAndLateFacts(t *testing.T) {
	for _, mode := range []string{"complete", "partial", "late_complete", "complete_error"} {
		t.Run(mode, func(t *testing.T) {
			client, _, now := idleEndpoints(t, 100)
			now.Store(60)
			calls := 0
			provider := idleWriterFunc(func(p []byte) (int, error) {
				calls++
				switch mode {
				case "partial":
					now.Add(30)
					return 1, nil
				case "late_complete":
					now.Store(100)
				case "complete_error":
					return len(p), io.ErrClosedPipe
				}
				return len(p), nil
			})
			writer, err := NewRecordWriter(client.engine, 0, provider)
			if err != nil {
				t.Fatal(err)
			}
			result, err := writer.Write(context.Background(), protocolv4.FramePing, pingBody(t, 1))
			if !result.Submitted {
				t.Fatal("actual ticket lost", result, err)
			}
			switch mode {
			case "complete":
				if err != nil || !result.Complete || calls != 1 {
					t.Fatal(result, err, calls)
				}
				idleRemaining(t, client, 100)
			case "partial":
				if !errors.Is(err, cryptov4.ErrIdle) || result.Complete || result.EnvelopeBytes != 2 || calls != 2 {
					t.Fatal("partial writes refreshed idle", result, err, calls)
				}
			case "late_complete":
				if !errors.Is(err, cryptov4.ErrIdle) || !result.Complete || result.EnvelopeBytes == 0 {
					t.Fatal("late completion revived or erased actual handoff", result, err)
				}
			case "complete_error":
				if !errors.Is(err, io.ErrClosedPipe) || !result.Complete {
					t.Fatal(result, err)
				}
				idleRemaining(t, client, 40)
			}
		})
	}
}

func TestIdleDatagramReplayAndForgedMessage(t *testing.T) {
	client, server, now := idleEndpoints(t, 100)
	now.Store(50)
	p, err := client.engine.SealBuild(protocolv4.FrameDatagram, protocolv4.DatagramScope(), 64, func(h protocolv4.RecordHeader, dst []byte) (int, error) {
		body, err := protocolv4.EncodeMap(dst, "DATAGRAM", []protocolv4.Field{{Name: "epoch", Number: uint64(h.Epoch)}, {Name: "sequence", Number: h.Sequence}, {Name: "scope", Number: h.Scope}, {Name: "data", Kind: protocolv4.ByteString, Bytes: []byte("dg")}})
		return len(body), err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Release()
	wire, err := p.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r, err := server.receiver.Receive(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.AcceptMessage(); err != nil {
		t.Fatal(err)
	}
	r.Release()
	idleRemaining(t, server, 100)
	now.Store(140)
	if _, err = server.receiver.Receive(context.Background(), wire); !errors.Is(err, cryptov4.ErrReplay) {
		t.Fatal(err)
	}
	idleRemaining(t, server, 10)
	now.Store(150)
	if _, _, err = server.engine.IdleRemainingMS(); !errors.Is(err, cryptov4.ErrIdle) {
		t.Fatal(err)
	}

	client, server, now = idleEndpoints(t, 100)
	now.Store(90)
	if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 2)); err != nil {
		t.Fatal(err)
	}
	forged := bytes.Clone(client.control.Bytes())
	forged[len(forged)-1] ^= 1
	if _, err = server.receiver.Receive(context.Background(), forged); !errors.Is(err, cryptov4.ErrAuthentication) {
		t.Fatal(err)
	}
	idleRemaining(t, server, 10)
	if r, err = server.receiver.Receive(context.Background(), client.control.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err = r.AcceptMessage(); err != nil {
		t.Fatal(err)
	}
	r.Release()
	idleRemaining(t, server, 100)
}

func TestIdleWatchdogExpiresWithoutTrafficAndHasOneWorker(t *testing.T) {
	e := newOpenEndpointIdle(t, protocolv4.ClientToServer, 2, 2, 1, sessionTestClock(t), 50)
	w, err := NewIdleWatchdog(e.admission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewIdleWatchdog(e.admission); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("second timer owner", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = w.Run(ctx); !errors.Is(err, cryptov4.ErrIdle) {
		t.Fatal("silent Session did not expire", err)
	}
	select {
	case <-e.engine.Done():
	default:
		t.Fatal("watchdog did not close original engine")
	}
	if err = w.Run(ctx); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("watchdog restarted", err)
	}
	if idleTimerChunk(math.MaxUint64) <= 0 || idleTimerChunk(math.MaxUint64) != time.Duration(math.MaxInt64/int64(time.Millisecond))*time.Millisecond {
		t.Fatal("unsigned duration narrowed")
	}
}

func TestIdleRekeyAndDrainDoNotRestartOriginalWindow(t *testing.T) {
	client, server, now := idleEndpoints(t, 100)
	c, s := exchange(t, client), exchange(t, server)
	now.Store(70)
	if _, err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	exchangeProgress(t, c)
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	idleRemaining(t, client, 100)
	idleRemaining(t, server, 100)
	now.Store(120)
	client.admission.Drain()
	server.admission.Drain()
	idleRemaining(t, client, 50)
	idleRemaining(t, server, 50)
	now.Store(170)
	if _, _, err := client.engine.IdleRemainingMS(); !errors.Is(err, cryptov4.ErrIdle) {
		t.Fatal("new epoch/Drain reset last real activity", err)
	}
}

func TestIdleClosePreservesEOFAndActualProviderCleanup(t *testing.T) {
	client, server, now := idleEndpoints(t, 100)
	local, peer, _, native := startTestOpen(t, client, server, 32)
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 32), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	out, _ := client.admission.Flow(local)
	in, _ := server.admission.Flow(peer)
	if _, err := out.send.Write(context.Background(), []byte("done"), true); err != nil {
		t.Fatal(err)
	}
	r, err := server.receiver.Read(context.Background(), native)
	if err != nil {
		t.Fatal(err)
	}
	if err = in.Apply(r); err != nil {
		t.Fatal(err)
	}
	r.Release()
	if n, terminal, err := in.receive.TryRead(make([]byte, 4)); n != 4 || terminal != protocolv4.V4ReadTerminalEof || err != nil {
		t.Fatal(n, terminal, err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	in.send.writer.writer = idleWriterFunc(func(p []byte) (int, error) {
		close(entered)
		<-release
		return len(p), nil
	})
	type outcome struct {
		result RecordWriteResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := in.send.Write(context.Background(), []byte("pending"), false)
		done <- outcome{result, err}
	}()
	<-entered
	now.Store(100)
	w, err := NewIdleWatchdog(server.admission)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Run(context.Background()); !errors.Is(err, cryptov4.ErrIdle) {
		t.Fatal(err)
	}
	result := in.CloseResult()
	if result.ReadTerminal != protocolv4.V4ReadTerminalEof || result.SendDrained || result.CleanupStatus.Status != protocolv4.V4CleanupStatePending {
		t.Fatal("idle close rewrote established facts or cleanup", result)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = server.admission.CleanupStream(cancelled, peer); !errors.Is(err, context.Canceled) {
		t.Fatal("timer released actual provider tail", err)
	}
	close(release)
	actual := <-done
	if !actual.result.Submitted || !actual.result.Complete || !errors.Is(actual.err, cryptov4.ErrClosed) {
		t.Fatal("late actual handoff facts lost", actual)
	}
	if err = server.admission.CleanupStream(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if result = in.CloseResult(); result.ReadTerminal != protocolv4.V4ReadTerminalEof || result.SendDrained || result.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(result)
	}
}

func TestIdleLateTimerCannotDeliverBufferedData(t *testing.T) {
	client, server, now := idleEndpoints(t, 100)
	local, peer, _, native := startTestOpen(t, client, server, 32)
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 32), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	out, _ := client.admission.Flow(local)
	in, _ := server.admission.Flow(peer)
	if _, err := out.send.Write(context.Background(), []byte("buffered"), false); err != nil {
		t.Fatal(err)
	}
	r, err := server.receiver.Read(context.Background(), native)
	if err != nil {
		t.Fatal(err)
	}
	if err = in.Apply(r); err != nil {
		t.Fatal(err)
	}
	r.Release()
	now.Store(100)
	if n, _, err := in.receive.TryRead(make([]byte, 8)); n != 0 || !errors.Is(err, cryptov4.ErrIdle) {
		t.Fatal("late watchdog allowed application delivery", n, err)
	}
	if in.receive.size != 8 {
		t.Fatal("blocked read consumed original backing")
	}
}

func TestIdleDisabledDoesNotDisableAuthorization(t *testing.T) {
	client, _, now := idleEndpoints(t, 0)
	now.Store(3600000)
	if _, armed, err := client.engine.IdleRemainingMS(); err != nil || armed {
		t.Fatal("zero signed idle enabled default", armed, err)
	}
	if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 1)); !errors.Is(err, cryptov4.ErrExpired) {
		t.Fatal("idle zero bypassed original authorization deadline", err)
	}
}
