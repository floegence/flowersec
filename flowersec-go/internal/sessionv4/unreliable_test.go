package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func datagramExpiry(t *testing.T, c *SessionCore) time.Time {
	t.Helper()
	now, err := c.Engine().Clock().Sample()
	if err != nil {
		t.Fatal(err)
	}
	return time.UnixMilli(int64(now.UpperMS + 5000))
}

func TestNativeDatagramSessionBothProfilesAndRekey(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			cores, ctx := nativeTransportCorePair(t, profile, "transport", "datagrams")
			channels := [2]*UnreliableMessages{}
			for i, core := range cores {
				var err error
				channels[i], err = core.UnreliableMessages()
				if err != nil {
					t.Fatal(err)
				}
				if channels[i].MaxMessageBytes() != 949 {
					t.Fatal(channels[i].MaxMessageBytes())
				}
				channels[i].mu.Lock()
				for _, slot := range channels[i].slots {
					if slot.input != nil {
						channels[i].mu.Unlock()
						t.Fatal("idle datagram slot allocated payload backing")
					}
				}
				channels[i].mu.Unlock()
			}
			transfer := func(role, size int) {
				t.Helper()
				payload := bytes.Repeat([]byte{byte(42 + role)}, size)
				if status, err := channels[role].Send(ctx, payload, datagramExpiry(t, cores[role])); err != nil || status != UnreliableAccepted {
					t.Fatal(status, err)
				}
				got, err := channels[1-role].Receive(ctx)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal(len(got), err)
				}
			}
			transfer(0, 949)
			transfer(1, 0)
			if status, err := channels[0].Send(ctx, []byte("expired"), time.UnixMilli(1)); err != nil || status != UnreliableDroppedExpired {
				t.Fatal(status, err)
			}
			if _, err := channels[0].Send(ctx, make([]byte, 950), datagramExpiry(t, cores[0])); !errors.Is(err, ErrUnreliableTooLarge) {
				t.Fatal(err)
			}
			if err := cores[0].Rekey(ctx); err != nil {
				t.Fatal("rekey", err)
			}
			transfer(0, 128)
			transfer(1, 129)
			stream := factoryOpenPair(t, cores, ctx)
			nativeTransfer(t, ctx, stream[0], stream[1], "reliable after datagram")
			cores[0].Close()
			if _, err := channels[0].Receive(context.Background()); !errors.Is(err, cryptov4.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeDatagramNotSelectedRemainsUnavailable(t *testing.T) {
	cores, _ := nativeTransportCorePair(t, protocolv4.DHProfileX25519)
	if _, err := cores[0].UnreliableMessages(); !errors.Is(err, ErrUnreliableUnavailable) {
		t.Fatal(err)
	}
}

func TestDatagramPendingBudgetKeepsCancelledOriginalJobs(t *testing.T) {
	cores, ctx := nativeTransportCorePair(t, protocolv4.DHProfileX25519, "transport", "datagrams")
	actual, err := cores[0].UnreliableMessages()
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the actual Send admission before its worker is scheduled. The
	// existing authenticated Engine supplies the original trusted expiry clock.
	dctx, cancel := context.WithCancel(context.Background())
	d := &UnreliableMessages{engine: actual.engine, maximum: actual.maximum, slots: make([]datagramSendSlot, 64),
		jobs: make(chan int, 64), stop: make(chan struct{}), cleanup: make(chan struct{}), context: dctx, cancel: cancel}
	defer d.Close()
	callCtx, stop := context.WithCancel(ctx)
	defer stop()
	results := make(chan error, 64)
	input := []byte("pending")
	for range 64 {
		go func() { _, err := d.Send(callCtx, input, datagramExpiry(t, cores[0])); results <- err }()
	}
	for {
		d.mu.Lock()
		full := d.active == 64
		d.mu.Unlock()
		if full {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
			runtime.Gosched()
		}
	}
	// Admission has copied every original payload before incrementing active.
	// Caller reuse cannot alter queued work; cancellation cannot return any of
	// its physical backing before the original sender is retired.
	copy(input, "changed")
	var staging [64][]byte
	d.mu.Lock()
	for i := range d.slots {
		staging[i] = d.slots[i].input
		if len(staging[i]) != len(input) || cap(staging[i]) != len(input) || !bytes.Equal(staging[i], []byte("pending")) || &staging[i][0] == &input[0] {
			d.mu.Unlock()
			t.Fatal("admitted datagram did not retain its exact immutable input")
		}
	}
	d.mu.Unlock()
	if status, err := d.Send(ctx, []byte("expired"), time.UnixMilli(1)); err != nil || status != UnreliableDroppedExpired {
		t.Fatal(status, err)
	}
	if status, err := d.Send(ctx, []byte("overflow"), datagramExpiry(t, cores[0])); err != nil || status != UnreliableDroppedBudget {
		t.Fatal(status, err)
	}
	stop()
	for range 64 {
		if err := <-results; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	d.mu.Lock()
	retained := d.active
	d.mu.Unlock()
	if retained != 64 {
		t.Fatal("cancelled original jobs released before worker exit", retained)
	}
	for _, original := range staging {
		if !bytes.Equal(original, []byte("pending")) {
			t.Fatal("observer cancellation erased a retained sender payload")
		}
	}
	if status, err := d.Send(ctx, []byte("reuse"), datagramExpiry(t, cores[0])); err != nil || status != UnreliableDroppedBudget {
		t.Fatal(status, err)
	}
	d.Close()
	if err := d.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	for _, original := range staging {
		if !bytes.Equal(original, make([]byte, len(original))) {
			t.Fatal("actual sender exit retained datagram payload bytes")
		}
	}
	if string(input) != "changed" || d.slots != nil || d.active != 0 {
		t.Fatal("datagram cleanup changed caller input or kept staged owners")
	}
}
