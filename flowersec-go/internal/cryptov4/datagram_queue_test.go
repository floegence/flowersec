package cryptov4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func datagramQueuePair(t *testing.T, profile string, slots int) (*Engine, *Engine, *DatagramQueue, *DatagramQueue) {
	t.Helper()
	mask, err := protocolv4.DatagramFeatureMask()
	if err != nil {
		t.Fatal(err)
	}
	c, s, _ := enginePair(t, profile, func(c *Config) { c.Features = mask; c.WorkSlots = 6 })
	queues := [2]*DatagramQueue{}
	for i, e := range []*Engine{c, s} {
		queues[i], err = e.NewDatagramQueue(make([]byte, slots*949), slots, 949)
		if err != nil {
			t.Fatal(err)
		}
	}
	return c, s, queues[0], queues[1]
}

func datagramPayload(_ protocolv4.RecordHeader, p []byte) ([]byte, error) { return p, nil }

func TestDatagramQueueFullConsumesReplayAndPreservesCryptoIsolation(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			c, s, _, q := datagramQueuePair(t, profile, 1)
			first := sealed(t, c, protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("first"))
			dropped := sealed(t, c, protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("full"))
			if err := q.Open(first, datagramPayload); err != nil {
				t.Fatal(err)
			}
			if err := q.Open(dropped, datagramPayload); err != nil {
				t.Fatal(err)
			}
			out := make([]byte, 949)
			if n, ok, err := q.Take(context.Background(), out); err != nil || !ok || string(out[:n]) != "first" {
				t.Fatal(n, ok, err)
			}
			if err := q.Open(dropped, datagramPayload); !errors.Is(err, ErrReplay) {
				t.Fatal("queue drop refunded replay", err)
			}
			if _, ok, err := q.Take(context.Background(), out); err != nil || ok {
				t.Fatal("queue drop delivered later", ok, err)
			}
			p, err := c.Seal(protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("held provider output"))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Release()
			if _, err = c.Seal(protocolv4.FrameDatagram, protocolv4.DatagramScope(), nil); !errors.Is(err, ErrCapacity) {
				t.Fatal("datagram lane borrowed ordinary", err)
			}
			wire := sealed(t, c, protocolv4.FrameStreamData, 1, []byte("reliable"))
			r, _, _, err := s.Open(wire, acceptRecord)
			if err != nil {
				t.Fatal("held datagram blocked reliable", err)
			}
			r.Release()
			c.Close()
			wait, cancel := context.WithCancel(context.Background())
			cancel()
			if err = c.WaitCleanup(wait); !errors.Is(err, context.Canceled) {
				t.Fatal("provider tail released early", err)
			}
			p.Release()
			if err = c.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDatagramQueueLateCompletionCannotPublishAfterClose(t *testing.T) {
	c, _, _, q := datagramQueuePair(t, protocolv4.DHProfileX25519, 2)
	wire := sealed(t, c, protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("late"))
	entered, finish := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- q.Open(wire, func(h protocolv4.RecordHeader, p []byte) ([]byte, error) { close(entered); <-finish; return p, nil })
	}()
	<-entered
	q.Close()
	close(finish)
	if err := <-result; !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, _, err := q.Take(context.Background(), make([]byte, 949)); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestDatagramQueueRejectsOldQueuedEpochAndReceiveGuard(t *testing.T) {
	c, s, _, q := datagramQueuePair(t, protocolv4.DHProfileP256, 2)
	wire := sealed(t, c, protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("old"))
	if err := q.Open(wire, datagramPayload); err != nil {
		t.Fatal(err)
	}
	born, err := s.Clock().Sample()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.StageEpoch([32]byte{99}, born); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitEpoch(); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := q.Take(context.Background(), make([]byte, 949)); err != nil || ok {
		t.Fatal(ok, err)
	}
	if err = q.Open(wire, datagramPayload); !errors.Is(err, ErrEpoch) {
		t.Fatal(err)
	}
	// A fresh pair exercises invalid input without a direct state mutation.
	c, s, _, q = datagramQueuePair(t, protocolv4.DHProfileP256, 2)
	wire = sealed(t, c, protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("queued"))
	if err = q.Open(wire, datagramPayload); err != nil {
		t.Fatal(err)
	}
	for range 8 {
		bad := sealed(t, c, protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("bad tag"))
		bad[len(bad)-1] ^= 1
		if err = q.Open(bad, datagramPayload); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
	}
	dst := bytes.Repeat([]byte{0x7f}, 949)
	if _, _, err = q.Take(context.Background(), dst); !errors.Is(err, ErrReceiveBlocked) {
		t.Fatal(err)
	}
	if !bytes.Equal(dst, bytes.Repeat([]byte{0x7f}, 949)) {
		t.Fatal("guarded Receive disclosed data")
	}
}
