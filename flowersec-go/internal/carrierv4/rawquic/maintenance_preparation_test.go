package rawquic

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func preparedMaintenancePair(t *testing.T) (*OwnedConnection, *OwnedConnection, *OwnedStream, *OwnedStream) {
	t.Helper()
	client, server := ownedTestPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	left, err := client.OpenMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, left)
	right, err := server.PrepareMaintenance(ctx)
	if err != nil {
		t.Fatal("empty native stream blocked physical preparation", err)
	}
	t.Cleanup(func() {
		_ = right.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := right.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := right.Retire(); err != nil {
			t.Error(err)
		}
	})
	if right.Context().Err() != nil || right.WriteContext().Err() != nil || right.WriteStopReason() != nil {
		t.Fatal("prepared maintenance lost its original live connection")
	}
	if _, err := server.AcceptStream(ctx); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("DATA accept was allowed to consume the maintenance stream", err)
	}
	if _, err := server.AcceptMaintenance(ctx); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("maintenance accepted a second owner", err)
	}
	return client, server, left, right
}

func waitMaintenanceMethods(t *testing.T, stream *OwnedStream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		stream.owner.mu.Lock()
		slot, err := stream.slotLocked()
		waiting := err == nil && slot.reading && slot.writing && slot.calls == 2 && stream.owner.calls == 2 && slot.native == nil && stream.owner.accepting
		stream.owner.mu.Unlock()
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("original read and write did not retain the single maintenance acceptance")
		case <-tick.C:
		}
	}
}

func TestOwnedQUICPreparedMaintenanceWaitsForOriginalPeerBytes(t *testing.T) {
	_, server, left, right := preparedMaintenancePair(t)
	read, write := make(chan error, 1), make(chan error, 1)
	go func() {
		var received [5]byte
		_, err := io.ReadFull(right, received[:])
		if err == nil && string(received[:]) != "hello" {
			err = errors.New("original maintenance bytes changed")
		}
		read <- err
	}()
	go func() { _, err := right.Write([]byte("reply")); write <- err }()
	waitMaintenanceMethods(t, right)
	if _, err := left.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	for _, result := range []<-chan error{read, write} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("first maintenance observers did not share the accepted stream")
		}
	}
	var received [5]byte
	if _, err := io.ReadFull(left, received[:]); err != nil || string(received[:]) != "reply" {
		t.Fatal(received, err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.calls != 0 || server.accepting || server.slots[right.slot].native == nil {
		t.Fatal("completed maintenance retained an acceptance or method position")
	}
}

func TestOwnedQUICPreparedMaintenanceCloseJoinsOriginalAccept(t *testing.T) {
	for _, closePeer := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "peer"}[closePeer], func(t *testing.T) {
			client, server, _, right := preparedMaintenancePair(t)
			read, write := make(chan error, 1), make(chan error, 1)
			go func() { var dst [1]byte; _, err := right.Read(dst[:]); read <- err }()
			go func() { _, err := right.Write([]byte("reply")); write <- err }()
			waitMaintenanceMethods(t, right)
			var err error
			if closePeer {
				err = client.Close()
			} else {
				err = right.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, result := range []<-chan error{read, write} {
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("closed maintenance observer succeeded")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("closed native accept retained a maintenance observer")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err = server.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if server.calls != 0 || server.slots[right.slot].calls != 0 || server.slots[right.slot].native != nil {
				t.Fatal("closed maintenance installed a late stream or released an active observer")
			}
		})
	}
}

func TestOwnedQUICPreparedMaintenanceCanCloseBeforeFirstIO(t *testing.T) {
	_, server, _, right := preparedMaintenancePair(t)
	if err := right.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if right.Context().Err() == nil || right.WriteContext().Err() == nil {
		t.Fatal("closed unmaterialized maintenance still appears live")
	}
}
