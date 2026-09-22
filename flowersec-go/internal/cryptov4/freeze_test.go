package cryptov4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestFreezeCapturesOutstandingTicketWithoutWaiting(t *testing.T) {
	client, _, _ := enginePair(t, protocolv4.DHProfileX25519)
	entered, resume := make(chan struct{}), make(chan struct{})
	defer close(resume)
	done := make(chan error, 1)
	go func() {
		packet, err := client.SealBuild(protocolv4.FrameStreamData, 1, 1, func(header protocolv4.RecordHeader, dst []byte) (int, error) {
			close(entered)
			<-resume
			dst[0] = 7
			return 1, nil
		})
		if packet != nil {
			packet.Release()
		}
		done <- err
	}()
	<-entered
	var snapshot [4]protocolv4.RecordHeader
	f, count, err := client.FreezeApplication(snapshot[:])
	if err != nil || count != 1 || snapshot[0] != (protocolv4.RecordHeader{Scope: 1, Sequence: 1}) {
		t.Fatal(count, snapshot, err)
	}
	if _, err := client.Seal(protocolv4.FrameStreamData, 1, nil); !errors.Is(err, ErrTransition) {
		t.Fatal("post-freeze DATA ticket", err)
	}
	if err := client.OpenLocalScope(3); !errors.Is(err, ErrTransition) {
		t.Fatal("freeze burned new scope", err)
	}
	if !client.unusedScope(3) {
		t.Fatal("failed OPEN burned ordinal")
	}
	control := sealed(t, client, protocolv4.FramePing, 0, nil)
	if len(control) == 0 {
		t.Fatal("maintenance stalled")
	}
	if err := f.Cancel(); err != nil {
		t.Fatal(err)
	}
	if err := client.ApplicationReady(); err != nil {
		t.Fatal(err)
	}
	resume <- struct{}{}
	if err := <-done; err != nil {
		t.Fatal("original ticket was cancelled by freeze", err)
	}
}

func TestFreezeDatagramCutoffAndIrreversibleResume(t *testing.T) {
	client, _, _ := enginePair(t, protocolv4.DHProfileX25519)
	packet, err := client.Seal(protocolv4.FrameDatagram, protocolv4.DatagramScope(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	var snapshot [4]protocolv4.RecordHeader
	f, _, err := client.FreezeApplication(snapshot[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Bytes(); err != nil {
		t.Fatal("pre-INIT datagram lost authority", err)
	}
	if err := f.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Bytes(); !errors.Is(err, ErrTransition) {
		t.Fatal("post-INIT datagram published", err)
	}
	if err := f.Cancel(); !errors.Is(err, ErrTransition) {
		t.Fatal("committed freeze rolled back", err)
	}
	if err := f.Resume(); !errors.Is(err, ErrTransition) {
		t.Fatal("old epoch reopened", err)
	}
	if err := client.StageEpoch([32]byte{9}, cryptoSample(t, client)); err != nil {
		t.Fatal(err)
	}
	if err := client.CommitEpoch(); err != nil {
		t.Fatal(err)
	}
	if err := f.Resume(); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Bytes(); !errors.Is(err, ErrEpoch) {
		t.Fatal("old datagram revived", err)
	}
	if err := client.ApplicationReady(); err != nil {
		t.Fatal(err)
	}
}

func TestFreezeStillAuthenticatesPendingOpenAfterRootPreparation(t *testing.T) {
	client, server, _ := enginePair(t, protocolv4.DHProfileP256, func(c *Config) { c.PendingScopes = 1 })
	if err := client.OpenLocalScope(3); err != nil {
		t.Fatal(err)
	}
	wire := sealed(t, client, protocolv4.FrameOpenStream, 3, nil)
	var snapshot [4]protocolv4.RecordHeader
	freeze, count, err := server.FreezeApplication(snapshot[:])
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err := freeze.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := server.StageEpoch([32]byte{8}, server.config.RootBorn); err != nil {
		t.Fatal(err)
	}
	packet, pending, err := server.OpenIncoming(wire, acceptRecord)
	if err != nil {
		t.Fatal("root preparation blocked legitimate old OPEN", err)
	}
	packet.Release()
	if err := pending.PrepareAccept(); err != nil {
		t.Fatal(err)
	}
	if err := pending.Resolve(true); err != nil {
		t.Fatal("freeze blocked outcome", err)
	}
	if _, err := server.Seal(protocolv4.FrameStreamData, 3, nil); !errors.Is(err, ErrTransition) {
		t.Fatal("late acceptance reopened send", err)
	}
	if err := server.CommitEpoch(); err != nil {
		t.Fatal(err)
	}
	if err := freeze.Resume(); err != nil {
		t.Fatal(err)
	}
	frontier, err := server.ScopeFrontier(3, protocolv4.ServerToClient)
	if err != nil || frontier.Epoch != 1 || frontier.Sequence != 0 {
		t.Fatal(frontier, err)
	}
}
