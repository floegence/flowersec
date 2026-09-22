package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func ioEngine(t *testing.T, direction protocolv4.Direction) *cryptov4.Engine {
	t.Helper()
	clock := sessionTestClock(t)
	born, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	e, err := cryptov4.NewEngine(cryptov4.Config{Authorization: testAuthorization{}, Profile: protocolv4.DHProfileX25519, Root: [32]byte{1}, HandshakeHash: [32]byte{2}, SendDirection: direction, MaxFrame: 4096, MaxScopes: 4, SignedMaxScopes: 4, WorkSlots: 2, RootBorn: born, AuthorizationDeadlineMS: born.LowerMS + 3600000, Clock: clock, Maintenance: cryptov4.MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Activate(); err != nil {
		t.Fatal(err)
	}
	if err = e.OpenScope(1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(input []byte) (int, error) {
	return w.Buffer.Write(input[:min(len(input), 3)])
}
func TestRecordIOSuffixAndReadReservation(t *testing.T) {
	client, server := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	provider := new(shortWriter)
	writer, err := NewRecordWriter(client, 1, provider)
	if err != nil {
		t.Fatal(err)
	}
	result, err := writer.Write(context.Background(), protocolv4.FrameStreamData, []byte("partial provider writes"))
	if err != nil || !result.Submitted || !result.Complete || result.EnvelopeBytes != provider.Len() {
		t.Fatal(result, err)
	}
	reader := bytes.NewReader(provider.Bytes())
	prefix, err := ReadRecordPrefix(reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = prefix.ReadBody(reader, make([]byte, 8)); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("peer size allocated unreserved body", err)
	}
	wire, err := prefix.ReadBody(reader, make([]byte, prefix.RequiredBytes()))
	if err != nil {
		t.Fatal(err)
	}
	packet, _, _, err := server.Open(wire, func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	plain, err := packet.Bytes()
	if err != nil || string(plain) != "partial provider writes" {
		t.Fatal(string(plain), err)
	}
}

type blockedWriter struct{ entered, finish chan struct{} }

func (w *blockedWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.finish
	return 2, io.ErrClosedPipe
}
func TestRecordIOCloseWaitKeepsActualOwner(t *testing.T) {
	e := ioEngine(t, protocolv4.ClientToServer)
	provider := &blockedWriter{make(chan struct{}), make(chan struct{})}
	writer, err := NewRecordWriter(e, 1, provider)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result RecordWriteResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := writer.Write(context.Background(), protocolv4.FrameStreamData, []byte("owned"))
		done <- outcome{result, err}
	}()
	<-provider.entered
	writer.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = writer.WaitCleanup(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("wait falsely completed", err)
	}
	if _, err = writer.Write(context.Background(), protocolv4.FrameStreamData, nil); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("close admitted another ticket", err)
	}
	close(provider.finish)
	got := <-done
	if !got.result.Submitted || got.result.EnvelopeBytes != 2 || got.result.Complete || !errors.Is(got.err, io.ErrClosedPipe) {
		t.Fatal("partial facts lost", got)
	}
	if err = writer.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}
