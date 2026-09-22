package cryptov4

import (
	"bytes"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func enginePair(t *testing.T, profile string, configure ...func(*Config)) (*Engine, *Engine, *time.Time) {
	t.Helper()
	now := time.Now()
	clock := cryptoClock(t, func() time.Time { return now })
	client, server := enginePairWithClock(t, profile, clock, configure...)
	return client, server, &now
}

func enginePairWithClock(t *testing.T, profile string, clock *timev4.Clock, configure ...func(*Config)) (*Engine, *Engine) {
	t.Helper()
	born, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Authorization: testAuthorization{}, Profile: profile, Root: [32]byte{1}, HandshakeHash: [32]byte{2}, MaxFrame: 4096, MaxScopes: 4, SignedMaxScopes: 4, WorkSlots: 4, Datagrams: true, RootBorn: born, AuthorizationDeadlineMS: born.LowerMS + 3600000, Clock: clock, Maintenance: MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}}
	var engines [2]*Engine
	for role := range engines {
		local := config
		local.SendDirection = protocolv4.Direction(role)
		for _, change := range configure {
			change(&local)
		}
		engines[role], err = NewEngine(local)
		if err != nil {
			t.Fatal(err)
		}
	}
	client, server := engines[0], engines[1]
	for _, e := range []*Engine{client, server} {
		if err = e.Activate(); err != nil {
			t.Fatal(err)
		}
		if err = e.OpenScope(1); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.Close)
	}
	return client, server
}
func acceptRecord(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error { return nil }
func sealed(t *testing.T, e *Engine, frame protocolv4.FrameType, scope uint64, payload []byte) []byte {
	t.Helper()
	packet, err := e.Seal(frame, scope, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	value, err := packet.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(value)
}
func TestRecordEngineProfilesAndOwnership(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			client, server, _ := enginePair(t, profile)
			payload := []byte("owned record body")
			wire := sealed(t, client, protocolv4.FrameStreamData, 1, payload)
			packet, frame, header, err := server.Open(wire, acceptRecord)
			if err != nil {
				t.Fatal(err)
			}
			if frame != protocolv4.FrameStreamData || header.Sequence != 0 || header.Scope != 1 {
				t.Fatal("wrong attribution")
			}
			got, err := packet.Bytes()
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("wrong plaintext", err)
			}
			packet.Release()
			if _, err = packet.Bytes(); !errors.Is(err, ErrClosed) {
				t.Fatal("released packet remained usable")
			}
			if !bytes.Equal(got, make([]byte, len(got))) {
				t.Fatal("released workspace retained plaintext")
			}
			if _, _, _, err = server.Open(wire, acceptRecord); !errors.Is(err, ErrSequence) {
				t.Fatal("reliable replay accepted", err)
			}
			server.RetireScope(1)
			if err = server.OpenScope(1); !errors.Is(err, ErrScope) {
				t.Fatal("retired ID reused")
			}
		})
	}
}
func TestRecordEngineDatagramFinalGateAndForgedJump(t *testing.T) {
	client, server, _ := enginePair(t, protocolv4.DHProfileX25519)
	scope := protocolv4.DatagramScope()
	client.current.keys.get(scope).keys[0].next = math.MaxUint64
	forged := sealed(t, client, protocolv4.FrameDatagram, scope, []byte("forged jump"))
	forged[len(forged)-1] ^= 1
	if _, _, _, err := server.Open(forged, acceptRecord); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	if server.current.keys.get(scope).keys[0].replay.present {
		t.Fatal("forged jump moved replay window")
	}
	// A separate sender models the original sequence-zero record delayed on the network.
	other, _, _ := enginePair(t, protocolv4.DHProfileX25519)
	wire := sealed(t, other, protocolv4.FrameDatagram, scope, []byte("once"))
	entered := make(chan struct{}, 2)
	finish := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			packet, _, _, err := server.Open(wire, func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error {
				entered <- struct{}{}
				<-finish
				return nil
			})
			if packet != nil {
				packet.Release()
			}
			results <- err
		})
	}
	<-entered
	<-entered
	close(finish)
	wg.Wait()
	close(results)
	accepted, replayed := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrReplay) {
			replayed++
		} else {
			t.Fatal(err)
		}
	}
	key := server.current.keys.get(scope).keys[0]
	if accepted != 1 || replayed != 1 || key.good.calls != 1 || key.usage.calls != 3 || server.invalidTotal != 1 {
		t.Fatalf("wrong final gate facts: accepted=%d replayed=%d good=%d attempts=%d invalid=%d", accepted, replayed, key.good.calls, key.usage.calls, server.invalidTotal)
	}
}
func TestRecordEngineDatagramProtectionSurvivesRekey(t *testing.T) {
	client, server, now := enginePair(t, protocolv4.DHProfileP256)
	scope := protocolv4.DatagramScope()
	wire := sealed(t, client, protocolv4.FrameDatagram, scope, []byte("bad tag"))
	wire[len(wire)-1] ^= 1
	for i := 0; i < 32; i++ {
		if _, _, _, err := server.Open(wire, acceptRecord); !errors.Is(err, ErrAuthentication) {
			t.Fatal(i, err)
		}
		if (i+1)%8 == 0 && i < 31 {
			if reason, remaining := server.DatagramReceiveState(); !errors.Is(reason, ErrReceiveBlocked) || remaining != time.Second {
				t.Fatal("pause not preserved", reason, remaining)
			}
			*now = now.Add(time.Second)
		}
	}
	if reason, _ := server.DatagramReceiveState(); !errors.Is(reason, ErrReceiveDisabled) {
		t.Fatal(reason)
	}
	if err := server.StageEpoch([32]byte{9}, cryptoSample(t, server)); err != nil {
		t.Fatal(err)
	}
	if err := server.CommitEpoch(); err != nil {
		t.Fatal(err)
	}
	if reason, _ := server.DatagramReceiveState(); !errors.Is(reason, ErrReceiveDisabled) {
		t.Fatal("rekey cleared permanent guard", reason)
	}
	if server.counts[0].calls != 32 || server.current.usage[0].calls != 0 {
		t.Fatal("rekey reset Session usage or retained epoch usage")
	}
	packet, err := server.Seal(protocolv4.FramePing, 0, []byte{0xa0})
	if err != nil {
		t.Fatal("receive disable affected reliable maintenance", err)
	}
	packet.Release()
}
func TestRecordEngineWorkspaceAndMaintenanceReserve(t *testing.T) {
	client, server, _ := enginePair(t, protocolv4.DHProfileX25519)
	var held []*Packet
	for range client.config.WorkSlots {
		packet, err := client.Seal(protocolv4.FrameStreamData, 1, []byte("held"))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, packet)
	}
	if _, err := client.Seal(protocolv4.FrameStreamData, 1, nil); !errors.Is(err, ErrCapacity) {
		t.Fatal("unbounded workspace", err)
	}
	ping, err := client.Seal(protocolv4.FramePing, 0, []byte{0xa0})
	if err != nil {
		t.Fatal("ordinary work occupied maintenance", err)
	}
	wire, err := ping.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	reply, _, _, err := server.Open(wire, acceptRecord)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := server.Seal(protocolv4.FramePong, 0, []byte{0xa0})
	if err != nil {
		t.Fatal("receive workspace blocked maintenance send", err)
	}
	reply.Release()
	reverse.Release()
	ping.Release()
	for _, packet := range held {
		packet.Release()
	}
	key := client.current.keys.get(0).keys[0]
	key.usage.calls = client.limits.Key.Seal - client.config.Maintenance.Calls
	if _, err := client.Seal(protocolv4.FramePing, 0, nil); !errors.Is(err, ErrUsage) {
		t.Fatal("ordinary maintenance consumed REKEY reserve", err)
	}
	packet, err := client.Seal(protocolv4.FrameRekey, 0, []byte{0xa0})
	if err != nil {
		t.Fatal("protected REKEY budget unavailable", err)
	}
	packet.Release()
}
func TestRecordEngineLateCompletionAndValidationFailure(t *testing.T) {
	client, server, _ := enginePair(t, protocolv4.DHProfileX25519)
	scope := protocolv4.DatagramScope()
	wire := sealed(t, client, protocolv4.FrameDatagram, scope, []byte("late"))
	invalid := errors.New("invalid body")
	if _, _, _, err := server.Open(wire, func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error { return invalid }); !errors.Is(err, invalid) {
		t.Fatal(err)
	}
	if server.current.keys.get(scope).keys[0].replay.present {
		t.Fatal("invalid protocol body consumed replay admission")
	}
	entered := make(chan struct{})
	finish := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		packet, _, _, err := server.Open(wire, func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error {
			close(entered)
			<-finish
			return nil
		})
		if packet != nil {
			packet.Release()
		}
		result <- err
	}()
	<-entered
	server.Close()
	close(finish)
	if err := <-result; !errors.Is(err, ErrClosed) {
		t.Fatal("late plaintext escaped close", err)
	}
	if server.counts[0].calls != 2 || server.flight != 0 {
		t.Fatal("close lost actual attempt accounting")
	}
}
func TestReplayWindowExtremes(t *testing.T) {
	var window replayWindow
	for _, value := range []uint64{0, 255, 256, math.MaxUint64 - 1, math.MaxUint64} {
		if !window.admits(value) {
			t.Fatal("fresh gap refused", value)
		}
		window.accept(value)
		if window.admits(value) {
			t.Fatal("duplicate", value)
		}
	}
	if window.admits(math.MaxUint64-256) || !window.admits(math.MaxUint64-255) {
		t.Fatal("window boundary")
	}
}
