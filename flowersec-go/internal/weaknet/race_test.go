package weaknet

import (
	"context"
	"sync"
	"testing"
)

func TestRelaysAreRaceSafeWithoutMakingConcurrentOrderDeterministic(t *testing.T) {
	const workers = 128
	udpExpected := Counters{
		InputUnits: workers, InputBytes: workers,
		OutputUnits: workers, OutputBytes: workers,
	}
	udp, err := NewUDPRelay(UDPProfile{
		Phase: "race", Direction: ClientToServer, Seed: 42, Expected: &udpExpected,
	}, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	byteExpected := Counters{
		InputUnits: workers, InputBytes: workers,
		OutputUnits: workers, OutputBytes: workers,
	}
	stream, err := NewByteRelay(ByteProfile{
		Phase: "race", Direction: ServerToClient, Seed: 42, Expected: &byteExpected,
	})
	if err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup
	for range workers {
		group.Add(2)
		go func() {
			defer group.Done()
			output, err := udp.Process(context.Background(), Datagram{Payload: []byte{1}})
			if err != nil {
				t.Errorf("UDP process: %v", err)
				return
			}
			for _, delivery := range output {
				if err := udp.Acknowledge(len(delivery.Payload)); err != nil {
					t.Errorf("UDP acknowledge: %v", err)
				}
			}
		}()
		go func() {
			defer group.Done()
			output, err := stream.Write(ByteChunk{Payload: []byte{1}})
			if err != nil {
				t.Errorf("byte write: %v", err)
				return
			}
			for _, delivery := range output {
				if err := stream.Acknowledge(uint64(len(delivery.Payload))); err != nil {
					t.Errorf("byte acknowledge: %v", err)
				}
			}
		}()
	}
	group.Wait()
	if err := udp.Verify(); err != nil {
		t.Fatalf("UDP verify: %v", err)
	}
	if err := stream.Verify(); err != nil {
		t.Fatalf("byte verify: %v; report=%+v", err, stream.Report())
	}
}

func TestTwoWayOutageRequiresTwoExplicitDirectionalProfiles(t *testing.T) {
	for _, direction := range []Direction{ClientToServer, ServerToClient} {
		expected := Counters{
			InputUnits: 1, InputBytes: 1,
			DroppedUnits: 1, DroppedBytes: 1, OutageUnits: 1,
		}
		relay, err := NewUDPRelay(UDPProfile{
			Phase: "two-way-outage", Direction: direction, Seed: 42,
			Outages: []OrdinalRange{{First: 1, Last: 1}}, Expected: &expected,
		}, UDPOptions{})
		if err != nil {
			t.Fatal(err)
		}
		output, err := relay.Process(context.Background(), Datagram{Payload: []byte{1}})
		if err != nil {
			t.Fatal(err)
		}
		if len(output) != 0 {
			t.Fatalf("%s outage delivered %+v", direction, output)
		}
		if err := relay.Verify(); err != nil {
			t.Fatalf("%s verify: %v", direction, err)
		}
	}
}
