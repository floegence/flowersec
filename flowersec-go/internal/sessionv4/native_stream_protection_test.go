package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestNativeCallerFloorAdoptsOriginalProviderAtFullCapacity(t *testing.T) {
	// Adoption needs the native transport plan, not asynchronous RPC bootstrap.
	cores, _ := nativeTransportCorePair(t, protocolv4.DHProfileX25519)
	p := cores[0].plan
	floor, err := reserveStreamCallerBacking(p.config, p.root, streamWorkloadTransportOwner(p.resourceOwner, 212), p.accounts[:p.accountCount], p.receivePool, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer floor.close()
	var original [1]native.StreamProtection
	if err := p.nativeConnection.ProtectNativeStreams(original[:]); err != nil {
		t.Fatal(err)
	}
	floor.provider, floor.connection = original[0], p.nativeConnection
	var held []native.StreamProtection
	defer func() {
		for _, position := range held {
			position.Close()
		}
	}()
	for {
		var position [1]native.StreamProtection
		err := p.nativeConnection.ProtectNativeStreams(position[:])
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, position[0])
	}
	before := p.root.Snapshot()
	p.mu.Lock()
	err = p.adoptStreamCallerFloorLocked(floor)
	p.mu.Unlock()
	if err != nil {
		t.Fatal("installation requested a second provider position", err)
	}
	if floor.native == nil || floor.native.provider != original[0] || floor.provider != nil || floor.connection != nil || floor.plan != p || p.root.Snapshot() != before {
		t.Fatal("installation replaced the original transport vector")
	}
	if err := floor.checkAvailable(); err != nil {
		t.Fatal(err)
	}
	floor.close()
	if !floor.cleanupComplete() || original[0].CheckAvailable() == nil {
		t.Fatal("closing the original floor left provider responsibility behind")
	}
}
