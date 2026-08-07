package tunnelworkload

import (
	"testing"

	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
)

func TestCapacityCoordinatorConfigHoldsExactReleaseSessionCount(t *testing.T) {
	config, err := capacityCoordinatorConfig(1000)
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxPendingLegs != 2000 || config.MaxActivePairs != 1000 {
		t.Fatalf("capacity coordinator limits = pending %d active %d", config.MaxPendingLegs, config.MaxActivePairs)
	}
	if _, err := capacityCoordinatorConfig(999); err == nil {
		t.Fatal("capacity coordinator accepted a non-release session count")
	}
}

func TestStreamCapacityWebSocketResourcesCoverAllPhysicalStreams(t *testing.T) {
	resources, err := webSocketResourcesForSession(128)
	if err != nil {
		t.Fatal(err)
	}
	if resources.InboundBidirectionalStreams != 130 || resources.MaxConcurrentStreams < 130 ||
		resources.MaxFrameBytes != 256*1024 || resources.MaxStreamReceiveBytes != 256*1024 ||
		resources.MaxSessionReceiveBytes != 130*256*1024 {
		t.Fatalf("stream capacity WebSocket resources = %+v", resources)
	}
	ordinary, err := webSocketResourcesForSession(defaultMaxInboundStreams)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.MaxSessionReceiveBytes != carrierws.DefaultResourcePolicy().MaxSessionReceiveBytes {
		t.Fatalf("ordinary WebSocket session memory changed: %+v", ordinary)
	}
}

func TestStreamCapacityUsesTightBridgeCopyBufferOnly(t *testing.T) {
	capacity := browserStreamCapacityCoordinatorConfig()
	if capacity.MaxPendingLegs != 200 || capacity.MaxActivePairs != 100 || capacity.BridgeLimits.CopyBufferBytes != 4*1024 {
		t.Fatalf("stream capacity coordinator = %+v", capacity)
	}
	if ordinary := tunnelv2.DefaultConfig().BridgeLimits.CopyBufferBytes; ordinary != 32*1024 {
		t.Fatalf("ordinary tunnel copy buffer = %d", ordinary)
	}
}
