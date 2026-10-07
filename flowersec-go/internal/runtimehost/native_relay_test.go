package runtimehost

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func TestRelayWebSocketCloseUnclaimedPreparation(t *testing.T) {
	slot := &relayWebSocket{ready: make(chan struct{}), result: make(chan relayWebSocketResult, 1), stop: make(chan struct{})}
	ctx := context.Background()
	returned := make(chan relayWebSocketResult, 1)
	go func() {
		prepared, err := slot.PrepareTunnel(ctx, sessionv4.PreparedCarrierConfig{})
		returned <- relayWebSocketResult{prepared, err}
	}()
	select {
	case <-slot.ready:
	case <-time.After(time.Second):
		t.Fatal("preparation did not start")
	}
	slot.Close()
	slot.Close()
	select {
	case result := <-returned:
		if result.prepared != nil || !errors.Is(result.err, resourcev4.ErrClosed) {
			t.Fatalf("closed preparation = %v, %v", result.prepared, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("endpoint Close did not release unclaimed preparation")
	}
	if ctx.Err() != nil {
		t.Fatal("endpoint Close canceled caller context")
	}
}

func TestRelayWebSocketCloseJoinsClaimedPreparation(t *testing.T) {
	slot := &relayWebSocket{ready: make(chan struct{}), result: make(chan relayWebSocketResult, 1), stop: make(chan struct{})}
	returned := make(chan relayWebSocketResult, 1)
	go func() {
		prepared, err := slot.PrepareTunnel(context.Background(), sessionv4.PreparedCarrierConfig{})
		returned <- relayWebSocketResult{prepared, err}
	}()
	select {
	case <-slot.ready:
	case <-time.After(time.Second):
		t.Fatal("preparation did not start")
	}
	slot.mu.Lock()
	slot.claimed = true
	slot.mu.Unlock()
	slot.Close()
	select {
	case <-returned:
		t.Fatal("claimed preparation returned before the handler settled")
	case <-time.After(20 * time.Millisecond):
	}
	prepared := &sessionv4.PreparedCarrier{}
	slot.result <- relayWebSocketResult{prepared: prepared}
	select {
	case result := <-returned:
		if result.prepared != prepared || !errors.Is(result.err, resourcev4.ErrClosed) {
			t.Fatalf("closed preparation lost handler result: %v, %v", result.prepared, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("claimed preparation did not return the handler result")
	}
}
