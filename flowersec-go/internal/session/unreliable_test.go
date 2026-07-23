package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

func TestUnreliableMessagesRequireNegotiationAndNeverOpenReliableStreams(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	clientChannel, err := client.UnreliableMessages()
	if err != nil {
		t.Fatal(err)
	}
	serverChannel, err := server.UnreliableMessages()
	if err != nil {
		t.Fatal(err)
	}
	if clientChannel.MaxMessageBytes() != 1024 {
		t.Fatalf("MaxMessageBytes = %d", clientChannel.MaxMessageBytes())
	}

	clientCarrier := client.carrier.(*memoryCarrierSession)
	clientCarrier.streamsMu.Lock()
	streamsBefore := len(clientCarrier.streams)
	clientCarrier.streamsMu.Unlock()
	payload := []byte("unreliable plaintext")
	status, err := clientChannel.Send(context.Background(), payload, UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)})
	if err != nil || status != UnreliableAccepted {
		t.Fatalf("Send = %q, %v", status, err)
	}
	clientCarrier.streamsMu.Lock()
	streamsAfter := len(clientCarrier.streams)
	clientCarrier.streamsMu.Unlock()
	if streamsAfter != streamsBefore {
		t.Fatalf("unreliable send opened %d reliable streams", streamsAfter-streamsBefore)
	}
	clientCarrier.datagramMu.Lock()
	wire := append([]byte(nil), clientCarrier.lastDatagram...)
	clientCarrier.datagramMu.Unlock()
	if bytes.Contains(wire, payload) {
		t.Fatal("native datagram exposed plaintext")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := serverChannel.Receive(ctx)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("Receive = %q, %v", got, err)
	}

	status, err = clientChannel.Send(context.Background(), []byte("late"), UnreliableSendOptions{ExpiresAt: time.Now().Add(-time.Millisecond)})
	if err != nil || status != UnreliableDroppedExpired {
		t.Fatalf("expired Send = %q, %v", status, err)
	}
	if _, err := clientChannel.Send(context.Background(), make([]byte, clientChannel.MaxMessageBytes()+1), UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)}); !errors.Is(err, ErrUnreliableMessageTooLarge) {
		t.Fatalf("oversize Send = %v", err)
	}
}

func TestUnreliableMessagesAreUnavailableWithoutHandshakeFeature(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindWebSocket, 1)
	defer client.Close()
	defer server.Close()
	clientCarrier := client.carrier.(*memoryCarrierSession)
	clientCarrier.streamsMu.Lock()
	streamsBefore := len(clientCarrier.streams)
	clientCarrier.streamsMu.Unlock()
	if channel, err := client.UnreliableMessages(); channel != nil || !errors.Is(err, ErrUnreliableUnavailable) {
		t.Fatalf("UnreliableMessages = %#v, %v", channel, err)
	}
	clientCarrier.streamsMu.Lock()
	streamsAfter := len(clientCarrier.streams)
	clientCarrier.streamsMu.Unlock()
	if streamsAfter != streamsBefore {
		t.Fatalf("WSS unavailable path opened %d reliable streams", streamsAfter-streamsBefore)
	}
}

func TestUnreliableHandshakeNegotiatesIntersection(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	serverCarrier.unreliableDisabled = true
	clientConfig, serverConfig := testEngineConfigs(1)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()
	for name, established := range map[string]*engineSession{"client": client, "server": server} {
		if channel, err := established.UnreliableMessages(); channel != nil || !errors.Is(err, ErrUnreliableUnavailable) {
			t.Fatalf("%s negotiated channel = %#v, %v", name, channel, err)
		}
	}
}

func TestUnreliableSendBudgetDropsWithoutBlockingOrFallback(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 1)
	defer client.Close()
	defer server.Close()
	channel, err := client.UnreliableMessages()
	if err != nil {
		t.Fatal(err)
	}
	clientCarrier := client.carrier.(*memoryCarrierSession)
	blocked := make(chan struct{})
	clientCarrier.datagramSendBlock = blocked
	results := make(chan error, unreliableSendBudget)
	for index := range unreliableSendBudget {
		go func(index int) {
			status, sendErr := channel.Send(context.Background(), []byte{byte(index + 1)}, UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)})
			if sendErr == nil && status != UnreliableAccepted {
				sendErr = errors.New("send was not accepted")
			}
			results <- sendErr
		}(index)
	}
	deadline := time.Now().Add(time.Second)
	for clientCarrier.datagramActive.Load() != unreliableSendBudget {
		if time.Now().After(deadline) {
			t.Fatalf("active native sends = %d", clientCarrier.datagramActive.Load())
		}
		time.Sleep(time.Millisecond)
	}
	status, err := channel.Send(context.Background(), []byte("budget"), UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)})
	if err != nil || status != UnreliableDroppedBudget {
		t.Fatalf("budget Send = %q, %v", status, err)
	}
	close(blocked)
	for range unreliableSendBudget {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnreliableReceiveDropsReplayAndExpiredFrames(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 1)
	defer client.Close()
	defer server.Close()
	clientChannel, err := client.UnreliableMessages()
	if err != nil {
		t.Fatal(err)
	}
	serverChannel, err := server.UnreliableMessages()
	if err != nil {
		t.Fatal(err)
	}
	clientCarrier := client.carrier.(*memoryCarrierSession)
	status, err := clientChannel.Send(context.Background(), []byte("first"), UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)})
	if err != nil || status != UnreliableAccepted {
		t.Fatalf("first Send = %q, %v", status, err)
	}
	clientCarrier.datagramMu.Lock()
	firstWire := append([]byte(nil), clientCarrier.lastDatagram...)
	clientCarrier.datagramMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := serverChannel.Receive(ctx); err != nil || string(got) != "first" {
		t.Fatalf("first Receive = %q, %v", got, err)
	}
	serverCarrier := server.carrier.(*memoryCarrierSession)
	serverCarrier.datagrams <- append([]byte(nil), firstWire...)
	status, err = clientChannel.Send(context.Background(), []byte("second"), UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)})
	if err != nil || status != UnreliableAccepted {
		t.Fatalf("second Send = %q, %v", status, err)
	}
	if got, err := serverChannel.Receive(ctx); err != nil || string(got) != "second" {
		t.Fatalf("Receive after replay = %q, %v", got, err)
	}

	status, err = clientChannel.Send(context.Background(), []byte("expires"), UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)})
	if err != nil || status != UnreliableAccepted {
		t.Fatalf("expiry Send = %q, %v", status, err)
	}
	clientCarrier.datagramMu.Lock()
	expiringWire := append([]byte(nil), clientCarrier.lastDatagram...)
	clientCarrier.datagramMu.Unlock()
	if plaintext, accepted := server.unreliable.open(expiringWire, time.Now().Add(2*time.Second)); accepted || plaintext != nil {
		t.Fatalf("expired frame accepted = %q, %v", plaintext, accepted)
	}
}

func TestUnreliableReceiveWakesOnCancellationAndSessionClose(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 1)
	defer server.Close()
	channel, err := client.UnreliableMessages()
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := channel.Receive(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Receive = %v", err)
	}
	receiveErr := make(chan error, 1)
	go func() {
		_, err := channel.Receive(context.Background())
		receiveErr <- err
	}()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-receiveErr:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("Receive after Close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Receive did not wake on session close")
	}
}
