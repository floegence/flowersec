package rawquic_test

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
)

func TestNativeQUICUnreliableMessages(t *testing.T) {
	client, server := newRawQUICPair(t, rawquic.ALPNDirect)
	clientUnreliable, ok := client.(carrier.UnreliableTransport)
	if !ok {
		t.Fatal("raw QUIC does not implement UnreliableTransport")
	}
	serverUnreliable, ok := server.(carrier.UnreliableTransport)
	if !ok {
		t.Fatal("raw QUIC peer does not implement UnreliableTransport")
	}
	payload := []byte("native-quic-datagram")
	if err := clientUnreliable.SendUnreliable(payload); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := serverUnreliable.ReceiveUnreliable(ctx)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("ReceiveUnreliable = %q, %v", got, err)
	}
}
