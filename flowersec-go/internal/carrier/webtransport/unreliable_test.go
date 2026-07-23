package webtransport_test

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
)

func TestNativeWebTransportUnreliableMessages(t *testing.T) {
	client, server := newSessionPair(t, webtransport.PathDirect)
	clientUnreliable, ok := client.(carrier.UnreliableTransport)
	if !ok {
		t.Fatal("WebTransport does not implement UnreliableTransport")
	}
	serverUnreliable, ok := server.(carrier.UnreliableTransport)
	if !ok {
		t.Fatal("WebTransport peer does not implement UnreliableTransport")
	}
	payload := []byte("native-webtransport-datagram")
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
