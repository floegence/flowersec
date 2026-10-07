package transporttest

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestPreparedDirectCapacityOutlivesPreparationCaller(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	endpoint, err := OpenProductDirectEndpoint(ctx, carrier.KindRawQUIC)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := endpoint.Close(); err != nil {
			t.Error(err)
		}
	}()
	preparation, stop := context.WithCancel(ctx)
	defer stop()
	if err := endpoint.PrepareCapacity(preparation, 1); err != nil {
		t.Fatal(err)
	}
	stop()
	if err := endpoint.PrepareCapacity(ctx, 1); err == nil {
		t.Fatal("completed capacity preparation was reusable")
	}
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		t.Fatal("preparation cancellation reached the transferred owner", err)
	}
	defer func() {
		if err := pair.Close(); err != nil {
			t.Error(err)
		}
	}()
	payload := []byte("original-prepared-direct-capacity")
	got, err := pair.CallEcho(ctx, payload)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("original prepared Session application failed", err)
	}
	if _, err := endpoint.Connect(ctx); err == nil {
		t.Fatal("consumed capacity material was recreated")
	}
}

// Keep every business stream active across a genuine rekey. Opening them all
// requires the signed aggregate credit and original provider backing; the
// rekey additionally decodes the actual complete active-scope barrier.
func TestCurrentDirectSignedStreamCapacitySurvivesRekey(t *testing.T) {
	// Each case owns its listener, namespace and accounts. Run this bounded
	// matrix while the independent restart test observes native idle loss.
	t.Parallel()
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			t.Run(string(kind)+"/"+profile, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				endpoint, err := openProductDirectEndpoint(ctx, kind, "127.0.0.1", "127.0.0.1", releaseRunnerOrigin, profile, 128, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := endpoint.Close(); err != nil {
						t.Errorf("original endpoint cleanup: %v", err)
					}
				}()
				pair, err := endpoint.Connect(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := pair.Close(); err != nil {
						t.Errorf("original pair cleanup: %v", err)
					}
				}()
				var client, server [128]flowersec.Stream
				defer func() {
					for index := range client {
						if client[index] != nil {
							_ = client[index].Reset()
						}
						if server[index] != nil {
							_ = server[index].Reset()
						}
					}
				}()
				for index := range client {
					metadata, err := flowersec.NewStreamMetadata(map[string]any{"stream_index": index})
					if err != nil {
						t.Fatal(err)
					}
					client[index], err = pair.Client.OpenStream(ctx, "native-stream-capacity", metadata)
					if err != nil {
						t.Fatalf("original stream %d OPEN: %v", index, err)
					}
					incoming, err := pair.Server.AcceptStream(ctx)
					if err != nil {
						t.Fatalf("original stream %d acceptance: %v", index, err)
					}
					server[index] = incoming.Stream
					if incoming.Kind != "native-stream-capacity" {
						t.Fatal("authenticated business kind changed")
					}
				}
				if err := pair.Client.Rekey(ctx); err != nil {
					t.Fatalf("original rekey with 128 active business streams: %v", err)
				}
				for index := range client {
					request := []byte{byte(index), 0x35}
					response := []byte{byte(index), 0x5a}
					if _, err := client[index].WriteAll(ctx, request); err != nil {
						t.Fatal(err)
					}
					if err := client[index].CloseWrite(); err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(server[index])
					if err != nil || !bytes.Equal(got, request) {
						t.Fatalf("original stream %d after rekey request = %x, %v", index, got, err)
					}
					if _, err := server[index].WriteAll(ctx, response); err != nil {
						t.Fatal(err)
					}
					if err := server[index].CloseWrite(); err != nil {
						t.Fatal(err)
					}
					got, err = io.ReadAll(client[index])
					if err != nil || !bytes.Equal(got, response) {
						t.Fatalf("original stream %d after rekey response = %x, %v", index, got, err)
					}
					if err := client[index].Finish(ctx); err != nil {
						t.Fatal(err)
					}
					if err := server[index].Finish(ctx); err != nil {
						t.Fatal(err)
					}
					// Both directions reached authenticated EOF and Finish. Release
					// the raw owners before discarding these original handles.
					if err := client[index].Close(); err != nil {
						t.Fatal(err)
					}
					if err := server[index].Close(); err != nil {
						t.Fatal(err)
					}
					client[index], server[index] = nil, nil
				}
				payload := []byte("after-original-capacity-rekey")
				result, err := pair.CallEcho(ctx, payload)
				if err != nil || !bytes.Equal(result, payload) {
					t.Fatalf("original application after rekey = %q, %v", result, err)
				}
				if pair.SpendCount() != 1 {
					t.Fatal("rekey or capacity transfer changed the original durable spend count")
				}
			})
		}
	}
}
