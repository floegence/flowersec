package rpc_test

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/framing/jsonframe"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpc"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v5/internal/rpcwire"
)

type notificationVectors struct {
	Version               int                         `json:"version"`
	TypeID                uint32                      `json:"type_id"`
	Payloads              []notificationPayloadVector `json:"payloads"`
	SubscriptionScenarios []string                    `json:"subscription_scenarios"`
}

type notificationPayloadVector struct {
	ID            string `json:"id"`
	JSON          string `json:"json"`
	Decoder       string `json:"decoder"`
	ExpectedValue string `json:"expected_value"`
	Outcome       string `json:"outcome"`
}

func TestRPCNotificationSharedVectors(t *testing.T) {
	vectors := loadNotificationVectors(t)
	if vectors.Version != 1 || vectors.TypeID == 0 {
		t.Fatalf("notification vector header = version %d type %d", vectors.Version, vectors.TypeID)
	}
	wantPayloadIDs := map[string]bool{
		"object_unicode_unknown": false,
		"array":                  false,
		"scalar":                 false,
		"decode_failure":         false,
	}
	for _, vector := range vectors.Payloads {
		if _, ok := wantPayloadIDs[vector.ID]; !ok {
			t.Fatalf("unexpected notification payload vector %q", vector.ID)
		}
		wantPayloadIDs[vector.ID] = true
		vector := vector
		t.Run("payload/"+vector.ID, func(t *testing.T) {
			t.Parallel()
			runNotificationPayloadVector(t, vectors.TypeID, vector)
		})
	}
	for id, seen := range wantPayloadIDs {
		if !seen {
			t.Fatalf("missing notification payload vector %q", id)
		}
	}

	scenarios := map[string]func(*testing.T, uint32){
		"duplicate_subscriptions_receive_independently": testDuplicateNotificationSubscriptions,
		"cancel_is_idempotent":                          testNotificationCancelIsIdempotent,
		"handler_failure_is_isolated":                   testNotificationHandlerFailureIsIsolated,
		"session_close_terminates_subscriptions":        testNotificationCloseTerminatesSubscriptions,
	}
	seenScenarios := make(map[string]bool, len(scenarios))
	for _, id := range vectors.SubscriptionScenarios {
		run, ok := scenarios[id]
		if !ok {
			t.Fatalf("unexpected notification subscription scenario %q", id)
		}
		if seenScenarios[id] {
			t.Fatalf("duplicate notification subscription scenario %q", id)
		}
		seenScenarios[id] = true
		t.Run("subscription/"+id, func(t *testing.T) { run(t, vectors.TypeID) })
	}
	for id := range scenarios {
		if !seenScenarios[id] {
			t.Fatalf("missing notification subscription scenario %q", id)
		}
	}
}

func loadNotificationVectors(t *testing.T) notificationVectors {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve notification vector test source")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "testdata", "transport_v3", "rpc_notification_vectors.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors notificationVectors
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func runNotificationPayloadVector(t *testing.T, typeID uint32, vector notificationPayloadVector) {
	t.Helper()
	clientSide, peerSide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close(); _ = peerSide.Close() })
	client := rpc.NewClient(clientSide)
	t.Cleanup(func() { _ = client.Close() })
	result := make(chan error, 1)
	unsubscribe := client.OnNotify(typeID, func(payload json.RawMessage) {
		message, err := decodeNotificationVector(vector.Decoder, payload)
		if err == nil && vector.ExpectedValue != "" && message != vector.ExpectedValue {
			err = errors.New("decoded notification message mismatch")
		}
		result <- err
	})
	t.Cleanup(unsubscribe)
	writeNotification(t, peerSide, typeID, json.RawMessage(vector.JSON))
	err := receiveNotificationResult(t, result)
	if vector.Outcome == "decode_failure" {
		if err == nil {
			t.Fatal("notification decoder unexpectedly accepted invalid payload")
		}
		return
	}
	if vector.Outcome != "success" {
		t.Fatalf("unsupported notification outcome %q", vector.Outcome)
	}
	if err != nil {
		t.Fatalf("decode notification: %v", err)
	}
}

func decodeNotificationVector(decoder string, payload json.RawMessage) (string, error) {
	switch decoder {
	case "state_object":
		var value struct {
			State string `json:"state"`
		}
		if err := json.Unmarshal(payload, &value); err != nil {
			return "", err
		}
		return value.State, nil
	case "string_array":
		var value []string
		return "", json.Unmarshal(payload, &value)
	case "string":
		var value string
		if err := json.Unmarshal(payload, &value); err != nil {
			return "", err
		}
		return value, nil
	default:
		return "", errors.New("unknown notification decoder")
	}
}

func testDuplicateNotificationSubscriptions(t *testing.T, typeID uint32) {
	client, peer, closePair := notificationClientPair(t)
	defer closePair()
	first := make(chan error, 1)
	second := make(chan error, 1)
	unsubscribeFirst := client.OnNotify(typeID, func(json.RawMessage) { first <- nil })
	unsubscribeSecond := client.OnNotify(typeID, func(json.RawMessage) { second <- nil })
	defer unsubscribeFirst()
	defer unsubscribeSecond()
	writeNotification(t, peer, typeID, json.RawMessage(`{"duplicate":true}`))
	if err := receiveNotificationResult(t, first); err != nil {
		t.Fatal(err)
	}
	if err := receiveNotificationResult(t, second); err != nil {
		t.Fatal(err)
	}
}

func testNotificationCancelIsIdempotent(t *testing.T, typeID uint32) {
	client, peer, closePair := notificationClientPair(t)
	defer closePair()
	delivered := make(chan error, 1)
	unsubscribe := client.OnNotify(typeID, func(json.RawMessage) { delivered <- nil })
	unsubscribe()
	unsubscribe()
	writeNotification(t, peer, typeID, json.RawMessage(`{"canceled":true}`))
	select {
	case <-delivered:
		t.Fatal("canceled notification subscription was invoked")
	case <-time.After(50 * time.Millisecond):
	}
}

func testNotificationHandlerFailureIsIsolated(t *testing.T, typeID uint32) {
	client, peer, closePair := notificationClientPair(t)
	defer closePair()
	unsubscribePanic := client.OnNotify(typeID, func(json.RawMessage) { panic("handler failure") })
	defer unsubscribePanic()
	delivered := make(chan error, 1)
	unsubscribeHealthy := client.OnNotify(typeID, func(json.RawMessage) { delivered <- nil })
	defer unsubscribeHealthy()
	writeNotification(t, peer, typeID, json.RawMessage(`{"isolated":true}`))
	if err := receiveNotificationResult(t, delivered); err != nil {
		t.Fatal(err)
	}
}

func testNotificationCloseTerminatesSubscriptions(t *testing.T, typeID uint32) {
	client, peer, closePair := notificationClientPair(t)
	defer closePair()
	delivered := make(chan error, 1)
	unsubscribe := client.OnNotify(typeID, func(json.RawMessage) { delivered <- nil })
	defer unsubscribe()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	err := jsonframe.WriteJSONFrame(peer, rpcv1.RpcEnvelope{TypeId: typeID, Payload: json.RawMessage(`{"closed":true}`)})
	if err == nil {
		t.Fatal("notification write succeeded after client close")
	}
	select {
	case <-delivered:
		t.Fatal("closed notification subscription was invoked")
	default:
	}
}

func notificationClientPair(t *testing.T) (*rpc.Client, net.Conn, func()) {
	t.Helper()
	clientSide, peerSide := net.Pipe()
	client := rpc.NewClient(clientSide)
	return client, peerSide, func() { _ = client.Close(); _ = peerSide.Close() }
}

func writeNotification(t *testing.T, peer net.Conn, typeID uint32, payload json.RawMessage) {
	t.Helper()
	if err := jsonframe.WriteJSONFrame(peer, rpcv1.RpcEnvelope{TypeId: typeID, Payload: payload}); err != nil {
		t.Fatal(err)
	}
}

func receiveNotificationResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for notification")
		return nil
	}
}
