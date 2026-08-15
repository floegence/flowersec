package rpc_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/framing/jsonframe"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/internal/rpcwire"
)

func TestRPC_NotificationAndRequest(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := rpc.NewRouter()
	notify3 := make(chan json.RawMessage, 1)
	router.Register(3, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		select {
		case notify3 <- payload:
		default:
		}
		return nil, nil
	})

	srv := rpc.NewServer(a, router)
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx)
		close(done)
	}()

	c := rpc.NewClient(b)
	defer c.Close()

	// Server -> client notification.
	got2 := make(chan json.RawMessage, 1)
	unsub := c.OnNotify(2, func(payload json.RawMessage) {
		select {
		case got2 <- payload:
		default:
		}
	})
	defer unsub()
	if err := srv.Notify(2, json.RawMessage(`{"hello":"world"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-got2:
		if string(payload) != `{"hello":"world"}` {
			t.Fatalf("unexpected notification payload: %s", string(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for notification")
	}

	// Client -> server notification (no response expected).
	if err := c.Notify(3, json.RawMessage(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-notify3:
		if string(payload) != `{"x":1}` {
			t.Fatalf("unexpected server notification payload: %s", string(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server handler")
	}

	_ = a.Close()
	<-done
}

func TestRPC_ClientCallFailsWhenTransportCloses(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := rpc.NewClient(a)
	defer c.Close()

	// Drain the request so Client.Call can move past the write and wait for the response.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = jsonframe.ReadJSONFrame(b, 1<<20)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.Call(ctx, 1, json.RawMessage(`{}`))
		errCh <- err
	}()

	select {
	case <-drained:
		_ = b.Close()
	case <-ctx.Done():
		t.Fatal("timeout waiting to drain request")
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for Call to return")
	}
}

func TestRPCClientEnforcesApplicationErrorInvariantAtReceiveBoundary(t *testing.T) {
	fixture := loadRPCErrorVectors(t)
	if fixture.MaximumMessageBytes != 1024 {
		t.Fatalf("maximum_message_bytes = %d, want 1024", fixture.MaximumMessageBytes)
	}
	tests := []struct {
		name        string
		payload     func(uint64) []byte
		valid       bool
		wantCode    uint32
		wantMessage *string
	}{}
	for _, vector := range fixture.Cases {
		errorObject := map[string]any{"code": vector.Code}
		message := strings.Repeat(vector.Message.Unit, vector.Message.Repeat) + vector.Message.Suffix
		var wantMessage *string
		if vector.Message.Presence == "present" {
			errorObject["message"] = message
			wantMessage = &message
		}
		if vector.ExtraField {
			errorObject["internal"] = "secret"
		}
		tests = append(tests, struct {
			name        string
			payload     func(uint64) []byte
			valid       bool
			wantCode    uint32
			wantMessage *string
		}{vector.ID, rpcErrorResponsePayload(t, errorObject), vector.Valid, vector.Code, wantMessage})
	}
	for _, vector := range fixture.RawCases {
		message, err := hex.DecodeString(vector.MessageHex)
		if err != nil {
			t.Fatalf("decode %s: %v", vector.ID, err)
		}
		tests = append(tests, struct {
			name        string
			payload     func(uint64) []byte
			valid       bool
			wantCode    uint32
			wantMessage *string
		}{
			name: vector.ID,
			payload: func(requestID uint64) []byte {
				prefix := []byte(fmt.Sprintf(`{"type_id":1,"request_id":0,"response_to":%d,"payload":null,"error":{"code":%d,"message":"`, requestID, vector.Code))
				return append(append(prefix, message...), []byte(`"}}`)...)
			},
			valid:    vector.Valid,
			wantCode: vector.Code,
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientStream, peerStream := net.Pipe()
			defer peerStream.Close()
			client := rpc.NewClient(clientStream)
			defer client.Close()

			peerDone := make(chan error, 1)
			go func() {
				requestBytes, err := jsonframe.ReadJSONFrame(peerStream, 1<<20)
				if err != nil {
					peerDone <- err
					return
				}
				var request rpcv1.RpcEnvelope
				if err := json.Unmarshal(requestBytes, &request); err != nil {
					peerDone <- err
					return
				}
				peerDone <- writeRawFrame(peerStream, test.payload(request.RequestId))
			}()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, applicationError, err := client.Call(ctx, 1, json.RawMessage(`{}`))
			if peerErr := <-peerDone; peerErr != nil {
				t.Fatal(peerErr)
			}
			if !test.valid {
				if err == nil || applicationError != nil {
					t.Fatalf("Call() = application error %#v, transport error %v; want protocol failure", applicationError, err)
				}
				if errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("invalid application error was ignored until caller timeout")
				}
				return
			}
			if err != nil || applicationError == nil || applicationError.Code != test.wantCode {
				t.Fatalf("Call() = application error %#v, transport error %v", applicationError, err)
			}
			if test.wantMessage == nil {
				if applicationError.Message != nil {
					t.Fatalf("Call() message = %q, want absent", *applicationError.Message)
				}
			} else if applicationError.Message == nil || *applicationError.Message != *test.wantMessage {
				t.Fatalf("Call() message = %#v, want %q", applicationError.Message, *test.wantMessage)
			}
		})
	}
}

type rpcErrorVectorMessage struct {
	Presence string `json:"presence"`
	Unit     string `json:"unit"`
	Repeat   int    `json:"repeat"`
	Suffix   string `json:"suffix"`
}

type rpcErrorVector struct {
	ID         string                `json:"id"`
	Code       uint32                `json:"code"`
	Message    rpcErrorVectorMessage `json:"message"`
	ExtraField bool                  `json:"extra_field"`
	Valid      bool                  `json:"valid"`
}

type rawRPCErrorVector struct {
	ID         string `json:"id"`
	Code       uint32 `json:"code"`
	MessageHex string `json:"message_hex"`
	Valid      bool   `json:"valid"`
}

type rpcErrorVectors struct {
	MaximumMessageBytes int                 `json:"maximum_message_bytes"`
	Cases               []rpcErrorVector    `json:"cases"`
	RawCases            []rawRPCErrorVector `json:"raw_cases"`
}

func loadRPCErrorVectors(t *testing.T) rpcErrorVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "transport_v2", "rpc_error_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture rpcErrorVectors
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func rpcErrorResponsePayload(t *testing.T, rpcError any) func(uint64) []byte {
	t.Helper()
	return func(requestID uint64) []byte {
		payload, err := json.Marshal(map[string]any{
			"type_id": 1, "request_id": 0, "response_to": requestID,
			"payload": nil, "error": rpcError,
		})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
}

func TestRPCServerSanitizesInvalidHandlerErrorsBeforeWrite(t *testing.T) {
	validASCII := strings.Repeat("a", 1024)
	validMultibyte := strings.Repeat("é", 512)
	invalidUTF8 := string([]byte{0xff})
	tests := []struct {
		name        string
		handlerErr  *rpcv1.RpcError
		wantCode    uint32
		wantMessage string
	}{
		{name: "ASCII 1024 bytes", handlerErr: &rpcv1.RpcError{Code: 7, Message: &validASCII}, wantCode: 7, wantMessage: validASCII},
		{name: "multibyte UTF-8 1024 bytes", handlerErr: &rpcv1.RpcError{Code: 7, Message: &validMultibyte}, wantCode: 7, wantMessage: validMultibyte},
		{name: "zero code", handlerErr: &rpcv1.RpcError{}, wantCode: 500, wantMessage: "internal error"},
		{name: "ASCII 1025 bytes", handlerErr: &rpcv1.RpcError{Code: 7, Message: strPointer(validASCII + "a")}, wantCode: 500, wantMessage: "internal error"},
		{name: "multibyte UTF-8 1025 bytes", handlerErr: &rpcv1.RpcError{Code: 7, Message: strPointer(validMultibyte + "a")}, wantCode: 500, wantMessage: "internal error"},
		{name: "malformed UTF-8", handlerErr: &rpcv1.RpcError{Code: 7, Message: &invalidUTF8}, wantCode: 500, wantMessage: "internal error"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverStream, peerStream := net.Pipe()
			defer peerStream.Close()
			router := rpc.NewRouter()
			router.Register(1, func(context.Context, json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
				return json.RawMessage(`null`), test.handlerErr
			})
			server := rpc.NewServer(serverStream, router)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			serveDone := make(chan error, 1)
			go func() { serveDone <- server.Serve(ctx) }()

			if err := jsonframe.WriteJSONFrame(peerStream, rpcv1.RpcEnvelope{TypeId: 1, RequestId: 1, Payload: json.RawMessage(`{}`)}); err != nil {
				t.Fatal(err)
			}
			responseBytes, err := jsonframe.ReadJSONFrame(peerStream, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			var response rpcv1.RpcEnvelope
			if err := json.Unmarshal(responseBytes, &response); err != nil {
				t.Fatal(err)
			}
			if response.Error == nil || response.Error.Code != test.wantCode || response.Error.Message == nil || *response.Error.Message != test.wantMessage {
				t.Fatalf("wire error = %#v, want code=%d message=%q", response.Error, test.wantCode, test.wantMessage)
			}
			cancel()
			_ = peerStream.Close()
			<-serveDone
		})
	}
}

func strPointer(value string) *string { return &value }

func TestRPC_CallCancelDoesNotPanicOnLateResponse(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := rpc.NewClient(a)
	defer c.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		bs, err := jsonframe.ReadJSONFrame(b, 1<<20)
		if err != nil {
			return
		}
		var env rpcv1.RpcEnvelope
		if err := json.Unmarshal(bs, &env); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
		resp := rpcv1.RpcEnvelope{
			TypeId:     env.TypeId,
			RequestId:  0,
			ResponseTo: env.RequestId,
			Payload:    json.RawMessage(`{}`),
		}
		_ = jsonframe.WriteJSONFrame(b, resp)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, _, err := c.Call(ctx, 1, json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server goroutine")
	}
}

func TestRPC_ServerServeHonorsContextCancel(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	router := rpc.NewRouter()
	srv := rpc.NewServer(a, router)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to exit")
	}
}

func TestRPC_ServerServeAcceptsNilContext(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	router := rpc.NewRouter()
	srv := rpc.NewServer(a, router)
	errCh := make(chan error, 1)
	go func() {
		// Nil ctx should behave like context.Background() (no panic).
		errCh <- srv.Serve(nil)
	}()

	_ = b.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to exit")
	}
}

func TestRPC_ClientCallAcceptsNilContext(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := rpc.NewClient(a)
	defer c.Close()

	// Drain the request so Call can move past the write and wait for the response.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = jsonframe.ReadJSONFrame(b, 1<<20)
	}()

	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.Call(nil, 1, json.RawMessage(`{}`))
		errCh <- err
	}()

	select {
	case <-drained:
		_ = b.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting to drain request")
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Call to return")
	}
}

func TestRPC_ServerServeRejectsInvalidJSON(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := rpc.NewRouter()
	srv := rpc.NewServer(a, router)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	for i := 0; i < 3; i++ {
		if err := writeRawFrame(b, []byte("{")); err != nil {
			t.Fatalf("write raw frame: %v", err)
		}
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to exit")
	}
}

func writeRawFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
