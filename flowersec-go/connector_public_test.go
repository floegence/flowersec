package flowersec_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
)

func TestConnectorPublicSurfaceIsCarrierNeutral(t *testing.T) {
	optionsType := reflect.TypeOf(flowersec.ConnectorOptions{})
	wantFields := []string{"TrustRoots", "Origin", "ConnectTimeout", "RPCHandlers"}
	if optionsType.NumField() != len(wantFields) {
		t.Fatalf("ConnectorOptions has %d fields, want %d", optionsType.NumField(), len(wantFields))
	}
	if got, want := optionsType.Field(3).Type, reflect.TypeOf((*flowersec.RPCHandlers)(nil)); got != want {
		t.Fatalf("ConnectorOptions.RPCHandlers type = %v, want %v", got, want)
	}
	for index, want := range wantFields {
		if got := optionsType.Field(index).Name; got != want {
			t.Fatalf("ConnectorOptions field %d = %q, want %q", index, got, want)
		}
	}

	options := flowersec.ConnectorOptions{
		TrustRoots: x509.NewCertPool(), Origin: "https://client.example",
		ConnectTimeout: time.Second,
	}
	var connect func(context.Context, flowersec.ArtifactLease, flowersec.ConnectorOptions) (flowersec.Session, error) = flowersec.Connect
	_ = options
	_ = connect
}

func TestRPCHandlersPublicSurfaceIsClientRoleOnlyAndOpaque(t *testing.T) {
	handlers := flowersec.NewRPCHandlers()
	if handlers == nil {
		t.Fatal("NewRPCHandlers() = nil")
	}
	wantMethods := map[string]bool{"GoString": true, "HandleNotification": true, "HandleRPC": true, "MarshalJSON": true, "String": true}
	handlerType := reflect.TypeOf(handlers)
	if handlerType.NumMethod() != len(wantMethods) {
		t.Fatalf("RPCHandlers methods = %d, want %d", handlerType.NumMethod(), len(wantMethods))
	}
	for index := range handlerType.NumMethod() {
		method := handlerType.Method(index)
		if !wantMethods[method.Name] {
			t.Fatalf("RPCHandlers unexpectedly exposes %s", method.Name)
		}
	}
	if got, want := fmt.Sprintf("%v %#v", handlers, handlers), "Flowersec.RPCHandlers flowersec.RPCHandlers"; got != want {
		t.Fatalf("RPCHandlers formatting = %q, want %q", got, want)
	}
	encoded, err := json.Marshal(handlers)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("RPCHandlers JSON = %s, %v", encoded, err)
	}
}

func TestSessionTerminationPublicSurfaceAlignsWithPortableCore(t *testing.T) {
	sessionType := reflect.TypeOf((*flowersec.Session)(nil)).Elem()
	for _, forbidden := range []string{"Termination", "WaitClosed"} {
		if _, ok := sessionType.MethodByName(forbidden); ok {
			t.Fatalf("Session retains duplicate termination entrypoint %s", forbidden)
		}
	}
	method, ok := sessionType.MethodByName("WaitTermination")
	if !ok {
		t.Fatal("Session is missing WaitTermination")
	}
	wantTerminationType := reflect.TypeOf(flowersec.SessionTermination{})
	if method.Type.NumIn() != 1 || method.Type.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		t.Fatalf("WaitTermination input signature = %v", method.Type)
	}
	if method.Type.NumOut() != 2 || method.Type.Out(0) != wantTerminationType || method.Type.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("WaitTermination output signature = %v, want (flowersec.SessionTermination, error)", method.Type)
	}

	terminationType := reflect.TypeOf(flowersec.SessionTermination{})
	if terminationType.NumField() != 1 || terminationType.Field(0).Name != "Error" ||
		terminationType.Field(0).Type != reflect.TypeOf(flowersec.SessionError{}) {
		t.Fatalf("SessionTermination fields = %v, want exported non-null Error SessionError", terminationType)
	}
	for index := range sessionType.NumMethod() {
		signature := sessionType.Method(index).Type.String()
		for _, forbidden := range []string{"Artifact", "Credential", "Admission", "Handshake", "Carrier", "QUIC", "WebTransport", "Yamux", "Wire"} {
			if strings.Contains(signature, forbidden) {
				t.Fatalf("public session signature %q exposes %q", signature, forbidden)
			}
		}
	}
}

func TestStreamMetadataHasNoPreReleaseCompatibilityAliases(t *testing.T) {
	source, err := os.ReadFile("metadata.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"type Metadata =", "func NewMetadata("} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("Go public API retains pre-release compatibility alias %q", forbidden)
		}
	}
}

func TestSessionHandlersPublicSurfaceIsCarrierNeutralAndOpaque(t *testing.T) {
	optionsType := reflect.TypeOf(flowersec.SessionHandlerOptions{})
	wantFields := []string{"MaxConcurrentStreams", "OnError"}
	if optionsType.NumField() != len(wantFields) {
		t.Fatalf("SessionHandlerOptions fields = %d, want %d", optionsType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if got := optionsType.Field(index).Name; got != want {
			t.Fatalf("SessionHandlerOptions field %d = %q, want %q", index, got, want)
		}
	}
	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprintf("%v %#v", handlers, handlers), "Flowersec.SessionHandlers flowersec.SessionHandlers"; got != want {
		t.Fatalf("handlers formatting = %q, want %q", got, want)
	}
	encoded, err := json.Marshal(handlers)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("handlers JSON = %s, %v", encoded, err)
	}
	for index := range reflect.TypeOf(handlers).NumMethod() {
		signature := reflect.TypeOf(handlers).Method(index).Type.String()
		for _, forbidden := range []string{"Artifact", "Credential", "Admission", "Handshake", "Carrier", "QUIC", "WebTransport", "Yamux", "Wire"} {
			if strings.Contains(signature, forbidden) {
				t.Fatalf("public handler signature %q exposes %q", signature, forbidden)
			}
		}
	}
}

func TestStreamHandlersPublicSurfaceIsCarrierNeutralOpaqueAndSealed(t *testing.T) {
	optionsType := reflect.TypeOf(flowersec.StreamHandlerOptions{})
	wantFields := []string{"MaxConcurrentStreams", "OnError"}
	if optionsType.NumField() != len(wantFields) {
		t.Fatalf("StreamHandlerOptions fields = %d, want %d", optionsType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if got := optionsType.Field(index).Name; got != want {
			t.Fatalf("StreamHandlerOptions field %d = %q, want %q", index, got, want)
		}
	}
	handlers, err := flowersec.NewStreamHandlers(flowersec.StreamHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var registrar flowersec.StreamHandlerRegistrar = handlers
	_ = registrar
	wantMethods := map[string]bool{
		"GoString": true, "HandleStream": true, "MarshalJSON": true, "Serve": true, "String": true,
	}
	handlerType := reflect.TypeOf(handlers)
	if handlerType.NumMethod() != len(wantMethods) {
		t.Fatalf("StreamHandlers methods = %d, want %d", handlerType.NumMethod(), len(wantMethods))
	}
	for index := range handlerType.NumMethod() {
		method := handlerType.Method(index)
		if !wantMethods[method.Name] {
			t.Fatalf("StreamHandlers unexpectedly exposes %s", method.Name)
		}
		for _, forbidden := range []string{"Artifact", "Credential", "Admission", "Handshake", "Carrier", "QUIC", "WebTransport", "Yamux", "Wire"} {
			if strings.Contains(method.Type.String(), forbidden) {
				t.Fatalf("public stream handler signature %q exposes %q", method.Type, forbidden)
			}
		}
	}
	if got, want := fmt.Sprintf("%v %#v", handlers, handlers), "Flowersec.StreamHandlers flowersec.StreamHandlers"; got != want {
		t.Fatalf("handlers formatting = %q, want %q", got, want)
	}
	encoded, err := json.Marshal(handlers)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("handlers JSON = %s, %v", encoded, err)
	}
}

func TestUnreliableMessagePublicSurfaceIsOpaqueAndCarrierNeutral(t *testing.T) {
	channel := reflect.TypeOf((*flowersec.UnreliableMessageChannel)(nil)).Elem()
	if channel.NumMethod() != 3 {
		t.Fatalf("UnreliableMessageChannel methods = %d, want 3", channel.NumMethod())
	}
	for index := range channel.NumMethod() {
		signature := channel.Method(index).Type.String()
		for _, forbidden := range []string{"Artifact", "Credential", "Admission", "Handshake", "Control", "Carrier", "QUIC", "WebTransport", "Yamux"} {
			if strings.Contains(signature, forbidden) {
				t.Fatalf("public unreliable signature %q exposes %q", signature, forbidden)
			}
		}
	}
	options := reflect.TypeOf(flowersec.UnreliableSendOptions{})
	if options.NumField() != 1 || options.Field(0).Name != "ExpiresAt" || options.Field(0).Type != reflect.TypeOf(time.Time{}) {
		t.Fatalf("UnreliableSendOptions = %v", options)
	}
	wantStatuses := []flowersec.UnreliableSendStatus{
		flowersec.UnreliableAccepted,
		flowersec.UnreliableDroppedExpired,
		flowersec.UnreliableDroppedBudget,
		flowersec.UnreliableDroppedCarrier,
	}
	for _, status := range wantStatuses {
		if status == "" {
			t.Fatal("empty unreliable send status")
		}
	}
}

func TestMetadataPublicConstructorValidatesAndCopiesJSONObjectBoundary(t *testing.T) {
	nested := map[string]any{
		"accepted": true,
	}
	source := map[string]any{
		"operation": "health",
		"attempt":   int64(1),
		"nested":    nested,
	}
	metadata, err := flowersec.NewStreamMetadata(source)
	if err != nil {
		t.Fatalf("NewStreamMetadata() error = %v", err)
	}
	source["operation"] = "mutated"
	nested["accepted"] = false
	values := metadata.Values()
	if values["operation"] != "health" {
		t.Fatalf("metadata was not defensively copied: %#v", values)
	}
	if child, ok := values["nested"].(map[string]any); !ok || child["accepted"] != true {
		t.Fatalf("nested metadata was not defensively copied: %#v", values)
	}
	values["operation"] = "changed"
	if metadata.Values()["operation"] != "health" {
		t.Fatalf("Values() exposed mutable state: %#v", metadata.Values())
	}
	if _, err := flowersec.NewStreamMetadata(map[string]any{"fraction": 1.5}); !errors.Is(err, flowersec.ErrInvalidMetadata) {
		t.Fatalf("NewStreamMetadata() float error = %v, want ErrInvalidMetadata", err)
	}
	if _, err := flowersec.NewStreamMetadata(map[string]any{"unsafe": int64(9_007_199_254_740_992)}); !errors.Is(err, flowersec.ErrInvalidMetadata) {
		t.Fatalf("NewStreamMetadata() unsafe integer error = %v, want ErrInvalidMetadata", err)
	}
	for _, negativeZero := range []any{math.Copysign(0, -1), json.Number("-0")} {
		if _, err := flowersec.NewStreamMetadata(map[string]any{"negative_zero": negativeZero}); !errors.Is(err, flowersec.ErrInvalidMetadata) {
			t.Fatalf("NewStreamMetadata(%T(%v)) negative zero error = %v, want ErrInvalidMetadata", negativeZero, negativeZero, err)
		}
	}
	if got := flowersec.EmptyStreamMetadata().Values(); len(got) != 0 {
		t.Fatalf("EmptyStreamMetadata() = %#v, want empty", got)
	}
}

func TestConnectErrorPublicSnapshotContainsNoInternalDetail(t *testing.T) {
	var err *flowersec.ConnectError
	want := "<nil>"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if err.Code() != flowersec.ConnectConnectionFailed {
		t.Fatalf("nil ConnectError code = %q, want %q", err.Code(), flowersec.ConnectConnectionFailed)
	}
	wantCodes := map[flowersec.ConnectErrorCode]string{
		flowersec.ConnectArtifactInvalid:              "artifact_invalid",
		flowersec.ConnectExpired:                      "expired_artifact",
		flowersec.ConnectTransportSecurityUnsupported: "transport_security_unsupported",
		flowersec.ConnectTransportSecurityFailed:      "transport_security_failed",
		flowersec.ConnectConnectionFailed:             "connection_failed",
	}
	for code, want := range wantCodes {
		if got := code.String(); got != want {
			t.Fatalf("ConnectErrorCode(%q).String() = %q, want %q", code, got, want)
		}
	}
	var _ interface{ Is(error) bool } = err
	var _ interface{ Unwrap() error } = (*flowersec.SessionError)(nil)
}

func TestRPCErrorPublicSnapshotPreservesApplicationSemantics(t *testing.T) {
	errorType := reflect.TypeOf(flowersec.RPCError{})
	wantFields := []string{"Code", "Message", "MessagePresent"}
	if errorType.NumField() != len(wantFields) {
		t.Fatalf("RPCError has %d fields, want %d", errorType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if got := errorType.Field(index).Name; got != want {
			t.Fatalf("RPCError field %d = %q, want %q", index, got, want)
		}
	}
	pointerType := reflect.PointerTo(errorType)
	if pointerType.NumMethod() != 1 || pointerType.Method(0).Name != "Error" {
		t.Fatalf("RPCError methods = %v, want only Error", pointerType)
	}

	err := &flowersec.RPCError{Code: 404, Message: "handler not found"}
	if got, want := err.Error(), "Flowersec RPC failed (code=404)"; got != want {
		t.Fatalf("RPC Error() = %q, want %q", got, want)
	}
	if err.Code != 404 || err.Message != "handler not found" {
		t.Fatalf("RPC error = %#v, want application code/message", err)
	}
	var _ error = err
}

func TestConnectorRejectsInvalidCarrierNeutralOptions(t *testing.T) {
	artifact := parseFixtureArtifact(t)
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flowersec.Connect(context.Background(), lease, flowersec.ConnectorOptions{
		TrustRoots: x509.NewCertPool(),
	}); err == nil {
		t.Fatal("Connect error = nil, want invalid options")
	} else {
		var connectErr *flowersec.ConnectError
		if !errors.As(err, &connectErr) || connectErr.Code() != flowersec.ConnectArtifactInvalid {
			t.Fatalf("Connect error = %#v, want ConnectArtifactInvalid", err)
		}
		if !errors.Is(err, flowersec.ErrInvalidConnectorOptions) {
			t.Fatalf("Connect error = %v, want errors.Is ErrInvalidConnectorOptions", err)
		}
		if got := connectErr.RetryDisposition().Kind; got != flowersec.RetryDispositionTerminal {
			t.Fatalf("retry disposition = %q, want terminal", got)
		}
	}
	if _, err := flowersec.Connect(context.Background(), flowersec.ArtifactLease{}, flowersec.ConnectorOptions{
		TrustRoots: fixtureTrustRoots(t),
	}); err == nil {
		t.Fatal("Connect zero lease error = nil, want artifact invalid")
	} else {
		var connectErr *flowersec.ConnectError
		if !errors.As(err, &connectErr) || connectErr.Code() != flowersec.ConnectArtifactInvalid {
			t.Fatalf("Connect zero lease error = %#v, want ConnectArtifactInvalid", err)
		}
		if got := connectErr.RetryDisposition().Kind; got != flowersec.RetryDispositionTerminal {
			t.Fatalf("zero lease retry disposition = %q, want terminal", got)
		}
	}
	for _, origin := range []string{
		"ftp://client.example",
		"https://user@client.example",
		"https://client.example/",
		"https://client.example/path",
		"https://client.example?query",
		"https://client.example#fragment",
	} {
		if _, err := flowersec.Connect(context.Background(), lease, flowersec.ConnectorOptions{
			TrustRoots: fixtureTrustRoots(t), Origin: origin,
		}); !errors.Is(err, flowersec.ErrInvalidConnectorOptions) {
			t.Fatalf("Connect origin %q error = %v, want invalid options", origin, err)
		}
	}
	if _, err := flowersec.Connect(context.Background(), lease, flowersec.ConnectorOptions{
		TrustRoots: fixtureTrustRoots(t), Origin: "https://client.example", RPCHandlers: &flowersec.RPCHandlers{},
	}); !errors.Is(err, flowersec.ErrInvalidConnectorOptions) {
		t.Fatalf("Connect zero handlers error = %v, want invalid options", err)
	}
}

func fixtureTrustRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil || len(pool.Subjects()) == 0 {
		t.Skip("system trust roots unavailable")
	}
	return pool
}
