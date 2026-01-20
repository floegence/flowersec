package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestConnect_AutoDetectDirect(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"ws_url":""}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageValidate || fe.Code != CodeMissingWSURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_AutoDetectTunnelURL(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"role":1,"tunnel_url":""}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeMissingTunnelURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_AutoDetectGrantClientWrapper(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"grant_client":{"role":1,"tunnel_url":""}}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeMissingTunnelURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_AutoDetectGrantServerWrapper(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"grant_server":{"role":2}}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageValidate || fe.Code != CodeRoleMismatch {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_PrefersDirectWhenBothPresent(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"ws_url":"","tunnel_url":"ws://tunnel.invalid/ws","role":1}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageValidate || fe.Code != CodeMissingWSURL {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_RejectsUnknownObject(t *testing.T) {
	_, err := Connect(context.Background(), []byte(`{"hello":"world"}`), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_RejectsInvalidJSON(t *testing.T) {
	_, err := Connect(context.Background(), strings.NewReader("not json"), WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_RejectsNonJSONString(t *testing.T) {
	_, err := Connect(context.Background(), "not json", WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestConnect_InvalidJSONStringPreservesCause(t *testing.T) {
	_, err := Connect(context.Background(), "{", WithOrigin("http://example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathAuto || fe.Stage != StageValidate || fe.Code != CodeInvalidInput {
		t.Fatalf("unexpected error: %+v", fe)
	}
	var se *json.SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("expected *json.SyntaxError in error chain, got %T", fe.Err)
	}
}
