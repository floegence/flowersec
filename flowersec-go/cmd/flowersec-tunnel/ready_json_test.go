package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteReadyJSON_PrettyAndCompact(t *testing.T) {
	out := ready{
		Version:    "v1.2.3",
		Commit:     "abc",
		Date:       "2026-01-01T00:00:00Z",
		Listen:     "127.0.0.1:0",
		WSPath:     "/ws",
		WSURL:      "ws://127.0.0.1:1234/ws",
		HTTPURL:    "http://127.0.0.1:1234",
		HealthzURL: "http://127.0.0.1:1234/healthz",
	}

	var compact bytes.Buffer
	if err := writeReadyJSON(&compact, out, false); err != nil {
		t.Fatalf("write compact: %v", err)
	}
	if strings.Contains(compact.String(), "\n  \"version\"") {
		t.Fatalf("expected compact JSON output, got %q", compact.String())
	}
	var got1 ready
	if err := json.Unmarshal(compact.Bytes(), &got1); err != nil {
		t.Fatalf("parse compact JSON: %v", err)
	}

	var pretty bytes.Buffer
	if err := writeReadyJSON(&pretty, out, true); err != nil {
		t.Fatalf("write pretty: %v", err)
	}
	if !strings.Contains(pretty.String(), "\n  \"version\"") {
		t.Fatalf("expected pretty JSON output, got %q", pretty.String())
	}
	var got2 ready
	if err := json.Unmarshal(pretty.Bytes(), &got2); err != nil {
		t.Fatalf("parse pretty JSON: %v", err)
	}
}
