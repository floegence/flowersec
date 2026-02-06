package cmdutil

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteJSON_WritesNewline(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, map[string]any{"x": 1}, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Fatalf("expected trailing newline, got %q", buf.String())
	}
}
