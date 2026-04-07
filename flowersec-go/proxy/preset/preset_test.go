package preset

import (
	"strings"
	"testing"

	fsproxy "github.com/floegence/flowersec/flowersec-go/proxy"
)

func TestResolveBuiltin(t *testing.T) {
	manifest, err := ResolveBuiltin("default")
	if err != nil {
		t.Fatalf("ResolveBuiltin(default): %v", err)
	}
	if manifest.PresetID != "default" {
		t.Fatalf("unexpected preset id: %q", manifest.PresetID)
	}

	codeServer, err := ResolveBuiltin("codeserver")
	if err != nil {
		t.Fatalf("ResolveBuiltin(codeserver): %v", err)
	}
	if codeServer.Limits.MaxWSFrameBytes == nil || *codeServer.Limits.MaxWSFrameBytes != 32*1024*1024 {
		t.Fatalf("unexpected codeserver ws frame limit: %+v", codeServer.Limits)
	}
}

func TestDecodeJSONRejectsOwnerDocAndZeroTimeout(t *testing.T) {
	_, err := DecodeJSON(strings.NewReader(`{
	  "v": 1,
	  "preset_id": "demo",
	  "owner_doc": "nope",
	  "limits": {}
	}`))
	if err == nil {
		t.Fatal("expected error")
	}

	_, err = DecodeJSON(strings.NewReader(`{
	  "v": 1,
	  "preset_id": "demo",
	  "limits": {
	    "timeout_ms": 0
	  }
	}`))
	if err == nil || !strings.Contains(err.Error(), "timeout_ms") {
		t.Fatalf("expected timeout_ms validation error, got %v", err)
	}
}

func TestApplyBridgeOptionsFillsZeroValuesOnly(t *testing.T) {
	manifest, err := ResolveBuiltin("codeserver")
	if err != nil {
		t.Fatalf("ResolveBuiltin: %v", err)
	}
	opts := ApplyBridgeOptions(fsproxy.BridgeOptions{}, manifest)
	if opts.MaxWSFrameBytes != 32*1024*1024 {
		t.Fatalf("unexpected ws frame bytes: %d", opts.MaxWSFrameBytes)
	}

	explicit := ApplyBridgeOptions(fsproxy.BridgeOptions{MaxWSFrameBytes: 2048}, manifest)
	if explicit.MaxWSFrameBytes != 2048 {
		t.Fatalf("explicit value must win, got %d", explicit.MaxWSFrameBytes)
	}
}
