package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

func TestRun_HelpIncludesExamplesAndExitCodes(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected empty stdout for --help, got %q", out.String())
	}
	help := errOut.String()
	if !strings.Contains(help, "Examples:") {
		t.Fatalf("expected help to include Examples, help=%q", help)
	}
	if !strings.Contains(help, "Output:") {
		t.Fatalf("expected help to include Output, help=%q", help)
	}
	if !strings.Contains(help, "Exit codes:") {
		t.Fatalf("expected help to include Exit codes, help=%q", help)
	}
}

func TestRun_MissingOriginIsUsageError(t *testing.T) {
	t.Setenv("FSEC_ORIGIN", "")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "missing --origin") {
		t.Fatalf("expected missing origin error, stderr=%q", errOut.String())
	}
}

func TestRun_VersionFlag(t *testing.T) {
	oldVersion := version
	oldCommit := commit
	oldDate := date
	t.Cleanup(func() {
		version = oldVersion
		commit = oldCommit
		date = oldDate
	})
	version = "v1.2.3"
	commit = "deadbeef"
	date = "2026-01-01T00:00:00Z"

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, errOut.String())
	}
	s := out.String()
	if !strings.Contains(s, "v1.2.3") || !strings.Contains(s, "deadbeef") || !strings.Contains(s, "2026-01-01T00:00:00Z") {
		t.Fatalf("unexpected version output: %q", s)
	}
}

func TestDecodeDirectInfoInput_AcceptsConnectArtifactEnvelope(t *testing.T) {
	artifact := protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportDirect,
		DirectInfo: &directv1.DirectConnectInfo{
			WsUrl:                    "ws://127.0.0.1:8081/ws",
			ChannelId:                "chan-direct",
			E2eePskB64u:              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ChannelInitExpireAtUnixS: 1735689600,
			DefaultSuite:             1,
		},
	}
	rawArtifact, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	envelope, err := json.Marshal(map[string]json.RawMessage{
		"connect_artifact": rawArtifact,
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	info, err := decodeDirectInfoInput(bytes.NewReader(envelope))
	if err != nil {
		t.Fatalf("decodeDirectInfoInput() failed: %v", err)
	}
	if info.ChannelId != "chan-direct" {
		t.Fatalf("unexpected channel id: %q", info.ChannelId)
	}
}
