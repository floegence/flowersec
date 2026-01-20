package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

func TestVersionFlag(t *testing.T) {
	oldV, oldC, oldD := version, commit, date
	version, commit, date = "v1.2.3", "abc", "2020-01-01T00:00:00Z"
	t.Cleanup(func() { version, commit, date = oldV, oldC, oldD })

	var stdout, stderr bytes.Buffer
	code := run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}
	got := strings.TrimSpace(stdout.String())
	want := "v1.2.3 (abc) 2020-01-01T00:00:00Z"
	if got != want {
		t.Fatalf("unexpected version output: got %q, want %q", got, want)
	}
}

func TestDirectInitOutputIsProtocolioCompatible(t *testing.T) {
	t.Setenv("FSEC_DIRECT_WS_URL", "")
	t.Setenv("FSEC_DIRECT_CHANNEL_ID", "")
	t.Setenv("FSEC_DIRECT_PSK_B64U", "")
	t.Setenv("FSEC_DIRECT_SUITE", "")
	t.Setenv("FSEC_DIRECT_INIT_EXP_SECONDS", "")
	t.Setenv("FSEC_DIRECT_OUT", "")

	oldV := version
	version = "v1.2.3"
	t.Cleanup(func() { version = oldV })

	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}

	args := []string{
		"--ws-url", "ws://127.0.0.1:8080/ws",
		"--channel-id", "ch_1",
		"--psk-b64u", base64.RawURLEncoding.EncodeToString(psk),
		"--init-exp-seconds", "120",
		"--suite", "x25519",
	}

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}

	var out output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("decode output: %v (stdout=%q)", err, stdout.String())
	}
	if out.Version != "v1.2.3" {
		t.Fatalf("unexpected version: %q", out.Version)
	}
	if out.WsUrl != "ws://127.0.0.1:8080/ws" || out.ChannelId != "ch_1" {
		t.Fatalf("unexpected connect info: %+v", out.DirectConnectInfo)
	}

	// Extra top-level fields must not break DirectConnectInfo decoders.
	info, err := protocolio.DecodeDirectConnectInfoJSON(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatalf("DecodeDirectConnectInfoJSON: %v", err)
	}
	if info.ChannelId != "ch_1" {
		t.Fatalf("unexpected channel_id: %q", info.ChannelId)
	}
}

func TestDirectInit_EnvDefaults(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	t.Setenv("FSEC_DIRECT_WS_URL", "ws://127.0.0.1:8080/ws")
	t.Setenv("FSEC_DIRECT_CHANNEL_ID", "ch_1")
	t.Setenv("FSEC_DIRECT_PSK_B64U", base64.RawURLEncoding.EncodeToString(psk))
	t.Setenv("FSEC_DIRECT_SUITE", "x25519")
	t.Setenv("FSEC_DIRECT_INIT_EXP_SECONDS", "120")
	t.Setenv("FSEC_DIRECT_OUT", "")

	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "\n  \"ws_url\"") {
		t.Fatalf("expected compact JSON by default, got indented output: %q", stdout.String())
	}

	var out output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("decode output: %v (stdout=%q)", err, stdout.String())
	}
	if out.WsUrl != "ws://127.0.0.1:8080/ws" || out.ChannelId != "ch_1" {
		t.Fatalf("unexpected connect info: %+v", out.DirectConnectInfo)
	}
}

func TestDirectInit_PrettyFlag(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 1
	}
	t.Setenv("FSEC_DIRECT_WS_URL", "")
	t.Setenv("FSEC_DIRECT_CHANNEL_ID", "")
	t.Setenv("FSEC_DIRECT_PSK_B64U", "")
	t.Setenv("FSEC_DIRECT_SUITE", "")
	t.Setenv("FSEC_DIRECT_INIT_EXP_SECONDS", "")
	t.Setenv("FSEC_DIRECT_OUT", "")

	args := []string{
		"--ws-url", "ws://127.0.0.1:8080/ws",
		"--channel-id", "ch_1",
		"--psk-b64u", base64.RawURLEncoding.EncodeToString(psk),
		"--init-exp-seconds", "120",
		"--suite", "x25519",
		"--pretty",
	}

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\n  \"ws_url\"") {
		t.Fatalf("expected indented JSON output, got %q", stdout.String())
	}
}
