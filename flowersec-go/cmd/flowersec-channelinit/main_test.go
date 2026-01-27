package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
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

func TestChannelInitOutputIsProtocolioCompatible(t *testing.T) {
	t.Setenv("FSEC_ISSUER_PRIVATE_KEY_FILE", "")
	t.Setenv("FSEC_TUNNEL_URL", "")
	t.Setenv("FSEC_TUNNEL_AUD", "")
	t.Setenv("FSEC_TUNNEL_ISS", "")
	t.Setenv("FSEC_ISSUER_ID", "")
	t.Setenv("FSEC_CHANNEL_ID", "")
	t.Setenv("FSEC_CHANNELINIT_OUT", "")
	t.Setenv("FSEC_CHANNELINIT_TOKEN_EXP_SECONDS", "")
	t.Setenv("FSEC_CHANNELINIT_IDLE_TIMEOUT_SECONDS", "")

	oldV := version
	version = "v1.2.3"
	t.Cleanup(func() { version = oldV })

	tmp := t.TempDir()
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	privJSON, err := ks.ExportPrivateKeyFile()
	if err != nil {
		t.Fatalf("export private key: %v", err)
	}
	privFile := filepath.Join(tmp, "issuer_key.json")
	if err := os.WriteFile(privFile, privJSON, 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}

	args := []string{
		"--issuer-private-key-file", privFile,
		"--tunnel-url", "ws://127.0.0.1:8080/ws",
		"--aud", "aud",
		"--iss", "iss",
		"--channel-id", "ch_1",
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
	if out.GrantClient == nil || out.GrantServer == nil {
		t.Fatalf("missing grants: %+v", out)
	}

	// Extra top-level fields must not break wrapper-based decoders.
	gc, err := protocolio.DecodeGrantClientJSON(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatalf("DecodeGrantClientJSON: %v", err)
	}
	if gc.ChannelId != "ch_1" {
		t.Fatalf("unexpected client channel_id: %q", gc.ChannelId)
	}
	gs, err := protocolio.DecodeGrantServerJSON(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatalf("DecodeGrantServerJSON: %v", err)
	}
	if gs.ChannelId != "ch_1" {
		t.Fatalf("unexpected server channel_id: %q", gs.ChannelId)
	}
}

func TestChannelInit_EnvDefaults(t *testing.T) {
	t.Setenv("FSEC_TUNNEL_URL", "ws://127.0.0.1:8080/ws")
	t.Setenv("FSEC_TUNNEL_AUD", "aud")
	t.Setenv("FSEC_TUNNEL_ISS", "iss")
	t.Setenv("FSEC_CHANNEL_ID", "ch_1")
	t.Setenv("FSEC_CHANNELINIT_OUT", "")
	t.Setenv("FSEC_CHANNELINIT_TOKEN_EXP_SECONDS", "")
	t.Setenv("FSEC_CHANNELINIT_IDLE_TIMEOUT_SECONDS", "")

	tmp := t.TempDir()
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	privJSON, err := ks.ExportPrivateKeyFile()
	if err != nil {
		t.Fatalf("export private key: %v", err)
	}
	privFile := filepath.Join(tmp, "issuer_key.json")
	if err := os.WriteFile(privFile, privJSON, 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}
	t.Setenv("FSEC_ISSUER_PRIVATE_KEY_FILE", privFile)

	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "\n  \"grant_client\"") {
		t.Fatalf("expected compact JSON by default, got indented output: %q", stdout.String())
	}

	var out output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("decode output: %v (stdout=%q)", err, stdout.String())
	}
	if out.GrantClient == nil || out.GrantServer == nil {
		t.Fatalf("missing grants: %+v", out)
	}
}

func TestChannelInit_PrettyFlag(t *testing.T) {
	t.Setenv("FSEC_ISSUER_PRIVATE_KEY_FILE", "")
	t.Setenv("FSEC_TUNNEL_URL", "")
	t.Setenv("FSEC_TUNNEL_AUD", "")
	t.Setenv("FSEC_TUNNEL_ISS", "")
	t.Setenv("FSEC_ISSUER_ID", "")
	t.Setenv("FSEC_CHANNEL_ID", "")
	t.Setenv("FSEC_CHANNELINIT_OUT", "")
	t.Setenv("FSEC_CHANNELINIT_TOKEN_EXP_SECONDS", "")
	t.Setenv("FSEC_CHANNELINIT_IDLE_TIMEOUT_SECONDS", "")

	tmp := t.TempDir()
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	privJSON, err := ks.ExportPrivateKeyFile()
	if err != nil {
		t.Fatalf("export private key: %v", err)
	}
	privFile := filepath.Join(tmp, "issuer_key.json")
	if err := os.WriteFile(privFile, privJSON, 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}

	args := []string{
		"--issuer-private-key-file", privFile,
		"--tunnel-url", "ws://127.0.0.1:8080/ws",
		"--aud", "aud",
		"--iss", "iss",
		"--channel-id", "ch_1",
		"--pretty",
	}

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\n  \"grant_client\"") {
		t.Fatalf("expected indented JSON output, got %q", stdout.String())
	}
}

func TestChannelInit_OutFileOverwrite_TightensPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not reliable on windows")
	}
	tmp := t.TempDir()
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	privJSON, err := ks.ExportPrivateKeyFile()
	if err != nil {
		t.Fatalf("export private key: %v", err)
	}
	privFile := filepath.Join(tmp, "issuer_key.json")
	if err := os.WriteFile(privFile, privJSON, 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}

	outFile := filepath.Join(tmp, "channel.json")
	if err := os.WriteFile(outFile, []byte("old"), 0o644); err != nil {
		t.Fatalf("write old out file: %v", err)
	}
	if err := os.Chmod(outFile, 0o644); err != nil {
		t.Fatalf("chmod old out file: %v", err)
	}

	args := []string{
		"--issuer-private-key-file", privFile,
		"--tunnel-url", "ws://127.0.0.1:8080/ws",
		"--aud", "aud",
		"--iss", "iss",
		"--channel-id", "ch_1",
		"--out", outFile,
		"--overwrite",
	}

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}

	st, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("stat out file: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected out file perms: got %o want %o", st.Mode().Perm(), 0o600)
	}
	if st.Size() == 0 {
		t.Fatalf("out file is empty")
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) {
	return 0, errors.New("boom")
}

func TestRun_RandomChannelIDFailure_Exits1(t *testing.T) {
	orig := randReader
	randReader = errReader{}
	t.Cleanup(func() { randReader = orig })

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"--issuer-private-key-file", "issuer_key.json",
			"--tunnel-url", "ws://127.0.0.1:8080/ws",
			"--aud", "aud",
			"--iss", "iss",
		},
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "generate random channel id") {
		t.Fatalf("expected stderr to contain random channel id error, got %q", stderr.String())
	}
}

func TestHelp_IncludesExamplesAndExitCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	help := stderr.String()
	if !strings.Contains(help, "Examples:") {
		t.Fatalf("expected help to include Examples, help=%q", help)
	}
	if !strings.Contains(help, "Exit codes:") {
		t.Fatalf("expected help to include exit codes, help=%q", help)
	}
	if !strings.Contains(help, "Flags:") {
		t.Fatalf("expected help to include Flags, help=%q", help)
	}
}

func TestChannelInit_RejectsNegativeTokenExpSeconds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"--issuer-private-key-file", "issuer_key.json",
			"--tunnel-url", "ws://127.0.0.1:8080/ws",
			"--aud", "aud",
			"--iss", "iss",
			"--token-exp-seconds", "-1",
		},
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--token-exp-seconds") {
		t.Fatalf("expected stderr to mention token-exp-seconds, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected stderr to include usage, got %q", stderr.String())
	}
}

func TestChannelInit_RejectsNegativeIdleTimeoutSeconds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"--issuer-private-key-file", "issuer_key.json",
			"--tunnel-url", "ws://127.0.0.1:8080/ws",
			"--aud", "aud",
			"--iss", "iss",
			"--idle-timeout-seconds", "-1",
		},
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--idle-timeout-seconds") {
		t.Fatalf("expected stderr to mention idle-timeout-seconds, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected stderr to include usage, got %q", stderr.String())
	}
}

func TestChannelInit_RejectsIdleTimeoutSecondsOutOfInt32Range(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"--issuer-private-key-file", "issuer_key.json",
			"--tunnel-url", "ws://127.0.0.1:8080/ws",
			"--aud", "aud",
			"--iss", "iss",
			"--idle-timeout-seconds", "2147483648",
		},
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--idle-timeout-seconds") {
		t.Fatalf("expected stderr to mention idle-timeout-seconds, got %q", stderr.String())
	}
}
