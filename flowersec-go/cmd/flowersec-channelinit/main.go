package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/floegence/flowersec/flowersec-go/internal/securefile"
	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"

	// randReader is overridden in tests.
	randReader io.Reader = rand.Reader
)

type output struct {
	Version     string                      `json:"version"`
	Commit      string                      `json:"commit"`
	Date        string                      `json:"date"`
	GrantClient *controlv1.ChannelInitGrant `json:"grant_client"`
	GrantServer *controlv1.ChannelInitGrant `json:"grant_server"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	showVersion := false

	issuerPrivFile := envString("FSEC_ISSUER_PRIVATE_KEY_FILE", "")
	tunnelURL := envString("FSEC_TUNNEL_URL", "")
	aud := envString("FSEC_TUNNEL_AUD", "")
	iss := envString("FSEC_TUNNEL_ISS", envString("FSEC_ISSUER_ID", ""))
	channelID := envString("FSEC_CHANNEL_ID", "")
	tokenExpSeconds, err := envInt64WithErr("FSEC_CHANNELINIT_TOKEN_EXP_SECONDS", 0)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_CHANNELINIT_TOKEN_EXP_SECONDS: %v\n", err)
		return 2
	}
	idleTimeoutSeconds, err := envIntWithErr("FSEC_CHANNELINIT_IDLE_TIMEOUT_SECONDS", 0)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_CHANNELINIT_IDLE_TIMEOUT_SECONDS: %v\n", err)
		return 2
	}
	outFile := envString("FSEC_CHANNELINIT_OUT", "")
	var overwrite bool
	var pretty bool

	fs := flag.NewFlagSet("flowersec-channelinit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&issuerPrivFile, "issuer-private-key-file", issuerPrivFile, "issuer private key file (required) (env: FSEC_ISSUER_PRIVATE_KEY_FILE)")
	fs.StringVar(&tunnelURL, "tunnel-url", tunnelURL, "tunnel websocket url (required; e.g. ws://127.0.0.1:8080/ws) (env: FSEC_TUNNEL_URL)")
	fs.StringVar(&aud, "aud", aud, "token audience (required; must match tunnel --aud) (env: FSEC_TUNNEL_AUD)")
	fs.StringVar(&iss, "iss", iss, "token issuer (required; must match tunnel --iss) (env: FSEC_TUNNEL_ISS or FSEC_ISSUER_ID)")
	fs.StringVar(&channelID, "channel-id", channelID, "channel id (default: random) (env: FSEC_CHANNEL_ID)")
	fs.Int64Var(&tokenExpSeconds, "token-exp-seconds", tokenExpSeconds, "token lifetime in seconds (0 uses default; capped by init exp) (env: FSEC_CHANNELINIT_TOKEN_EXP_SECONDS)")
	fs.IntVar(&idleTimeoutSeconds, "idle-timeout-seconds", idleTimeoutSeconds, "tunnel idle timeout in seconds (0 uses default; embedded into tokens and enforced by the tunnel) (env: FSEC_CHANNELINIT_IDLE_TIMEOUT_SECONDS)")
	fs.StringVar(&outFile, "out", outFile, "output file (default: stdout) (env: FSEC_CHANNELINIT_OUT)")
	fs.BoolVar(&overwrite, "overwrite", false, "overwrite existing --out file")
	fs.BoolVar(&pretty, "pretty", false, "pretty-print JSON output")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  flowersec-channelinit --issuer-private-key-file <file> --tunnel-url <ws://...> --aud <aud> --iss <iss> [flags]")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Mint a one-time ChannelInitGrant pair (client/server).")
		fmt.Fprintln(out, "  flowersec-channelinit \\")
		fmt.Fprintln(out, "    --issuer-private-key-file ./keys/issuer_key.json \\")
		fmt.Fprintln(out, "    --tunnel-url ws://127.0.0.1:8080/ws \\")
		fmt.Fprintln(out, "    --aud flowersec-tunnel:dev \\")
		fmt.Fprintln(out, "    --iss issuer-dev \\")
		fmt.Fprintln(out, "    --pretty \\")
		fmt.Fprintln(out, "    > channel.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Output:")
		fmt.Fprintln(out, "  stdout: JSON object with grant_client/grant_server (when --out is not set)")
		fmt.Fprintln(out, "  stderr: errors")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Exit codes:")
		fmt.Fprintln(out, "  0: success")
		fmt.Fprintln(out, "  2: usage error (bad flags/missing required)")
		fmt.Fprintln(out, "  1: runtime error")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Env defaults:")
		fmt.Fprintln(out, "  FSEC_ISSUER_PRIVATE_KEY_FILE, FSEC_TUNNEL_URL, FSEC_TUNNEL_AUD, FSEC_TUNNEL_ISS/FSEC_ISSUER_ID, FSEC_CHANNELINIT_* (flags override env)")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if showVersion {
		_, _ = fmt.Fprintln(stdout, fsversion.String(version, commit, date))
		return 0
	}

	usageErr := func(msg string) int {
		if msg != "" {
			fmt.Fprintln(stderr, msg)
		}
		fs.Usage()
		return 2
	}

	issuerPrivFile = strings.TrimSpace(issuerPrivFile)
	tunnelURL = strings.TrimSpace(tunnelURL)
	aud = strings.TrimSpace(aud)
	iss = strings.TrimSpace(iss)
	channelID = strings.TrimSpace(channelID)
	outFile = strings.TrimSpace(outFile)

	if issuerPrivFile == "" || tunnelURL == "" || aud == "" || iss == "" {
		return usageErr("missing --issuer-private-key-file, --tunnel-url, --aud, or --iss")
	}
	if tokenExpSeconds < 0 {
		return usageErr("--token-exp-seconds must be >= 0 (0 uses default)")
	}
	if idleTimeoutSeconds < 0 {
		return usageErr("--idle-timeout-seconds must be >= 0 (0 uses default)")
	}
	const maxInt32 = int(^uint32(0) >> 1)
	if idleTimeoutSeconds > maxInt32 {
		return usageErr(fmt.Sprintf("--idle-timeout-seconds must be <= %d", maxInt32))
	}
	if channelID == "" {
		id, err := randomB64u(24)
		if err != nil {
			fmt.Fprintln(stderr, fmt.Errorf("generate random channel id: %w", err))
			return 1
		}
		channelID = id
	}

	ks, err := issuer.LoadPrivateKeyFile(issuerPrivFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	svc := &channelinit.Service{
		Issuer: ks,
		Params: channelinit.Params{
			TunnelURL:          tunnelURL,
			TunnelAudience:     aud,
			IssuerID:           iss,
			TokenExpSeconds:    tokenExpSeconds,
			IdleTimeoutSeconds: int32(idleTimeoutSeconds),
		},
	}
	client, server, err := svc.NewChannelInit(channelID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	out := output{
		Version:     version,
		Commit:      commit,
		Date:        date,
		GrantClient: client,
		GrantServer: server,
	}
	var b []byte
	if pretty {
		b, err = json.MarshalIndent(out, "", "  ")
	} else {
		b, err = json.Marshal(out)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if outFile == "" {
		_, _ = stdout.Write(b)
		_, _ = fmt.Fprintln(stdout)
		return 0
	}
	if !overwrite && fileExists(outFile) {
		fmt.Fprintf(stderr, "refusing to overwrite existing file: %s (use --overwrite)\n", outFile)
		return 2
	}
	if err := securefile.WriteFileAtomic(outFile, b, 0o600); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func randomB64u(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", err
	}
	return base64url.Encode(b), nil
}

func envString(key string, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envIntWithErr(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	return v, nil
}

func envInt64WithErr(key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}
