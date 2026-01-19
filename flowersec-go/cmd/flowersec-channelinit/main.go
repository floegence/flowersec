package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
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

	var issuerPrivFile string
	var tunnelURL string
	var aud string
	var iss string
	var channelID string
	var tokenExpSeconds int64
	var idleTimeoutSeconds int
	var outFile string
	var overwrite bool

	fs := flag.NewFlagSet("flowersec-channelinit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&issuerPrivFile, "issuer-private-key-file", "", "issuer private key file (required)")
	fs.StringVar(&tunnelURL, "tunnel-url", "", "tunnel websocket url (required; e.g. ws://127.0.0.1:8080/ws)")
	fs.StringVar(&aud, "aud", "", "token audience (required; must match tunnel --aud)")
	fs.StringVar(&iss, "iss", "", "token issuer (required; must match tunnel --iss)")
	fs.StringVar(&channelID, "channel-id", "", "channel id (default: random)")
	fs.Int64Var(&tokenExpSeconds, "token-exp-seconds", 60, "token lifetime in seconds (capped by init exp)")
	fs.IntVar(&idleTimeoutSeconds, "idle-timeout-seconds", 60, "tunnel idle timeout in seconds (embedded into tokens and enforced by the tunnel)")
	fs.StringVar(&outFile, "out", "", "output file (default: stdout)")
	fs.BoolVar(&overwrite, "overwrite", false, "overwrite existing --out file")
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

	issuerPrivFile = strings.TrimSpace(issuerPrivFile)
	tunnelURL = strings.TrimSpace(tunnelURL)
	aud = strings.TrimSpace(aud)
	iss = strings.TrimSpace(iss)
	channelID = strings.TrimSpace(channelID)
	outFile = strings.TrimSpace(outFile)

	if issuerPrivFile == "" || tunnelURL == "" || aud == "" || iss == "" {
		fmt.Fprintln(stderr, "missing --issuer-private-key-file, --tunnel-url, --aud, or --iss")
		return 2
	}
	if channelID == "" {
		channelID = randomB64u(24)
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
	b, err := json.MarshalIndent(output{
		Version:     version,
		Commit:      commit,
		Date:        date,
		GrantClient: client,
		GrantServer: server,
	}, "", "  ")
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
	if err := os.WriteFile(outFile, b, 0o600); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func randomB64u(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64url.Encode(b)
}
