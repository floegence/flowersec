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
	"github.com/floegence/flowersec/flowersec-go/internal/cmdutil"
	"github.com/floegence/flowersec/flowersec-go/internal/securefile"
	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
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

	issuerPrivFile := cmdutil.EnvString("FSEC_ISSUER_PRIVATE_KEY_FILE", "")
	tunnelURL := cmdutil.EnvString("FSEC_TUNNEL_URL", "")
	aud := cmdutil.EnvString("FSEC_TUNNEL_AUD", "")
	iss := cmdutil.EnvString("FSEC_TUNNEL_ISS", cmdutil.EnvString("FSEC_ISSUER_ID", ""))
	channelID := cmdutil.EnvString("FSEC_CHANNEL_ID", "")
	tokenExpSeconds, err := cmdutil.EnvInt64("FSEC_CHANNELINIT_TOKEN_EXP_SECONDS", 0)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_CHANNELINIT_TOKEN_EXP_SECONDS: %v\n", err)
		return 2
	}
	idleTimeoutSeconds, err := cmdutil.EnvInt("FSEC_CHANNELINIT_IDLE_TIMEOUT_SECONDS", 0)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_CHANNELINIT_IDLE_TIMEOUT_SECONDS: %v\n", err)
		return 2
	}
	outFile := cmdutil.EnvString("FSEC_CHANNELINIT_OUT", "")
	serverGrantOut := cmdutil.EnvString("FSEC_CHANNELINIT_SERVER_GRANT_OUT", "")
	format := cmdutil.EnvString("FSEC_CHANNELINIT_FORMAT", "legacy")
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
	fs.StringVar(&format, "format", format, "output format: legacy or artifact (env: FSEC_CHANNELINIT_FORMAT)")
	fs.StringVar(&outFile, "out", outFile, "output file (default: stdout) (env: FSEC_CHANNELINIT_OUT)")
	fs.StringVar(&serverGrantOut, "server-grant-out", serverGrantOut, "when --format=artifact, optional output file for the paired raw server grant (env: FSEC_CHANNELINIT_SERVER_GRANT_OUT)")
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
		fmt.Fprintln(out, "  # Emit a client-facing ConnectArtifact and write the paired server grant separately.")
		fmt.Fprintln(out, "  flowersec-channelinit \\")
		fmt.Fprintln(out, "    --issuer-private-key-file ./keys/issuer_key.json \\")
		fmt.Fprintln(out, "    --tunnel-url ws://127.0.0.1:8080/ws \\")
		fmt.Fprintln(out, "    --aud flowersec-tunnel:dev \\")
		fmt.Fprintln(out, "    --iss issuer-dev \\")
		fmt.Fprintln(out, "    --format artifact \\")
		fmt.Fprintln(out, "    --server-grant-out ./server-grant.json \\")
		fmt.Fprintln(out, "    > connect-artifact.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Output:")
		fmt.Fprintln(out, "  stdout: legacy wrapper JSON or ConnectArtifact JSON (when --out is not set)")
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
	serverGrantOut = strings.TrimSpace(serverGrantOut)
	format = strings.ToLower(strings.TrimSpace(format))

	if issuerPrivFile == "" || tunnelURL == "" || aud == "" || iss == "" {
		return usageErr("missing --issuer-private-key-file, --tunnel-url, --aud, or --iss")
	}
	if format == "" {
		format = "legacy"
	}
	if format != "legacy" && format != "artifact" {
		return usageErr("invalid --format (want legacy or artifact)")
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

	if outFile == "" {
		var stdoutPayload any = out
		if format == "artifact" {
			stdoutPayload = protocolio.ConnectArtifact{
				V:           1,
				Transport:   protocolio.ConnectArtifactTransportTunnel,
				TunnelGrant: client,
			}
		}
		b, err = marshalOutput(stdoutPayload, pretty)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		_, _ = stdout.Write(b)
		_, _ = fmt.Fprintln(stdout)
	} else {
		var filePayload any = out
		if format == "artifact" {
			filePayload = protocolio.ConnectArtifact{
				V:           1,
				Transport:   protocolio.ConnectArtifactTransportTunnel,
				TunnelGrant: client,
			}
		}
		b, err = marshalOutput(filePayload, pretty)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := cmdutil.RefuseOverwrite(outFile, overwrite); err != nil {
			fmt.Fprintln(stderr, err)
			if cmdutil.IsUsage(err) {
				return 2
			}
			return 1
		}
		if err := securefile.WriteFileAtomic(outFile, b, 0o600); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if format == "artifact" && serverGrantOut != "" {
		if outFile != "" && outFile == serverGrantOut {
			return usageErr("--server-grant-out must differ from --out")
		}
		serverBytes, err := marshalOutput(server, pretty)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := cmdutil.RefuseOverwrite(serverGrantOut, overwrite); err != nil {
			fmt.Fprintln(stderr, err)
			if cmdutil.IsUsage(err) {
				return 2
			}
			return 1
		}
		if err := securefile.WriteFileAtomic(serverGrantOut, serverBytes, 0o600); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	return 0
}

func marshalOutput(v any, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}

func randomB64u(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", err
	}
	return base64url.Encode(b), nil
}
