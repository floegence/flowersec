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
	"time"

	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type output struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	directv1.DirectConnectInfo
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	showVersion := false

	wsURL := envString("FSEC_DIRECT_WS_URL", "")
	channelID := envString("FSEC_DIRECT_CHANNEL_ID", "")
	pskB64u := envString("FSEC_DIRECT_PSK_B64U", "")
	suiteStr := envString("FSEC_DIRECT_SUITE", "x25519")
	initExpSeconds, err := envInt64WithErr("FSEC_DIRECT_INIT_EXP_SECONDS", 60)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_DIRECT_INIT_EXP_SECONDS: %v\n", err)
		return 2
	}
	outFile := envString("FSEC_DIRECT_OUT", "")
	var overwrite bool
	var pretty bool

	fs := flag.NewFlagSet("flowersec-directinit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&wsURL, "ws-url", wsURL, "direct websocket url (required; e.g. ws://127.0.0.1:8080/ws) (env: FSEC_DIRECT_WS_URL)")
	fs.StringVar(&channelID, "channel-id", channelID, "channel id (default: random) (env: FSEC_DIRECT_CHANNEL_ID)")
	fs.StringVar(&pskB64u, "psk-b64u", pskB64u, "base64url-encoded 32-byte PSK (default: random) (env: FSEC_DIRECT_PSK_B64U)")
	fs.StringVar(&suiteStr, "suite", suiteStr, "cipher suite: x25519 or p256 (default: x25519) (env: FSEC_DIRECT_SUITE)")
	fs.Int64Var(&initExpSeconds, "init-exp-seconds", initExpSeconds, "handshake init window lifetime in seconds (default: 60) (env: FSEC_DIRECT_INIT_EXP_SECONDS)")
	fs.StringVar(&outFile, "out", outFile, "output file (default: stdout) (env: FSEC_DIRECT_OUT)")
	fs.BoolVar(&overwrite, "overwrite", false, "overwrite existing --out file")
	fs.BoolVar(&pretty, "pretty", false, "pretty-print JSON output")
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

	wsURL = strings.TrimSpace(wsURL)
	channelID = strings.TrimSpace(channelID)
	pskB64u = strings.TrimSpace(pskB64u)
	suiteStr = strings.TrimSpace(suiteStr)
	outFile = strings.TrimSpace(outFile)

	if wsURL == "" {
		return usageErr("missing --ws-url")
	}
	if initExpSeconds <= 0 {
		return usageErr("--init-exp-seconds must be > 0")
	}
	if channelID == "" {
		channelID = randomB64u(24)
	}

	var psk []byte
	if pskB64u == "" {
		psk = make([]byte, 32)
		if _, err := rand.Read(psk); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		pskB64u = base64url.Encode(psk)
	} else {
		var err error
		psk, err = base64url.Decode(pskB64u)
		if err != nil || len(psk) != 32 {
			if err == nil {
				err = errors.New("psk must decode to 32 bytes")
			}
			return usageErr("invalid --psk-b64u: " + err.Error())
		}
	}

	suite, err := parseSuite(suiteStr)
	if err != nil {
		return usageErr(err.Error())
	}

	now := time.Now()
	initExpUnixS := now.Add(time.Duration(initExpSeconds) * time.Second).Unix()

	out := output{
		Version: version,
		Commit:  commit,
		Date:    date,
		DirectConnectInfo: directv1.DirectConnectInfo{
			WsUrl:                    wsURL,
			ChannelId:                channelID,
			E2eePskB64u:              pskB64u,
			ChannelInitExpireAtUnixS: initExpUnixS,
			DefaultSuite:             suite,
		},
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
	if err := os.WriteFile(outFile, b, 0o600); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseSuite(s string) (directv1.Suite, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "1", "x25519", "x25519_hkdf_sha256_aes_256_gcm", "suite_x25519_hkdf_sha256_aes_256_gcm":
		return directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM, nil
	case "2", "p256", "p-256", "p_256", "p256_hkdf_sha256_aes_256_gcm", "suite_p256_hkdf_sha256_aes_256_gcm":
		return directv1.Suite_P256_HKDF_SHA256_AES_256_GCM, nil
	default:
		return 0, fmt.Errorf("invalid --suite %q (want x25519 or p256)", s)
	}
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

func envString(key string, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
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
