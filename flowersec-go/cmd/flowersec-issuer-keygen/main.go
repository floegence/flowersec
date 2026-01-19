package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type ready struct {
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	Date           string `json:"date"`
	KID            string `json:"kid"`
	PrivateKeyFile string `json:"private_key_file"`
	IssuerKeysFile string `json:"issuer_keys_file"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	showVersion := false

	kid := envString("FSEC_ISSUER_KID", "k1")
	outDir := envString("FSEC_ISSUER_OUT_DIR", ".")
	privFile := envString("FSEC_ISSUER_PRIVATE_KEY_FILE", "")
	pubFile := envString("FSEC_ISSUER_KEYS_FILE", envString("FSEC_TUNNEL_ISSUER_KEYS_FILE", ""))
	var overwrite bool

	fs := flag.NewFlagSet("flowersec-issuer-keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&kid, "kid", kid, "issuer key id (kid) (env: FSEC_ISSUER_KID)")
	fs.StringVar(&outDir, "out-dir", outDir, "output directory for generated files (env: FSEC_ISSUER_OUT_DIR)")
	fs.StringVar(&privFile, "private-key-file", privFile, "output file for issuer private key (default: <out-dir>/issuer_key.json) (env: FSEC_ISSUER_PRIVATE_KEY_FILE)")
	fs.StringVar(&pubFile, "issuer-keys-file", pubFile, "output file for tunnel issuer keyset (public keys) (default: <out-dir>/issuer_keys.json) (env: FSEC_ISSUER_KEYS_FILE or FSEC_TUNNEL_ISSUER_KEYS_FILE)")
	fs.BoolVar(&overwrite, "overwrite", false, "overwrite existing files")
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

	kid = strings.TrimSpace(kid)
	if kid == "" {
		return usageErr("missing --kid")
	}
	outDir = strings.TrimSpace(outDir)
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if privFile == "" {
		privFile = filepath.Join(outDir, "issuer_key.json")
	} else if !filepath.IsAbs(privFile) {
		privFile = filepath.Join(outDir, privFile)
	}
	if pubFile == "" {
		pubFile = filepath.Join(outDir, "issuer_keys.json")
	} else if !filepath.IsAbs(pubFile) {
		pubFile = filepath.Join(outDir, pubFile)
	}

	if !overwrite {
		if fileExists(privFile) {
			fmt.Fprintf(stderr, "refusing to overwrite existing file: %s (use --overwrite)\n", privFile)
			return 2
		}
		if fileExists(pubFile) {
			fmt.Fprintf(stderr, "refusing to overwrite existing file: %s (use --overwrite)\n", pubFile)
			return 2
		}
	}

	ks, err := issuer.NewRandom(kid)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	privJSON, err := ks.ExportPrivateKeyFile()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	pubJSON, err := ks.ExportTunnelKeyset()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if err := os.WriteFile(privFile, privJSON, 0o600); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.WriteFile(pubFile, pubJSON, 0o644); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	privOut := absOr(privFile)
	pubOut := absOr(pubFile)
	_ = json.NewEncoder(stdout).Encode(ready{
		Version:        version,
		Commit:         commit,
		Date:           date,
		KID:            kid,
		PrivateKeyFile: privOut,
		IssuerKeysFile: pubOut,
	})
	return 0
}

func absOr(path string) string {
	if path == "" {
		return ""
	}
	a, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return a
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func envString(key string, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
