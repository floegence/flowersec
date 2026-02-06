package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/internal/cmdutil"
	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type ready struct {
	Status string `json:"status"`

	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`

	Listen  string `json:"listen"`
	HTTPURL string `json:"http_url"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	logger := log.New(stderr, "", log.LstdFlags)

	showVersion := false
	configPath := cmdutil.EnvString("FSEC_PROXY_GATEWAY_CONFIG", "")

	fs := flag.NewFlagSet("flowersec-proxy-gateway", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&configPath, "config", configPath, "path to JSON config file (required) (env: FSEC_PROXY_GATEWAY_CONFIG)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  flowersec-proxy-gateway --config ./gateway.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Start an HTTP/WS gateway that forwards to a server endpoint over Flowersec streams.")
		fmt.Fprintln(out, "  flowersec-proxy-gateway --config ./gateway.json | tee ready.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Config file schema (JSON):")
		fmt.Fprintln(out, `  {`)
		fmt.Fprintln(out, `    "listen": "127.0.0.1:0",`)
		fmt.Fprintln(out, `    "origin": "http://127.0.0.1:5173",`)
		fmt.Fprintln(out, `    "routes": [`)
		fmt.Fprintln(out, `      { "host": "code.example.com", "grant_client_file": "./channel.json" }`)
		fmt.Fprintln(out, `    ]`)
		fmt.Fprintln(out, `  }`)
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Output:")
		fmt.Fprintln(out, "  stdout: a single JSON ready object")
		fmt.Fprintln(out, "  stderr: logs and errors")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Exit codes:")
		fmt.Fprintln(out, "  0: success")
		fmt.Fprintln(out, "  2: usage error (bad flags/missing required)")
		fmt.Fprintln(out, "  1: runtime error")
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

	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return usageErr("missing --config (or env: FSEC_PROXY_GATEWAY_CONFIG)")
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Connect all routes eagerly (fail fast on invalid grants).
	routeClients := make(map[string]client.Client, len(cfg.Routes))
	for _, r := range cfg.Routes {
		grantFile := strings.TrimSpace(r.GrantClientFile)
		b, err := os.ReadFile(grantFile)
		if err != nil {
			logger.Printf("read grant_client_file for host %q: %v", r.Host, err)
			return 1
		}
		grant, err := protocolio.DecodeGrantClientJSON(bytes.NewReader(b))
		if err != nil {
			logger.Printf("decode grant_client_file for host %q: %v", r.Host, err)
			return 1
		}
		cli, err := client.ConnectTunnel(
			ctx,
			grant,
			client.WithOrigin(cfg.Origin),
			client.WithConnectTimeout(10*time.Second),
			client.WithHandshakeTimeout(10*time.Second),
			client.WithMaxRecordBytes(1<<20),
		)
		if err != nil {
			logger.Printf("connect tunnel for host %q: %v", r.Host, err)
			return 1
		}
		routeClients[r.Host] = cli
	}
	defer func() {
		for _, c := range routeClients {
			_ = c.Close()
		}
	}()

	gw := newGateway(routeClients, logger)

	listen := cfg.Listen
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		logger.Print(err)
		return 1
	}
	defer ln.Close()

	httpSrv := &http.Server{
		Handler:           gw,
		ReadHeaderTimeout: 10 * time.Second,
	}

	addr := ln.Addr().String()
	// Print a JSON "ready" line for scripts.
	_ = json.NewEncoder(stdout).Encode(ready{
		Status:  "ready",
		Version: version,
		Commit:  commit,
		Date:    date,
		Listen:  addr,
		HTTPURL: "http://" + addr,
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return 0
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return 0
		}
		logger.Print(err)
		return 1
	}
}
