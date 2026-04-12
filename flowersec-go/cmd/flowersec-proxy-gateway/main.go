package main

import (
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

	"github.com/floegence/flowersec/flowersec-go/internal/cmdutil"
	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
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
		fmt.Fprintln(out, "  # Route by canonical host and load fresh grants from files managed by an external controller.")
		fmt.Fprintln(out, "  flowersec-proxy-gateway --config ./gateway.json | tee ready.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Config file schema (JSON):")
		fmt.Fprintln(out, `  {`)
		fmt.Fprintln(out, `    "listen": "127.0.0.1:8080",`)
		fmt.Fprintln(out, `    "browser": {`)
		fmt.Fprintln(out, `      "allowed_origins": ["https://gateway.example.com"]`)
		fmt.Fprintln(out, `    },`)
		fmt.Fprintln(out, `    "tunnel": {`)
		fmt.Fprintln(out, `      "origin": "https://gateway.example.com"`)
		fmt.Fprintln(out, `    },`)
		fmt.Fprintln(out, `    "proxy": {`)
		fmt.Fprintln(out, `      "preset_file": "./reference/presets/default/manifest.json",`)
		fmt.Fprintln(out, `      "timeout_ms": 30000`)
		fmt.Fprintln(out, `    },`)
		fmt.Fprintln(out, `    "routes": [`)
		fmt.Fprintln(out, `      {`)
		fmt.Fprintln(out, `        "host": "code.example.com",`)
		fmt.Fprintln(out, `        "grant": { "file": "./grants/code.example.com.json" }`)
		fmt.Fprintln(out, `      },`)
		fmt.Fprintln(out, `      {`)
		fmt.Fprintln(out, `        "host": "shell.example.com",`)
		fmt.Fprintln(out, `        "grant": { "command": ["./bin/mint-gateway-grant", "shell.example.com"], "timeout_ms": 10000 }`)
		fmt.Fprintln(out, `      }`)
		fmt.Fprintln(out, `    ]`)
		fmt.Fprintln(out, `  }`)
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Notes:")
		fmt.Fprintln(out, "  - browser.allowed_origins controls browser -> gateway HTTP/WS boundary checks.")
		fmt.Fprintln(out, "  - browser.allow_no_origin is additive only; it does not replace browser.allowed_origins.")
		fmt.Fprintln(out, "  - tunnel.origin controls gateway -> tunnel/client attach Origin.")
		fmt.Fprintln(out, "  - proxy.timeout_ms overrides preset timeout_ms and must be a positive integer when set.")
		fmt.Fprintln(out, "  - routes.host is matched by canonical host only; port is ignored.")
		fmt.Fprintln(out, "  - grants are one-time; the configured grant source must provide a fresh client grant for reconnects.")
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

	routes, closers, err := buildRoutes(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	bridge, err := cfg.newBridge()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	gw := newGateway(routes, bridge, browserPolicy{allowedOrigins: append([]string(nil), cfg.Browser.AllowedOrigins...), allowNoOrigin: cfg.Browser.AllowNoOrigin}, logger)

	ln, err := net.Listen("tcp", cfg.Listen)
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
	if err := json.NewEncoder(stdout).Encode(ready{
		Status:  "ready",
		Version: version,
		Commit:  commit,
		Date:    date,
		Listen:  addr,
		HTTPURL: "http://" + addr,
	}); err != nil {
		logger.Print(err)
		return 1
	}

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

func buildRoutes(cfg *config) (map[string]streamOpener, []*routeManager, error) {
	routes := make(map[string]streamOpener, len(cfg.Routes))
	closers := make([]*routeManager, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		source, err := newGrantSource(route.Grant)
		if err != nil {
			return nil, nil, fmt.Errorf("route %q: %w", route.Host, err)
		}
		manager := newRouteManager(route.Host, cfg.Tunnel.Origin, source)
		routes[route.Host] = manager
		closers = append(closers, manager)
	}
	return routes, closers, nil
}
