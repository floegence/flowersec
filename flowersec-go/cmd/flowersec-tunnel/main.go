package main

import (
	"context"
	"crypto/tls"
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
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/observability/prom"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type switchHandler struct {
	mu      sync.RWMutex
	handler http.Handler
}

func newSwitchHandler() *switchHandler {
	return &switchHandler{handler: http.NotFoundHandler()}
}

func (h *switchHandler) Set(next http.Handler) {
	if next == nil {
		next = http.NotFoundHandler()
	}
	h.mu.Lock()
	h.handler = next
	h.mu.Unlock()
}

func (h *switchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	handler := h.handler
	h.mu.RUnlock()
	handler.ServeHTTP(w, r)
}

type metricsController struct {
	mu       sync.Mutex
	enabled  bool
	handler  *switchHandler
	observer *observability.AtomicTunnelObserver
	srv      *server.Server
}

func newMetricsController(handler *switchHandler, observer *observability.AtomicTunnelObserver, srv *server.Server) *metricsController {
	return &metricsController{
		handler:  handler,
		observer: observer,
		srv:      srv,
	}
}

func (c *metricsController) Enable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enabled {
		return
	}
	reg := prom.NewRegistry()
	tunnelObs := prom.NewTunnelObserver(reg)
	c.handler.Set(prom.Handler(reg))
	c.observer.Set(tunnelObs)
	stats := c.srv.Stats()
	tunnelObs.ConnCount(stats.ConnCount)
	tunnelObs.ChannelCount(stats.ChannelCount)
	c.enabled = true
}

func (c *metricsController) Disable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return
	}
	c.handler.Set(nil)
	c.observer.Set(observability.NoopTunnelObserver)
	c.enabled = false
}

func validateTLSFiles(certFile string, keyFile string) error {
	if certFile == "" && keyFile == "" {
		return nil
	}
	if certFile == "" || keyFile == "" {
		return errors.New("tls requires both --tls-cert-file and --tls-key-file")
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	cfg := server.DefaultConfig()

	logger := log.New(stderr, "", log.LstdFlags)

	listen := envString("FSEC_TUNNEL_LISTEN", "127.0.0.1:0")
	path := envString("FSEC_TUNNEL_WS_PATH", "/ws")
	issuerKeysFile := envString("FSEC_TUNNEL_ISSUER_KEYS_FILE", "")
	aud := envString("FSEC_TUNNEL_AUD", "")
	iss := envString("FSEC_TUNNEL_ISS", "")
	metricsListen := envString("FSEC_TUNNEL_METRICS_LISTEN", "")
	tlsCertFile := envString("FSEC_TUNNEL_TLS_CERT_FILE", "")
	tlsKeyFile := envString("FSEC_TUNNEL_TLS_KEY_FILE", "")

	allowedOrigins := stringSliceFlag(splitCSVEnv("FSEC_TUNNEL_ALLOW_ORIGIN"))

	allowNoOrigin, err := envBoolWithErr("FSEC_TUNNEL_ALLOW_NO_ORIGIN", cfg.AllowNoOrigin)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_TUNNEL_ALLOW_NO_ORIGIN: %v\n", err)
		return 2
	}

	maxConns, err := envIntWithErr("FSEC_TUNNEL_MAX_CONNS", 0)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_TUNNEL_MAX_CONNS: %v\n", err)
		return 2
	}
	maxChannels, err := envIntWithErr("FSEC_TUNNEL_MAX_CHANNELS", 0)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_TUNNEL_MAX_CHANNELS: %v\n", err)
		return 2
	}
	maxTotalPendingBytes, err := envIntWithErr("FSEC_TUNNEL_MAX_TOTAL_PENDING_BYTES", cfg.MaxTotalPendingBytes)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_TUNNEL_MAX_TOTAL_PENDING_BYTES: %v\n", err)
		return 2
	}
	writeTimeout, err := envDurationWithErr("FSEC_TUNNEL_WRITE_TIMEOUT", cfg.WriteTimeout)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_TUNNEL_WRITE_TIMEOUT: %v\n", err)
		return 2
	}
	maxWriteQueueBytes, err := envIntWithErr("FSEC_TUNNEL_MAX_WRITE_QUEUE_BYTES", cfg.MaxWriteQueueBytes)
	if err != nil {
		fmt.Fprintf(stderr, "invalid FSEC_TUNNEL_MAX_WRITE_QUEUE_BYTES: %v\n", err)
		return 2
	}

	fs := flag.NewFlagSet("flowersec-tunnel", flag.ContinueOnError)
	fs.SetOutput(stderr)

	showVersion := false
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&listen, "listen", listen, "listen address (env: FSEC_TUNNEL_LISTEN)")
	fs.StringVar(&path, "ws-path", path, "websocket path (env: FSEC_TUNNEL_WS_PATH)")
	fs.StringVar(&issuerKeysFile, "issuer-keys-file", issuerKeysFile, "issuer keyset file (kid->ed25519 pubkey) (required) (env: FSEC_TUNNEL_ISSUER_KEYS_FILE)")
	fs.StringVar(&aud, "aud", aud, "expected token audience (required) (env: FSEC_TUNNEL_AUD)")
	fs.StringVar(&iss, "iss", iss, "expected token issuer (required; must match token payload 'iss') (env: FSEC_TUNNEL_ISS)")
	fs.Var(&allowedOrigins, "allow-origin", "allowed Origin value (repeatable; required): full Origin, hostname, hostname:port, wildcard hostname (*.example.com), or exact non-standard values (e.g. null) (env: FSEC_TUNNEL_ALLOW_ORIGIN)")
	fs.BoolVar(&allowNoOrigin, "allow-no-origin", allowNoOrigin, "allow requests without Origin header (non-browser clients; discouraged) (env: FSEC_TUNNEL_ALLOW_NO_ORIGIN)")
	fs.IntVar(&maxConns, "max-conns", maxConns, "max concurrent websocket connections (0 uses default) (env: FSEC_TUNNEL_MAX_CONNS)")
	fs.IntVar(&maxChannels, "max-channels", maxChannels, "max concurrent channels (0 uses default) (env: FSEC_TUNNEL_MAX_CHANNELS)")
	fs.StringVar(&tlsCertFile, "tls-cert-file", tlsCertFile, "enable TLS with the given certificate file (default: disabled) (env: FSEC_TUNNEL_TLS_CERT_FILE)")
	fs.StringVar(&tlsKeyFile, "tls-key-file", tlsKeyFile, "enable TLS with the given private key file (default: disabled) (env: FSEC_TUNNEL_TLS_KEY_FILE)")
	fs.StringVar(&metricsListen, "metrics-listen", metricsListen, "listen address for metrics server (empty disables) (env: FSEC_TUNNEL_METRICS_LISTEN)")
	fs.IntVar(&maxTotalPendingBytes, "max-total-pending-bytes", maxTotalPendingBytes, "max total pending bytes buffered across all channels (0 disables) (env: FSEC_TUNNEL_MAX_TOTAL_PENDING_BYTES)")
	fs.DurationVar(&writeTimeout, "write-timeout", writeTimeout, "per-frame websocket write timeout (0 disables) (env: FSEC_TUNNEL_WRITE_TIMEOUT)")
	fs.IntVar(&maxWriteQueueBytes, "max-write-queue-bytes", maxWriteQueueBytes, "max buffered bytes for websocket writes per endpoint (0 uses default) (env: FSEC_TUNNEL_MAX_WRITE_QUEUE_BYTES)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if showVersion {
		_, _ = fmt.Fprintln(stdout, versionString())
		return 0
	}

	if issuerKeysFile == "" || aud == "" || iss == "" {
		fmt.Fprintln(stderr, "missing --issuer-keys-file, --aud, or --iss")
		return 2
	}
	if err := validateTLSFiles(tlsCertFile, tlsKeyFile); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(allowedOrigins) == 0 {
		fmt.Fprintln(stderr, "missing --allow-origin")
		return 2
	}

	observer := observability.NewAtomicTunnelObserver()
	cfg.Observer = observer
	cfg.Path = path
	cfg.IssuerKeysFile = issuerKeysFile
	cfg.TunnelAudience = aud
	cfg.TunnelIssuer = iss
	cfg.AllowedOrigins = allowedOrigins
	cfg.AllowNoOrigin = allowNoOrigin
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	if maxChannels > 0 {
		cfg.MaxChannels = maxChannels
	}
	cfg.MaxTotalPendingBytes = maxTotalPendingBytes
	cfg.WriteTimeout = writeTimeout
	cfg.MaxWriteQueueBytes = maxWriteQueueBytes

	s, err := server.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer s.Close()

	mux := http.NewServeMux()
	s.Register(mux)

	var metrics *metricsController
	var metricsSrv *http.Server
	var metricsLn net.Listener
	if metricsListen != "" {
		metricsMux := http.NewServeMux()
		metricsHandler := newSwitchHandler()
		metricsMux.Handle("/metrics", metricsHandler)
		metrics = newMetricsController(metricsHandler, observer, s)
		metrics.Enable()

		metricsLn, err = net.Listen("tcp", metricsListen)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		metricsSrv = newHTTPServer(metricsMux)
		if tlsCertFile != "" {
			if metricsSrv.TLSConfig == nil {
				metricsSrv.TLSConfig = &tls.Config{}
			}
			if metricsSrv.TLSConfig.MinVersion == 0 {
				metricsSrv.TLSConfig.MinVersion = tls.VersionTLS12
			}
		}
		go func() {
			var err error
			if tlsCertFile != "" {
				err = metricsSrv.ServeTLS(metricsLn, tlsCertFile, tlsKeyFile)
			} else {
				err = metricsSrv.Serve(metricsLn)
			}
			if err != nil && err != http.ErrServerClosed {
				logger.Fatal(err)
			}
		}()
	}

	// Bind to the listen address and serve HTTP/WebSocket traffic.
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	srv := newHTTPServer(mux)
	if tlsCertFile != "" {
		if srv.TLSConfig == nil {
			srv.TLSConfig = &tls.Config{}
		}
		// TLS is optional and disabled by default. When enabled, enforce a conservative minimum version.
		if srv.TLSConfig.MinVersion == 0 {
			srv.TLSConfig.MinVersion = tls.VersionTLS12
		}
	}

	go func() {
		var err error
		if tlsCertFile != "" {
			err = srv.ServeTLS(ln, tlsCertFile, tlsKeyFile)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Fatal(err)
		}
	}()

	ready := map[string]string{
		"listen":  ln.Addr().String(),
		"ws_path": path,
	}
	wsScheme := "ws"
	httpScheme := "http"
	metricsScheme := "http"
	if tlsCertFile != "" {
		wsScheme = "wss"
		httpScheme = "https"
		metricsScheme = "https"
	}
	host := ln.Addr().String()
	ready["ws_url"] = wsScheme + "://" + host + path
	ready["http_url"] = httpScheme + "://" + host
	ready["healthz_url"] = ready["http_url"] + "/healthz"
	if metricsLn != nil {
		ready["metrics_url"] = metricsScheme + "://" + metricsLn.Addr().String() + "/metrics"
	}
	_ = json.NewEncoder(stdout).Encode(ready)

	// Handle reloads and shutdowns.
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	for {
		switch <-sig {
		case syscall.SIGHUP:
			if err := s.ReloadKeys(); err != nil {
				logger.Printf("reload keys failed: %v", err)
			} else {
				logger.Printf("reloaded issuer keyset")
			}
		case syscall.SIGUSR1:
			if metrics == nil {
				logger.Printf("metrics server disabled (missing --metrics-listen)")
				continue
			}
			metrics.Enable()
			logger.Printf("metrics enabled")
		case syscall.SIGUSR2:
			if metrics == nil {
				continue
			}
			metrics.Disable()
			logger.Printf("metrics disabled")
		default:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			if metricsSrv != nil {
				_ = metricsSrv.Shutdown(ctx)
			}
			cancel()
			return 0
		}
	}
}

func envString(key string, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func splitCSVEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func envBoolWithErr(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, err
	}
	return v, nil
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

func envDurationWithErr(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	return d, nil
}

func versionString() string {
	v := strings.TrimSpace(version)
	c := strings.TrimSpace(commit)
	d := strings.TrimSpace(date)

	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "" || v == "dev" || v == "(devel)" {
			if strings.TrimSpace(info.Main.Version) != "" && info.Main.Version != "(devel)" {
				v = info.Main.Version
			}
		}
		if c == "" || c == "unknown" {
			if rev := buildSetting(info, "vcs.revision"); rev != "" {
				c = rev
			}
		}
		if d == "" || d == "unknown" {
			if t := buildSetting(info, "vcs.time"); t != "" {
				d = t
			}
		}
	}

	out := v
	if c != "" && c != "unknown" {
		out += " (" + c + ")"
	}
	if d != "" && d != "unknown" {
		out += " " + d
	}
	return out
}

func buildSetting(info *debug.BuildInfo, key string) string {
	if info == nil {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}
