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
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
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

type ready struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Date          string `json:"date"`
	Listen        string `json:"listen"`
	WSPath        string `json:"ws_path"`
	AdvertiseHost string `json:"advertise_host,omitempty"`
	WSURL         string `json:"ws_url"`
	HTTPURL       string `json:"http_url"`
	HealthzURL    string `json:"healthz_url"`
	MetricsURL    string `json:"metrics_url,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	cfg := server.DefaultConfig()

	logger := log.New(stderr, "", log.LstdFlags)

	listen := envString("FSEC_TUNNEL_LISTEN", "127.0.0.1:0")
	advertiseHost := envString("FSEC_TUNNEL_ADVERTISE_HOST", "")
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
	fs.StringVar(&advertiseHost, "advertise-host", advertiseHost, "public host[:port] for ready URLs (optional; avoids ws://0.0.0.0) (env: FSEC_TUNNEL_ADVERTISE_HOST)")
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

	if issuerKeysFile == "" || aud == "" || iss == "" {
		return usageErr("missing --issuer-keys-file, --aud, or --iss")
	}
	if err := validateTLSFiles(tlsCertFile, tlsKeyFile); err != nil {
		return usageErr(err.Error())
	}
	if len(allowedOrigins) == 0 {
		return usageErr("missing --allow-origin")
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

	wsScheme := "ws"
	httpScheme := "http"
	metricsScheme := "http"
	if tlsCertFile != "" {
		wsScheme = "wss"
		httpScheme = "https"
		metricsScheme = "https"
	}
	bindAddr := ln.Addr().String()
	advMainHostPort, advHostOnly, advWasSet, err := resolveAdvertiseHost(bindAddr, advertiseHost)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	out := ready{
		Version:    version,
		Commit:     commit,
		Date:       date,
		Listen:     bindAddr,
		WSPath:     path,
		WSURL:      wsScheme + "://" + advMainHostPort + path,
		HTTPURL:    httpScheme + "://" + advMainHostPort,
		HealthzURL: httpScheme + "://" + advMainHostPort + "/healthz",
	}
	if advWasSet {
		out.AdvertiseHost = advertiseHost
	}
	if metricsLn != nil {
		metricsAddr := metricsLn.Addr().String()
		out.MetricsURL = metricsScheme + "://" + metricsAddr + "/metrics"
		if advWasSet {
			if _, port, err := net.SplitHostPort(metricsAddr); err == nil {
				out.MetricsURL = metricsScheme + "://" + net.JoinHostPort(advHostOnly, port) + "/metrics"
			}
		}
	}
	_ = json.NewEncoder(stdout).Encode(out)

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

func resolveAdvertiseHost(bindHostPort string, advertiseHost string) (mainHostPort string, hostOnly string, wasSet bool, err error) {
	bindHost, bindPort, err := net.SplitHostPort(bindHostPort)
	if err != nil {
		return "", "", false, err
	}
	if strings.TrimSpace(advertiseHost) == "" {
		return bindHostPort, bindHost, false, nil
	}
	raw := strings.TrimSpace(advertiseHost)
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", "", true, fmt.Errorf("invalid advertise host: %w", err)
		}
		if u.Host == "" {
			return "", "", true, errors.New("invalid advertise host: missing host")
		}
		raw = u.Host
	}
	hostOnly = raw
	if h, p, err := net.SplitHostPort(raw); err == nil {
		return net.JoinHostPort(h, p), h, true, nil
	}
	hostOnly = strings.TrimSuffix(strings.TrimPrefix(hostOnly, "["), "]")
	return net.JoinHostPort(hostOnly, bindPort), hostOnly, true, nil
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
