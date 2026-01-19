package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/observability/prom"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
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

// main launches a tunnel server with CLI-configurable settings.
func main() {
	cfg := server.DefaultConfig()

	var listen string
	var path string
	var issuerKeysFile string
	var aud string
	var iss string
	var allowedOrigins stringSliceFlag
	allowNoOrigin := cfg.AllowNoOrigin
	var maxConns int
	var maxChannels int
	var tlsCertFile string
	var tlsKeyFile string
	var metricsListen string
	maxTotalPendingBytes := cfg.MaxTotalPendingBytes
	writeTimeout := cfg.WriteTimeout
	maxWriteQueueBytes := cfg.MaxWriteQueueBytes
	flag.StringVar(&listen, "listen", "127.0.0.1:0", "listen address")
	flag.StringVar(&path, "ws-path", "/ws", "websocket path")
	flag.StringVar(&issuerKeysFile, "issuer-keys-file", "", "issuer keyset file (kid->ed25519 pubkey)")
	flag.StringVar(&aud, "aud", "", "expected token audience")
	flag.StringVar(&iss, "iss", "", "expected token issuer (required; must match token payload 'iss')")
	flag.Var(&allowedOrigins, "allow-origin", "allowed Origin value (repeatable; required): full Origin, hostname, hostname:port, wildcard hostname (*.example.com), or exact non-standard values (e.g. null)")
	flag.BoolVar(&allowNoOrigin, "allow-no-origin", cfg.AllowNoOrigin, "allow requests without Origin header (non-browser clients; discouraged)")
	flag.IntVar(&maxConns, "max-conns", 0, "max concurrent websocket connections (0 uses default)")
	flag.IntVar(&maxChannels, "max-channels", 0, "max concurrent channels (0 uses default)")
	flag.StringVar(&tlsCertFile, "tls-cert-file", "", "enable TLS with the given certificate file (default: disabled)")
	flag.StringVar(&tlsKeyFile, "tls-key-file", "", "enable TLS with the given private key file (default: disabled)")
	flag.StringVar(&metricsListen, "metrics-listen", "", "listen address for metrics server (empty disables)")
	flag.IntVar(&maxTotalPendingBytes, "max-total-pending-bytes", cfg.MaxTotalPendingBytes, "max total pending bytes buffered across all channels (0 disables)")
	flag.DurationVar(&writeTimeout, "write-timeout", cfg.WriteTimeout, "per-frame websocket write timeout (0 disables)")
	flag.IntVar(&maxWriteQueueBytes, "max-write-queue-bytes", cfg.MaxWriteQueueBytes, "max buffered bytes for websocket writes per endpoint (0 uses default)")
	flag.Parse()

	if issuerKeysFile == "" || aud == "" || iss == "" {
		log.Fatal("missing --issuer-keys-file, --aud, or --iss")
	}
	if err := validateTLSFiles(tlsCertFile, tlsKeyFile); err != nil {
		log.Fatal(err)
	}
	if len(allowedOrigins) == 0 {
		log.Fatal("missing --allow-origin")
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
		log.Fatal(err)
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
			log.Fatal(err)
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
				log.Fatal(err)
			}
		}()
	}

	// Bind to the listen address and serve HTTP/WebSocket traffic.
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
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
			log.Fatal(err)
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
	_ = json.NewEncoder(os.Stdout).Encode(ready)

	// Handle reloads and shutdowns.
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	for {
		switch <-sig {
		case syscall.SIGHUP:
			if err := s.ReloadKeys(); err != nil {
				log.Printf("reload keys failed: %v", err)
			} else {
				log.Printf("reloaded issuer keyset")
			}
		case syscall.SIGUSR1:
			if metrics == nil {
				log.Printf("metrics server disabled (missing --metrics-listen)")
				continue
			}
			metrics.Enable()
			log.Printf("metrics enabled")
		case syscall.SIGUSR2:
			if metrics == nil {
				continue
			}
			metrics.Disable()
			log.Printf("metrics disabled")
		default:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			if metricsSrv != nil {
				_ = metricsSrv.Shutdown(ctx)
			}
			cancel()
			return
		}
	}
}
