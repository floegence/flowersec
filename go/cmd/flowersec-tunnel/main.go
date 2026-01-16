package main

import (
	"context"
	"encoding/json"
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

	"github.com/floegence/flowersec/observability"
	"github.com/floegence/flowersec/observability/prom"
	"github.com/floegence/flowersec/tunnel/server"
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
	maxTotalPendingBytes := cfg.MaxTotalPendingBytes
	writeTimeout := cfg.WriteTimeout
	maxWriteQueueBytes := cfg.MaxWriteQueueBytes
	flag.StringVar(&listen, "listen", "127.0.0.1:0", "listen address")
	flag.StringVar(&path, "ws-path", "/ws", "websocket path")
	flag.StringVar(&issuerKeysFile, "issuer-keys-file", "", "issuer keyset file (kid->ed25519 pubkey)")
	flag.StringVar(&aud, "aud", "", "expected token audience")
	flag.StringVar(&iss, "iss", "", "expected token issuer")
	flag.Var(&allowedOrigins, "allow-origin", "allowed Origin value (repeatable)")
	flag.BoolVar(&allowNoOrigin, "allow-no-origin", cfg.AllowNoOrigin, "allow requests without Origin header (non-browser clients)")
	flag.IntVar(&maxConns, "max-conns", 0, "max concurrent websocket connections (0 uses default)")
	flag.IntVar(&maxChannels, "max-channels", 0, "max concurrent channels (0 uses default)")
	flag.IntVar(&maxTotalPendingBytes, "max-total-pending-bytes", cfg.MaxTotalPendingBytes, "max total pending bytes buffered across all channels (0 disables)")
	flag.DurationVar(&writeTimeout, "write-timeout", cfg.WriteTimeout, "per-frame websocket write timeout (0 disables)")
	flag.IntVar(&maxWriteQueueBytes, "max-write-queue-bytes", cfg.MaxWriteQueueBytes, "max buffered bytes for websocket writes per endpoint (0 uses default)")
	flag.Parse()

	if issuerKeysFile == "" || aud == "" {
		log.Fatal("missing --issuer-keys-file or --aud")
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
	metricsHandler := newSwitchHandler()
	mux.Handle("/metrics", metricsHandler)
	metrics := newMetricsController(metricsHandler, observer, s)

	// Bind to the listen address and serve HTTP/WebSocket traffic.
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	ready := map[string]string{
		"listen":  ln.Addr().String(),
		"ws_path": path,
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
			metrics.Enable()
			log.Printf("metrics enabled")
		case syscall.SIGUSR2:
			metrics.Disable()
			log.Printf("metrics disabled")
		default:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			return
		}
	}
}
