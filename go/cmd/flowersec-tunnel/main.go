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
	"syscall"
	"time"

	"github.com/flowersec/flowersec/tunnel/server"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// main launches a tunnel server with CLI-configurable settings.
func main() {
	var listen string
	var path string
	var issuerKeysFile string
	var aud string
	var iss string
	var allowedOrigins stringSliceFlag
	var allowNoOrigin bool
	var maxConns int
	var maxChannels int
	flag.StringVar(&listen, "listen", "127.0.0.1:0", "listen address")
	flag.StringVar(&path, "ws-path", "/ws", "websocket path")
	flag.StringVar(&issuerKeysFile, "issuer-keys-file", "", "issuer keyset file (kid->ed25519 pubkey)")
	flag.StringVar(&aud, "aud", "", "expected token audience")
	flag.StringVar(&iss, "iss", "", "expected token issuer")
	flag.Var(&allowedOrigins, "allow-origin", "allowed Origin value (repeatable)")
	flag.BoolVar(&allowNoOrigin, "allow-no-origin", true, "allow requests without Origin header (non-browser clients)")
	flag.IntVar(&maxConns, "max-conns", 0, "max concurrent websocket connections (0 uses default)")
	flag.IntVar(&maxChannels, "max-channels", 0, "max concurrent channels (0 uses default)")
	flag.Parse()

	if issuerKeysFile == "" || aud == "" {
		log.Fatal("missing --issuer-keys-file or --aud")
	}

	cfg := server.DefaultConfig()
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

	s, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	mux := http.NewServeMux()
	s.Register(mux)

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
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		switch <-sig {
		case syscall.SIGHUP:
			if err := s.ReloadKeys(); err != nil {
				log.Printf("reload keys failed: %v", err)
			} else {
				log.Printf("reloaded issuer keyset")
			}
		default:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			return
		}
	}
}
