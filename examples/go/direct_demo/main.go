package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/floegence/flowersec-examples/go/exampleutil"
	"github.com/floegence/flowersec/crypto/e2ee"
	rpcv1 "github.com/floegence/flowersec/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/realtime/ws"
	"github.com/floegence/flowersec/rpc"
	hyamux "github.com/hashicorp/yamux"
)

type ready struct {
	WSURL               string            `json:"ws_url"`
	ChannelID           string            `json:"channel_id"`
	E2EEPskB64u         string            `json:"e2ee_psk_b64u"`
	DefaultSuite        int               `json:"default_suite"`
	ChannelInitExpireAt int64             `json:"channel_init_expire_at_unix_s"`
	ExampleTypeIDs      map[string]uint32 `json:"example_type_ids"`
	ExampleStreamKinds  map[string]string `json:"example_stream_kinds"`
}

func main() {
	var listen string
	var wsPath string
	var channelID string
	var allowedOrigins stringSliceFlag
	flag.StringVar(&listen, "listen", "127.0.0.1:0", "listen address")
	flag.StringVar(&wsPath, "ws-path", "/ws", "websocket path")
	flag.StringVar(&channelID, "channel-id", "", "fixed channel id (default: random)")
	flag.Var(&allowedOrigins, "allow-origin", "allowed Origin host or full Origin value (repeatable; required)")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if len(allowedOrigins) == 0 {
		log.Fatal("missing --allow-origin")
	}

	if channelID == "" {
		channelID = randomB64u(24)
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		log.Fatal(err)
	}
	pskB64u := exampleutil.Encode(psk)
	initExp := time.Now().Add(120 * time.Second).Unix()

	mux := http.NewServeMux()
	mux.HandleFunc(wsPath, func(w http.ResponseWriter, r *http.Request) {
		c, err := ws.Upgrade(w, r, ws.UpgraderOptions{CheckOrigin: ws.NewOriginChecker(allowedOrigins, false)})
		if err != nil {
			return
		}
		uc := c.Underlying()
		go func() {
			defer uc.Close()

			bt := e2ee.NewWebSocketBinaryTransport(uc)
			cache := e2ee.NewServerHandshakeCache()
			secure, err := e2ee.ServerHandshake(ctx, bt, cache, e2ee.HandshakeOptions{
				PSK:                 psk,
				Suite:               e2ee.SuiteX25519HKDFAES256GCM,
				ChannelID:           channelID,
				InitExpireAtUnixS:   initExp,
				ClockSkew:           30 * time.Second,
				ServerFeatureBits:   1,
				MaxHandshakePayload: 8 * 1024,
				MaxRecordBytes:      1 << 20,
			})
			if err != nil {
				return
			}
			defer secure.Close()

			ycfg := hyamux.DefaultConfig()
			ycfg.EnableKeepAlive = false
			ycfg.LogOutput = io.Discard
			sess, err := hyamux.Server(secure, ycfg)
			if err != nil {
				return
			}
			defer sess.Close()

			for {
				stream, err := sess.AcceptStream()
				if err != nil {
					return
				}
				go handleStream(ctx, stream)
			}
		}()
	})

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	wsURL := "ws://" + ln.Addr().String() + wsPath
	_ = json.NewEncoder(os.Stdout).Encode(ready{
		WSURL:               wsURL,
		ChannelID:           channelID,
		E2EEPskB64u:         pskB64u,
		DefaultSuite:        1,
		ChannelInitExpireAt: initExp,
		ExampleTypeIDs: map[string]uint32{
			"rpc_request": 1,
			"rpc_notify":  2,
		},
		ExampleStreamKinds: map[string]string{
			"rpc":  "rpc",
			"echo": "echo",
		},
	})

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	cancel()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(ctx2)
	cancel2()
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return "" }

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func handleStream(ctx context.Context, stream net.Conn) {
	defer stream.Close()

	h, err := rpc.ReadStreamHello(stream, 8*1024)
	if err != nil {
		return
	}
	switch h.Kind {
	case "rpc":
		router := rpc.NewRouter()
		srv := rpc.NewServer(stream, router)
		router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
			_ = payload
			_ = srv.Notify(2, json.RawMessage(`{"hello":"world"}`))
			return json.RawMessage(`{"ok":true}`), nil
		})
		_ = srv.Serve(ctx)
	case "echo":
		_, _ = io.Copy(stream, stream)
	default:
		return
	}
}

func randomB64u(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return exampleutil.Encode(b)
}
