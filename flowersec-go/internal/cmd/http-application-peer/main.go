// http-application-peer serves the current signed transport on the original
// application listener, using the same admission and service owners as peers.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (err error) {
	if os.Getenv("FLOWERSEC_SERVER_PARITY_PEER") != "1" {
		return errors.New("HTTP application peer is test-only")
	}
	mode := flag.String("mode", "", "direct or local application deployment")
	flag.Parse()
	if flag.NArg() != 0 || (*mode != "direct" && *mode != "local") {
		return errors.New("select one explicit direct or local deployment")
	}
	lifetime, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()
	ctx, cancel := context.WithTimeout(lifetime, 30*time.Second)
	defer cancel()
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, reporter.Close()) }()
	reporter.ApplicationProfile = "services"
	label := "http-direct"
	if *mode == "local" {
		label = "private-loopback"
	}
	configure := func(runtime *interopharness.Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
		interopharness.ConfigurePeerRPC(runtime, role, label)
		return fs.StreamHandlerPlanConfig{RuntimeBytes: 16384}, nil
	}
	var positions []*interopharness.Server
	if *mode == "local" {
		var secret [32]byte
		if _, err = rand.Read(secret[:]); err != nil {
			return err
		}
		token := hex.EncodeToString(secret[:])
		clear(secret[:])
		server, e := interopharness.NewServer(ctx, reporter, interopharness.ServerOptions{
			Carrier: "local-websocket", LocalBridgeToken: token, Handlers: configure,
		})
		if e != nil {
			return e
		}
		wire, e := server.Material().JSON()
		if e != nil {
			return e
		}
		if err = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"wire_revision": 4, "origin": server.Origin, "bridge_token": token,
			"artifact_json": wire, "trust_pem": server.TrustPEM,
		}); err != nil {
			return err
		}
		positions = []*interopharness.Server{server}
	} else {
		listener, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
		if e != nil {
			return e
		}
		defer func() {
			if e := listener.Close(); e != nil && !errors.Is(e, net.ErrClosed) {
				err = errors.Join(err, e)
			}
		}()
		address := listener.Addr().(*net.TCPAddr).AddrPort()
		origin := "http://" + address.String()
		var materials *interopharness.AcceptedMaterials
		first, e := interopharness.NewServer(ctx, reporter, interopharness.ServerOptions{
			Carrier: "websocket", Origin: origin, ExternalHTTP: true, Address: address, Handlers: configure,
			OnTransportError: func(stage string, failure error) { fmt.Fprintln(os.Stderr, stage+":", failure) },
			SourceFactory: func(runtime *interopharness.Runtime) fs.AcceptedMaterialSource {
				materials = interopharness.NewAcceptedMaterials(runtime.Authority, nil)
				return materials.ForRuntime(runtime)
			},
		})
		if e != nil {
			return e
		}
		secondAuthority, e := first.IndependentAuthority()
		if e != nil {
			return e
		}
		if e = materials.InstallSecond(secondAuthority); e != nil {
			return e
		}
		second, e := first.NewHTTPAcceptPosition(materials, configure)
		if e != nil {
			return e
		}
		positions = []*interopharness.Server{first, second}
		var issued, accepted atomic.Uint32
		claim := func(counter *atomic.Uint32) (uint32, bool) {
			for {
				index := counter.Load()
				if index >= 2 {
					return 0, false
				}
				if counter.CompareAndSwap(index, index+1) {
					return index, true
				}
			}
		}
		handlers := [2]http.Handler{first.HTTPHandler, second.HTTPHandler}
		first.HTTPHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			index, ok := claim(&accepted)
			if !ok {
				http.Error(w, "application session capacity exhausted", http.StatusServiceUnavailable)
				return
			}
			handlers[index].ServeHTTP(w, r)
		})
		firstWire, e := first.Material().JSON()
		if e != nil {
			return e
		}
		secondWire, e := first.MaterialFor(secondAuthority).JSON()
		if e != nil {
			return e
		}
		wires := [2]string{firstWire, secondWire}
		application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != http.MethodGet || r.Host != address.String() || r.URL.RawQuery != "" {
				http.Error(w, "invalid application request", http.StatusBadRequest)
				return
			}
			switch r.URL.Path {
			case "/":
				_, _ = w.Write([]byte("application"))
			case "/artifact":
				index, ok := claim(&issued)
				if !ok {
					http.Error(w, "application material capacity exhausted", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(wires[index]))
			default:
				http.NotFound(w, r)
			}
		})
		if err = first.ServeHTTPListener(reporter, listener, application, true); err != nil {
			return err
		}
		if err = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"wire_revision": 4, "origin": origin, "trust_pem": first.TrustPEM,
		}); err != nil {
			return err
		}
	}
	for _, position := range positions {
		session, e := position.WaitSession(ctx)
		if e != nil {
			return e
		}
		if e = session.WaitTermination(ctx); e != nil {
			var terminal *fs.SessionError
			// Session.Close retires its carrier without a graceful peer result.
			// The client asserts application success and local physical cleanup;
			// this side independently requires termination and lease release.
			if ctx.Err() != nil || !errors.As(e, &terminal) ||
				(terminal.Code() != fs.SessionClosed && terminal.Code() != fs.SessionOperationFailed) {
				return e
			}
		}
		closing, stop := context.WithTimeout(context.Background(), 5*time.Second)
		e = session.WaitCleanup(closing)
		stop()
		if e != nil {
			return e
		}
		if position.Runtime.Authorized[1].Load() != 1 || position.Runtime.Released[1].Load() != 1 {
			return errors.New("original application lease was not authorized and released exactly once")
		}
	}
	return nil
}
