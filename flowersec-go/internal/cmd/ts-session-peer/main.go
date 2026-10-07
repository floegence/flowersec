// ts-session-peer runs the complete original notification/payload/rekey
// exchange through current ordinary direct or actual PoolService tunnel peers.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

const namespace = "flowersec.session.exchange"
const kind = "interop.echo"
const origin = "https://client.example"

type exchangeState struct {
	definition  *interopharness.RPCDefinition
	queryType   uint32
	queryDigest []byte
	notified    chan struct{}
}

func (s *exchangeState) configure(runtime *interopharness.Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
	if role != 1 {
		return fs.StreamHandlerPlanConfig{}, errors.New("original exchange requires its accepted role")
	}
	s.definition = interopharness.ConfigureRPC(runtime, role, namespace, []interopharness.RPCMethod{{Type: 9001, Notify: true}, {Type: 9002, Notify: true}})
	s.queryType = runtime.Services[role].Query.Type
	s.queryDigest = append([]byte(nil), runtime.Services[role].Query.Contract[:]...)
	return fs.StreamHandlerPlanConfig{RuntimeBytes: 16384, Handlers: []fs.RawStreamHandlerConfig{{Kind: kind, Slots: 1, WorkClass: fs.WorkResident, Manual: true, AuthorizeOpen: func(_ context.Context, binding any, metadata []byte) error {
		if binding != role {
			return errors.New("exchange stream has the wrong original application lease")
		}
		if !bytes.Equal(metadata, fs.EmptyStreamMetadata().Bytes()) {
			return errors.New("exchange stream metadata differs")
		}
		return nil
	}}}}, nil
}
func (s *exchangeState) run(ctx context.Context, session *fs.Session) (err error) {
	if session == nil || s.definition == nil {
		return errors.New("original exchange Session/service registration is absent")
	}
	cleanup := func(action func(context.Context) error) error {
		closing, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return action(closing)
	}
	defer func() {
		err = errors.Join(err, cleanup(func(closing context.Context) error { return errors.Join(session.Close(), session.WaitCleanup(closing)) }))
	}()
	subscription, err := session.SubscribeNotification(fs.MethodSelector{Namespace: namespace, Type: 9001}, fs.NotificationDropNewest, fs.NotificationObserver{
		Decode: func(_ context.Context, wire []byte) (any, error) {
			var state struct {
				State string `json:"state"`
			}
			decoder := json.NewDecoder(bytes.NewReader(wire))
			decoder.DisallowUnknownFields()
			if e := decoder.Decode(&state); e != nil {
				return nil, e
			}
			if decoder.Decode(&struct{}{}) != io.EOF || state.State != "ready" {
				return nil, errors.New("original client notification payload differs")
			}
			return state.State, nil
		},
		Handle: func(_ context.Context, value any) error {
			if value != "ready" {
				return errors.New("original notification decode differs")
			}
			select {
			case s.notified <- struct{}{}:
				return nil
			default:
				return errors.New("original client notification exceeds its one position")
			}
		},
	})
	if err != nil {
		return err
	}
	defer func() {
		subscription.Close()
		err = errors.Join(err, cleanup(func(closing context.Context) error {
			if e := subscription.WaitClosed(closing); e != nil {
				return e
			}
			return subscription.Release()
		}))
	}()
	service, err := s.definition.Bind(ctx, session)
	if err != nil {
		return err
	}
	defer func() { service.Close(); err = errors.Join(err, cleanup(service.WaitCleanup)) }()
	select {
	case <-s.notified:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	result, err := service.NotifyMethod(ctx, fs.MethodSelector{Namespace: namespace, Type: 9002}, []byte(`{"state":"accepted"}`), fs.OperationOptions{DurationMS: 10000})
	if err != nil {
		return err
	}
	if !result.MessageAccepted {
		return errors.New("original reverse notification was not accepted")
	}
	incoming, err := session.AcceptStream(ctx)
	if err != nil {
		return err
	}
	if incoming.Kind != kind {
		_ = incoming.Stream.Reset()
		return errors.New("original exchange stream kind differs")
	}
	stream := incoming.Stream
	resetDone := make(chan struct{})
	stopReset := context.AfterFunc(ctx, func() { defer close(resetDone); _ = stream.Reset() })
	defer func() {
		if !stopReset() {
			<-resetDone
		}
	}()
	defer func() {
		if err != nil {
			_ = stream.Reset()
		}
	}()
	readExact := func(want string) error {
		wire := make([]byte, len(want))
		if _, e := io.ReadFull(stream, wire); e != nil {
			return fmt.Errorf("read %q: %w", want, e)
		}
		if string(wire) != want {
			return errors.New("original exchange payload differs")
		}
		return nil
	}
	writeExact := func(payload string) error {
		_, e := stream.WriteAll(ctx, []byte(payload))
		if e != nil {
			return fmt.Errorf("write %q: %w", payload, e)
		}
		return nil
	}
	if err = readExact("hello-go"); err != nil {
		return err
	}
	if err = writeExact("hello-ts"); err != nil {
		return err
	}
	if err = session.Rekey(ctx); err != nil {
		return fmt.Errorf("server rekey: %w", err)
	}
	if err = writeExact("go-rekey-ok"); err != nil {
		return err
	}
	if err = readExact("ts-rekey-ok"); err != nil {
		return err
	}
	var end [1]byte
	if count, e := stream.Read(end[:]); count != 0 || !errors.Is(e, io.EOF) {
		return errors.Join(e, errors.New("original exchange client FIN is absent"))
	}
	if err = writeExact("done"); err != nil {
		return err
	}
	if err = stream.CloseWrite(); err != nil {
		return err
	}
	if err = stream.Finish(ctx); err != nil {
		return err
	}
	// The TypeScript peer uses immediate Session.close after the final stream
	// proof. Its carrier may be terminated before the encrypted CLOSE record
	// reaches this passive peer, which is an acceptable terminal observation
	// for this interop exchange.
	if err = session.WaitTermination(ctx); err != nil {
		var failure *fs.SessionError
		if ctx.Err() != nil || !errors.As(err, &failure) ||
			(failure.Code() != fs.SessionClosed && failure.Code() != fs.SessionOperationFailed) {
			return err
		}
	}
	return session.WaitCleanup(ctx)
}
func run() (err error) {
	if os.Getenv("FLOWERSEC_SERVER_PARITY_PEER") != "1" {
		return errors.New("original session exchange peer is test-only")
	}
	path := flag.String("path", "direct", "original direct or tunnel source")
	notification := flag.Bool("server-notify", false, "require original reverse notification")
	flag.Parse()
	if flag.NArg() != 0 || (*path != "direct" && *path != "tunnel") || !*notification {
		return errors.New("original exchange requires explicit direct/tunnel and server notification")
	}
	signals, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()
	ctx, cancel := context.WithTimeout(signals, 30*time.Second)
	defer cancel()
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	reporter.ApplicationProfile = "services"
	defer func() { err = errors.Join(err, reporter.Close()) }()
	state := &exchangeState{notified: make(chan struct{}, 1)}
	var material interopharness.Material
	var trust string
	var await func(context.Context) (*fs.Session, error)
	var tlsInstallation map[string]string
	var poolInstallation *interopharness.RegisteredPoolClientInstallation
	var poolBinding *interopharness.PoolServerAllowBinding
	if *path == "direct" {
		server, e := interopharness.NewServer(ctx, reporter, interopharness.ServerOptions{Carrier: "websocket", Profile: protocolv4.DHProfileX25519, Origin: origin, Handlers: state.configure})
		if e != nil {
			return e
		}
		material = server.Material()
		trust = server.TrustPEM
		await = server.WaitSession
	} else {
		relay, e := interopharness.NewPoolRelay(ctx, reporter, [2]string{"websocket", "websocket"}, origin, interopharness.PoolRelayOptions{EndpointListeners: [2]bool{false, false}})
		if e != nil {
			return e
		}
		serverReporter, e := interopharness.NewPeerReporter()
		if e != nil {
			return e
		}
		serverReporter.ApplicationProfile = "services"
		defer func() { err = errors.Join(err, serverReporter.Close()) }()
		serverWire, e := relay.MaterialJSON(1)
		if e != nil {
			return e
		}
		server, e := interopharness.NewTunnelServer(ctx, serverReporter, serverWire, relay.TrustPEM, origin, state.configure)
		if e != nil {
			return e
		}
		poolInstallation, poolBinding, e = server.LocalPoolClientConfiguration()
		if e != nil {
			return e
		}
		material = relay.Material[0]
		trust = relay.TrustPEM
		await = server.Accept
		tlsInstallation = map[string]string{"certificatePEM": relay.ClientTLSCertificatePEM, "privateKeyPEM": relay.ClientTLSPrivateKeyPEM}
		relay.Start()
	}
	wire, err := material.JSON()
	if err != nil {
		return err
	}
	contracts := make([]map[string]any, 0, len(state.definition.Contracts))
	for index, contract := range state.definition.Contracts {
		contracts = append(contracts, map[string]any{"type_id": state.definition.Policies[index].Type, "contract": contract})
	}
	ready := map[string]any{"type": "ready", "runtime": "go", "carrier": "websocket", "path": *path, "wire_revision": 4, "profile": material.Profile, "source": material.Source, "artifact_json": wire, "trust_pem": trust, "origin": origin, "application_namespace": namespace, "service_query_type": state.queryType, "service_query_digest": state.queryDigest, "service_contracts": contracts, "service_schema_digest": state.definition.SchemaDigest[:], "client_listener_tls": tlsInstallation}
	if poolInstallation != nil {
		ready["pool_client_deployment"], ready["server_allow"] = poolInstallation, poolBinding
	}
	if err = json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		return err
	}
	session, err := await(ctx)
	if err != nil {
		return err
	}
	return state.run(ctx, session)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
