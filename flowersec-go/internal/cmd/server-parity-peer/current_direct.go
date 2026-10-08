package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

const parityNamespace = "flowersec.parity"

type currentReady struct {
	Type, Runtime, Carrier, Path string
	ArtifactJSON                 string `json:"artifact_json"`
	TrustPEM                     string `json:"trust_pem"`
	Origin                       string `json:"origin"`
	WireRevision                 int    `json:"wire_revision"`
	Profile                      string `json:"profile"`
	Source                       string `json:"source"`
}

func (r currentReady) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"type": r.Type, "runtime": r.Runtime, "carrier": r.Carrier, "path": r.Path, "artifact_json": r.ArtifactJSON, "trust_pem": r.TrustPEM, "origin": r.Origin, "wire_revision": r.WireRevision, "profile": r.Profile, "source": r.Source})
}
func (r *currentReady) UnmarshalJSON(wire []byte) error {
	type fields struct {
		Type         string `json:"type"`
		Runtime      string `json:"runtime"`
		Carrier      string `json:"carrier"`
		Path         string `json:"path"`
		ArtifactJSON string `json:"artifact_json"`
		TrustPEM     string `json:"trust_pem"`
		Origin       string `json:"origin"`
		WireRevision int    `json:"wire_revision"`
		Profile      string `json:"profile"`
		Source       string `json:"source"`
	}
	var value fields
	if err := json.Unmarshal(wire, &value); err != nil {
		return err
	}
	*r = currentReady{value.Type, value.Runtime, value.Carrier, value.Path, value.ArtifactJSON, value.TrustPEM, value.Origin, value.WireRevision, value.Profile, value.Source}
	return nil
}

type currentParityState struct {
	cell                               string
	sdkExample                         bool
	ledger                             *executionLedger
	definitions                        [2]*interopharness.RPCDefinition
	notified, datagramReady, completed chan struct{}
	peerReady                          chan struct{}
	observersReady                     chan struct{}
	notificationsObserved              chan struct{}
	exampleNotificationObserved        chan struct{}
	notificationCount                  atomic.Uint32
	active                             atomic.Int32
	session                            *fs.Session
	subscription                       *fs.NotificationSubscription
}

func newCurrentParityState() *currentParityState {
	return &currentParityState{cell: "direct", ledger: newExecutionLedger(), notified: make(chan struct{}, 8), datagramReady: make(chan struct{}, 1), completed: make(chan struct{}, 1), peerReady: make(chan struct{}, 1), observersReady: make(chan struct{}), notificationsObserved: make(chan struct{}), exampleNotificationObserved: make(chan struct{})}
}

func (s *currentParityState) configure(runtime *interopharness.Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
	s.definitions[role] = interopharness.ConfigureRPC(runtime, role, parityNamespace, []interopharness.RPCMethod{
		{Type: echoRPC, Handle: func(ctx context.Context, payload []byte) ([]byte, error) {
			if err := waitSignal(ctx, s.observersReady, "notification observer admission"); err != nil {
				return nil, err
			}
			if currentJSONValue(payload, "notifications-observed") {
				// Submission alone does not prove remote application admission.
				// Confirm both observations before the client closes that gate.
				if err := waitSignal(ctx, s.notificationsObserved, "notification observations"); err != nil {
					return nil, err
				}
			} else if !currentJSONValue(payload, "ping") {
				return nil, errors.New("invalid echo payload")
			}
			s.ledger.record("rpc")
			select {
			case s.peerReady <- struct{}{}:
			default:
			}
			return append([]byte(nil), payload...), nil
		}},
		{Type: notifyRPC, Notify: true},
		{Type: completeRPC, Handle: func(ctx context.Context, payload []byte) ([]byte, error) {
			if !currentJSONValue(payload, "complete") || s.session == nil {
				return nil, errors.New("invalid completion barrier")
			}
			if err := s.session.Rekey(ctx); err != nil {
				return nil, err
			}
			s.ledger.record("rekey")
			if _, err := s.session.ProbeLiveness(ctx, 1000); err != nil {
				return nil, err
			}
			s.ledger.record("liveness")
			select {
			case s.completed <- struct{}{}:
			default:
			}
			return append([]byte(nil), payload...), nil
		}},
		{Type: datagramRPC, Handle: func(_ context.Context, payload []byte) ([]byte, error) {
			if !currentJSONValue(payload, "datagram-ready") {
				return nil, errors.New("invalid datagram barrier")
			}
			select {
			case s.datagramReady <- struct{}{}:
			default:
			}
			return append([]byte(nil), payload...), nil
		}},
	})
	config := fs.StreamHandlerPlanConfig{RuntimeBytes: 16384}
	for _, kind := range []string{echoKind, resetKind} {
		config.Handlers = append(config.Handlers, fs.RawStreamHandlerConfig{Kind: kind, Slots: 2, WorkClass: fs.WorkResident,
			AuthorizeOpen: func(_ context.Context, binding any, _ []byte) error {
				if binding != role {
					return errors.New("incorrect authenticated application lease")
				}
				return nil
			},
			Handler: func(ctx context.Context, _ any, metadata []byte, stream *fs.StreamOwnership) error {
				s.active.Add(1)
				defer s.active.Add(-1)
				expected, err := fs.NewStreamMetadata(map[string]any{"cell": s.cell})
				if err != nil {
					return err
				}
				if kind == echoKind && !bytes.Equal(metadata, expected.Bytes()) {
					return errors.New("stream metadata was not preserved")
				}
				var input [16]byte
				n := 0
				for {
					if n == len(input) {
						return errors.New("parity stream exceeds its input bound")
					}
					result, err := stream.ReadInto(ctx, input[n:])
					n += int(result.Progress.Filled)
					if errors.Is(err, io.EOF) || result.ReadTerminal == fs.ReadTerminalEof {
						break
					}
					if err != nil {
						return err
					}
				}
				if kind == resetKind {
					if string(input[:n]) != "reset" {
						return errors.New("invalid reset stream input")
					}
					s.ledger.record("stream-reset")
					return stream.Cancel()
				}
				if string(input[:n]) != "hello" {
					return errors.New("invalid echo stream input")
				}
				if s.sdkExample {
					// Submission is not remote observation. The example's reply
					// confirms its preceding notification before the client closes.
					if err := waitSignal(ctx, s.exampleNotificationObserved, "example notification observation"); err != nil {
						return err
					}
				}
				s.ledger.record("stream-metadata")
				if _, err := stream.WriteAll(ctx, []byte("world")); err != nil {
					return err
				}
				if err := stream.Finish(ctx); err != nil {
					return err
				}
				s.ledger.record("stream-fin")
				return nil
			},
		})
	}
	return config, nil
}

func currentJSONValue(wire []byte, want string) bool {
	var payload map[string]string
	return json.Unmarshal(wire, &payload) == nil && payload["value"] == want
}
func currentPayload(value string) []byte {
	wire, _ := json.Marshal(map[string]string{"value": value})
	return wire
}

func (s *currentParityState) bind(ctx context.Context, role uint8, session *fs.Session, reporter *interopharness.Reporter) (*fs.ServiceClient, error) {
	s.session = session
	subscription, err := session.SubscribeNotification(fs.MethodSelector{Namespace: parityNamespace, Type: notifyRPC}, fs.NotificationDropNewest, fs.NotificationObserver{
		Decode: func(_ context.Context, payload []byte) (any, error) {
			if !currentJSONValue(payload, "notify") {
				return nil, errors.New("invalid notification payload")
			}
			return true, nil
		},
		Handle: func(_ context.Context, value any) error {
			if value != true {
				return errors.New("notification decoder mismatch")
			}
			s.ledger.record("notification")
			select {
			case s.notified <- struct{}{}:
			default:
				return errors.New("notification observation exceeded its bound")
			}
			count := s.notificationCount.Add(1)
			if count == 1 {
				close(s.exampleNotificationObserved)
			}
			if count == 2 {
				close(s.notificationsObserved)
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("subscribe current notification: %w", err)
	}
	reporter.Cleanup(func() {
		subscription.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := subscription.WaitClosed(cleanup); err != nil {
			reporter.Error(err)
		} else {
			reporter.ErrorIf(subscription.Release())
		}
	})
	s.subscription = subscription
	close(s.observersReady)
	service, err := s.definitions[role].Bind(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("bind current contracts: %w", err)
	}
	reporter.Cleanup(func() {
		service.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reporter.ErrorIf(service.WaitCleanup(cleanup))
	})
	return service, nil
}
func (s *currentParityState) waitNotification(ctx context.Context, name string) error {
	if err := waitSignal(ctx, s.notified, name); err != nil {
		return fmt.Errorf("%w; observer status: %+v", err, s.subscription.Status())
	}
	return nil
}

func currentCall(ctx context.Context, service *fs.ServiceClient, method uint32, value string) error {
	op, err := service.PrepareMethod(ctx, fs.MethodSelector{Namespace: parityNamespace, Type: method}, currentPayload(value), fs.OperationOptions{ResponseLimitBytes: 4096, DurationMS: 10000})
	if err != nil {
		return fmt.Errorf("prepare current RPC: %w", err)
	}
	started := op.StartContext(ctx)
	var result fs.Result
	if started.Err != nil {
		err = fmt.Errorf("start current RPC: %w", started.Err)
	} else {
		result, err = op.TakeResultContext(ctx)
		if err != nil {
			err = fmt.Errorf("take current RPC result: %w", err)
		}
	}
	op.Close()
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if cleanupErr := op.WaitCleanup(cleanup); cleanupErr != nil {
		err = errors.Join(err, fmt.Errorf("clean up current RPC: %w", cleanupErr))
	}
	if err != nil {
		return fmt.Errorf("complete current RPC: %w", err)
	}
	payload := result.Payload
	if len(payload) == 0 {
		if value, ok := result.Value.([]byte); ok {
			payload = value
		}
	}
	if !currentJSONValue(payload, value) {
		return errors.New("current RPC response mismatch")
	}
	return nil
}
func currentNotify(ctx context.Context, service *fs.ServiceClient) error {
	op, err := service.PrepareNotifyMethod(ctx, fs.MethodSelector{Namespace: parityNamespace, Type: notifyRPC}, currentPayload("notify"), fs.OperationOptions{DurationMS: 10000})
	if err != nil {
		return err
	}
	started := op.Start(ctx)
	if started.Err != nil {
		op.Close()
		return started.Err
	}
	progress, err := op.WaitSubmission(ctx)
	if err == nil && !progress.MessageAccepted {
		err = fmt.Errorf("current notification was not accepted: %+v", progress)
	}
	op.Close()
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(err, op.WaitCleanup(cleanup))
}

func runCurrentDirectServer(ctx context.Context, carrier string, sdkExample bool) (err error) {
	ctx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(context.Canceled)
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	reporter.ApplicationProfile = "services"
	defer func() { err = errors.Join(err, reporter.Close()) }()
	state := newCurrentParityState()
	state.sdkExample = sdkExample
	server, err := interopharness.NewServer(ctx, reporter, interopharness.ServerOptions{Carrier: carrier, Profile: protocolv4.DHProfileX25519, Origin: parityOrigin(), Handlers: state.configure})
	if err != nil {
		return err
	}
	material := server.Material()
	artifactJSON, err := material.JSON()
	if err != nil {
		return err
	}
	browserInstallation, err := prepareCurrentBrowserInstallation(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, browserInstallation.Close()) }()
	var browserApplication interopharness.BrowserApplicationDeclaration
	if browserInstallation != nil {
		browserApplication, err = server.Runtime.OriginalBrowserApplication(1, "parity")
		if err != nil {
			return err
		}
	}
	if err = writeJSON(currentReady{Type: "ready", Runtime: "go", Carrier: carrier, Path: "direct", ArtifactJSON: artifactJSON, TrustPEM: server.TrustPEM, Origin: server.Origin, WireRevision: 4, Profile: material.Profile, Source: material.Source}); err != nil {
		return err
	}
	if err = browserInstallation.Start(ctx, cancelRun, server.Runtime, material, artifactJSON, server.TrustPEM, server.Origin, browserApplication); err != nil {
		return err
	}
	session, err := server.WaitSession(ctx)
	if err != nil {
		return err
	}
	state.ledger.record("admission")
	if sdkExample {
		err = exerciseCurrentExampleServer(ctx, session, state, reporter)
	} else {
		err = exerciseCurrentServer(ctx, session, carrier, state, reporter)
	}
	if err != nil {
		return fmt.Errorf("server workflow after %v: %w", state.ledger.snapshot(), err)
	}
	if state.active.Load() != 0 || server.Runtime.Authorized[1].Load() != 1 || server.Runtime.Released[1].Load() != 1 {
		return errors.New("accepted Session did not retire its original streams and lease exactly once")
	}
	state.ledger.record("cleanup")
	return writeJSON(map[string]any{"type": "server-result", "runtime": "go", "carrier": carrier, "path": "direct", "cases": state.ledger.snapshot(), "wire_revision": 4, "profile": material.Profile, "source": material.Source})
}

func runCurrentDirectClient(ctx context.Context, carrier string) (err error) {
	var ready currentReady
	if err = json.NewDecoder(bufio.NewReader(os.Stdin)).Decode(&ready); err != nil {
		return err
	}
	if ready.Type != "ready" || ready.Carrier != carrier || ready.Path != "direct" || ready.WireRevision != 4 || ready.ArtifactJSON == "" {
		return errors.New("invalid current ready message")
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	reporter.ApplicationProfile = "services"
	defer func() { err = errors.Join(err, reporter.Close()) }()
	state := newCurrentParityState()
	client, err := interopharness.NewClient(ctx, reporter, ready.ArtifactJSON, ready.TrustPEM, ready.Origin, state.configure)
	if err != nil {
		return fmt.Errorf("install current %s client: %w", carrier, err)
	}
	if client.Kind != carrier {
		return errors.New("signed carrier disagrees with runner carrier")
	}
	session, err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("connect current %s client: %w", carrier, err)
	}
	state.ledger.record("admission")
	if err = exerciseCurrentClient(ctx, session, carrier, state, reporter); err != nil {
		return fmt.Errorf("client workflow after %v: %w", state.ledger.snapshot(), err)
	}
	if state.active.Load() != 0 || client.Runtime.SourceAcquisitions.Load() != 1 || client.Runtime.Authorized[0].Load() != 1 || client.Runtime.Released[0].Load() != 1 {
		return errors.New("source Session did not retire its actual streams and lease exactly once")
	}
	state.ledger.record("cleanup")
	return writeJSON(map[string]any{"type": "client-result", "runtime": "go", "carrier": carrier, "path": "direct", "cases": state.ledger.snapshot(), "wire_revision": 4, "profile": ready.Profile, "source": ready.Source})
}

func exchangeCurrentDatagram(ctx context.Context, session *fs.Session, carrier string, initiator bool) error {
	if carrier == "websocket" {
		return nil
	}
	channel, err := session.UnreliableMessages()
	if err != nil {
		return err
	}
	request, response := []byte{1, 2, 3}, []byte{3, 2, 1}
	send := func(payload []byte) error {
		status, err := channel.Send(ctx, payload, fs.UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)})
		if err != nil {
			return err
		}
		if status != fs.UnreliableAccepted {
			return errors.New("native datagram was not admitted by its original provider")
		}
		return nil
	}
	if initiator {
		if err = send(request); err != nil {
			return err
		}
	}
	payload, err := channel.Receive(ctx)
	if err != nil {
		return err
	}
	want := request
	if initiator {
		want = response
	}
	if !bytes.Equal(payload, want) {
		return errors.New("native datagram payload mismatch")
	}
	if !initiator {
		return send(response)
	}
	return nil
}

// Public SDK examples declare one outbound RPC, notification and reliable stream.
// Their server uses the same original admission and handlers without requiring
// the separate bidirectional interop workload's client callbacks and barriers.
func exerciseCurrentExampleServer(ctx context.Context, session *fs.Session, state *currentParityState, reporter *interopharness.Reporter) error {
	if _, err := state.bind(ctx, 1, session, reporter); err != nil {
		return err
	}
	if err := waitSignal(ctx, state.peerReady, "example RPC"); err != nil {
		return err
	}
	if err := state.waitNotification(ctx, "example notification"); err != nil {
		return err
	}
	if _, err := session.ProbeLiveness(ctx, 1000); err != nil {
		return err
	}
	state.ledger.record("liveness")
	if err := session.WaitTermination(ctx); err != nil {
		var failure *fs.SessionError
		if ctx.Err() != nil || !errors.As(err, &failure) ||
			(failure.Code() != fs.SessionClosed && failure.Code() != fs.SessionOperationFailed) {
			return err
		}
	}
	state.ledger.record("close")
	return session.WaitCleanup(ctx)
}

func exerciseCurrentServer(ctx context.Context, session *fs.Session, carrier string, state *currentParityState, reporter *interopharness.Reporter) error {
	service, err := state.bind(ctx, 1, session, reporter)
	if err != nil {
		return err
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err = session.WaitTermination(canceled); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("passive termination cancellation: %w", err)
	}
	state.ledger.record("cancel")
	if err = currentCall(ctx, service, echoRPC, "ping"); err != nil {
		return err
	}
	if err = waitSignal(ctx, state.peerReady, "client observer readiness"); err != nil {
		return err
	}
	if err = currentNotify(ctx, service); err != nil {
		return err
	}
	if err = state.waitNotification(ctx, "client notification"); err != nil {
		return err
	}
	if err = waitSignal(ctx, state.datagramReady, "client datagram barrier"); err != nil {
		return err
	}
	if err = exchangeCurrentDatagram(ctx, session, carrier, false); err != nil {
		return err
	}
	if carrier != "websocket" {
		state.ledger.record("datagram")
	}
	if err = waitSignal(ctx, state.completed, "verified completion operations"); err != nil {
		return err
	}
	if err = state.waitNotification(ctx, "post-rekey client notification"); err != nil {
		return err
	}
	// All application proofs above must complete before observing teardown.
	// Native connection closure can overtake the final encrypted CLOSE record;
	// a passive peer then reports the opaque carrier failure, not a graceful
	// communication receipt. The client's original Drain proves its own work.
	if err = session.WaitTermination(ctx); err != nil {
		var failure *fs.SessionError
		if ctx.Err() != nil || !errors.As(err, &failure) ||
			(failure.Code() != fs.SessionClosed && failure.Code() != fs.SessionOperationFailed) {
			return fmt.Errorf("server termination: %w", err)
		}
	}
	state.ledger.record("close")
	if err = session.WaitCleanup(ctx); err != nil {
		return err
	}
	return nil
}

func exerciseCurrentClient(ctx context.Context, session *fs.Session, carrier string, state *currentParityState, reporter *interopharness.Reporter) error {
	service, err := state.bind(ctx, 0, session, reporter)
	if err != nil {
		return err
	}
	if err = currentCall(ctx, service, echoRPC, "ping"); err != nil {
		return err
	}
	if err = currentNotify(ctx, service); err != nil {
		return err
	}
	if err = state.waitNotification(ctx, "server notification"); err != nil {
		return err
	}
	metadata, err := fs.NewStreamMetadata(map[string]any{"cell": state.cell})
	if err != nil {
		return err
	}
	stream, err := session.OpenStream(ctx, echoKind, metadata)
	if err != nil {
		return err
	}
	defer stream.Close()
	if _, err = stream.WriteAll(ctx, []byte("hello")); err != nil {
		return err
	}
	if err = stream.CloseWrite(); err != nil {
		return err
	}
	payload, err := io.ReadAll(stream)
	if err != nil || string(payload) != "world" {
		return fmt.Errorf("echo stream input/FIN mismatch: %q %w", payload, err)
	}
	if err = stream.Finish(ctx); err != nil {
		return err
	}
	if err = stream.Close(); err != nil {
		return err
	}
	state.ledger.record("stream-metadata", "stream-fin")
	if err = currentCall(ctx, service, echoRPC, "ping"); err != nil {
		return err
	}
	reset, err := session.OpenStream(ctx, resetKind, fs.EmptyStreamMetadata())
	if err != nil {
		return err
	}
	if _, err = reset.WriteAll(ctx, []byte("reset")); err != nil {
		return err
	}
	if err = reset.CloseWrite(); err != nil {
		return err
	}
	_, readErr := io.ReadAll(reset)
	_ = reset.Close()
	if readErr == nil {
		return errors.New("reset stream did not produce its authenticated failure")
	}
	state.ledger.record("stream-reset")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err = session.WaitTermination(canceled); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("passive termination cancellation: %w", err)
	}
	state.ledger.record("cancel")
	if err = currentCall(ctx, service, echoRPC, "ping"); err != nil {
		return err
	}
	if err = currentCall(ctx, service, datagramRPC, "datagram-ready"); err != nil {
		return err
	}
	if err = exchangeCurrentDatagram(ctx, session, carrier, true); err != nil {
		return err
	}
	if carrier != "websocket" {
		state.ledger.record("datagram")
	}
	if err = session.Rekey(ctx); err != nil {
		return err
	}
	state.ledger.record("rekey")
	if _, err = session.ProbeLiveness(ctx, 1000); err != nil {
		return err
	}
	state.ledger.record("liveness")
	if err = currentCall(ctx, service, completeRPC, "complete"); err != nil {
		return err
	}
	if err = currentNotify(ctx, service); err != nil {
		return err
	}
	if err = currentCall(ctx, service, echoRPC, "notifications-observed"); err != nil {
		return err
	}
	if err = drainCurrentSession(ctx, session); err != nil {
		return fmt.Errorf("client drain: %w", err)
	}
	if err = session.Close(); err != nil {
		return err
	}
	state.ledger.record("close")
	if err = session.WaitCleanup(ctx); err != nil {
		return err
	}
	return nil
}

// The successful traffic path proves graceful communication before testing
// idempotent Close and physical cleanup. Immediate Close may abort the carrier
// before the peer receives CLOSE, so it cannot promise a nil peer terminal cause.
func drainCurrentSession(ctx context.Context, session *fs.Session) error {
	if err := session.Drain(5000); err != nil {
		return err
	}
	result, err := session.WaitDrain(ctx)
	if err != nil {
		return err
	}
	if result.Outcome != fs.Drained || result.Cause != nil {
		return fmt.Errorf("current parity communication did not drain: %+v", result)
	}
	// Drain freezes communication proof before the final CLOSE publication.
	// Let its original owner finish; an immediate local Close would interrupt
	// that publication and prevent the peer from observing normal termination.
	err = session.WaitTermination(ctx)
	var failure *fs.SessionError
	if err != nil && (!errors.As(err, &failure) || failure.Code() != fs.SessionClosed) {
		return fmt.Errorf("drained Session termination: %w", err)
	}
	return nil
}
