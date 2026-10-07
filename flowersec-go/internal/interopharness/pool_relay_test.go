package interopharness

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/gorilla/websocket"
)

func TestTunnelNativeUpgradePrecedesAllowAndRetiresUnusedSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reporter := func() *Reporter {
		r, err := NewPeerReporter()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
		return r
	}
	relay, err := NewPoolRelay(ctx, reporter(), [2]string{"websocket", "websocket"}, "https://parity.example", PoolRelayOptions{EndpointListeners: [2]bool{false, true}})
	if err != nil {
		t.Fatal(err)
	}
	publication, err := relay.EndpointMaterialsJSON()
	if err != nil {
		t.Fatal(err)
	}
	serverReporter := reporter()
	server, err := NewTunnelServer(ctx, serverReporter, publication[1], relay.TrustPEM, relay.Origin, manualEchoPlan,
		TunnelServerOptions{TLSCertificatePEM: relay.ServerTLSCertificatePEM, TLSPrivateKeyPEM: relay.ServerTLSPrivateKeyPEM})
	if err != nil {
		t.Fatal(err)
	}
	address, _, _, err := materialRoute(server.Client.Material.Route, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoder, _ := protocolv4.NewDecoder(16384, 1024)
	route, err := decoder.DecodeMap(server.Client.Material.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	leg := route.Root().Named("Route", "server_leg")
	host, _ := leg.Named("Leg", "host").Text()
	path, _ := leg.Named("Leg", "path").Text()
	route.Release()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(relay.TrustPEM)) {
		t.Fatal("missing independently installed TLS root")
	}
	dialer := websocket.Dialer{HandshakeTimeout: time.Second, Subprotocols: []string{"flowersec.tunnel.v4"},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: host, NextProtos: []string{"http/1.1"}},
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address.String())
		}}
	connection, _, err := dialer.DialContext(ctx, "wss://"+net.JoinHostPort(host, fmt.Sprint(address.Port()))+path, http.Header{"Origin": []string{relay.Origin}})
	if err != nil {
		t.Fatal("native upgrade waited for the later server allow", err)
	}
	defer connection.Close()
	if server.delivered || server.allowed || server.accepted || server.Client.Runtime.Authorized[1].Load() != 0 {
		t.Fatal("native preparation granted application authority")
	}
	if err := serverReporter.Close(); err != nil {
		t.Fatal("unused native preparation did not retire", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("unused upgraded socket remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("cleanup returned before closing the physical socket", err)
	}
}

// Each case constructs real PoolService issuance, independent original stores,
// namespace bootstrap, native carriers and the public endpoint admission path.
// No cleanup counts or reconstructed receipts substitute for their joins.
func TestOriginalPoolPublicationAndTunnelNativeDirections(t *testing.T) {
	for _, carriers := range [][2]string{{"websocket", "websocket"}, {"websocket", "raw-quic"}, {"raw-quic", "websocket"}, {"raw-quic", "raw-quic"}} {
		for _, endpointListeners := range [][2]bool{{false, false}, {false, true}, {true, false}, {true, true}} {
			t.Run(fmt.Sprintf("%s_to_%s_client_listener_%t_server_listener_%t", carriers[0], carriers[1], endpointListeners[0], endpointListeners[1]), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				reporter := func() *Reporter {
					result, err := NewPeerReporter()
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := result.Close(); err != nil {
							t.Error(err)
						}
					})
					return result
				}
				relay, err := NewPoolRelay(ctx, reporter(), carriers, "https://parity.example", PoolRelayOptions{EndpointListeners: endpointListeners})
				if err != nil {
					t.Fatal(err)
				}
				publication, err := relay.EndpointMaterialsJSON()
				if err != nil {
					t.Fatal(err)
				}
				var original [2]Material
				for side, wire := range publication {
					if err := json.Unmarshal([]byte(wire), &original[side]); err != nil {
						t.Fatal(err)
					}
					if original[side].Role != uint8(side) || original[side].Source != "preauthorized_pool" || len(original[side].Tunnels) != 2 {
						t.Fatal("whole original endpoint publication was not retained")
					}
				}
				if !bytes.Equal(original[0].Artifact, original[1].Artifact) || !bytes.Equal(original[0].Activation, original[1].Activation) || !reflect.DeepEqual(original[0].Tunnels, original[1].Tunnels) || !reflect.DeepEqual(original[0].Namespaces, original[1].Namespaces) {
					t.Fatal("paired records reconstructed different signed bytes or namespace pins")
				}
				if original[0].RelayDeployment != original[1].RelayDeployment || original[0].RelayDeployment.RouteDigest != [32]byte(original[0].RouteDigest) {
					t.Fatal("paired records lost their independently installed relay deployment")
				}
				decoder, err := protocolv4.NewDecoder(16384, 1024)
				if err != nil {
					t.Fatal(err)
				}
				route, err := decoder.DecodeMap(original[0].Route, "Route", protocolv4.DecodeContext{})
				if err != nil {
					t.Fatal(err)
				}
				for side, name := range []string{"client_leg", "server_leg"} {
					leg := route.Root().Named("Route", name)
					endpoint, endpointOK := leg.Named("Leg", "endpoint_role").Uint()
					dialer, dialerOK := leg.Named("Leg", "dialer_role").Uint()
					listener, listenerOK := leg.Named("Leg", "listener_role").Uint()
					wantDialer, wantListener := uint64(side), uint64(2)
					if endpointListeners[side] {
						wantDialer, wantListener = 2, uint64(side)
					}
					if !endpointOK || !dialerOK || !listenerOK || endpoint != uint64(side) || dialer != wantDialer || listener != wantListener {
						t.Fatal("physical direction changed logical endpoint or Grant side")
					}
				}
				route.Release()
				handlerResult := make(chan error, 1)
				configure := func(runtime *Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
					ConfigureRPC(runtime, role, "flowersec.publication.regression", []RPCMethod{{Type: 7001, Handle: func(ctx context.Context, input []byte) ([]byte, error) {
						return append([]byte(nil), input...), ctx.Err()
					}}})
					return fs.StreamHandlerPlanConfig{RuntimeBytes: 16384, Handlers: []fs.RawStreamHandlerConfig{{
						Kind: "original_tunnel_v1", Slots: 1, WorkClass: fs.WorkResident,
						AuthorizeOpen: func(ctx context.Context, binding any, _ []byte) error {
							if binding != role {
								return errors.New("wrong original application lease")
							}
							return ctx.Err()
						},
						Handler: func(ctx context.Context, _ any, _ []byte, stream *fs.StreamOwnership) (err error) {
							defer func() { handlerResult <- err }()
							var payload [64]byte
							filled := 0
							for {
								result, readErr := stream.ReadInto(ctx, payload[filled:])
								filled += int(result.Progress.Filled)
								if result.ReadTerminal == fs.ReadTerminalEof || errors.Is(readErr, io.EOF) {
									break
								}
								if readErr != nil {
									return readErr
								}
								if filled == len(payload) {
									return errors.New("regression stream exceeded its bound")
								}
							}
							if !bytes.Equal(payload[:filled], []byte("original publication")) {
								return errors.New("opaque tunnel altered application bytes")
							}
							if _, err = stream.Write(ctx, payload[:filled]); err != nil {
								return err
							}
							if err = stream.CloseWrite(ctx); err != nil {
								return err
							}
							return stream.Finish(ctx)
						},
					}}}, nil
				}
				server, err := NewTunnelServer(ctx, reporter(), publication[1], relay.TrustPEM, relay.Origin, configure, TunnelServerOptions{TLSCertificatePEM: relay.ServerTLSCertificatePEM, TLSPrivateKeyPEM: relay.ServerTLSPrivateKeyPEM})
				if err != nil {
					t.Fatal(err)
				}
				installed, binding, err := server.LocalPoolClientConfiguration()
				if err != nil {
					t.Fatal(err)
				}
				client, err := NewClient(ctx, reporter(), publication[0], relay.TrustPEM, relay.Origin, configure, ClientOptions{TLSCertificatePEM: relay.ClientTLSCertificatePEM, TLSPrivateKeyPEM: relay.ClientTLSPrivateKeyPEM, PoolClientDeployment: installed, ServerAllowBinding: binding})
				if err != nil {
					t.Fatal(err)
				}
				relay.Start()
				if err := server.DeliverOriginalAllow(ctx); err == nil {
					t.Fatal("pool server published Allow outside original client Connect")
				}
				type acceptResult struct {
					session *fs.Session
					err     error
				}
				accepted := make(chan acceptResult, 1)
				go func() { session, err := server.Accept(ctx); accepted <- acceptResult{session, err} }()
				session, err := client.Connect(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = session.Close()
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					if err := session.WaitCleanup(cleanup); err != nil {
						t.Error(err)
					}
				})
				var remote *fs.Session
				select {
				case result := <-accepted:
					if result.err != nil {
						t.Fatal(result.err)
					}
					remote = result.session
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				t.Cleanup(func() {
					_ = remote.Close()
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					if err := remote.WaitCleanup(cleanup); err != nil {
						t.Error(err)
					}
				})
				metadata, err := fs.NewStreamMetadata(map[string]any{"publication": "original"})
				if err != nil {
					t.Fatal(err)
				}
				stream, err := session.OpenStream(ctx, "original_tunnel_v1", metadata)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				if _, err := stream.Write([]byte("original publication")); err != nil {
					t.Fatal(err)
				}
				if err := stream.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				reply, err := io.ReadAll(io.LimitReader(stream, 65))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(reply, []byte("original publication")) {
					t.Fatal("original stream FIN/payload did not cross both actual native legs")
				}
				if err := stream.Finish(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-handlerResult:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			})
		}
	}
}
