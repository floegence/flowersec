package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func typedResultConfig(t *testing.T) TypedMessageConfig {
	t.Helper()
	wire := bytes.Replace(initialFixture(t, "typed_definition_fields"), []byte("chat/messages"), []byte("example/typed"), 1)
	decoder, err := protocolv4.NewMessageDefinitionCodec()
	if err != nil {
		t.Fatal(err)
	}
	definition, err := decoder.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	opener, acceptor, err := definition.Directions(false)
	if err != nil {
		t.Fatal(err)
	}
	a, err := BytesMessageCodec(opener)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BytesMessageCodec(acceptor)
	if err != nil {
		t.Fatal(err)
	}
	return TypedMessageConfig{Definition: definition, OpenerToAcceptor: a, AcceptorToOpener: b,
		AssemblyTimeoutMS: 3000, SendTimeoutMS: 3000, CleanupTimeoutMS: 3000, RuntimeBytes: 8192}
}

func TestTypedMessageResultsCarryDetachedCodecFactsOnBothOpenerRoles(t *testing.T) {
	for _, framing := range []string{"stream", "messages"} {
		t.Run(framing, func(t *testing.T) {
			config := typedResultConfig(t)
			reports := make(chan error, 2)
			cores, _, _, ctx := handlerCorePair(t, framing, func(role int) RawStreamHandlerConfig {
				registration, err := RegisterMessageStream(config, 1, ApplicationResident, nil,
					func(call context.Context, binding any, metadata []byte, messages *TypedMessageStream) (failure error) {
						defer func() { reports <- failure }()
						if binding != role || len(metadata) != 0 {
							return errors.New("typed handler changed the original binding or empty metadata")
						}
						inbound, _, err := config.Definition.Directions(false)
						if err != nil {
							return err
						}
						for _, expected := range [][]byte{{}, {7}, {8, 9}} {
							result, err := messages.ReceiveEncoded(call)
							if err != nil {
								return err
							}
							if !bytes.Equal(result.Payload, expected) || result.ApplicationInputDelivered ||
								result.Codec.SchemaDigest != inbound.SchemaDigest || result.Codec.Revision != inbound.Revision() {
								return errors.New("encoded message lost its payload or original inbound codec facts")
							}
							if _, err := messages.Send(call, result.Payload, MessageSendOptions{}); err != nil {
								return err
							}
						}
						if _, err := messages.ReceiveEncoded(call); !errors.Is(err, io.EOF) {
							return errors.New("clean EOF became an empty message or a decode error")
						}
						return messages.Finish(call)
					})
				if err != nil {
					t.Fatal(err)
				}
				return registration
			}, nil)
			for source := range 2 {
				messages, err := cores[source].OpenMessageStream(ctx, config, nil, streamTestDeadline(t, cores[source].Engine()))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(messages.Close)
				inbound, _, err := config.Definition.Directions(true)
				if err != nil {
					t.Fatal(err)
				}
				for index, expected := range [][]byte{{}, {7}, {8, 9}} {
					if _, err := messages.Send(ctx, expected, MessageSendOptions{}); err != nil {
						t.Fatal(err)
					}
					if index == 1 {
						result, err := messages.Receive(ctx)
						if err != nil {
							t.Fatal(err)
						}
						payload, ok := result.Value.([]byte)
						if !ok || !bytes.Equal(payload, expected) || result.ApplicationInputDelivered ||
							result.Codec.SchemaDigest != inbound.SchemaDigest || result.Codec.Revision != inbound.Revision() {
							t.Fatal("SDK private decode changed the original codec facts", result)
						}
					} else {
						result, err := messages.ReceiveEncoded(ctx)
						if err != nil || !bytes.Equal(result.Payload, expected) || result.ApplicationInputDelivered ||
							result.Codec.SchemaDigest != inbound.SchemaDigest || result.Codec.Revision != inbound.Revision() {
							t.Fatal("encoded handoff changed the original codec facts", result, err)
						}
					}
				}
				if err := messages.CloseWrite(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := messages.ReceiveEncoded(ctx); !errors.Is(err, io.EOF) {
					t.Fatal("clean EOF was not distinct from the preceding zero-length message", err)
				}
				if err := messages.Finish(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-reports:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				messages.Close()
				if err := messages.WaitCleanup(ctx); err != nil {
					t.Fatal(err)
				}
				if err := messages.CloseWrite(ctx); err != nil {
					t.Fatal("the original completed FIN observation was lost after cleanup", err)
				}
				if err := messages.Finish(ctx); err != nil {
					t.Fatal("the original authenticated drain observation was lost after cleanup", err)
				}
			}
		})
	}
}

func TestTypedMessagesUseOriginalIndependentNativeCarrierForBothOpenerRoles(t *testing.T) {
	config := typedResultConfig(t)
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			reports := make(chan error, 2)
			cores, ctx := nativeTransportCorePairPrepared(t, profile, nil,
				func(role int, f *executorFixture, plan *SessionPlanConfig) {
					registration, err := RegisterMessageStream(config, 1, ApplicationResident, nil,
						func(call context.Context, _ any, metadata []byte, messages *TypedMessageStream) (failure error) {
							defer func() { reports <- failure }()
							if len(metadata) != 0 {
								return errors.New("typed native handler received reserved wrapper metadata")
							}
							result, err := messages.ReceiveEncoded(call)
							if err != nil {
								return err
							}
							if _, err := messages.Send(call, result.Payload, MessageSendOptions{}); err != nil {
								return err
							}
							if _, err := messages.ReceiveEncoded(call); !errors.Is(err, io.EOF) {
								return errors.New("native typed peer FIN did not produce authenticated EOF")
							}
							return messages.Finish(call)
						})
					if err != nil {
						t.Fatal(err)
					}
					capture := StreamHandlerPlanConfig{Handlers: []RawStreamHandlerConfig{registration}, RuntimeBytes: 8192, ApplicationContext: role}
					charge, err := StreamHandlerPlanCharge(capture)
					if err != nil {
						t.Fatal(err)
					}
					delegates := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 8192, resourcev4.Items: 1})
					borrow, err := delegates.Borrow()
					if err != nil {
						t.Fatal(err)
					}
					plan.Handlers, err = NewStreamHandlerPlan(capture, f.executor, f.reserve(t, 1, charge), borrow)
					if err != nil {
						borrow.Release()
						t.Fatal(err)
					}
				}, func(int, *executorFixture, *SessionPlan, *RPCServicesConfig) {}, "services")
			// The fixture also starts its admitted RPC channel. Join that
			// original initializer before testing an independent typed OPEN;
			// the native provider has one ordinary opening call position.
			for _, core := range cores {
				select {
				case <-core.plan.rpc.firstReady:
				case <-ctx.Done():
					t.Fatal("original RPC channel did not initialize", ctx.Err())
				}
			}
			for opener := range 2 {
				messages, err := cores[opener].OpenMessageStream(ctx, config, nil, streamTestDeadline(t, cores[opener].Engine()))
				if err != nil {
					t.Fatalf("native typed OPEN from role %d: %v, resources=%+v", opener, err, cores[opener].plan.root.Snapshot())
				}
				t.Cleanup(messages.Close)
				payload := []byte{byte(opener + 1), 7, 9}
				if _, err := messages.Send(ctx, payload, MessageSendOptions{}); err != nil {
					t.Fatal(err)
				}
				result, err := messages.ReceiveEncoded(ctx)
				if err != nil || !bytes.Equal(result.Payload, payload) {
					t.Fatal("native typed stream lost the original independent DATA path", result, err)
				}
				if err := messages.Finish(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := messages.ReceiveEncoded(ctx); !errors.Is(err, io.EOF) {
					t.Fatal("native typed FIN was not authenticated EOF", err)
				}
			}
			for range 2 {
				select {
				case err := <-reports:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		})
	}
}
