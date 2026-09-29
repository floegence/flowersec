package sessionv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// This application definition selects explicit bytes, positions of 1..256
// bytes, and the existing type 5 reader. The reader's request is the three
// original digests followed by a position; its response is three flags,
// commit/expiry timestamps, length, digest and any available payload.
type retainedStreamFixture struct {
	wire, readWire     []byte
	policy, readPolicy protocolv4.ServiceContractPolicy
	shape, readShape   [32]byte
	calls              atomic.Uint32
	saved              ledgerv4.SQLiteContentObservation
}

func (f *retainedStreamFixture) prepare(t *testing.T) {
	t.Helper()
	if f.wire != nil {
		return
	}
	definition := []byte{0xa6}
	fields := []string{"explicit-selected-bytes", "bytes:1..256", "", "target96+position", "flags3+commit8+expiry8+length4+sha256+payload", "missing-or-expired-without-payload"}
	for i, text := range fields {
		definition = append(definition, byte(i))
		if i == 2 {
			definition = append(definition, 5)
			continue
		}
		if len(text) < 24 {
			definition = append(definition, 0x60+byte(len(text)))
		} else {
			definition = append(definition, 0x78, byte(len(text)))
		}
		definition = append(definition, text...)
	}
	original := initialFixture(t, "service_stream_retained")
	at := bytes.Index(original, []byte{0x18, 0x1c})
	if at < 0 {
		t.Fatal("content fixture changed")
	}
	f.wire = append([]byte(nil), original[:at]...)
	f.wire = bytes.Replace(f.wire, []byte{1, 1, 2, 1}, []byte{1, 4, 2, 1}, 1)
	// content_commit origin; 60 s; two positions; 64 bytes total.
	f.wire = append(f.wire, []byte{0x18, 0x1c, 0xa7, 0, 1, 1, 1, 2, 0x19, 0xea, 0x60, 3, 2, 4, 0x18, 0x40, 5, 0x69}...)
	f.wire = append(f.wire, "content/1"...)
	f.wire = append(f.wire, 6, 0x58, byte(len(definition)))
	f.wire = append(f.wire, definition...)
	f.readWire = bytes.Replace(initialFixture(t, "service_unary_transient"), []byte{1, 1, 2, 0}, []byte{1, 5, 2, 0}, 1)
	for i, wire := range [][]byte{f.wire, f.readWire} {
		codec, err := protocolv4.NewServiceContractCodec(256)
		if err != nil {
			t.Fatal(err)
		}
		contract, err := codec.Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := contract.Policy()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			f.policy = policy
			f.shape, err = contract.MethodShapeDigest()
		} else {
			f.readPolicy = policy
			f.readShape, err = contract.MethodShapeDigest()
		}
		contract.Release()
		if err != nil {
			t.Fatal(err)
		}
	}
}
func (f *retainedStreamFixture) configure(c *ledgerv4.SQLiteExecutionConfig) {
	c.ContentItemsPerOperation, c.ContentBytesPerOperation, c.ContentItemBytes = 2, 64, 32
	c.Methods = append(c.Methods, ledgerv4.SQLiteExecutionMethod{Type: 4, Shape: f.shape, ContentDefinition: f.policy.Content.Definition, ContentReadType: 5}, ledgerv4.SQLiteExecutionMethod{Type: 5, Shape: f.readShape})
}
func (f *retainedStreamFixture) client(c *RPCServicesConfig) {
	c.Routes.Methods = append(c.Routes.Methods,
		rpcv4.MethodRoutes{Contracts: [][]byte{f.wire}, ContentDefinition: f.policy.Content.Definition, OfferWindowMS: 1000,
			InitialOffers: []protocolv4.AdmissionOfferBounds{{Digest: f.policy.Digest, NotBeforeMS: 1200, NotAfterMS: 2200}}, AdvertisedContract: f.policy.Digest},
		rpcv4.MethodRoutes{Contracts: [][]byte{f.readWire}, AdvertisedContract: f.readPolicy.Digest})
}
func (f *retainedStreamFixture) install(t *testing.T, s *resumeLiveServerFixture, c *RPCServicesConfig, initial ledgerv4.SQLiteExecutionRegistration) {
	t.Helper()
	if s.reopenPath == "" {
		var scratch [8192]byte
		latest, err := s.storage.store.ReadRegistration(context.Background(), s.businessPolicy.Digest, scratch[:], func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		bounds := initial.Offers[0]
		if _, err := s.storage.store.InstallContract(context.Background(), latest.Revision, f.wire, []timev4.Interval{{LowerMS: bounds.NotBeforeMS, UpperMS: bounds.NotAfterMS}}, true, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	f.client(c)
	c.StreamSlots = 1
	c.StreamMethods = []StreamRegistration{{Method: 2, Namespace: f.policy.Namespace, Type: 4, ContractDigest: f.policy.Digest, Kind: "example/content", Handler: func(ctx context.Context, _ StreamRequest, stream *StreamMessages) (uint32, error) {
		f.calls.Add(1)
		saved, err := stream.SaveContent(ctx, []byte{1}, []byte("one"))
		if err != nil {
			return 0, err
		}
		again, err := stream.SaveContent(ctx, []byte{1}, []byte("one"))
		if err != nil {
			return 0, err
		}
		if saved != again || !saved.Available {
			return 0, errors.New("save renewed original content")
		}
		f.saved = saved
		if err = stream.SendItemEncoded(ctx, []byte("one"), 0); err != nil {
			return 0, err
		}
		// An ordinary sent item is intentionally not retained.
		return 0, stream.SendItemEncoded(ctx, []byte("two"), 0)
	}}}
	c.Methods = append(c.Methods, UnaryRegistration{Method: 3, Namespace: f.policy.Namespace, Type: 5, Handler: func(ctx context.Context, request UnaryRequest, response *UnaryResponse) (uint32, error) {
		input, _, err := request.Input.Bytes()
		if err != nil {
			return 0, err
		}
		if len(input) != 97 {
			return 0, errors.New("invalid content query")
		}
		target := rpcv4.ExecutionTarget{Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: f.policy.Namespace}, Caller: rpcv4.ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}, Operation: [32]byte(input[:32]), RequestDigest: [32]byte(input[32:64]), ContractDigest: [32]byte(input[64:96])}
		var payload [32]byte
		observation, n, err := response.ReadRetainedContent(ctx, target, input[96:], payload[:])
		if err != nil {
			return 0, err
		}
		var result [87]byte
		if observation.Found {
			result[0] = 1
		}
		if observation.Available {
			result[1] = 1
		}
		if observation.Expired {
			result[2] = 1
		}
		binary.BigEndian.PutUint64(result[3:], observation.CommittedAtMS)
		binary.BigEndian.PutUint64(result[11:], observation.ExpiresAtMS)
		binary.BigEndian.PutUint32(result[19:], observation.Bytes)
		copy(result[23:55], observation.Digest[:])
		copy(result[55:], payload[:n])
		_, err = response.Write(result[:55+n])
		return 0, err
	}})
}
func (f *retainedStreamFixture) bind(t *testing.T, core *SessionCore, ctx context.Context) *UnaryServiceClient {
	t.Helper()
	decode := func(_ context.Context, p []byte) (any, error) { return string(p), nil }
	definition := ServiceDefinition{Namespace: f.policy.Namespace, Methods: []ServiceMethod{
		{Shape: 1, Type: 4, StreamKind: "example/content", Method: UnaryMethodDefinition{Contract: f.policy.Digest, Decode: decode, DefaultResponseLimitBytes: 1024}},
		{Shape: 0, Type: 5, Method: UnaryMethodDefinition{Contract: f.readPolicy.Digest, Decode: decode, DefaultResponseLimitBytes: 1024}},
	}}
	client, err := core.plan.rpc.bindMethods(ctx, definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}
func TestDurableStreamExplicitContentReopensThroughAuthorizedReadMethod(t *testing.T) {
	first := &resumeLiveServerFixture{issueViaRPC: true, deferTarget: true, content: &retainedStreamFixture{}}
	cores, _, _, _, ctx := resumeSessionPair(t, first)
	client := first.content.bind(t, cores[0], ctx)
	operation, err := client.PrepareStreamingMethod(ctx, 4, nil, rpcv4.UnaryPreparation{DefaultLifetimeMS: 6000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(operation.Close)
	reference, err := operation.Reference()
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.Start(ctx).Error; err != nil {
		t.Fatal(err)
	}
	if value, _, err := operation.ReadNext(ctx); err != nil || value != "one" {
		t.Fatal("retained first item", value, err)
	}
	if value, _, err := operation.ReadNextEncoded(ctx); err != nil || string(value) != "two" {
		t.Fatal("unretained second item", string(value), err)
	}
	if _, status, err := operation.ReadNext(ctx); !errors.Is(err, io.EOF) || !status.EOF {
		t.Fatal(status, err)
	}
	operation.Close()
	client.Close()
	if err := operation.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	first.stopPair()
	first.storage.shutdown()
	second := &resumeLiveServerFixture{issueViaRPC: true, deferTarget: true, reopenPath: first.storage.path, content: &retainedStreamFixture{}}
	cores, _, _, _, ctx = resumeSessionPair(t, second)
	client = second.content.bind(t, cores[0], ctx)
	query, err := cores[0].plan.rpc.referenceManagement(ctx, reference, false, 5000)
	if err != nil || query.Status != "ok" || query.Observation.State != rpcv4.ExecutionCompleted || query.Observation.ResultAvailable {
		t.Fatal("stream history is not a unary result", query, err)
	}
	target := reference.Target()
	for _, position := range []byte{1, 2} {
		var request [97]byte
		copy(request[:32], target.Operation[:])
		copy(request[32:64], target.RequestDigest[:])
		copy(request[64:96], target.ContractDigest[:])
		request[96] = position
		read, err := client.PrepareMethod(ctx, 5, request[:], rpcv4.UnaryPreparation{DefaultLifetimeMS: 6000})
		if err != nil {
			t.Fatal(err)
		}
		if err := read.Start(ctx).Error; err != nil {
			read.Close()
			t.Fatal(err)
		}
		value, status, err := read.TakeEncodedResult(ctx)
		read.Close()
		if err != nil || !status.Delivered {
			t.Fatal("authorized content read", status, err)
		}
		if position == 1 {
			if len(value) != 58 || value[0] != 1 || value[1] != 1 || value[2] != 0 || string(value[55:]) != "one" || binary.BigEndian.Uint64(value[3:]) != first.content.saved.CommittedAtMS || binary.BigEndian.Uint64(value[11:]) != first.content.saved.ExpiresAtMS {
				t.Fatal("retained bytes or fixed timestamps changed", value)
			}
		} else if len(value) != 55 || value[0] != 0 || value[1] != 0 || value[2] != 0 {
			t.Fatal("sent item became retained", value)
		}
		if err := read.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if first.content.calls.Load() != 1 || second.content.calls.Load() != 0 {
		t.Fatal("content read replayed generator")
	}
	client.Close()
}
