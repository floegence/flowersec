package flowersec

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func publicMessageDefinition(t *testing.T) MessageStreamDefinition {
	t.Helper()
	f := newPublicReferenceFixture(t)
	charge, err := MessageDefinitionCodecCharge()
	codec, err := NewMessageDefinitionCodec(f.reserve(t, charge, err))
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	wire := publicResumeVector(t, "typed_definition_fields")
	definition, err := codec.ImportDefinition(wire)
	if err != nil {
		t.Fatal(err)
	}
	opener, acceptor, err := definition.Directions(false)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := codec.Define(definition.Kind(), definition.Revision(),
		MessageDirectionDefinition{SchemaDigest: opener.SchemaDigest, Revision: opener.Revision(), MaximumBytes: opener.MaximumBytes},
		MessageDirectionDefinition{SchemaDigest: acceptor.SchemaDigest, Revision: acceptor.Revision(), MaximumBytes: acceptor.MaximumBytes})
	if err != nil || captured != definition {
		t.Fatal("local definition fields changed the canonical wire binding", captured, definition, err)
	}
	clear(wire)
	a, err := BytesMessageCodec(opener)
	if err != nil {
		t.Fatal(err)
	}
	b, err := UTF8MessageCodec(acceptor)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewMessageStreamDefinition(definition, a, b, MessageStreamOptions{
		AssemblyTimeoutMS: 1000, SendTimeoutMS: 1000, CleanupTimeoutMS: 1000, RuntimeBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPublicTypedMessageDefinitionAndRegistrationUseOriginalLocalBinding(t *testing.T) {
	definition := publicMessageDefinition(t)
	registration, err := RegisterMessageStream(definition, 2, WorkResident, nil,
		func(context.Context, any, []byte, *TypedMessageStream) error { return nil })
	if err != nil || registration.Kind != definition.Kind() || registration.Messages == nil || registration.Slots != 2 || registration.WorkClass != WorkResident {
		t.Fatal(registration, err)
	}
	if registration.Messages.Messages.Definition.Digest() != definition.Digest() {
		t.Fatal("registration replaced the original trusted definition")
	}
	if _, err := RegisterMessageStream(definition, 1, WorkResident, nil, nil); err == nil {
		t.Fatal("nil typed handler acquired a registration")
	}
	if _, err := NewMessageStreamDefinition(definition.config.Definition, definition.config.AcceptorToOpener, definition.config.OpenerToAcceptor, MessageStreamOptions{
		AssemblyTimeoutMS: 1000, SendTimeoutMS: 1000, CleanupTimeoutMS: 1000, RuntimeBytes: 8192}); err == nil {
		t.Fatal("reversed local codecs changed opener-relative definition roles")
	}
}

func TestPublicOpenMessageStreamForwardsOrdinaryMetadataAndOriginalDefinition(t *testing.T) {
	definition := publicMessageDefinition(t)
	metadata, err := NewStreamMetadataEnvelope("example/messages", 1, map[string][]byte{"scope": {1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	called := 0
	stop := errors.New("original OPEN failed")
	session := &Session{openMessages: func(gotCtx context.Context, config sessionv4.TypedMessageConfig, wire []byte) (*sessionv4.TypedMessageStream, error) {
		called++
		if gotCtx != ctx || config.Definition != definition.config.Definition || !bytes.Equal(wire, metadata.wire) {
			t.Error("public OPEN changed the original context, definition or metadata")
		}
		return nil, stop
	}}
	if _, err := session.OpenMessageStream(ctx, definition, metadata); !errors.Is(err, stop) || called != 1 {
		t.Fatal(called, err)
	}
	session.closed = true
	if _, err := session.OpenMessageStream(ctx, definition, metadata); !errors.Is(err, ErrOperationClosed) || called != 1 {
		t.Fatal("closed facade invoked a second OPEN", called, err)
	}
}

func TestPublicApplicationMessageCodecRequiresExplicitAllocation(t *testing.T) {
	definition := publicMessageDefinition(t)
	direction, _, err := definition.Directions(false)
	if err != nil {
		t.Fatal(err)
	}
	f := newPublicReferenceFixture(t)
	delegates := f.reserve(t, ResourceVector{SDKBytes: 8192, Items: 1}, nil)
	encode := func(context.Context, any) ([]byte, error) { return nil, nil }
	decode := func(context.Context, []byte) (any, error) { return nil, nil }
	if _, err := ApplicationMessageCodec(direction, encode, decode, ApplicationMessageCodecOptions{Delegates: delegates}); err == nil {
		t.Fatal("zero application allocation was treated as a bounded codec")
	}
	if _, err := ApplicationMessageCodec(direction, encode, decode, ApplicationMessageCodecOptions{
		Delegates: delegates, ApplicationBytes: 65536, Execution: MessageCodecIndependent}); err != nil {
		t.Fatal(err)
	}
}
