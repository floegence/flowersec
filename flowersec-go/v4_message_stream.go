package flowersec

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// MessageWireDefinition is an immutable canonical declaration. Importing one
// establishes its local binding only; it does not grant remote OPEN authority.
type MessageWireDefinition = protocolv4.MessageStreamDefinition
type MessageStreamDirection = protocolv4.MessageStreamDirection
type MessageDirectionDefinition = protocolv4.MessageDirectionDefinition
type MessageCodec = sessionv4.MessageCodec
type MessageCodecExecution = sessionv4.MessageCodecExecution

var (
	ErrMessageWouldBlock     = sessionv4.ErrMessageWouldBlock
	ErrMessageEncodeFailed   = sessionv4.ErrMessageEncodeFailed
	ErrMessageDecodeFailed   = sessionv4.ErrStreamDecodeFailed
	ErrMessageInputDelivered = sessionv4.ErrStreamInputDelivered
)

const (
	MessageCodecSynchronous = sessionv4.MessageCodecSynchronous
	MessageCodecIndependent = sessionv4.MessageCodecIndependent
)

// MessageDefinitionCodec owns admitted parsing workspace. Each returned
// definition is detached from that workspace and survives its Close.
type MessageDefinitionCodec struct {
	mu          sync.Mutex
	inner       *protocolv4.MessageDefinitionCodec
	reservation resourcev4.Reference
}

func MessageDefinitionCodecCharge() (ResourceVector, error) {
	bytes, err := protocolv4.MessageDefinitionCodecBackingBytes()
	if err != nil {
		return ResourceVector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: bytes + uint64(unsafe.Sizeof(MessageDefinitionCodec{})), resourcev4.Items: 1}, nil
}

func NewMessageDefinitionCodec(reservation ResourceReference) (*MessageDefinitionCodec, error) {
	charge, err := MessageDefinitionCodecCharge()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	inner, err := protocolv4.NewMessageDefinitionCodec()
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &MessageDefinitionCodec{inner: inner, reservation: owned}, nil
}

func (c *MessageDefinitionCodec) ImportDefinition(wire []byte) (MessageWireDefinition, error) {
	if c == nil {
		return MessageWireDefinition{}, ErrOperationClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner == nil {
		return MessageWireDefinition{}, ErrOperationClosed
	}
	if err := c.reservation.Check(); err != nil {
		return MessageWireDefinition{}, err
	}
	return c.inner.Decode(wire)
}

// Define captures local fields through the same canonical encoder and parser
// used to import definitions; application code need not assemble CBOR bytes.
func (c *MessageDefinitionCodec) Define(kind, revision string, openerToAcceptor, acceptorToOpener MessageDirectionDefinition) (MessageWireDefinition, error) {
	if c == nil {
		return MessageWireDefinition{}, ErrOperationClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner == nil {
		return MessageWireDefinition{}, ErrOperationClosed
	}
	if err := c.reservation.Check(); err != nil {
		return MessageWireDefinition{}, err
	}
	return c.inner.Define(kind, revision, openerToAcceptor, acceptorToOpener)
}

func (c *MessageDefinitionCodec) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inner = nil
	c.reservation.Release()
	c.reservation = resourcev4.Reference{}
}

func BytesMessageCodec(direction MessageStreamDirection) (MessageCodec, error) {
	return sessionv4.BytesMessageCodec(direction)
}

func UTF8MessageCodec(direction MessageStreamDirection) (MessageCodec, error) {
	return sessionv4.UTF8MessageCodec(direction)
}

// ApplicationMessageCodecOptions admits opaque application allocation before
// callback entry. Delegates owns the captured callback graph; ApplicationBytes
// covers callback allocation beyond known input and maximum encoded output.
// The declaration is a resource bound, never permission to use the SDK writer.
type ApplicationMessageCodecOptions = sessionv4.ApplicationMessageCodecOptions

func ApplicationMessageCodec(direction MessageStreamDirection, encode func(context.Context, any) ([]byte, error), decode func(context.Context, []byte) (any, error), options ApplicationMessageCodecOptions) (MessageCodec, error) {
	return sessionv4.ApplicationMessageCodecWithOptions(direction, encode, decode, options)
}

// MessageStreamOptions is trusted local lifecycle policy. It is absent from
// the wire definition and cannot be increased by a peer's OPEN metadata.
type MessageStreamOptions struct {
	AssemblyTimeoutMS uint64
	SendTimeoutMS     uint64
	CleanupTimeoutMS  uint64
	RuntimeBytes      uint64
}

func NewMessageStreamDefinition(wire MessageWireDefinition, openerToAcceptor, acceptorToOpener MessageCodec, options MessageStreamOptions) (MessageStreamDefinition, error) {
	config := sessionv4.TypedMessageConfig{Definition: wire, OpenerToAcceptor: openerToAcceptor, AcceptorToOpener: acceptorToOpener,
		AssemblyTimeoutMS: options.AssemblyTimeoutMS, SendTimeoutMS: options.SendTimeoutMS, CleanupTimeoutMS: options.CleanupTimeoutMS, RuntimeBytes: options.RuntimeBytes}
	if err := sessionv4.ValidateTypedMessageConfig(config); err != nil {
		return MessageStreamDefinition{}, err
	}
	return MessageStreamDefinition{config: config}, nil
}

func (d MessageStreamDefinition) Kind() string     { return d.config.Definition.Kind() }
func (d MessageStreamDefinition) Revision() string { return d.config.Definition.Revision() }
func (d MessageStreamDefinition) Digest() [32]byte { return d.config.Definition.Digest() }
func (d MessageStreamDefinition) Directions(localOpener bool) (MessageStreamDirection, MessageStreamDirection, error) {
	return d.config.Definition.Directions(localOpener)
}

// RegisterMessageStream installs a typed declaration in the existing frozen
// Stream plan. Slots includes authorization and actual handler execution.
// Metadata is the original ordinary application shell, without typed wrapping.
func RegisterMessageStream(definition MessageStreamDefinition, slots uint32, class WorkClass, authorize func(context.Context, any, []byte) error, handler func(context.Context, any, []byte, *TypedMessageStream) error) (RawStreamHandlerConfig, error) {
	if handler == nil {
		return RawStreamHandlerConfig{}, cryptov4.ErrConfiguration
	}
	return sessionv4.RegisterMessageStream(definition.config, slots, class, authorize,
		func(ctx context.Context, binding any, metadata []byte, inner *sessionv4.TypedMessageStream) error {
			return handler(ctx, binding, metadata, &TypedMessageStream{inner: inner})
		})
}

func (s *Session) OpenMessageStream(ctx context.Context, definition MessageStreamDefinition, metadata StreamMetadata) (*TypedMessageStream, error) {
	if s == nil || s.openMessages == nil || ctx == nil {
		return nil, ErrTransportUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrOperationClosed
	}
	inner, err := s.openMessages(ctx, definition.config, metadata.wire)
	if err != nil {
		return nil, err
	}
	// Cancellation/Close racing facade handoff disposes the original claimed
	// owner. It cannot restore the OPEN ordinal or raw I/O qualification.
	if err := ctx.Err(); err != nil {
		inner.Close()
		return nil, err
	}
	s.mu.Lock()
	closed = s.closed
	s.mu.Unlock()
	if closed {
		inner.Close()
		return nil, ErrOperationClosed
	}
	return &TypedMessageStream{inner: inner}, nil
}

func (m *TypedMessageStream) Definition() MessageWireDefinition {
	if m == nil || m.inner == nil {
		return MessageWireDefinition{}
	}
	return m.inner.Definition()
}

// CopyApplicationMetadata copies into caller-owned storage; the caller chooses
// its allocation and no uncharged detached SDK buffer is created.
func (m *TypedMessageStream) CopyApplicationMetadata(dst []byte) (int, error) {
	if m == nil || m.inner == nil {
		return 0, ErrTransportUnavailable
	}
	return m.inner.CopyApplicationMetadata(dst)
}
