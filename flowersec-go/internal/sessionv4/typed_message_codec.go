package sessionv4

import (
	"context"
	"unicode/utf8"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// MessageCodec binds concrete SDK code to one trusted definition direction.
// Its private implementation cannot be granted to an arbitrary marshal hook
// by a caller-supplied safety flag, callback shape or peer capability.
type MessageCodec struct {
	direction         protocolv4.MessageStreamDirection
	implementation    uint8
	encodeApplication func(context.Context, any) ([]byte, error)
	decodeApplication func(context.Context, []byte) (any, error)
	delegates         resourcev4.Reference
	delegatesOwned    bool
}

// ApplicationMessageCodec never receives the private incremental writer.
// The declared output maximum comes from the definition, while the opaque
// callback graph remains an application borrow with its own admitted backing.
// The returned byte view must describe at most MaximumBytes of backing; the
// SDK copies it before publication and never clears application-owned output.
func ApplicationMessageCodec(direction protocolv4.MessageStreamDirection, encode func(context.Context, any) ([]byte, error), decode func(context.Context, []byte) (any, error), delegates resourcev4.Reference) (MessageCodec, error) {
	c, err := primitiveMessageCodec(direction, 3)
	if err != nil || encode == nil || decode == nil {
		return MessageCodec{}, cryptov4.ErrConfiguration
	}
	if err := delegates.Check(); err != nil {
		return MessageCodec{}, err
	}
	c.encodeApplication, c.decodeApplication, c.delegates = encode, decode, delegates
	return c, nil
}

func (c MessageCodec) capture(backing resourcev4.Reference) (MessageCodec, error) {
	if c.implementation != 3 {
		return c, nil
	}
	if err := c.delegates.CheckSameEnvironment(backing); err != nil {
		return MessageCodec{}, err
	}
	ref, err := c.delegates.Borrow()
	if err != nil {
		return MessageCodec{}, err
	}
	c.delegates, c.delegatesOwned = ref, true
	return c, nil
}
func (c *MessageCodec) release() {
	if c.delegatesOwned {
		c.delegates.Release()
	}
	*c = MessageCodec{}
}

func BytesMessageCodec(direction protocolv4.MessageStreamDirection) (MessageCodec, error) {
	return primitiveMessageCodec(direction, 1)
}
func UTF8MessageCodec(direction protocolv4.MessageStreamDirection) (MessageCodec, error) {
	return primitiveMessageCodec(direction, 2)
}
func primitiveMessageCodec(direction protocolv4.MessageStreamDirection, implementation uint8) (MessageCodec, error) {
	if direction.MaximumBytes == 0 || direction.MaximumBytes > 1048576 || direction.Revision() == "" {
		return MessageCodec{}, cryptov4.ErrConfiguration
	}
	return MessageCodec{direction: direction, implementation: implementation}, nil
}
func (c MessageCodec) matches(direction protocolv4.MessageStreamDirection) bool {
	return c.implementation >= 1 && c.implementation <= 3 && c.direction == direction && (c.implementation != 3 || c.encodeApplication != nil && c.decodeApplication != nil)
}
func (c MessageCodec) inputBytes(value any) (uint64, error) {
	switch c.implementation {
	case 1:
		input, ok := value.([]byte)
		if ok && uint64(len(input)) <= uint64(c.direction.MaximumBytes) {
			return uint64(cap(input)), nil
		}
	case 2:
		input, ok := value.(string)
		if ok && uint64(len(input)) <= uint64(c.direction.MaximumBytes) {
			return uint64(len(input)), nil
		}
	case 3:
		// No getter, custom marshal hook or arbitrary object traversal is used
		// to quote an application's graph. Charge the retained interface and
		// directly known byte/string view; the rest remains application scope.
		n := uint64(unsafe.Sizeof(value))
		switch input := value.(type) {
		case []byte:
			n += uint64(cap(input))
		case string:
			n += uint64(len(input))
		}
		return n, nil
	}
	return 0, cryptov4.ErrConfiguration
}
func (c MessageCodec) encode(ctx context.Context, value any, output *messageSegments) error {
	switch c.implementation {
	case 1:
		input, ok := value.([]byte)
		if ok {
			return output.encodeBytes(input)
		}
	case 2:
		input, ok := value.(string)
		if ok {
			return output.encodeUTF8(input)
		}
	case 3:
		if err := c.delegates.Check(); err != nil {
			return err
		}
		input, err := c.encodeApplication(ctx, value)
		if err != nil {
			return ErrMessageEncodeFailed
		}
		if uint64(cap(input)) > uint64(c.direction.MaximumBytes) {
			return ErrMessageEncodeFailed
		}
		return output.append(input)
	}
	return cryptov4.ErrConfiguration
}
func (c MessageCodec) decode(input []byte) (any, error) {
	switch c.implementation {
	case 1:
		return input, nil
	case 2:
		if utf8.Valid(input) {
			return string(input), nil
		}
	}
	return nil, ErrStreamDecodeFailed
}
