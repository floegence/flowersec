package protocolv4

import "encoding/binary"

// MessageFraming owns the single typed-message prefix and byte frontier. The
// enclosing Stream cursor owns actual body, deadline and budget admission. No
// allocation, decoder, resynchronization or next-message prefetch occurs here.
type MessageFraming struct {
	prefix                  [4]byte
	maximum, length, filled uint32
	header                  uint8
	admitted, complete, eof bool
	failure                 error
}

func NewMessageFraming(maximum uint32) (MessageFraming, error) {
	if maximum == 0 || maximum > 1048576 {
		return MessageFraming{}, CBORFailure("configuration_capacity")
	}
	return MessageFraming{maximum: maximum}, nil
}

func (f *MessageFraming) PrefixRemaining() int {
	if f == nil || f.failure != nil || f.eof || f.complete {
		return 0
	}
	return 4 - int(f.header)
}

// Prefix copies only the current four-byte prefix. Even if body bytes already
// exist in the authenticated Stream queue, they stay there until AdmitBody.
// The caller fixes the assembly clock when this first returns consumed > 0.
func (f *MessageFraming) Prefix(input []byte) (consumed int, err error) {
	if f == nil || f.maximum == 0 {
		return 0, CBORFailure("configuration_capacity")
	}
	if f.failure != nil {
		return 0, f.failure
	}
	if f.eof || f.complete {
		return 0, CBORFailure("message_boundary")
	}
	n := copy(f.prefix[f.header:], input)
	f.header += uint8(n)
	if f.header == 4 {
		f.length = binary.BigEndian.Uint32(f.prefix[:])
		if f.length > f.maximum {
			f.failure = CBORFailure("message_length")
			return n, f.failure
		}
	}
	return n, nil
}

func (f *MessageFraming) Length() (uint32, bool) {
	return f.length, f.header == 4 && f.failure == nil
}

// Admission includes the selected encoded/typed completion and all original
// body backing. A zero-length body still has a real message consumption gate.
func (f *MessageFraming) AdmitBody(length uint32) error {
	if f.failure != nil {
		return f.failure
	}
	if f.header != 4 || length != f.length || f.admitted || f.eof {
		return CBORFailure("message_boundary")
	}
	f.admitted = true
	f.complete = length == 0
	return nil
}

func (f *MessageFraming) BodyRemaining() uint32 {
	if !f.admitted || f.failure != nil || f.complete {
		return 0
	}
	return f.length - f.filled
}

// Body is called only after ownership has transferred from the original
// authenticated Stream queue into the cursor's admitted exact-size backing.
func (f *MessageFraming) Body(consumed uint32) error {
	if f.failure != nil {
		return f.failure
	}
	if !f.admitted || f.complete || consumed > f.length-f.filled {
		return CBORFailure("message_boundary")
	}
	f.filled += consumed
	f.complete = f.filled == f.length
	return nil
}

func (f *MessageFraming) Complete() bool { return f.complete && f.failure == nil }
func (f *MessageFraming) EOF() bool      { return f.eof && f.failure == nil }

// Consume happens only when the current value or decode-failed outcome is
// actually handed off. Canceled waits must never advance to another prefix.
func (f *MessageFraming) Consume() error {
	if f.failure != nil {
		return f.failure
	}
	if !f.complete {
		return CBORFailure("message_boundary")
	}
	clear(f.prefix[:])
	f.header, f.length, f.filled = 0, 0, 0
	f.admitted, f.complete = false, false
	return nil
}

// EOF at a pristine prefix is normal. An authenticated EOF after a complete
// retained body preserves that candidate; partial prefix/body is always local
// framing failure and the owning adapter must terminate its whole Stream.
func (f *MessageFraming) End() error {
	if f.failure != nil {
		return f.failure
	}
	if f.header != 0 && !f.complete {
		f.failure = CBORFailure("message_truncated")
		return f.failure
	}
	f.eof = true
	return nil
}
