package protocolv4

import "sync"

var initialTextCapacity = sync.OnceValues(func() (int, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	return schemaTextCapacity(r, []string{
		"ClientHello", "ServerHello", "FSB4", "FSA4", "READY",
		"HOP_AUTH_HELLO", "HOP_AUTH_ENDPOINT_PROOF", "HOP_AUTH_RELAY_PROOF",
		"TransportContext",
	})
})

// InitialDecoderBackingBytes retains the full frame and node capacities while
// bounding Unicode workspaces by the generated initial handshake schemas.
func InitialDecoderBackingBytes(byteCap, nodeCap int) (uint64, error) {
	textCap, err := initialTextCapacity()
	if err != nil {
		return 0, err
	}
	return decoderBackingBytes(byteCap, nodeCap, min(byteCap, textCap))
}

func NewInitialDecoder(byteCap, nodeCap int) (*Decoder, error) {
	textCap, err := initialTextCapacity()
	if err != nil {
		return nil, err
	}
	return newDecoder(byteCap, nodeCap, min(byteCap, textCap))
}
