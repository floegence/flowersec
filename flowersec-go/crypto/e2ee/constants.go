package e2ee

const (
	// HandshakeMagic prefixes every handshake frame to identify protocol traffic.
	HandshakeMagic = "FSEH"
	// RecordMagic prefixes every encrypted record frame.
	RecordMagic = "FSEC"
	// ProtocolVersion is the wire-format version for E2EE framing.
	ProtocolVersion = 1
)

const (
	// HandshakeTypeInit begins the client->server handshake.
	HandshakeTypeInit uint8 = 1
	// HandshakeTypeResp is the server response with its ephemeral key and nonce.
	HandshakeTypeResp uint8 = 2
	// HandshakeTypeAck finalizes the handshake with the auth tag.
	HandshakeTypeAck uint8 = 3
)
