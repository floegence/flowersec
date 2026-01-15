package e2ee

const (
	HandshakeMagic  = "FSEH"
	RecordMagic     = "FSEC"
	ProtocolVersion = 1
)

const (
	HandshakeTypeInit uint8 = 1
	HandshakeTypeResp uint8 = 2
	HandshakeTypeAck  uint8 = 3
)
