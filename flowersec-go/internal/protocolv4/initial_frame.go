package protocolv4

// InitialFrameSpec is the fixed plaintext handshake mapping. It grants no
// permission to send a flight; the original connection owns phase and direction.
type InitialFrameSpec struct {
	Schema         string
	Maximum, Exact int
}

func InitialFrame(frame FrameType, sender Direction, profile string) (InitialFrameSpec, error) {
	if sender > ServerToClient {
		return InitialFrameSpec{}, ErrUnknownFrame
	}
	var schema string
	switch frame {
	case FrameNegotiate:
		schema = "ClientHello"
		if sender == ServerToClient {
			schema = "ServerHello"
		}
	case FrameAdmission:
		if sender != ClientToServer {
			return InitialFrameSpec{}, ErrUnknownFrame
		}
		schema = "FSB4"
	case FrameAdmissionResult:
		if sender != ServerToClient {
			return InitialFrameSpec{}, ErrUnknownFrame
		}
		schema = "FSA4"
	case FrameHandshake:
		p, err := Profile(profile)
		if err != nil {
			return InitialFrameSpec{}, err
		}
		if p.HandshakeMessageBytes <= 0 || p.HandshakeMessageBytes > MaxPayloadLength {
			return InitialFrameSpec{}, ErrRecordRegistry
		}
		return InitialFrameSpec{Maximum: p.HandshakeMessageBytes, Exact: p.HandshakeMessageBytes}, nil
	case FrameReady:
		schema = "READY"
	case FrameHopAuth:
		// HOP_AUTH is deliberately excluded from the direct InitialExchange.
		// Callers must carry an explicit tunnel activated-preauth context.
		return InitialFrameSpec{}, ErrHopAuthStage
	default:
		return InitialFrameSpec{}, ErrUnknownFrame
	}
	r, err := runtimeSchema()
	if err != nil {
		return InitialFrameSpec{}, err
	}
	m := r.Maps[schema]
	if m == nil {
		return InitialFrameSpec{}, ErrRecordRegistry
	}
	if m.EncodedBytes != nil {
		return InitialFrameSpec{Schema: schema, Maximum: int(*m.EncodedBytes), Exact: int(*m.EncodedBytes)}, nil
	}
	maximum, err := SchemaByteLimit(schema)
	return InitialFrameSpec{Schema: schema, Maximum: maximum}, err
}

// InitialFrameContext is the explicit phase proof required before admitting a
// HOP_AUTH frame. A frame type or ALPN alone cannot put a carrier into this
// state; the tunnel owner installs this context only after its activated
// pre-auth checks have succeeded.
type InitialFrameContext struct {
	Tunnel           bool
	ActivatedPreauth bool
	HopSenderRole    HopSenderRole
	HopPhase         HopAuthPhase
}

func InitialFrameForContext(frame FrameType, sender Direction, profile string, context InitialFrameContext) (InitialFrameSpec, error) {
	if frame == FrameHopAuth {
		if !context.Tunnel {
			return InitialFrameSpec{}, ErrHopAuthStage
		}
		return HopAuthFrameSpec(context.ActivatedPreauth, sender, context.HopSenderRole, context.HopPhase)
	}
	return InitialFrame(frame, sender, profile)
}

func (s InitialFrameSpec) CheckLength(n int) error {
	if n <= 0 || n > s.Maximum || s.Exact != 0 && n != s.Exact {
		return ErrPayloadTooLarge
	}
	return nil
}
