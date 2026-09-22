package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"

// StreamFlow joins the two directions of an accepted Stream. The Session owns
// OPEN arbitration, terminal tokens, rekey barriers and eventual retirement;
// this object owns data/credit/terminal facts for the original association.
type StreamFlow struct {
	send          *SendFlow
	receive       *ReceiveFlow
	nativeReceive *NativeDataAssembly
}

func NewStreamFlow(send *SendFlow, receive *ReceiveFlow) (*StreamFlow, error) {
	if send == nil || receive == nil || send.writer.scope != receive.scope || send.direction == receive.direction {
		return nil, ErrStreamData
	}
	receive.pool.mu.Lock()
	defer receive.pool.mu.Unlock()
	if receive.engine != nil {
		return nil, ErrStreamData
	}
	receive.engine = send.writer.engine
	return &StreamFlow{send: send, receive: receive}, nil
}

func tupleValue(value protocolv4.Value) (TerminalTuple, error) {
	epoch, a := value.Named("terminal_tuple", "epoch").Uint()
	sequence, b := value.Named("terminal_tuple", "next_sequence").Uint()
	offset, c := value.Named("terminal_tuple", "offset").Uint()
	if !a || !b || !c || epoch > uint64(^uint32(0)) {
		return TerminalTuple{}, ErrTerminal
	}
	return TerminalTuple{Epoch: uint32(epoch), NextSequence: sequence, Offset: offset}, nil
}

// Apply consumes only authenticated, still-owned records. The Session invokes
// this before releasing its receiver slot and before handing data to an app.
func (s *StreamFlow) Apply(record *ReceivedRecord) (err error) {
	if record == nil || record.receiver.engine != s.send.writer.engine {
		return ErrStreamData
	}
	defer record.acceptOnSuccess(&err)
	frame, err := record.Body()
	if err != nil {
		return err
	}
	if frame.Type == protocolv4.FrameStreamData {
		if err := record.receiver.engine.ApplicationInputReady(frame.Header.Epoch); err != nil {
			return err
		}
		return s.receive.ApplyData(frame)
	}
	if frame.Type != protocolv4.FrameStreamAck {
		return ErrStreamData
	}
	scope, ok := frame.Field("stream_id").Uint()
	if !ok || scope != s.receive.scope {
		return ErrStreamData
	}
	direction, ok := frame.Field("direction").Uint()
	if !ok {
		return ErrStreamData
	}
	switch frame.Schema {
	case "STREAM_ACK_CREDIT":
		if direction != uint64(s.send.direction) {
			return ErrStreamData
		}
		ack, ok := frame.Field("ack_offset").Uint()
		limit, yes := frame.Field("receive_limit").Uint()
		if !ok || !yes {
			return ErrCredit
		}
		return s.send.ApplyCredit(ack, limit)
	case "STREAM_ACK_STOP":
		if direction != uint64(s.send.direction) {
			return ErrStreamData
		}
		s.send.Stop()
		return nil
	case "STREAM_ACK_STOPPED":
		if direction != uint64(s.receive.direction) {
			return ErrStreamData
		}
		epoch, a := frame.Field("final_epoch").Uint()
		sequence, b := frame.Field("final_next_sequence").Uint()
		offset, c := frame.Field("final_offset").Uint()
		if !a || !b || !c {
			return ErrTerminal
		}
		return s.receive.ApplyStopped(TerminalTuple{Epoch: uint32(epoch), NextSequence: sequence, Offset: offset})
	case "STREAM_ACK_DRAINED":
		if direction != uint64(s.send.direction) {
			return ErrStreamData
		}
		terminal, err := tupleValue(frame.Field("terminal_tuple"))
		if err != nil {
			return err
		}
		observed, err := tupleValue(frame.Field("observed_tuple"))
		if err != nil {
			return err
		}
		outcome, ok := frame.Field("outcome").Uint()
		aborted, err := protocolv4.EnumValue(frame.Schema, "outcome", "aborted")
		if err != nil || !ok {
			return ErrTerminal
		}
		return s.send.ApplyDrained(DrainProof{Terminal: terminal, Observed: observed, Aborted: outcome == aborted})
	default:
		return ErrStreamData
	}
}

func encodeTuple(dst []byte, tuple TerminalTuple) ([]byte, error) {
	fields := [...]protocolv4.Field{{Name: "epoch", Number: uint64(tuple.Epoch)}, {Name: "next_sequence", Number: tuple.NextSequence}, {Name: "offset", Number: tuple.Offset}}
	return protocolv4.EncodeMap(dst, "terminal_tuple", fields[:])
}

func (s *StreamFlow) EncodeStopped(dst []byte) ([]byte, error) {
	tuple, ok := s.send.Terminal()
	if !ok {
		return nil, ErrTerminal
	}
	variant, err := protocolv4.ConstantField("STREAM_ACK_STOPPED", "variant")
	if err != nil {
		return nil, err
	}
	fields := [...]protocolv4.Field{variant, {Name: "stream_id", Number: s.receive.scope}, {Name: "direction", Number: uint64(s.send.direction)}, {Name: "final_epoch", Number: uint64(tuple.Epoch)}, {Name: "final_next_sequence", Number: tuple.NextSequence}, {Name: "final_offset", Number: tuple.Offset}}
	return protocolv4.EncodeMap(dst, "STREAM_ACK_STOPPED", fields[:])
}

func (s *StreamFlow) EncodeStop(dst []byte) ([]byte, error) {
	variant, err := protocolv4.ConstantField("STREAM_ACK_STOP", "variant")
	if err != nil {
		return nil, err
	}
	fields := [...]protocolv4.Field{variant, {Name: "stream_id", Number: s.receive.scope}, {Name: "direction", Number: uint64(s.receive.direction)}}
	return protocolv4.EncodeMap(dst, "STREAM_ACK_STOP", fields[:])
}

func (s *StreamFlow) EncodeDrained(dst []byte) ([]byte, error) {
	proof, ok := s.receive.DrainProof()
	if !ok {
		return nil, ErrTerminal
	}
	return s.encodeDrainProof(dst, proof)
}

// Admission may retain this exact immutable proof after receive backing has
// been cleaned, for permitted repeated terminal replies before retirement.
func (s *StreamFlow) encodeDrainProof(dst []byte, proof DrainProof) ([]byte, error) {
	var first, second [64]byte
	terminal, err := encodeTuple(first[:], proof.Terminal)
	if err != nil {
		return nil, err
	}
	observed, err := encodeTuple(second[:], proof.Observed)
	if err != nil {
		return nil, err
	}
	variant, err := protocolv4.ConstantField("STREAM_ACK_DRAINED", "variant")
	if err != nil {
		return nil, err
	}
	label := "drained"
	if proof.Aborted {
		label = "aborted"
	}
	outcome, err := protocolv4.EnumValue("STREAM_ACK_DRAINED", "outcome", label)
	if err != nil {
		return nil, err
	}
	fields := [...]protocolv4.Field{variant, {Name: "stream_id", Number: s.receive.scope}, {Name: "direction", Number: uint64(s.receive.direction)}, {Name: "terminal_tuple", Kind: protocolv4.EncodedMap, Bytes: terminal}, {Name: "outcome", Number: outcome}, {Name: "observed_tuple", Kind: protocolv4.EncodedMap, Bytes: observed}}
	return protocolv4.EncodeMap(dst, "STREAM_ACK_DRAINED", fields[:])
}

// CloseResult preserves wire and application facts independently of cleanup.
// In particular neither local provider exit nor Reset can invent send_drained
// or read EOF. Public adapters attach their own callback cleanup obligations.
func (s *StreamFlow) CloseResult() protocolv4.V4CloseResult {
	_, _, _, drained, sendClean := s.send.Snapshot()
	_, _, _, readTerminal := s.receive.Snapshot()
	s.receive.pool.mu.Lock()
	receiveClean := s.receive.cleaned
	s.receive.pool.mu.Unlock()
	direction := protocolv4.V4DirectionC2s
	if s.send.direction == protocolv4.ServerToClient {
		direction = protocolv4.V4DirectionS2c
	}
	cleanup := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if sendClean && receiveClean {
		cleanup.Status = protocolv4.V4CleanupStateComplete
		cleanup.CoreCleanup = protocolv4.V4CoreCleanupComplete
	}
	return protocolv4.V4CloseResult{Direction: direction, SendDrained: drained, ReadTerminal: readTerminal, CleanupStatus: cleanup}
}
