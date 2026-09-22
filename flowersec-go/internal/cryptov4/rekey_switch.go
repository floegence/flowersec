package cryptov4

import (
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

var ErrInputPending = errors.New("cryptov4: original application epoch pending")

// NativeDataInputReady lets a complete original native candidate wait in its
// receive promise until the ACK transition, without borrowing a full crypto
// position. It never admits an unknown future epoch or authenticates a header.
func (e *Engine) NativeDataInputReady(header protocolv4.RecordHeader) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.inputLive(); err != nil {
		return err
	}
	if err := protocolv4.ValidateRecordScope(protocolv4.FrameStreamData, header.Scope); err != nil {
		return err
	}
	epoch, err := e.receiveEpoch(protocolv4.FrameStreamData, header, nil)
	if err != nil {
		return err
	}
	if epoch != e.current {
		return ErrInputPending
	}
	return nil
}

// epochSwitch is protected by the Engine gate. Its direction gates are separate:
// COMMIT opens client maintenance while server maintenance still uses old keys.
type epochSwitch struct {
	round                                      *RekeyRound
	installed, sent, received, markerPreparing bool
}

// ApplicationInputReady is a delivery gate, separate from authenticated private
// input admission. A future frame keeps its existing receiver reservation until
// the original ACK completes; there is no new per-stream future-frame queue.
func (e *Engine) ApplicationInputReady(epoch uint32) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	if epoch > e.current.number {
		return ErrTransition
	}
	return nil
}

func (r *RekeyRound) BelongsTo(engine *Engine) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && r.engine == engine
}

func (e *Engine) sendEpoch(scope uint64) *epochState {
	if e.switching != nil && e.switching.sent && e.staged != nil {
		return e.staged
	}
	return e.current
}

func (e *Engine) receiveEpoch(frame protocolv4.FrameType, header protocolv4.RecordHeader, marker *RekeyRound) (*epochState, error) {
	s := e.switching
	if header.Epoch == e.current.number {
		if marker != nil || s != nil && s.received {
			return nil, ErrEpoch
		}
		return e.current, nil
	}
	if s == nil || e.staged == nil || header.Epoch != e.staged.number {
		return nil, ErrEpoch
	}
	if err := e.staged.deadline.Check(); err != nil {
		return nil, securityTimeError(err)
	}
	if marker != nil {
		if s.round != marker || !s.installed || s.received || header.Scope != 0 || header.Sequence != 0 || frame != protocolv4.FrameRekey {
			return nil, ErrTransition
		}
		return e.staged, nil
	}
	if header.Scope == 0 && s.received {
		return e.staged, nil
	}
	// New application input remains private at the Session delivery gate. The
	// client can receive it after COMMIT; the server only after its ACK ticket.
	if header.Scope != 0 && s.sent {
		return e.staged, nil
	}
	return nil, ErrTransition
}

// InstallCandidate reserves both epoch key sets without enabling any future
// record. It is valid only for this original, fully verified INIT/REPLY pair.
func (r *RekeyRound) InstallCandidate() (err error) {
	if err = r.begin(); err != nil {
		return err
	}
	defer func() { err = r.end(err) }()
	if r.state != 2 {
		return ErrRekey
	}
	return r.engine.stageEpoch(r.root, r.born, r)
}

// ArmMarker enables only the unique scope0/seq0 receive key. The caller invokes
// this at the server's actual REPLY ticket or before the client's COMMIT ticket.
func (r *RekeyRound) ArmMarker() (err error) {
	if err = r.begin(); err != nil {
		return err
	}
	defer func() { err = r.end(err) }()
	e := r.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	if r.state != 2 || e.switching == nil || e.switching.round != r || e.switching.installed {
		return ErrTransition
	}
	e.switching.installed = true
	return nil
}

// SealMarker is called only by the original scope0 publisher after its peer
// barrier and required DRAINED tickets are satisfied. Holding its one output
// workspace proves that previous old maintenance publication has really exited.
// The frontier is captured before MAC work; competing maintenance cannot ticket
// until this exact immutable marker has consumed the new sequence zero.
func (r *RekeyRound) SealMarker() (packet *Packet, err error) {
	return r.SealMarkerTicket(nil)
}

// SealMarkerTicket applies only original bounded accounting at the marker's
// actual ticket; the server ACK anchor is not a late provider callback timestamp.
// The hook has SealBuildTicket's restrictions.
func (r *RekeyRound) SealMarkerTicket(ticket func() error) (packet *Packet, err error) {
	if err = r.begin(); err != nil {
		return nil, err
	}
	nextEpoch := r.epoch.number + 1
	defer func() {
		err = r.end(err)
		if err != nil && packet != nil {
			packet.Release()
			packet = nil
			err = &TicketError{Cause: err, Header: protocolv4.RecordHeader{Epoch: nextEpoch}}
		}
	}()
	e := r.engine
	e.mu.Lock()
	if err := e.live(); err != nil {
		e.mu.Unlock()
		return nil, err
	}
	s := e.switching
	if s == nil || s.round != r || !s.installed || s.sent || s.markerPreparing || e.freeze == nil || !e.freeze.committed || e.maintenance[e.config.SendDirection] == nil || r.state != 2 && r.state != 3 {
		e.mu.Unlock()
		return nil, ErrTransition
	}
	if e.config.SendDirection == protocolv4.ServerToClient && (!s.received || r.state != 3) || e.config.SendDirection == protocolv4.ClientToServer && r.state != 2 {
		e.mu.Unlock()
		return nil, ErrRekey
	}
	frontier := e.current.keys.get(0).keys[e.config.SendDirection].next
	s.markerPreparing = true
	e.mu.Unlock()
	schema := "REKEY_COMMIT"
	if e.config.SendDirection == protocolv4.ServerToClient {
		schema = "REKEY_ACK"
	}
	wire, err := r.buildMarker(r.reply, schema, frontier)
	if err != nil {
		return nil, err
	}
	packet, err = e.sealBuild(protocolv4.FrameRekey, 0, len(wire), func(_ protocolv4.RecordHeader, dst []byte) (int, error) { return copy(dst, wire), nil }, r, ticket, nil)
	if err != nil {
		return nil, err
	}
	if e.config.SendDirection == protocolv4.ClientToServer {
		r.state = 3
	} else {
		r.state = 4
	}
	return packet, nil
}

// OpenRekeyMarker authenticates a future marker with the one preinstalled key.
// decode is the original receiver's bounded parser. The phase MAC, transaction,
// transcript and exact authenticated old frontier are mandatory before the
// receive gate changes; callers cannot bypass them with a permissive validator.
func (e *Engine) OpenRekeyMarker(input []byte, decode func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) (*protocolv4.Frame, error)) (packet *Packet, body *protocolv4.Frame, err error) {
	if decode == nil {
		return nil, nil, ErrConfiguration
	}
	e.mu.Lock()
	r := e.rekey
	e.mu.Unlock()
	if r == nil {
		return nil, nil, ErrTransition
	}
	if err = r.begin(); err != nil {
		return nil, nil, err
	}
	decoded := false
	defer func() {
		if err == ErrCapacity && !decoded {
			err = r.endUnattempted()
		} else {
			err = r.end(err)
		}
		if err != nil {
			if packet != nil {
				packet.Release()
				packet = nil
			}
			if body != nil {
				body.Release()
				body = nil
			}
		}
	}()
	schema := "REKEY_COMMIT"
	state := uint8(2)
	if e.config.SendDirection == protocolv4.ClientToServer {
		schema = "REKEY_ACK"
		state = 3
	}
	if r.state != state {
		return nil, nil, ErrRekey
	}
	packet, _, _, err = e.open(input, func(frame protocolv4.FrameType, header protocolv4.RecordHeader, plain []byte) error {
		decoded = true
		var decodeErr error
		body, decodeErr = decode(frame, header, plain)
		if decodeErr != nil {
			return decodeErr
		}
		e.mu.Lock()
		if err := e.live(); err != nil {
			e.mu.Unlock()
			return err
		}
		if e.rekey != r || e.current != r.epoch {
			e.mu.Unlock()
			return ErrTransition
		}
		frontier := e.current.keys.get(0).keys[1-e.config.SendDirection].next
		e.mu.Unlock()
		return r.verifyMarker(body, schema, frontier)
	}, r)
	if err != nil {
		return packet, body, err
	}
	if e.config.SendDirection == protocolv4.ServerToClient {
		r.state = 3
	} else {
		r.state = 4
	}
	return packet, body, nil
}

// Complete follows the server ACK ticket or the client's authenticated ACK.
// Application resumption remains owned by the original Session barrier owner.
func (r *RekeyRound) Complete() error {
	if err := r.begin(); err != nil {
		return err
	}
	e := r.engine
	e.mu.Lock()
	if err := e.live(); err != nil {
		e.mu.Unlock()
		return r.end(err)
	}
	if r.state != 4 || e.switching == nil || e.switching.round != r || !e.switching.sent || !e.switching.received || e.staged == nil {
		e.mu.Unlock()
		return r.end(ErrTransition)
	}
	old := e.current
	e.current = e.staged
	e.staged = nil
	e.switching = nil
	clear(old.root[:])
	e.recycleScopeTable(&old.keys)

	e.mu.Unlock()
	r.mu.Lock()
	r.busy = false
	r.closed = true
	r.cleanup()
	r.mu.Unlock()
	return nil
}
